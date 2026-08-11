"""Durable, verified construction of provider-compatible RSI candidates."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Callable, Mapping, Sequence

from .events import EventEnvelope
from .hooks import LifecycleError, canonical_digest
from .sanitize import sanitize_evidence
from .storage import EventStore, StoreIntegrityError
from .validation import observation_digest, validate_observation


KINDS = frozenset({"procedure", "gotcha", "fact", "reference", "script-opportunity"})
CHANGE_CLASSES = frozenset({"knowledge", "behavior"})
DESTINATION_CLASSES = frozenset({"skill", "reference", "script", "profile", "agents"})
RISKS = frozenset({"low", "medium", "high"})
_NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_SCOPE_RE = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*\Z")
_DEDUPE_RE = re.compile(r"[a-z0-9]+(?:[.:-][a-z0-9]+)*\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EVALUATION_FIELDS = frozenset(
    {
        "runId", "eventId", "evaluationId", "observationEventId", "targetSkill",
        "targetSkillVersionHash", "taskClass", "evaluatorVersion", "baselineRef",
        "hardInvariantsPassed", "metricDeltas", "findingRefs", "findings", "decision",
        "requestDigest", "verificationBinding",
    }
)
_SEED_FIELDS = frozenset(
    {
        "sourceSkill", "targetSkill", "targetSkillVersionHash", "kind", "changeClass",
        "scope", "destinationClass", "dedupeKey", "relatedSkills", "targetHint", "title",
        "finding", "evidence", "confidence", "risk", "novel", "causallyRelated",
    }
)


@dataclass(frozen=True, slots=True)
class ImprovementCandidateDraft:
    evaluation_id: str
    operation_id: str
    source_skill: str
    target_skill: str
    kind: str
    change_class: str
    scope: str
    destination_class: str
    dedupe_key: str
    related_skills: tuple[str, ...]
    target_hint: str | None
    title: str
    finding: str
    evidence: tuple[str, ...]
    confidence: float
    risk: str

    def canonical_mapping(self) -> dict[str, object]:
        return {
            "evaluationId": self.evaluation_id,
            "operationId": self.operation_id,
            "sourceSkill": self.source_skill,
            "targetSkill": self.target_skill,
            "kind": self.kind,
            "changeClass": self.change_class,
            "scope": self.scope,
            "destinationClass": self.destination_class,
            "dedupeKey": self.dedupe_key,
            "relatedSkills": list(self.related_skills),
            "targetHint": self.target_hint,
            "title": self.title,
            "finding": self.finding,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "risk": self.risk,
        }


def _strict_json(data: bytes, label: str) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    if (
        not data
        or not data.endswith(b"\n")
        or b"\r" in data
        or data[:-1].endswith((b"\n", b" ", b"\t"))
    ):
        raise LifecycleError(f"durable {label} is unavailable")
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON number")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise LifecycleError(f"durable {label} is unavailable") from None


def _safe_text(
    value: object,
    label: str,
    limit: int,
    *,
    max_output_chars: int | None = None,
) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or value != value.strip():
        raise LifecycleError(f"candidate {label} is invalid")
    result = sanitize_evidence(
        [{"kind": "candidate", "summary": value}],
        max_output_chars=max_output_chars,
    )
    if result.rejected_count or result.truncated_count or len(result.accepted) != 1:
        raise LifecycleError(f"candidate {label} is unsafe")
    admitted = result.accepted[0]["summary"]
    if admitted != value:
        raise LifecycleError(f"candidate {label} contains a task-specific identifier")
    return value


def _safe_hint(value: object) -> str | None:
    if value is None:
        return None
    hint = _safe_text(value, "targetHint", 500)
    path = PurePosixPath(hint)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts) or "\\" in hint:
        raise LifecycleError("candidate targetHint is unsafe")
    return hint


def validate_candidate_seed(
    value: object, *, declared_targets: Sequence[tuple[str, str]]
) -> dict[str, object]:
    """Admit one complete seed before it can be persisted or hashed."""
    if not isinstance(value, Mapping) or set(value) != set(_SEED_FIELDS) or any(not isinstance(key, str) for key in value):
        raise LifecycleError("candidate seed has an invalid schema")
    source = value["sourceSkill"]
    target = value["targetSkill"]
    version = value["targetSkillVersionHash"]
    if not isinstance(source, str) or not _NAME_RE.fullmatch(source):
        raise LifecycleError("candidate sourceSkill is invalid")
    if not isinstance(target, str) or not _NAME_RE.fullmatch(target):
        raise LifecycleError("candidate targetSkill is invalid")
    if not isinstance(version, str) or not _DIGEST_RE.fullmatch(version):
        raise LifecycleError("candidate target version is invalid")
    declared = set(declared_targets)
    if (target, version) not in declared or source not in {name for name, _ in declared}:
        raise LifecycleError("candidate target binding is invalid")
    kind = value["kind"]
    change_class = value["changeClass"]
    destination = value["destinationClass"]
    risk = value["risk"]
    if kind not in KINDS or change_class not in CHANGE_CLASSES or destination not in DESTINATION_CLASSES or risk not in RISKS:
        raise LifecycleError("candidate enums are invalid")
    compatible = {
        "knowledge": {"skill", "reference", "agents"},
        "behavior": {"skill", "script", "profile", "agents"},
    }
    if destination not in compatible[str(change_class)]:
        raise LifecycleError("candidate destination is incompatible with change class")
    if kind == "script-opportunity" and (change_class, destination) != ("behavior", "script"):
        raise LifecycleError("script opportunity must be a behavior script candidate")
    scope = value["scope"]
    dedupe = value["dedupeKey"]
    if not isinstance(scope, str) or len(scope) > 200 or not _SCOPE_RE.fullmatch(scope):
        raise LifecycleError("candidate scope is invalid")
    scope = _safe_text(scope, "scope", 200)
    if not isinstance(dedupe, str) or len(dedupe) > 200 or not _DEDUPE_RE.fullmatch(dedupe):
        raise LifecycleError("candidate dedupeKey is invalid")
    dedupe = _safe_text(dedupe, "dedupeKey", 200)
    related = value["relatedSkills"]
    if not isinstance(related, list) or len(related) > 32 or any(not isinstance(item, str) or not _NAME_RE.fullmatch(item) for item in related):
        raise LifecycleError("candidate relatedSkills are invalid")
    canonical_related = sorted({_safe_text(item, "relatedSkill", 64) for item in related})
    evidence = value["evidence"]
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 5:
        raise LifecycleError("candidate evidence is invalid")
    admitted_evidence = sorted({_safe_text(item, "evidence", 1200) for item in evidence})
    if not admitted_evidence:
        raise LifecycleError("candidate evidence is invalid")
    confidence = value["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise LifecycleError("candidate confidence is invalid")
    if value["novel"] is not True or value["causallyRelated"] is not True:
        raise LifecycleError("candidate must be novel and causally related")
    return {
        "sourceSkill": source,
        "targetSkill": target,
        "targetSkillVersionHash": version,
        "kind": kind,
        "changeClass": change_class,
        "scope": scope,
        "destinationClass": destination,
        "dedupeKey": dedupe,
        "relatedSkills": canonical_related,
        "targetHint": _safe_hint(value["targetHint"]),
        "title": _safe_text(value["title"], "title", 120),
        "finding": _safe_text(
            value["finding"], "finding", 2000, max_output_chars=2000
        ),
        "evidence": admitted_evidence,
        "confidence": float(confidence),
        "risk": risk,
        "novel": True,
        "causallyRelated": True,
    }


def candidate_seed_digest(seed: Mapping[str, object]) -> str:
    return canonical_digest(seed)


def evaluation_digest(evaluation: Mapping[str, object]) -> str:
    semantic = {key: evaluation[key] for key in sorted(_EVALUATION_FIELDS - {"requestDigest"})}
    try:
        encoded = json.dumps(
            semantic,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise LifecycleError("durable evaluation contains a non-canonical value") from None
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class CandidateBuilder:
    """Reconstruct a deterministic task-wide candidate set from durable objects."""

    def __init__(self, store: EventStore, *, max_candidates: int = 3) -> None:
        self.store = store
        if type(max_candidates) is not int:
            raise LifecycleError("candidate limit must be an integer")
        self.max_candidates = max(0, min(3, max_candidates))

    def build(self, evaluation: Mapping[str, object]) -> list[ImprovementCandidateDraft]:
        events = self.store.read_events()
        return self.build_from_snapshot(
            evaluation,
            events,
            lambda relative: self.store.read_sidecar(self.store.home / "objects" / relative),
        )

    def build_from_snapshot(
        self,
        evaluation: Mapping[str, object],
        events: Sequence[EventEnvelope],
        read_object: Callable[[str], bytes],
    ) -> list[ImprovementCandidateDraft]:
        """Build from one already-locked journal snapshot and its object reader."""
        supplied = self._bound_evaluation(evaluation, events, read_object)
        all_evaluations = self._run_evaluations(str(supplied["runId"]), events, read_object)
        drafts: list[ImprovementCandidateDraft] = []
        for durable in all_evaluations:
            if (
                durable["decision"] != "candidate-worthy"
                or durable["hardInvariantsPassed"] is not True
                or not durable["findingRefs"]
            ):
                continue
            event = self._event(str(durable["eventId"]), "evaluation.completed", events)
            if event.payload["evidenceStatus"] != "verified":
                continue
            for finding_ref in durable["findingRefs"]:
                seed = self._bound_seed(str(finding_ref), durable, events, read_object)
                drafts.append(self._draft(durable, seed))
        deduped: dict[tuple[str, str], ImprovementCandidateDraft] = {}
        for draft in drafts:
            key = (draft.target_skill, draft.dedupe_key)
            previous = deduped.get(key)
            if previous is None:
                deduped[key] = draft
            elif previous.canonical_mapping() != draft.canonical_mapping():
                raise LifecycleError("durable candidate dedupe key has conflicting semantics")
        selected = sorted(
            deduped.values(),
            key=lambda item: (item.target_skill, item.scope, item.dedupe_key, item.title, item.finding),
        )[: self.max_candidates]
        return [item for item in selected if item.evaluation_id == supplied["evaluationId"]]

    @staticmethod
    def _event(event_id: str, event_type: str, events: Sequence[EventEnvelope]) -> EventEnvelope:
        event = next((item for item in events if item.event_id == event_id and item.event_type == event_type), None)
        if event is None:
            raise LifecycleError(f"durable {event_type} event is absent")
        return event

    def _bound_evaluation(
        self,
        supplied: Mapping[str, object],
        events: Sequence[EventEnvelope],
        read_object: Callable[[str], bytes],
    ) -> dict[str, object]:
        if not isinstance(supplied, Mapping) or set(supplied) != set(_EVALUATION_FIELDS):
            raise LifecycleError("durable evaluation is invalid")
        event_id = supplied.get("eventId")
        if not isinstance(event_id, str):
            raise LifecycleError("durable evaluation is invalid")
        event = self._event(event_id, "evaluation.completed", events)
        if event.payload_ref != f"evaluations/{event_id}.json":
            raise LifecycleError("durable evaluation binding is invalid")
        try:
            try:
                raw = read_object(str(event.payload_ref))
            except (OSError, StoreIntegrityError):
                raise LifecycleError("durable evaluation is unavailable") from None
        except (OSError, StoreIntegrityError):
            raise LifecycleError("durable evaluation is unavailable") from None
        durable = _strict_json(raw, "evaluation")
        if not isinstance(durable, dict) or durable != dict(supplied) or set(durable) != set(_EVALUATION_FIELDS):
            raise LifecycleError("supplied evaluation conflicts with durable evaluation")
        digest = evaluation_digest(durable)
        if durable["requestDigest"] != digest or event.correlation_id != digest:
            raise LifecycleError("durable evaluation digest is inconsistent")
        if (
            durable["runId"] != event.run_id
            or durable["targetSkill"] != event.payload["targetSkill"]
            or durable["baselineRef"] != event.payload["baseline"]
            or durable["metricDeltas"] != dict(event.payload["metricDeltas"])
        ):
            raise LifecycleError("durable evaluation event binding is inconsistent")
        observation = self._event(str(durable["observationEventId"]), "task.observed", events)
        if observation.event_id != event.causation_id or observation.payload["verificationStatus"] != "verified" or event.payload["evidenceStatus"] != "verified":
            raise LifecycleError("durable evaluation lacks trusted verification")
        if observation.payload_ref != f"observations/{observation.event_id}.json":
            raise LifecycleError("durable observation binding is invalid")
        try:
            observation_value = _strict_json(
                read_object(str(observation.payload_ref)),
                "observation",
            )
            admitted_observation = validate_observation(observation_value)
        except (OSError, StoreIntegrityError, LifecycleError):
            raise LifecycleError("durable observation is unavailable") from None
        observation_request_digest = observation_digest(admitted_observation)
        if (
            admitted_observation["requestDigest"] != observation_request_digest
            or observation.correlation_id != observation_request_digest
            or admitted_observation["runId"] != durable["runId"]
            or admitted_observation["outcome"] not in {"verified-success", "verified-failure"}
            or observation.payload["taskOutcome"] != admitted_observation["outcome"]
            or list(observation.payload["targetSkillHashes"]) != [item["versionHash"] for item in admitted_observation["targetSkills"]]
        ):
            raise LifecycleError("durable observation binding is inconsistent")
        target_matches = [
            item for item in admitted_observation["targetSkills"]
            if item["name"] == durable["targetSkill"] and item["versionHash"] == durable["targetSkillVersionHash"]
        ]
        if len(target_matches) != 1 or durable["evaluationId"] != f"evaluation:{durable['runId']}:{durable['targetSkill']}":
            raise LifecycleError("durable evaluation target binding is inconsistent")
        verification = durable["verificationBinding"]
        observation_bindings = admitted_observation["verificationBindings"]
        if (
            not isinstance(verification, Mapping)
            or set(verification) != {"targetRoot", "contractRoots"}
            or not isinstance(observation_bindings, Mapping)
        ):
            raise LifecycleError("durable evaluation verification binding is invalid")
        observation_target_roots = observation_bindings["targetRoots"]
        observation_contract_roots = observation_bindings["contractRoots"]
        assert isinstance(observation_target_roots, list) and isinstance(observation_contract_roots, list)
        expected_target_roots = [
            item for item in observation_target_roots
            if isinstance(item, Mapping)
            and item.get("name") == durable["targetSkill"]
            and item.get("versionHash") == durable["targetSkillVersionHash"]
        ]
        expected_target = dict(expected_target_roots[0]) if expected_target_roots else None
        if (
            len(expected_target_roots) > 1
            or verification["targetRoot"] != expected_target
            or verification["contractRoots"] != observation_contract_roots
        ):
            raise LifecycleError("durable evaluation verification binding is inconsistent")
        finding_refs = durable["findingRefs"]
        if not isinstance(finding_refs, list) or len(finding_refs) > 32 or any(not isinstance(item, str) for item in finding_refs) or len(set(finding_refs)) != len(finding_refs):
            raise LifecycleError("durable evaluation finding references are invalid")
        return durable

    def _run_evaluations(
        self,
        run_id: str,
        events: Sequence[EventEnvelope],
        read_object: Callable[[str], bytes],
    ) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        for event in events:
            if event.run_id != run_id or event.event_type != "evaluation.completed":
                continue
            if event.payload_ref != f"evaluations/{event.event_id}.json":
                raise LifecycleError("durable evaluation binding is invalid")
            raw = read_object(str(event.payload_ref))
            value = _strict_json(raw, "evaluation")
            if not isinstance(value, dict):
                raise LifecycleError("durable evaluation is invalid")
            results.append(self._bound_evaluation(value, events, read_object))
        return results

    def _bound_seed(
        self,
        finding_ref: str,
        evaluation: Mapping[str, object],
        events: Sequence[EventEnvelope],
        read_object: Callable[[str], bytes],
    ) -> dict[str, object]:
        if not finding_ref.startswith("event:"):
            raise LifecycleError("durable finding reference is invalid")
        event_id = finding_ref.removeprefix("event:")
        event = self._event(event_id, "finding.drafted", events)
        if event.run_id != evaluation["runId"] or event.payload_ref != f"findings/{event_id}.json":
            raise LifecycleError("durable finding binding is invalid")
        try:
            raw = read_object(str(event.payload_ref))
        except (OSError, StoreIntegrityError):
            raise LifecycleError("durable finding is unavailable") from None
        value = _strict_json(raw, "finding")
        started = next((item for item in events if item.run_id == event.run_id and item.event_type == "run.started"), None)
        if started is None:
            raise LifecycleError("durable run start is absent")
        declared = []
        for identity in started.payload["activeSkills"]:
            name, separator, digest = str(identity).partition("@")
            if not separator:
                raise LifecycleError("durable run target identity is invalid")
            declared.append((name, digest))
        seed = validate_candidate_seed(value, declared_targets=declared)
        if (
            value != seed
            or event.correlation_id != candidate_seed_digest(seed)
            or event.payload["targetSkill"] != seed["targetSkill"]
            or event.payload["proposedScope"] != seed["scope"]
            or event.payload["summary"] != seed["title"]
        ):
            raise LifecycleError("durable finding digest is inconsistent")
        if (seed["targetSkill"], seed["targetSkillVersionHash"]) != (evaluation["targetSkill"], evaluation["targetSkillVersionHash"]):
            raise LifecycleError("durable finding target does not match evaluation")
        observation_id = str(evaluation["observationEventId"])
        by_id = {item.event_id: item for item in events if item.run_id == evaluation["runId"]}
        current = by_id.get(observation_id)
        ancestors: set[str] = set()
        while current is not None and current.causation_id is not None:
            ancestors.add(current.causation_id)
            current = by_id.get(current.causation_id)
        if event_id not in ancestors:
            raise LifecycleError("durable finding is outside the observation causal chain")
        return seed

    @staticmethod
    def _draft(evaluation: Mapping[str, object], seed: Mapping[str, object]) -> ImprovementCandidateDraft:
        semantics = {
            "evaluationId": evaluation["evaluationId"],
            **{key: seed[key] for key in sorted(_SEED_FIELDS - {"targetSkillVersionHash", "novel", "causallyRelated"})},
        }
        digest = hashlib.sha256(json.dumps(semantics, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
        return ImprovementCandidateDraft(
            evaluation_id=str(evaluation["evaluationId"]),
            operation_id="rsi-capture-" + digest[:48],
            source_skill=str(seed["sourceSkill"]),
            target_skill=str(seed["targetSkill"]),
            kind=str(seed["kind"]),
            change_class=str(seed["changeClass"]),
            scope=str(seed["scope"]),
            destination_class=str(seed["destinationClass"]),
            dedupe_key=str(seed["dedupeKey"]),
            related_skills=tuple(seed["relatedSkills"]),  # type: ignore[arg-type]
            target_hint=seed["targetHint"] if isinstance(seed["targetHint"], str) else None,
            title=str(seed["title"]),
            finding=str(seed["finding"]),
            evidence=tuple(seed["evidence"]),  # type: ignore[arg-type]
            confidence=float(seed["confidence"]),
            risk=str(seed["risk"]),
        )
