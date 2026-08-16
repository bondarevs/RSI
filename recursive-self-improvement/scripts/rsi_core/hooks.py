"""Observe-only orchestration hooks backed by the strict RSI event journal."""
from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from .events import EventEnvelope, derive_idempotency_key
from .storage import EventStore, StoreIntegrityError
from .target_identity import (
    ContractRootBinding,
    TargetRootBinding,
    build_verification_bindings,
)
from .validation import (
    HOOK_MODES,
    MODES,
    LifecycleError,
    target_identity,
    validate_cli_identifiers,
    validate_evidence,
    validate_finding,
    validate_targets,
    validate_task_class,
)


PRODUCER_VERSION = "1.0.0"
MAX_DRAFTS = 3
LATE_REVIEW_WARNING = "late-review: in-dialog-only signals were unavailable"
_ATTESTED_CLOCK_DOMAIN = "rsi-dry-run-attested-clock-v1"
_ATTESTED_NOW_ENV = "CODEX_RSI_ATTESTED_NOW"
_ATTESTED_CLOCK_ENV = "CODEX_RSI_ATTESTED_CLOCK_AUTHORITY"
_UTC_SECONDS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerificationResult:
    outcome: str
    run_id: str
    task_fingerprint: str
    target_skills: tuple[tuple[str, str], ...]
    artifact_digest: str
    target_root_bindings: tuple[TargetRootBinding, ...] = ()
    contract_root_bindings: tuple[ContractRootBinding, ...] = ()

    @classmethod
    def success(
        cls,
        run_id: str,
        task_fingerprint: str,
        targets: Sequence[Mapping[str, str]],
        artifact_digest: str,
        *,
        target_roots: Sequence[Path | str] | None = None,
        contract_roots: Sequence[Path | str] | None = None,
    ) -> "VerificationResult":
        target_bindings: tuple[TargetRootBinding, ...] = ()
        contract_bindings: tuple[ContractRootBinding, ...] = ()
        if target_roots is not None or contract_roots is not None:
            if target_roots is None or contract_roots is None:
                raise LifecycleError("trusted verification must bind target and contract roots together")
            target_bindings, contract_bindings = build_verification_bindings(
                targets, target_roots, contract_roots
            )
        return cls(
            "verified-success",
            run_id,
            task_fingerprint,
            tuple((str(item["name"]), str(item["versionHash"])) for item in targets),
            artifact_digest,
            target_bindings,
            contract_bindings,
        )


def _digest(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def _now() -> str:
    attested_now = os.environ.get(_ATTESTED_NOW_ENV)
    authority = os.environ.get(_ATTESTED_CLOCK_ENV)
    if attested_now is not None or authority is not None:
        expected = (
            "sha256:"
            + hashlib.sha256(
                (_ATTESTED_CLOCK_DOMAIN + "\0" + str(attested_now)).encode("utf-8")
            ).hexdigest()
        )
        if (
            attested_now is None
            or authority is None
            or _UTC_SECONDS.fullmatch(attested_now) is None
            or authority != expected
        ):
            raise LifecycleError("attested dry-run clock authority is invalid")
        return attested_now
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _active_names(active_skills: Sequence[object]) -> list[str]:
    return [target_identity(value) for value in validate_targets(list(active_skills), "activeSkills")]


def find_event(store: EventStore, idempotency_key: str) -> EventEnvelope | None:
    for event in store.read_events():
        if event.idempotency_key == idempotency_key:
            return event
    return None


def append_event(
    store: EventStore,
    *,
    event_type: str,
    run_id: str,
    logical_operation_id: str,
    target_skill: str,
    payload: Mapping[str, Any],
    causation_id: str | None,
    correlation_id: str | None = None,
    payload_ref: str | None = None,
    sidecar_path: Path | None = None,
    sidecar_bytes: bytes | None = None,
    freshness_witness: object | None = None,
) -> EventEnvelope:
    """Append one logical event, returning its durable record on retry.

    The storage layer validates the event again under its exclusive lock.  Looking
    up the normative idempotency key before materialising a timestamp makes an
    ordinary at-least-once retry byte-for-byte stable.
    """
    key = derive_idempotency_key(PRODUCER_VERSION, event_type, run_id, logical_operation_id, target_skill)
    existing = find_event(store, key)
    if existing is not None:
        expected_payload = {**payload, "logicalOperationId": logical_operation_id, "targetSkill": target_skill}
        if (
            existing.event_type == event_type
            and existing.run_id == run_id
            and existing.causation_id == causation_id
            and existing.correlation_id == correlation_id
            and existing.payload_ref == payload_ref
            and existing.to_dict()["payload"] == expected_payload
        ):
            return existing
        raise LifecycleError("logical operation id conflicts with its recorded request")
    complete_payload = {**payload, "logicalOperationId": logical_operation_id, "targetSkill": target_skill}
    event = EventEnvelope(
        schema_version=1,
        event_type=event_type,
        event_id="evt_" + _digest(event_type, run_id, logical_operation_id, target_skill)[:32],
        run_id=run_id,
        correlation_id=correlation_id,
        causation_id=causation_id,
        created_at=_now(),
        idempotency_key=key,
        producer_version=PRODUCER_VERSION,
        payload=complete_payload,
        payload_ref=payload_ref,
    )
    if (sidecar_path is None) is not (sidecar_bytes is None):
        raise LifecycleError("sidecar event publication is incomplete")
    if sidecar_path is not None and sidecar_bytes is not None:
        if freshness_witness is None:
            return store.append_with_sidecar(event, sidecar_path, sidecar_bytes)
        return store.append_with_sidecar(
            event,
            sidecar_path,
            sidecar_bytes,
            freshness_witness=freshness_witness,
        )
    if freshness_witness is None:
        return store.append(event)
    return store.append(event, freshness_witness=freshness_witness)


class RunCoordinator:
    """Coordinates the four hook operations without invoking a learning provider."""

    def __init__(self, store: EventStore, *, max_drafts: int = MAX_DRAFTS, verification_authority: object | None = None) -> None:
        self.store = store
        self.max_drafts = max(0, min(MAX_DRAFTS, max_drafts))
        self.verification_authority = verification_authority

    @staticmethod
    def no_rsi(store: EventStore | None = None) -> dict[str, object]:
        """Represent the explicit legacy/no-invocation case without touching RSI."""
        return {"status": "no-rsi", "rsiGuarantees": False, "eventIds": []}

    def start(
        self,
        *,
        run_id: str,
        active_skills: Sequence[object],
        task_class: str,
        logical_operation_id: str,
        mode: str = "observe",
        hook_mode: str = "coordinated",
        final_artifacts: Sequence[str] | None = None,
    ) -> dict[str, object]:
        validate_cli_identifiers(run_id, logical_operation_id)
        task_class = validate_task_class(task_class)
        if mode not in MODES:
            raise LifecycleError("mode is invalid")
        if hook_mode not in HOOK_MODES:
            raise LifecycleError("hook mode must be coordinated or late-review")
        if hook_mode == "late-review" and not final_artifacts:
            raise LifecycleError("late-review requires supplied final artifacts")
        names = _active_names(active_skills)
        final = validate_evidence(list(final_artifacts or []), "finalArtifacts", require_nonempty=hook_mode == "late-review")
        request_digest = canonical_digest({"activeSkills": names, "taskClass": task_class, "mode": mode, "hookMode": hook_mode, "finalArtifacts": final})
        event = append_event(
            self.store,
            event_type="run.started",
            run_id=run_id,
            logical_operation_id=logical_operation_id,
            target_skill="rsi",
            causation_id=None,
            payload={
                "mode": mode,
                "hookMode": hook_mode,
                "activeSkills": names,
                "policyVersion": "1",
                "controlPlaneVersion": PRODUCER_VERSION,
            },
            correlation_id=request_digest,
        )
        warnings = [LATE_REVIEW_WARNING] if hook_mode == "late-review" else []
        return {
            "schemaVersion": 1,
            "status": "completed",
            "runId": run_id,
            "mode": mode,
            "eventIds": [event.event_id],
            "warnings": warnings,
            "coordinatedCapture": hook_mode == "coordinated",
        }

    def _run_started(self, run_id: str) -> EventEnvelope:
        events = [event for event in self.store.read_events() if event.run_id == run_id]
        if not events or events[0].event_type != "run.started":
            raise LifecycleError("unknown RSI run")
        return events[0]

    def note_finding(self, run_id: str, draft: Mapping[str, object], logical_operation_id: str) -> dict[str, object]:
        validate_cli_identifiers(run_id, logical_operation_id)
        started = self._run_started(run_id)
        if started.payload["hookMode"] != "coordinated":
            raise LifecycleError("late-review does not accept in-dialog drafts")
        admitted = validate_finding(draft)
        scope, dedupe_key, summary = admitted["proposedScope"], admitted["proposedDedupeKey"], admitted["summary"]
        draft_id = "draft_" + _digest(run_id, str(scope), str(dedupe_key))[:24]
        run_events = [event for event in self.store.read_events() if event.run_id == run_id]
        existing = find_event(self.store, derive_idempotency_key(PRODUCER_VERSION, "finding.drafted", run_id, logical_operation_id, "rsi"))
        if existing is not None:
            expected = {"draftId": draft_id, "proposedScope": scope, "summary": summary, "logicalOperationId": logical_operation_id, "targetSkill": "rsi"}
            if existing.to_dict()["payload"] != expected:
                raise LifecycleError("logical operation id conflicts with its recorded request")
            return {"schemaVersion": 1, "status": "completed", "runId": run_id, "draftId": existing.payload["draftId"], "eventIds": [existing.event_id], "merged": False, "candidateIds": []}
        if any(event.event_type == "task.observed" for event in run_events):
            raise LifecycleError("finding drafts must be recorded before task observation")
        for event in run_events:
            if event.event_type == "finding.drafted" and event.payload["draftId"] == draft_id:
                return {"schemaVersion": 1, "status": "completed", "runId": run_id, "draftId": draft_id, "eventIds": [event.event_id], "merged": True, "candidateIds": []}
        drafts = [event for event in run_events if event.event_type == "finding.drafted"]
        if len(drafts) >= self.max_drafts:
            return {"schemaVersion": 1, "status": "no-op", "runId": run_id, "reason": "draft-cap-reached", "eventIds": [], "candidateIds": []}
        try:
            event = append_event(
                self.store,
                event_type="finding.drafted",
                run_id=run_id,
                logical_operation_id=logical_operation_id,
                target_skill="rsi",
                causation_id=run_events[-1].event_id if run_events[-1].event_type == "finding.drafted" else started.event_id,
                payload={"draftId": draft_id, "proposedScope": scope, "summary": summary}, correlation_id=canonical_digest({"scope": scope, "dedupe": dedupe_key, "summary": summary}),
            )
        except StoreIntegrityError as error:
            if str(error) == "finding draft cap reached":
                return {"schemaVersion": 1, "status": "no-op", "runId": run_id, "reason": "draft-cap-reached", "eventIds": [], "candidateIds": []}
            raise
        return {
            "schemaVersion": 1,
            "status": "completed",
            "runId": run_id,
            "draftId": event.payload["draftId"],
            "eventIds": [event.event_id],
            "merged": event.payload["logicalOperationId"] != logical_operation_id,
            "candidateIds": [],
        }

    def note_candidate_finding(
        self,
        *,
        run_id: str,
        seed: Mapping[str, object],
        logical_operation_id: str,
    ) -> dict[str, object]:
        """Persist a complete sanitized seed without making it capture-eligible."""
        from .candidates import candidate_seed_digest, validate_candidate_seed

        validate_cli_identifiers(run_id, logical_operation_id)
        started = self._run_started(run_id)
        if started.payload["hookMode"] != "coordinated":
            raise LifecycleError("late-review does not accept in-dialog candidate findings")
        declared: list[tuple[str, str]] = []
        for identity in started.payload["activeSkills"]:
            name, separator, version = str(identity).partition("@")
            if not separator:
                raise LifecycleError("run target identity is invalid")
            declared.append((name, version))
        admitted = validate_candidate_seed(seed, declared_targets=declared)
        digest = candidate_seed_digest(admitted)
        run_events = [event for event in self.store.read_events() if event.run_id == run_id]
        if any(event.event_type == "task.observed" for event in run_events):
            raise LifecycleError("candidate findings must be recorded before task observation")
        for event in run_events:
            if event.event_type != "finding.drafted" or not event.payload_ref:
                continue
            try:
                prior = json.loads(
                    self.store.read_sidecar(self.store.home / "objects" / str(event.payload_ref)).decode("utf-8")
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                raise LifecycleError("durable candidate finding is unavailable") from None
            if not isinstance(prior, Mapping):
                raise LifecycleError("durable candidate finding is invalid")
            key = (prior.get("targetSkill"), prior.get("dedupeKey"))
            requested = (admitted["targetSkill"], admitted["dedupeKey"])
            if key == requested:
                if dict(prior) != admitted:
                    raise LifecycleError("candidate dedupe key conflicts with different semantics")
                return {
                    "schemaVersion": 1, "status": "completed", "runId": run_id,
                    "draftId": event.payload["draftId"], "eventIds": [event.event_id],
                    "merged": True, "candidateIds": [],
                }
        target = str(admitted["targetSkill"])
        # The canonical provider owns dedupe identity at target+dedupeKey.
        # Scope is semantics to compare, not a way to create another branch.
        draft_id = "draft_" + _digest(run_id, target, str(admitted["dedupeKey"]))[:24]
        drafts = [event for event in run_events if event.event_type == "finding.drafted"]
        if len(drafts) >= self.max_drafts:
            return {
                "schemaVersion": 1, "status": "no-op", "runId": run_id,
                "reason": "draft-cap-reached", "eventIds": [], "candidateIds": [],
            }
        cause = drafts[-1].event_id if drafts else started.event_id
        event_id = "evt_" + _digest("finding.drafted", run_id, logical_operation_id, target)[:32]
        encoded = json.dumps(admitted, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        try:
            event = append_event(
                self.store,
                event_type="finding.drafted",
                run_id=run_id,
                logical_operation_id=logical_operation_id,
                target_skill=target,
                causation_id=cause,
                payload={"draftId": draft_id, "proposedScope": admitted["scope"], "summary": admitted["title"]},
                correlation_id=digest,
                payload_ref=f"findings/{event_id}.json",
                sidecar_path=self.store.home / "objects" / "findings" / f"{event_id}.json",
                sidecar_bytes=encoded,
            )
        except Exception as error:
            if isinstance(error, StoreIntegrityError) and str(error) == "finding draft cap reached":
                return {
                    "schemaVersion": 1, "status": "no-op", "runId": run_id,
                    "reason": "draft-cap-reached", "eventIds": [], "candidateIds": [],
                }
            if isinstance(error, StoreIntegrityError) and str(error) == "finding draft dedupe conflict":
                raise LifecycleError("candidate dedupe key conflicts with different semantics") from None
            raise LifecycleError("candidate finding replay conflicts with durable payload") from error
        return {
            "schemaVersion": 1, "status": "completed", "runId": run_id,
            "draftId": event.payload["draftId"], "eventIds": [event.event_id],
            "merged": event.payload["logicalOperationId"] != logical_operation_id,
            "candidateIds": [],
        }

    def verify_primary_task(self, *, run_id: str, logical_operation_id: str, task_class: str, target_skills: Sequence[Mapping[str, str]], task_fingerprint: str, artifact_digest: str, signals_by_target: Mapping[str, object] | None = None, evidence: Sequence[object] | None = None, baseline_lookup: object | None = None) -> dict[str, object]:
        """Record the verified task outcome and produce noncanonical evaluations."""
        from .evaluate import Evaluator
        from .observe import Observer

        if not callable(self.verification_authority):
            raise LifecycleError("trusted verification authority is required")
        result = self.verification_authority(run_id=run_id, task_fingerprint=task_fingerprint, target_skills=target_skills, artifact_digest=artifact_digest)
        expected_targets = tuple((item["name"], item["versionHash"]) for item in target_skills)
        if not isinstance(result, VerificationResult) or result.outcome not in {"verified-success", "verified-failure"} or (result.run_id, result.task_fingerprint, result.target_skills, result.artifact_digest) != (run_id, task_fingerprint, expected_targets, artifact_digest):
            raise LifecycleError("verification result is not bound to this task")
        observed = Observer(self.store, verification_authority=lambda **_: result).observe(run_id=run_id, logical_operation_id=logical_operation_id + ":observe", task_class=task_class, outcome=result.outcome, target_skills=target_skills, signals_by_target=signals_by_target or {}, evidence=evidence or [], task_fingerprint=task_fingerprint, artifact_digest=artifact_digest)
        results = Evaluator(self.store, baseline_lookup=baseline_lookup).evaluate_per_target(run_id=run_id, observation=observed["observation"], observation_event_id=observed["eventIds"][0], logical_operation_id=logical_operation_id + ":evaluate")
        return {"schemaVersion": 1, "status": "completed", "runId": run_id, "eventIds": [*observed["eventIds"], *[result["eventId"] for result in results]], "evaluationIds": [result["eventId"] for result in results], "evaluations": results, "candidateIds": []}

    def close(self, *, run_id: str, logical_operation_id: str, status: str = "completed") -> dict[str, object]:
        events = [event for event in self.store.read_events() if event.run_id == run_id]
        if not events:
            raise LifecycleError("unknown RSI run")
        key = derive_idempotency_key(PRODUCER_VERSION, "run.closed", run_id, logical_operation_id, "rsi")
        existing = find_event(self.store, key)
        if existing is not None:
            if existing.payload["status"] != status:
                raise LifecycleError("logical operation id conflicts with its recorded request")
            return {"schemaVersion": 1, "status": status, "runId": run_id, "eventIds": [existing.event_id], "candidateIds": [], "mutationPerformed": False}
        observed = [event for event in events if event.event_type == "task.observed"]
        evaluated = [event for event in events if event.event_type == "evaluation.completed"]
        declared = {str(value).split("@", 1)[0] for value in events[0].payload["activeSkills"]}
        if len(observed) != 1 or {event.payload["targetSkill"] for event in evaluated} != declared or len(evaluated) != len(declared):
            raise LifecycleError("close requires observation and all target evaluations")
        trusted_root_witness: str | None = None
        terminal_freshness: object | None = None
        freshness_ref: str | None = None
        freshness_path: Path | None = None
        freshness_bytes: bytes | None = None
        if events[0].payload["mode"] == "propose":
            from .candidates import CandidateBuilder

            reports = [event for event in events if event.event_type == "report.generated"]
            admissions = [event for event in events if event.event_type == "candidate.admission_decided"]
            captures = [event for event in events if event.event_type == "candidate.captured"]
            expected_correlations: set[str] = set()
            durable_evaluations: list[dict[str, object]] = []
            builder = CandidateBuilder(self.store)
            for evaluation_event in evaluated:
                if not evaluation_event.payload_ref:
                    raise LifecycleError("proposal close requires durable evaluations")
                try:
                    evaluation = json.loads(
                        self.store.read_sidecar(self.store.home / "objects" / str(evaluation_event.payload_ref)).decode("utf-8")
                    )
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    raise LifecycleError("proposal close requires durable evaluations") from None
                if not isinstance(evaluation, Mapping):
                    raise LifecycleError("proposal close requires durable evaluations")
                durable_evaluations.append(dict(evaluation))
                expected_correlations.update(
                    canonical_digest(draft.canonical_mapping()) for draft in builder.build(evaluation)
                )
            admission_correlations = {event.correlation_id for event in admissions}
            if len(admissions) != len(expected_correlations) or admission_correlations != expected_correlations:
                raise LifecycleError("proposal close requires every candidate admission branch")
            capture_counts: dict[str | None, int] = {}
            for capture in captures:
                capture_counts[capture.causation_id] = capture_counts.get(capture.causation_id, 0) + 1
            if len(reports) != 1 or reports[0] is not events[-1]:
                raise LifecycleError("proposal close requires exactly one final report")
            for admission in admissions:
                expected_count = 1 if admission.payload["decision"] == "allow" else 0
                if capture_counts.get(admission.event_id, 0) != expected_count:
                    raise LifecycleError("proposal close requires every branch terminal")
            if admissions:
                from .target_identity import (
                    encode_freshness_witness_document,
                    revalidate_verification_bindings_with_witness,
                )

                target_bindings: list[dict[str, object]] = []
                contract_bindings: list[dict[str, object]] | None = None
                for evaluation in durable_evaluations:
                    verification = evaluation.get("verificationBinding")
                    if not isinstance(verification, Mapping):
                        raise LifecycleError("proposal close trusted root binding is unavailable")
                    target = verification.get("targetRoot")
                    contracts = verification.get("contractRoots")
                    if not isinstance(target, Mapping) or not isinstance(contracts, list):
                        raise LifecycleError("proposal close trusted root binding is unavailable")
                    if contract_bindings is None:
                        contract_bindings = [dict(item) for item in contracts if isinstance(item, Mapping)]
                        if len(contract_bindings) != len(contracts):
                            raise LifecycleError("proposal close trusted root binding is invalid")
                    elif contracts != contract_bindings:
                        raise LifecycleError("proposal close trusted root bindings conflict")
                    target_bindings.append(dict(target))
                binding_path = self.store.home / "objects" / "proposals" / f"{run_id}.json"
                try:
                    binding_bytes = self.store.read_sidecar(binding_path)
                    if not binding_bytes.endswith(b"\n") or binding_bytes[:-1].endswith((b"\n", b" ", b"\t")):
                        raise ValueError

                    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
                        result: dict[str, object] = {}
                        for key, value in pairs:
                            if key in result:
                                raise ValueError
                            result[key] = value
                        return result

                    provider_binding = json.loads(
                        binding_bytes.decode("utf-8"),
                        object_pairs_hook=unique,
                        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
                    )
                except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, StoreIntegrityError):
                    raise LifecycleError("proposal close provider binding is unavailable") from None
                if (
                    not isinstance(provider_binding, Mapping)
                    or not isinstance(provider_binding.get("targetRoots"), list)
                    or not isinstance(provider_binding.get("contractRoots"), list)
                    or not target_bindings
                    or not contract_bindings
                ):
                    raise LifecycleError("proposal close trusted root binding is invalid")
                verification_bindings = {
                    "targetRoots": target_bindings,
                    "contractRoots": contract_bindings,
                }
                _, _, terminal_freshness = revalidate_verification_bindings_with_witness(
                    verification_bindings,
                    [str(item) for item in provider_binding["targetRoots"]],
                    [str(item) for item in provider_binding["contractRoots"]],
                )
                freshness_bytes = encode_freshness_witness_document(
                    terminal_freshness,
                    run_id=run_id,
                    verification_binding_digest=canonical_digest(verification_bindings),
                )
                raw_freshness_digest = hashlib.sha256(freshness_bytes).hexdigest()
                trusted_root_witness = "sha256:" + raw_freshness_digest
                freshness_ref = (
                    f"proposals/{run_id}-freshness-{raw_freshness_digest}.json"
                )
                freshness_path = self.store.home / "objects" / freshness_ref
        close_binding: dict[str, object] = {
            "status": status,
            "observation": observed[0].event_id,
            "evaluations": [item.event_id for item in evaluated],
        }
        if trusted_root_witness is not None:
            close_binding["trustedRootWitness"] = trusted_root_witness
        event = append_event(
            self.store,
            event_type="run.closed",
            run_id=run_id,
            logical_operation_id=logical_operation_id,
            target_skill="rsi",
            causation_id=events[-1].event_id,
            payload={"status": status, "linkedIds": []},
            correlation_id=canonical_digest(close_binding),
            payload_ref=freshness_ref,
            sidecar_path=freshness_path,
            sidecar_bytes=freshness_bytes,
            freshness_witness=terminal_freshness,
        )
        return {"schemaVersion": 1, "status": status, "runId": run_id, "eventIds": [event.event_id], "candidateIds": [], "mutationPerformed": False}
