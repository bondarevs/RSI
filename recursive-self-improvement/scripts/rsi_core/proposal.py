"""Restart-safe Stage-2 proposal lifecycle; never mutates a target skill."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping, Protocol, Sequence

from .candidates import CandidateBuilder, ImprovementCandidateDraft
from .evolver_adapter import CandidateRef, ProviderValidationResult, RouteDecision
from .hooks import LifecycleError, RunCoordinator, append_event, canonical_digest
from .sanitize import sanitize_evidence
from .storage import EventStore, StoreIntegrityError
from .target_identity import (
    admit_freshness_witness_document,
    freshness_witness_roots,
    revalidate_verification_bindings,
)


_HEX_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_PROPOSAL_BINDING_FIELDS = frozenset(
    {
        "schemaVersion", "runId", "providerRoot", "providerLearningHome",
        "providerDigest", "contractRoots", "targetRoots",
    }
)
_ROUTE_RECEIPT_FIELDS = frozenset(
    {
        "schemaVersion", "runId", "candidateCorrelation", "providerBindingRef",
        "providerBindingDigest", "decision", "hardReasons", "routeDecision",
    }
)
_ROUTE_DECISION_FIELDS = frozenset(
    {"status", "ownerSkill", "ownerPath", "matchedScope", "reason", "routeBinding"}
)


class ProposalProvider(Protocol):
    learning_home: Path
    provider_root: Path

    def validate(self) -> ProviderValidationResult: ...
    def route(self, scope: str, contract_roots: Sequence[Path | str]) -> RouteDecision: ...
    def route_capture(self, candidate: ImprovementCandidateDraft, contract_roots: Sequence[Path | str], route_binding: str) -> CandidateRef: ...


def _canonical_root(path: Path | str, *, must_exist: bool) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute == Path(absolute.anchor):
        raise LifecycleError("control roots must not be filesystem roots")
    current = Path(absolute.anchor)
    for position, part in enumerate(absolute.parts[1:]):
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if must_exist or position < len(absolute.parts[1:]) - 1:
                raise LifecycleError("control root is unavailable") from None
            break
        if stat.S_ISLNK(metadata.st_mode):
            raise LifecycleError("control roots cannot use symlink aliases")
        if position < len(absolute.parts[1:]) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise LifecycleError("control root topology is invalid")
    if must_exist and not absolute.is_dir():
        raise LifecycleError("target root must be an existing real directory")
    return absolute


def _overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _strict_json_object(data: bytes, label: str) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError

    if (
        not data
        or not data.endswith(b"\n")
        or b"\r" in data
        or data[:-1].endswith((b"\n", b" ", b"\t"))
    ):
        raise LifecycleError(f"durable {label} is unavailable")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise LifecycleError(f"durable {label} is unavailable") from None
    if not isinstance(value, dict):
        raise LifecycleError(f"durable {label} is invalid")
    return value


class ProposalService:
    def __init__(
        self,
        store: EventStore,
        provider: ProposalProvider,
        *,
        contract_roots: Sequence[Path | str],
        target_roots: Sequence[Path | str],
    ) -> None:
        self.store = store
        self.provider = provider
        self.contract_roots = tuple(contract_roots)
        self.target_roots = tuple(target_roots)

    def _assert_topology(self) -> tuple[Path, Path, tuple[Path, ...]]:
        state = _canonical_root(self.store.home, must_exist=True)
        learning = _canonical_root(self.provider.learning_home, must_exist=False)
        targets = tuple(_canonical_root(path, must_exist=True) for path in self.target_roots)
        if not targets:
            raise LifecycleError("at least one target root is required")
        roots = (state, learning, *targets)
        for number, first in enumerate(roots):
            for second in roots[number + 1 :]:
                if _overlap(first, second):
                    raise LifecycleError("RSI home, provider learning home, and target roots must be disjoint")
        if len(set(targets)) != len(targets):
            raise LifecycleError("target roots must be distinct")
        return state, learning, targets

    @staticmethod
    def _verification_bindings(
        evaluations: Sequence[Mapping[str, object]],
    ) -> dict[str, object]:
        targets: list[dict[str, object]] = []
        contracts: list[dict[str, object]] | None = None
        for evaluation in evaluations:
            binding = evaluation.get("verificationBinding")
            if not isinstance(binding, Mapping) or set(binding) != {"targetRoot", "contractRoots"}:
                raise LifecycleError("trusted verification root binding is unavailable")
            target = binding["targetRoot"]
            current_contracts = binding["contractRoots"]
            if not isinstance(target, Mapping) or not isinstance(current_contracts, list):
                raise LifecycleError("trusted verification root binding is unavailable")
            if contracts is None:
                contracts = [dict(item) for item in current_contracts if isinstance(item, Mapping)]
                if len(contracts) != len(current_contracts):
                    raise LifecycleError("trusted contract root binding is unavailable")
            elif current_contracts != contracts:
                raise LifecycleError("trusted contract root bindings conflict across evaluations")
            targets.append(dict(target))
        if not targets or not contracts:
            raise LifecycleError("trusted verification root binding is unavailable")
        return {"targetRoots": targets, "contractRoots": contracts}

    def _assert_verified_roots(
        self, bindings: Mapping[str, object]
    ) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
        return revalidate_verification_bindings(
            bindings, self.target_roots, self.contract_roots
        )

    @staticmethod
    def _binding_ref(run_id: str) -> str:
        return f"proposals/{run_id}.json"

    def _binding_base(self, run_id: str, target_roots: Sequence[Path]) -> dict[str, object]:
        provider_root = _canonical_root(self.provider.provider_root, must_exist=True)
        learning_home = _canonical_root(self.provider.learning_home, must_exist=False)
        contract_roots = sorted(
            str(_canonical_root(path, must_exist=True)) for path in self.contract_roots
        )
        return {
            "schemaVersion": 1,
            "runId": run_id,
            "providerRoot": str(provider_root),
            "providerLearningHome": str(learning_home),
            "contractRoots": contract_roots,
            "targetRoots": sorted(str(path) for path in target_roots),
        }

    def _read_binding(self, run_id: str) -> dict[str, object] | None:
        path = self.store.home / "objects" / self._binding_ref(run_id)
        try:
            return _strict_json_object(self.store.read_sidecar(path), "proposal binding")
        except FileNotFoundError:
            return None
        except StoreIntegrityError as error:
            raise LifecycleError("durable proposal binding is unavailable") from error

    def _prepare_binding(self, run_id: str, target_roots: Sequence[Path]) -> tuple[str, dict[str, object]]:
        base = self._binding_base(run_id, target_roots)
        existing = self._read_binding(run_id)
        if existing is not None:
            if set(existing) != _PROPOSAL_BINDING_FIELDS or {
                key: existing[key] for key in base
            } != base:
                raise LifecycleError("provider configuration conflicts with durable proposal binding")
        validation = self.provider.validate()
        if not isinstance(validation.provider_digest, str) or not _HEX_DIGEST_RE.fullmatch(validation.provider_digest):
            raise LifecycleError("provider validation digest is invalid")
        expected = {**base, "providerDigest": "sha256:" + validation.provider_digest}
        if existing is not None and existing != expected:
            raise LifecycleError("provider identity conflicts with durable proposal binding")
        encoded = json.dumps(
            expected,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8") + b"\n"
        try:
            self.store.write_once(
                self.store.home / "objects" / self._binding_ref(run_id),
                encoded,
            )
        except StoreIntegrityError as error:
            raise LifecycleError("provider configuration conflicts with durable proposal binding") from error
        return self._binding_ref(run_id), expected

    @staticmethod
    def _receipt_ref(draft: ImprovementCandidateDraft, encoded: bytes) -> str:
        digest = hashlib.sha256(encoded).hexdigest()
        return f"proposals/{draft.operation_id}-{digest}.json"

    @staticmethod
    def _receipt_digest(draft: ImprovementCandidateDraft, receipt_ref: str) -> str:
        prefix = f"proposals/{draft.operation_id}-"
        if not receipt_ref.startswith(prefix) or not receipt_ref.endswith(".json"):
            raise LifecycleError("candidate admission lacks a durable route receipt")
        digest = receipt_ref[len(prefix) : -len(".json")]
        if not _HEX_DIGEST_RE.fullmatch(digest):
            raise LifecycleError("candidate admission route receipt digest is invalid")
        return digest

    @staticmethod
    def _safe_route_reason(value: object) -> str:
        if not isinstance(value, str) or not value or len(value) > 1000:
            raise LifecycleError("route receipt reason is invalid")
        admitted = sanitize_evidence([{"kind": "route", "summary": value}])
        if (
            admitted.rejected_count
            or admitted.truncated_count
            or len(admitted.accepted) != 1
            or admitted.accepted[0]["summary"] != value
        ):
            raise LifecycleError("route receipt reason is unsafe")
        return value

    def _write_route_receipt(
        self,
        *,
        run_id: str,
        draft: ImprovementCandidateDraft,
        correlation: str,
        provider_binding_ref: str,
        provider_binding: Mapping[str, object],
        route: RouteDecision,
        decision: str,
        reasons: Sequence[str],
    ) -> str:
        route_reason = self._safe_route_reason(route.reason)
        value = {
            "schemaVersion": 1,
            "runId": run_id,
            "candidateCorrelation": correlation,
            "providerBindingRef": provider_binding_ref,
            "providerBindingDigest": canonical_digest(provider_binding),
            "decision": decision,
            "hardReasons": list(reasons),
            "routeDecision": {
                "status": route.status,
                "ownerSkill": route.owner_skill,
                "ownerPath": route.owner_path,
                "matchedScope": route.matched_scope,
                "reason": route_reason,
                "routeBinding": route.route_binding,
            },
        }
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8") + b"\n"
        receipt_ref = self._receipt_ref(draft, encoded)
        try:
            self.store.write_once(self.store.home / "objects" / receipt_ref, encoded)
        except StoreIntegrityError as error:
            raise LifecycleError("route receipt conflicts with durable proposal branch") from error
        return receipt_ref

    def _read_route_receipt(
        self, receipt_ref: str, draft: ImprovementCandidateDraft
    ) -> dict[str, object]:
        expected_digest = self._receipt_digest(draft, receipt_ref)
        try:
            raw = self.store.read_sidecar(self.store.home / "objects" / receipt_ref)
        except (OSError, StoreIntegrityError):
            raise LifecycleError("durable route receipt is unavailable") from None
        if hashlib.sha256(raw).hexdigest() != expected_digest:
            raise LifecycleError("durable route receipt digest binding is invalid")
        return _strict_json_object(raw, "route receipt")

    def _validated_receipt_route(
        self,
        *,
        receipt: Mapping[str, object],
        admission: object,
        run_id: str,
        draft: ImprovementCandidateDraft,
        correlation: str,
        provider_binding_ref: str,
        provider_binding: Mapping[str, object],
    ) -> RouteDecision:
        if set(receipt) != _ROUTE_RECEIPT_FIELDS:
            raise LifecycleError("durable route receipt has an invalid schema")
        route_value = receipt.get("routeDecision")
        if not isinstance(route_value, Mapping) or set(route_value) != _ROUTE_DECISION_FIELDS:
            raise LifecycleError("durable route receipt has an invalid route schema")
        if (
            receipt.get("schemaVersion") != 1
            or receipt.get("runId") != run_id
            or receipt.get("candidateCorrelation") != correlation
            or receipt.get("providerBindingRef") != provider_binding_ref
            or receipt.get("providerBindingDigest") != canonical_digest(provider_binding)
            or receipt.get("decision") != getattr(admission, "payload")["decision"]
            or receipt.get("hardReasons") != list(getattr(admission, "payload")["hardReasons"])
        ):
            raise LifecycleError("durable route receipt binding is invalid")
        status = route_value.get("status")
        reason = route_value.get("reason")
        if status not in {"resolved", "needs-owner", "ownership-conflict"}:
            raise LifecycleError("durable route receipt decision is invalid")
        reason = self._safe_route_reason(reason)
        if status == "resolved":
            owner = route_value.get("ownerSkill")
            owner_path = route_value.get("ownerPath")
            scope = route_value.get("matchedScope")
            binding = route_value.get("routeBinding")
            if (
                not isinstance(owner, str)
                or not isinstance(owner_path, str)
                or not isinstance(scope, str)
                or not isinstance(binding, str)
                or not _HEX_DIGEST_RE.fullmatch(binding)
            ):
                raise LifecycleError("durable resolved route receipt is invalid")
            return RouteDecision(status, owner, owner_path, scope, reason, binding)
        if any(route_value.get(key) is not None for key in ("ownerSkill", "ownerPath", "matchedScope", "routeBinding")):
            raise LifecycleError("durable unresolved route receipt is invalid")
        return RouteDecision(str(status), None, None, None, reason, None)

    @staticmethod
    def _route_reasons(
        route: RouteDecision,
        draft: ImprovementCandidateDraft,
        target_roots: Sequence[Path],
    ) -> list[str]:
        reasons: list[str] = []
        if route.status != "resolved":
            reasons.append(route.status)
        elif route.owner_skill != draft.target_skill:
            reasons.append("owner-target-mismatch")
        elif route.owner_path is None or _canonical_root(route.owner_path, must_exist=True) not in target_roots:
            reasons.append("owner-path-not-allowlisted")
        elif route.matched_scope is None or not (draft.scope == route.matched_scope or draft.scope.startswith(route.matched_scope + ".")):
            reasons.append("route-scope-mismatch")
        elif route.route_binding is None or not _HEX_DIGEST_RE.fullmatch(route.route_binding):
            reasons.append("route-binding-missing")
        return reasons

    @staticmethod
    def _assert_capture_mode() -> None:
        if os.environ.get("CODEX_RSI_ENABLED") == "0" or os.environ.get("CODEX_RSI_MODE") in {"off", "observe"}:
            raise LifecycleError("RSI kill switch or effective mode blocks canonical capture")

    def resume(self, run_id: str, logical_operation_id: str) -> dict[str, object]:
        events = [event for event in self.store.read_events() if event.run_id == run_id]
        if not events or events[0].event_type != "run.started":
            raise LifecycleError("unknown RSI run")
        if events[0].payload["mode"] != "propose":
            raise LifecycleError("canonical proposal requires propose mode")
        if any(event.event_type == "run.closed" for event in events):
            return self._result(run_id)
        _, _, target_roots = self._assert_topology()
        observed = [event for event in events if event.event_type == "task.observed"]
        evaluations = [event for event in events if event.event_type == "evaluation.completed"]
        declared = {str(item).split("@", 1)[0] for item in events[0].payload["activeSkills"]}
        if (
            len(observed) != 1
            or observed[0].payload["verificationStatus"] != "verified"
            or {event.payload["targetSkill"] for event in evaluations} != declared
            or len(evaluations) != len(declared)
            or any(event.payload["evidenceStatus"] != "verified" for event in evaluations)
        ):
            raise LifecycleError("trusted verification and all bound evaluations are required")
        durable_evaluations: list[Mapping[str, object]] = []
        builder = CandidateBuilder(self.store)
        drafts: list[ImprovementCandidateDraft] = []
        for event in evaluations:
            if not event.payload_ref:
                raise LifecycleError("trusted evaluation object is unavailable")
            try:
                value = json.loads(
                    self.store.read_sidecar(self.store.home / "objects" / str(event.payload_ref)).decode("utf-8")
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                raise LifecycleError("trusted evaluation object is unavailable") from None
            if not isinstance(value, Mapping):
                raise LifecycleError("trusted evaluation object is invalid")
            durable_evaluations.append(value)
            drafts.extend(builder.build(value))
        drafts.sort(key=lambda item: (item.target_skill, item.scope, item.dedupe_key, item.operation_id))

        # Compatibility and the capture kill switch are needed only when a
        # canonical provider write could occur; an empty proposal is read-only.
        binding_ref: str | None = None
        provider_binding: Mapping[str, object] | None = None
        verification_bindings: Mapping[str, object] | None = None
        if drafts:
            verification_bindings = self._verification_bindings(durable_evaluations)
            self._assert_verified_roots(verification_bindings)
            self._assert_capture_mode()
            binding_ref, provider_binding = self._prepare_binding(run_id, target_roots)
        branch_events = []
        candidate_ids: list[str] = []
        rejected = 0
        for draft in drafts:
            evaluation_event_id = self._evaluation_event_id(durable_evaluations, draft.evaluation_id)
            correlation = canonical_digest(draft.canonical_mapping())
            existing_admissions = [
                event for event in self.store.read_events()
                if event.run_id == run_id
                and event.event_type == "candidate.admission_decided"
                and event.correlation_id == correlation
            ]
            if len(existing_admissions) > 1:
                raise LifecycleError("candidate has duplicate admission branches")
            if existing_admissions:
                admission = existing_admissions[0]
                if (
                    admission.causation_id != evaluation_event_id
                    or admission.payload["targetSkill"] != draft.target_skill
                    or admission.payload_ref is None
                ):
                    raise LifecycleError("recorded candidate admission conflicts with current request")
                assert binding_ref is not None and provider_binding is not None and admission.payload_ref is not None
                route = self._validated_receipt_route(
                    receipt=self._read_route_receipt(admission.payload_ref, draft),
                    admission=admission,
                    run_id=run_id,
                    draft=draft,
                    correlation=correlation,
                    provider_binding_ref=binding_ref,
                    provider_binding=provider_binding,
                )
                if admission.payload["decision"] == "reject":
                    if not admission.payload["hardReasons"]:
                        raise LifecycleError("recorded candidate rejection lacks a terminal reason")
                    branch_events.append(admission)
                    rejected += 1
                    continue
                if admission.payload["decision"] != "allow" or admission.payload["hardReasons"]:
                    raise LifecycleError("recorded candidate admission conflicts with current request")
                reasons = self._route_reasons(route, draft, target_roots)
                if reasons:
                    raise LifecycleError("recorded allowed route receipt is no longer admissible")
            else:
                assert verification_bindings is not None
                self._assert_verified_roots(verification_bindings)
                self._assert_capture_mode()
                route = self.provider.route(draft.scope, self.contract_roots)
                reasons = self._route_reasons(route, draft, target_roots)
            decision = "reject" if reasons else "allow"
            expected_payload = {"decision": decision, "hardReasons": reasons}
            if existing_admissions:
                if decision != "allow":
                    raise LifecycleError("recorded candidate admission conflicts with current request")
            else:
                assert binding_ref is not None and provider_binding is not None
                receipt_ref = self._write_route_receipt(
                    run_id=run_id,
                    draft=draft,
                    correlation=correlation,
                    provider_binding_ref=binding_ref,
                    provider_binding=provider_binding,
                    route=route,
                    decision=decision,
                    reasons=reasons,
                )
                admission = append_event(
                    self.store,
                    event_type="candidate.admission_decided",
                    run_id=run_id,
                    logical_operation_id=f"proposal:admit:{draft.operation_id}",
                    target_skill=draft.target_skill,
                    causation_id=evaluation_event_id,
                    payload=expected_payload,
                    correlation_id=correlation,
                    payload_ref=receipt_ref,
                )
            branch_events.append(admission)
            if decision == "reject":
                rejected += 1
                continue
            assert verification_bindings is not None
            self._assert_verified_roots(verification_bindings)
            self._assert_capture_mode()
            if route.route_binding is None:
                raise LifecycleError("admitted route lacks its atomic binding")
            captured = self.provider.route_capture(draft, self.contract_roots, route.route_binding)
            if captured.candidate_id in candidate_ids:
                raise LifecycleError("provider candidate ID collision across distinct drafts")
            capture_correlation = canonical_digest(
                {"draft": draft.canonical_mapping(), "providerCandidateId": captured.candidate_id}
            )
            expected_capture = {
                "providerCandidateId": captured.candidate_id,
                "captureOperationId": draft.operation_id,
                "owner": str(route.owner_skill),
            }
            existing_captures = [
                event for event in self.store.read_events()
                if event.run_id == run_id
                and event.event_type == "candidate.captured"
                and event.causation_id == admission.event_id
            ]
            if len(existing_captures) > 1:
                raise LifecycleError("candidate has duplicate capture terminals")
            if existing_captures:
                capture_event = existing_captures[0]
                if (
                    capture_event.correlation_id != capture_correlation
                    or capture_event.to_dict()["payload"]
                    != {**expected_capture, "logicalOperationId": capture_event.payload["logicalOperationId"], "targetSkill": draft.target_skill}
                ):
                    raise LifecycleError("recorded candidate capture conflicts with provider replay")
            else:
                capture_event = append_event(
                    self.store,
                    event_type="candidate.captured",
                    run_id=run_id,
                    logical_operation_id=f"proposal:capture-journal:{draft.operation_id}",
                    target_skill=draft.target_skill,
                    causation_id=admission.event_id,
                    payload=expected_capture,
                    correlation_id=capture_correlation,
                )
            branch_events.append(capture_event)
            candidate_ids.append(captured.candidate_id)
        self._assert_complete_branches(drafts, branch_events)
        if not drafts:
            status = "no-op"
        elif candidate_ids:
            status = "completed"
        else:
            status = "rejected"
        causation = branch_events[-1].event_id if branch_events else evaluations[-1].event_id
        report = {
            "schemaVersion": 1,
            "runId": run_id,
            "mode": "propose",
            "status": status,
            "evaluationIds": sorted(event.event_id for event in evaluations),
            "candidateIds": sorted(candidate_ids),
            "rejectedCount": rejected,
            "mutationPerformed": False,
        }
        self._write_report(run_id, f"proposal:{run_id}:report", causation, report)
        RunCoordinator(self.store).close(
            run_id=run_id,
            logical_operation_id=f"proposal:{run_id}:close",
            status=status,
        )
        return self._result(run_id)

    @staticmethod
    def _evaluation_event_id(evaluations: Sequence[Mapping[str, object]], evaluation_id: str) -> str:
        matches = [item for item in evaluations if item.get("evaluationId") == evaluation_id]
        if len(matches) != 1 or not isinstance(matches[0].get("eventId"), str):
            raise LifecycleError("candidate evaluation binding is invalid")
        return str(matches[0]["eventId"])

    @staticmethod
    def _assert_complete_branches(
        drafts: Sequence[ImprovementCandidateDraft], branch_events: Sequence[object]
    ) -> None:
        admissions = [event for event in branch_events if getattr(event, "event_type", None) == "candidate.admission_decided"]
        captures = [event for event in branch_events if getattr(event, "event_type", None) == "candidate.captured"]
        if len(admissions) != len(drafts):
            raise LifecycleError("proposal branches are incomplete")
        capture_counts: dict[str | None, int] = {}
        for capture in captures:
            capture_counts[capture.causation_id] = capture_counts.get(capture.causation_id, 0) + 1  # type: ignore[attr-defined]
        for admission in admissions:
            allowed = admission.payload["decision"] == "allow"  # type: ignore[attr-defined]
            expected_count = 1 if allowed else 0
            if capture_counts.get(admission.event_id, 0) != expected_count:  # type: ignore[attr-defined]
                raise LifecycleError("proposal branch terminal is incomplete")

    def _write_report(self, run_id: str, operation: str, causation_id: str, report: Mapping[str, object]):
        encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
        path = self.store.home / "reports" / f"local-review-{run_id}.json"
        try:
            self.store.write_once(path, encoded)
        except Exception as error:
            raise LifecycleError("proposal report conflicts with durable payload") from error
        return append_event(
            self.store,
            event_type="report.generated",
            run_id=run_id,
            logical_operation_id=operation,
            target_skill="rsi",
            causation_id=causation_id,
            payload={
                "reportKind": "local", "pathDigest": digest,
                "inputRefs": list(report["evaluationIds"]), "mutationPerformed": False,
            },
            correlation_id=canonical_digest(report),
        )

    def _result(self, run_id: str) -> dict[str, object]:
        events = [event for event in self.store.read_events() if event.run_id == run_id]
        closed = [event for event in events if event.event_type == "run.closed"]
        report = [event for event in events if event.event_type == "report.generated"]
        if len(closed) != 1 or len(report) != 1:
            raise LifecycleError("proposal run is not durably closed")
        evaluations = [event for event in events if event.event_type == "evaluation.completed"]
        builder = CandidateBuilder(self.store)
        drafts: list[ImprovementCandidateDraft] = []
        for evaluation_event in evaluations:
            if not evaluation_event.payload_ref:
                raise LifecycleError("durable evaluation is unavailable")
            try:
                value = _strict_json_object(
                    self.store.read_sidecar(self.store.home / "objects" / evaluation_event.payload_ref),
                    "evaluation",
                )
            except OSError:
                raise LifecycleError("durable evaluation is unavailable") from None
            drafts.extend(builder.build(value))
        expected_admissions = {
            canonical_digest(draft.canonical_mapping()): draft for draft in drafts
        }
        admissions = [event for event in events if event.event_type == "candidate.admission_decided"]
        captures = [event for event in events if event.event_type == "candidate.captured"]
        if len(expected_admissions) != len(drafts) or len(admissions) != len(drafts):
            raise LifecycleError("proposal run has incomplete durable branches")
        by_evaluation = {
            f"evaluation:{run_id}:{event.payload['targetSkill']}": event.event_id
            for event in evaluations
        }
        seen: set[str] = set()
        binding = self._read_binding(run_id) if admissions else None
        trusted_root_witness: str | None = None
        if admissions:
            verification_bindings = self._verification_bindings(
                [
                    _strict_json_object(
                        self.store.read_sidecar(
                            self.store.home / "objects" / str(event.payload_ref)
                        ),
                        "evaluation",
                    )
                    for event in evaluations
                    if event.payload_ref is not None
                ]
            )
            self._assert_verified_roots(verification_bindings)
            _, _, target_roots = self._assert_topology()
            base = self._binding_base(run_id, target_roots)
            if (
                binding is None
                or set(binding) != _PROPOSAL_BINDING_FIELDS
                or {key: binding[key] for key in base} != base
                or not isinstance(binding.get("providerDigest"), str)
                or not str(binding["providerDigest"]).startswith("sha256:")
                or not _HEX_DIGEST_RE.fullmatch(str(binding["providerDigest"])[7:])
            ):
                raise LifecycleError("durable proposal provider binding is invalid")
            freshness_ref = closed[0].payload_ref
            prefix = f"proposals/{run_id}-freshness-"
            if (
                not isinstance(freshness_ref, str)
                or not freshness_ref.startswith(prefix)
                or not freshness_ref.endswith(".json")
                or not _HEX_DIGEST_RE.fullmatch(
                    freshness_ref[len(prefix) : -len(".json")]
                )
            ):
                raise LifecycleError("durable historical freshness binding is invalid")
            try:
                freshness_bytes = self.store.read_sidecar(
                    self.store.home / "objects" / freshness_ref
                )
            except (OSError, StoreIntegrityError):
                raise LifecycleError("durable historical freshness witness is unavailable") from None
            raw_freshness_digest = hashlib.sha256(freshness_bytes).hexdigest()
            if raw_freshness_digest != freshness_ref[len(prefix) : -len(".json")]:
                raise LifecycleError("durable historical freshness digest is invalid")
            historical, _, _ = admit_freshness_witness_document(
                freshness_bytes,
                run_id=run_id,
                verification_binding_digest=canonical_digest(verification_bindings),
            )
            witness_targets, witness_contracts = freshness_witness_roots(historical)
            if (
                sorted(witness_targets) != sorted(str(item) for item in binding["targetRoots"])
                or sorted(witness_contracts)
                != sorted(str(item) for item in binding["contractRoots"])
            ):
                raise LifecycleError("durable historical freshness roots are invalid")
            trusted_root_witness = "sha256:" + raw_freshness_digest
        for admission in admissions:
            correlation = str(admission.correlation_id)
            draft = expected_admissions.get(correlation)
            if (
                draft is None
                or correlation in seen
                or admission.causation_id != by_evaluation.get(draft.evaluation_id)
                or admission.payload["targetSkill"] != draft.target_skill
                or admission.payload_ref is None
            ):
                raise LifecycleError("proposal run has invalid durable admission binding")
            assert binding is not None and admission.payload_ref is not None
            route = self._validated_receipt_route(
                receipt=self._read_route_receipt(admission.payload_ref, draft),
                admission=admission,
                run_id=run_id,
                draft=draft,
                correlation=correlation,
                provider_binding_ref=self._binding_ref(run_id),
                provider_binding=binding,
            )
            route_reasons = self._route_reasons(route, draft, tuple(Path(item) for item in binding["targetRoots"]))  # type: ignore[arg-type]
            expected_decision = "reject" if route_reasons else "allow"
            if (
                route_reasons != list(admission.payload["hardReasons"])
                or admission.payload["decision"] != expected_decision
            ):
                raise LifecycleError("proposal run has invalid durable route decision")
            seen.add(correlation)
            branch_captures = [
                capture for capture in captures if capture.causation_id == admission.event_id
            ]
            expected_capture_count = 1 if expected_decision == "allow" else 0
            if len(branch_captures) != expected_capture_count:
                raise LifecycleError("proposal run has incomplete durable branch terminal")
            if branch_captures:
                capture = branch_captures[0]
                candidate_id = str(capture.payload["providerCandidateId"])
                expected_capture_payload = {
                    "logicalOperationId": f"proposal:capture-journal:{draft.operation_id}",
                    "targetSkill": draft.target_skill,
                    "providerCandidateId": candidate_id,
                    "captureOperationId": draft.operation_id,
                    "owner": route.owner_skill,
                }
                expected_capture_correlation = canonical_digest(
                    {"draft": draft.canonical_mapping(), "providerCandidateId": candidate_id}
                )
                if (
                    capture.to_dict()["payload"] != expected_capture_payload
                    or capture.correlation_id != expected_capture_correlation
                    or capture.payload_ref is not None
                ):
                    raise LifecycleError("proposal run has invalid durable capture binding")
        candidate_ids = sorted(
            str(event.payload["providerCandidateId"])
            for event in captures
        )
        if len(set(candidate_ids)) != len(candidate_ids):
            raise LifecycleError("proposal run has duplicate provider candidate IDs")
        expected_status = "no-op" if not drafts else "completed" if candidate_ids else "rejected"
        expected_report = {
            "schemaVersion": 1,
            "runId": run_id,
            "mode": "propose",
            "status": expected_status,
            "evaluationIds": sorted(event.event_id for event in evaluations),
            "candidateIds": candidate_ids,
            "rejectedCount": sum(event.payload["decision"] == "reject" for event in admissions),
            "mutationPerformed": False,
        }
        report_path = self.store.home / "reports" / f"local-review-{run_id}.json"
        try:
            report_bytes = self.store.read_sidecar(report_path)
        except (OSError, StoreIntegrityError):
            raise LifecycleError("durable proposal report is unavailable") from None
        report_value = _strict_json_object(report_bytes, "proposal report")
        report_event = report[0]
        report_digest = "sha256:" + hashlib.sha256(report_bytes).hexdigest()
        observation_event = next(
            (event for event in events if event.event_type == "task.observed"), None
        )
        if observation_event is None:
            raise LifecycleError("durable proposal observation is unavailable")
        close_binding: dict[str, object] = {
            "status": expected_status,
            "observation": observation_event.event_id,
            "evaluations": [event.event_id for event in evaluations],
        }
        if trusted_root_witness is not None:
            close_binding["trustedRootWitness"] = trusted_root_witness
        if (
            report_value != expected_report
            or report_event.payload["pathDigest"] != report_digest
            or report_event.correlation_id != canonical_digest(expected_report)
            or list(report_event.payload["inputRefs"]) != expected_report["evaluationIds"]
            or closed[0].causation_id != report_event.event_id
            or closed[0].payload["status"] != expected_status
            or (not admissions and closed[0].payload_ref is not None)
            or closed[0].correlation_id != canonical_digest(close_binding)
        ):
            raise LifecycleError("durable proposal report binding is invalid")
        return {
            "schemaVersion": 1,
            "command": "local-review",
            "status": expected_status,
            "mode": "propose",
            "runId": run_id,
            "eventIds": [event.event_id for event in events],
            "candidateIds": candidate_ids,
            "mutationPerformed": False,
            "warnings": [],
            "errors": [],
        }
