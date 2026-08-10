"""Read-only observation persistence with trusted verification binding."""
from __future__ import annotations

import json
from typing import Mapping, Sequence

from .hooks import LifecycleError, VerificationResult, _digest, append_event, canonical_digest, target_identity, find_event, PRODUCER_VERSION
from .events import derive_idempotency_key
from .storage import EventStore
from .validation import (
    OUTCOMES,
    observation_digest,
    validate_digest,
    validate_evidence,
    validate_signals,
    validate_targets,
    validate_task_class,
)


def _targets(values: object) -> list[dict[str, str]]:
    return validate_targets(values)


def _signals(value: object, targets: list[dict[str, str]]) -> dict[str, dict[str, int]]:
    return validate_signals(value, targets)


class Observer:
    def __init__(self, store: EventStore, *, verification_authority: object | None = None) -> None:
        self.store = store
        self.verification_authority = verification_authority

    def observe(self, *, run_id: str, logical_operation_id: str, task_class: str, outcome: str, target_skills: object, signals_by_target: object | None = None, signals: object | None = None, evidence: Sequence[object], task_fingerprint: str = "sha256:" + "0" * 64, artifact_digest: str = "sha256:" + "0" * 64) -> dict[str, object]:
        task_class = validate_task_class(task_class)
        task_fingerprint = validate_digest(task_fingerprint, "taskFingerprint")
        artifact_digest = validate_digest(artifact_digest, "artifactDigest")
        if outcome not in OUTCOMES:
            raise LifecycleError("observation input is invalid")
        targets = _targets(target_skills)
        started = next((event for event in self.store.read_events() if event.run_id == run_id and event.event_type == "run.started"), None)
        if started is None:
            raise LifecycleError("unknown RSI run")
        if list(started.payload["activeSkills"]) != [target_identity(item) for item in targets]:
            raise LifecycleError("observed targets do not match run start")
        # Legacy shared signals are deliberately never accepted for verified input.
        scoped = _signals(signals_by_target if signals_by_target is not None else {target_identity(item): {} for item in targets}, targets)
        accepted = validate_evidence(list(evidence))
        resolved = "unverified"
        verification_bindings: dict[str, object] = {"targetRoots": [], "contractRoots": []}
        if callable(self.verification_authority):
            candidate = self.verification_authority(run_id=run_id, task_fingerprint=task_fingerprint, target_skills=targets, artifact_digest=artifact_digest)
            expected = tuple((item["name"], item["versionHash"]) for item in targets)
            if isinstance(candidate, VerificationResult) and candidate.outcome in {"verified-success", "verified-failure"} and (candidate.run_id, candidate.task_fingerprint, candidate.target_skills, candidate.artifact_digest) == (run_id, task_fingerprint, expected, artifact_digest):
                resolved = candidate.outcome
                verification_bindings = {
                    "targetRoots": [item.to_mapping() for item in candidate.target_root_bindings],
                    "contractRoots": [item.to_mapping() for item in candidate.contract_root_bindings],
                }
            elif outcome != "unverified":
                raise LifecycleError("verification result is not bound to this task")
        observation: dict[str, object] = {
            "runId": run_id,
            "taskClass": task_class,
            "outcome": resolved,
            "targetSkills": targets,
            "signalsByTarget": scoped,
            "evidence": accepted,
            "taskFingerprint": task_fingerprint,
            "artifactDigest": artifact_digest,
            "privacy": {
                "rawContentStored": False,
                "redactionApplied": bool(accepted),
                "sensitiveContentDetected": False,
            },
            "draftCount": min(3, len([item for item in self.store.read_events() if item.run_id == run_id and item.event_type == "finding.drafted"])),
            "canonicalCaptureAllowed": resolved != "unverified",
            "verificationBindings": verification_bindings,
        }
        request_digest = observation_digest(observation)
        observation["requestDigest"] = request_digest
        existing = find_event(self.store, derive_idempotency_key(PRODUCER_VERSION, "task.observed", run_id, logical_operation_id, "rsi"))
        cause = existing.causation_id if existing is not None else self._cause(run_id, started.event_id)
        event_id = "evt_" + _digest("task.observed", run_id, logical_operation_id, "rsi")[:32]
        if existing is None:
            self._write(event_id, observation)
        event = append_event(self.store, event_type="task.observed", run_id=run_id, logical_operation_id=logical_operation_id, target_skill="rsi", causation_id=cause, payload={"taskOutcome": resolved, "verificationStatus": "verified" if resolved != "unverified" else "unverified", "targetSkillHashes": [item["versionHash"] for item in targets]}, correlation_id=request_digest, payload_ref="observations/" + event_id + ".json")
        if existing is not None:
            self._write(event_id, observation)
        if event.event_id != event_id:
            raise LifecycleError("observation event identity conflicts with durable payload")
        return {"schemaVersion": 1, "status": "completed", "runId": run_id, "eventIds": [event.event_id], "candidateIds": [], "mutationPerformed": False, "observation": observation}

    def _cause(self, run_id: str, started: str) -> str:
        events = [item for item in self.store.read_events() if item.run_id == run_id]
        if any(item.event_type == "task.observed" for item in events):
            # A concurrent writer may publish between the preflight lookup and
            # cause selection. Reuse its predecessor, never self-cause the retry.
            observed = next(item for item in events if item.event_type == "task.observed")
            assert observed.causation_id is not None
            return observed.causation_id
        drafts = [item for item in events if item.event_type == "finding.drafted"]
        return drafts[-1].event_id if drafts else started

    def _write(self, event_id: str, value: Mapping[str, object]) -> None:
        path = self.store.home / "objects" / "observations" / (event_id + ".json")
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
        try:
            self.store.write_once(path, encoded)
        except Exception as error:
            raise LifecycleError("observation replay conflicts with durable payload") from error
