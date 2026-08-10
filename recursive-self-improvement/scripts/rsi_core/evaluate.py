"""Per-target, read-only evaluator for pre-provider-v2 RSI."""
from __future__ import annotations

from typing import Callable, Mapping
import json

from .hooks import LifecycleError, append_event, canonical_digest, target_identity
from .storage import EventStore
from .validation import MAX_SIGNAL, SIGNALS, observation_digest, validate_observation
from .candidates import evaluation_digest


BaselineLookup = Callable[[str, str, str, str], Mapping[str, object] | None]
EVALUATOR_VERSION = "1.0.0"


class Evaluator:
    def __init__(self, store: EventStore, *, baseline_lookup: BaselineLookup | object | None = None) -> None:
        self.store = store
        self.baseline_lookup = baseline_lookup if callable(baseline_lookup) else self._missing_baseline

    @staticmethod
    def _missing_baseline(_name: str, _task_class: str, _version_hash: str, _evaluator_version: str) -> None:
        return None

    def evaluate_per_target(self, *, run_id: str, observation: Mapping[str, object], observation_event_id: str, logical_operation_id: str) -> list[dict[str, object]]:
        try:
            supplied = validate_observation(observation)
        except LifecycleError:
            raise LifecycleError("evaluation observation is invalid or undeclared") from None
        if supplied["runId"] != run_id:
            raise LifecycleError("evaluation observation does not match the run")
        events = self.store.read_events()
        durable_event = next((item for item in events if item.event_id == observation_event_id and item.run_id == run_id and item.event_type == "task.observed"), None)
        if durable_event is None:
            raise LifecycleError("durable observation is absent")
        path = self.store.home / "objects" / "observations" / (observation_event_id + ".json")
        try:
            durable_raw = json.loads(self.store.read_sidecar(path).decode("utf-8"))
            durable = validate_observation(durable_raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, LifecycleError):
            raise LifecycleError("durable observation is unavailable") from None
        if durable != supplied:
            raise LifecycleError("supplied observation conflicts with durable observation")
        recomputed_digest = observation_digest(durable)
        if durable["requestDigest"] != recomputed_digest:
            raise LifecycleError("durable observation digest is inconsistent")
        started = next((item for item in events if item.run_id == run_id and item.event_type == "run.started"), None)
        if started is None:
            raise LifecycleError("durable run start is absent")
        targets = durable.get("targetSkills")
        if not isinstance(targets, list) or [target_identity(item) for item in targets if isinstance(item, Mapping)] != list(started.payload["activeSkills"]):
            raise LifecycleError("durable observation targets are undeclared or reordered")
        expected_verification = "verified" if durable["outcome"] != "unverified" else "unverified"
        if (
            durable_event.payload_ref != "observations/" + observation_event_id + ".json"
            or durable_event.correlation_id != recomputed_digest
            or durable_event.payload["taskOutcome"] != durable["outcome"]
            or durable_event.payload["verificationStatus"] != expected_verification
            or list(durable_event.payload["targetSkillHashes"]) != [item["versionHash"] for item in targets]
        ):
            raise LifecycleError("durable observation binding is inconsistent")
        results: list[dict[str, object]] = []
        for target in targets:
            if not isinstance(target, Mapping) or not isinstance(target.get("name"), str) or not isinstance(target.get("versionHash"), str):
                raise LifecycleError("observation target skills are invalid")
            name, version_hash, task_class = target["name"], target["versionHash"], durable["taskClass"]
            if not any(item.get("name") == name and item.get("versionHash") == version_hash for item in durable.get("targetSkills", [])):
                raise LifecycleError("undeclared evaluation target")
            operation = logical_operation_id + ":" + name + ":" + version_hash
            baseline = self.baseline_lookup(name, task_class, version_hash, EVALUATOR_VERSION)
            finding_events = [
                item for item in events
                if item.run_id == run_id
                and item.event_type == "finding.drafted"
                and item.payload_ref is not None
                and item.payload["targetSkill"] == name
            ]
            finding_refs = ["event:" + item.event_id for item in finding_events]
            finding_summaries: list[dict[str, object]] = []
            for finding_event in finding_events:
                try:
                    seed = json.loads(
                        self.store.read_sidecar(self.store.home / "objects" / str(finding_event.payload_ref)).decode("utf-8")
                    )
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    raise LifecycleError("durable candidate finding is unavailable") from None
                if not isinstance(seed, Mapping):
                    raise LifecycleError("durable candidate finding is invalid")
                finding_summaries.append(
                    {
                        "title": seed.get("title"),
                        "novel": seed.get("novel"),
                        "causallyRelated": seed.get("causallyRelated"),
                        "confidence": seed.get("confidence"),
                    }
                )
            if not isinstance(baseline, Mapping) or baseline.get("stale") is True or not isinstance(baseline.get("ref"), str):
                baseline_ref, deltas, hard, decision = "unknown", {"baselineStatus": "unknown"}, None, "unknown"
            else:
                baseline_ref = baseline["ref"]
                scoped = durable.get("signalsByTarget", {}).get(name + "@" + version_hash, {}) if isinstance(durable.get("signalsByTarget"), Mapping) else {}
                baseline_signals = self._baseline_signals(baseline.get("signals"))
                deltas = self._metric_deltas(scoped, baseline_signals)
                hard = baseline.get("hardInvariantsPassed") if type(baseline.get("hardInvariantsPassed")) is bool else None
                if hard is True and durable.get("outcome") != "unverified":
                    decision = "candidate-worthy" if finding_refs else "no-finding"
                else:
                    decision = "unknown"
            evaluation_id = f"evaluation:{run_id}:{name}"
            event_id = "evt_" + __import__("hashlib").sha256(
                "\x1f".join(("evaluation.completed", run_id, operation, name)).encode("utf-8")
            ).hexdigest()[:32]
            verification = durable["verificationBindings"]
            assert isinstance(verification, Mapping)
            target_proofs = verification["targetRoots"]
            contract_proofs = verification["contractRoots"]
            assert isinstance(target_proofs, list) and isinstance(contract_proofs, list)
            matched_proofs = [
                item for item in target_proofs
                if isinstance(item, Mapping)
                and item.get("name") == name
                and item.get("versionHash") == version_hash
            ]
            if target_proofs and len(matched_proofs) != 1:
                raise LifecycleError("verified target root binding is incomplete")
            result: dict[str, object] = {
                "runId": run_id,
                "eventId": event_id,
                "evaluationId": evaluation_id,
                "observationEventId": observation_event_id,
                "targetSkill": name,
                "targetSkillVersionHash": version_hash,
                "taskClass": task_class,
                "evaluatorVersion": EVALUATOR_VERSION,
                "baselineRef": baseline_ref,
                "hardInvariantsPassed": hard,
                "metricDeltas": deltas,
                "findingRefs": finding_refs,
                "findings": finding_summaries,
                "decision": decision,
                "verificationBinding": {
                    "targetRoot": dict(matched_proofs[0]) if matched_proofs else None,
                    "contractRoots": [dict(item) for item in contract_proofs],
                },
            }
            result["requestDigest"] = evaluation_digest(result)
            try:
                encoded = json.dumps(
                    result,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8") + b"\n"
            except (TypeError, ValueError):
                raise LifecycleError("evaluation contains a non-canonical metric value") from None
            try:
                self.store.write_once(
                    self.store.home / "objects" / "evaluations" / f"{event_id}.json",
                    encoded,
                )
            except Exception as error:
                raise LifecycleError("evaluation replay conflicts with durable payload") from error
            event = append_event(
                self.store, event_type="evaluation.completed", run_id=run_id, logical_operation_id=operation, target_skill=name,
                causation_id=observation_event_id,
                payload={"baseline": baseline_ref, "metricDeltas": deltas, "evidenceStatus": "verified" if durable.get("outcome") != "unverified" else "unverified"}, correlation_id=str(result["requestDigest"]),
                payload_ref=f"evaluations/{event_id}.json",
            )
            if event.event_id != event_id:
                raise LifecycleError("evaluation event identity conflicts with durable payload")
            result["eventId"] = event.event_id
            results.append(result)
        return results

    @staticmethod
    def _idempotency_key(run_id: str, logical_operation_id: str, target_skill: str) -> str:
        from .events import derive_idempotency_key
        from .hooks import PRODUCER_VERSION
        return derive_idempotency_key(PRODUCER_VERSION, "evaluation.completed", run_id, logical_operation_id, target_skill)

    @staticmethod
    def _metric_deltas(signals: object, baseline_signals: object) -> dict[str, object]:
        if not isinstance(signals, Mapping) or not isinstance(baseline_signals, Mapping):
            return {"baselineStatus": "known"}
        deltas: dict[str, object] = {"baselineStatus": "known"}
        for field in ("retryCount", "toolFailureCount", "userCorrectionCount", "testPassed", "testFailed"):
            current, before = signals.get(field), baseline_signals.get(field)
            if type(current) is int and type(before) is int:
                deltas[field] = current - before
        return deltas

    @staticmethod
    def _baseline_signals(value: object) -> dict[str, int]:
        if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value) or set(value) - SIGNALS:
            raise LifecycleError("baseline signals have an invalid schema")
        result: dict[str, int] = {}
        for key, metric in value.items():
            if type(metric) is not int or metric < 0 or metric > MAX_SIGNAL:
                raise LifecycleError("baseline metric is outside finite bounds")
            result[key] = metric
        return result
