"""Causal, immutable monitoring and global reporting for RSI Task 9."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import PurePosixPath

from .events import EventEnvelope
from .hooks import LifecycleError, append_event, canonical_digest
from .metrics import (
    MetricError,
    MetricRecord,
    aggregate_global,
    evaluate_monitoring,
    summarize_records,
    wilson_interval,
)
from .storage import EventStore, StoreIntegrityError

_MAX_REPORT_BYTES = 16 * 1024 * 1024


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _raw_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _event_id(reference: object, label: str) -> str:
    if type(reference) is not str or not reference.startswith("event:"):
        raise LifecycleError(f"{label} must be an immutable event reference")
    value = reference[6:]
    if not value:
        raise LifecycleError(f"{label} must be an immutable event reference")
    return value


def _index(events: Iterable[EventEnvelope]) -> dict[str, EventEnvelope]:
    return {event.event_id: event for event in events}


def _require_event(
    by_id: Mapping[str, EventEnvelope], reference: object, event_type: str, label: str
) -> EventEnvelope:
    event = by_id.get(_event_id(reference, label))
    if event is None or event.event_type != event_type:
        raise LifecycleError(f"{label} does not name a durable {event_type} event")
    return event


def _predecessor(
    by_id: Mapping[str, EventEnvelope], event: EventEnvelope, event_type: str
) -> EventEnvelope:
    predecessor = by_id.get(event.causation_id or "")
    if predecessor is None or predecessor.event_type != event_type:
        raise LifecycleError("promotion lineage is incomplete")
    return predecessor


def _report_ref(prefix: str, body: Mapping[str, object]) -> tuple[str, bytes, str]:
    encoded = _canonical_bytes(body)
    if len(encoded) > _MAX_REPORT_BYTES:
        raise LifecycleError("report exceeds its byte limit")
    digest = _raw_digest(encoded)
    return f"reports/{prefix}-{digest[7:]}.json", encoded, digest


def _append_close(
    store: EventStore,
    *,
    run_id: str,
    logical_operation_id: str,
    causation_id: str,
    status: str,
    linked_ids: list[str],
) -> EventEnvelope:
    return append_event(
        store,
        event_type="run.closed",
        run_id=run_id,
        logical_operation_id=logical_operation_id,
        target_skill="rsi",
        causation_id=causation_id,
        payload={"status": status, "linkedIds": linked_ids},
    )


def summarize_monitoring_window(
    events: Iterable[EventEnvelope],
    promotion_ref: str,
    *,
    required_tasks: int = 10,
) -> dict[str, object]:
    """Fold the fixed post-promotion window without writing state."""
    _event_id(promotion_ref, "promotionRef")
    if type(required_tasks) is not int or not 1 <= required_tasks <= 10_000:
        raise LifecycleError("monitoring window size is invalid")
    by_evaluation: dict[str, str] = {}
    for event in events:
        if event.event_type != "monitoring.recorded" or event.payload["promotionRef"] != promotion_ref:
            continue
        evaluation_ref = str(event.payload["evaluationId"])
        _event_id(evaluation_ref, "evaluationId")
        outcome = str(event.payload["outcome"])
        if outcome not in {"stable", "rollback-proposed", "quarantined"}:
            raise LifecycleError("monitoring window outcome is invalid")
        prior = by_evaluation.setdefault(evaluation_ref, outcome)
        if prior != outcome:
            raise LifecycleError("monitoring window has a conflicting duplicate evaluation")
    observed = len(by_evaluation)
    counts = {
        outcome: sum(value == outcome for value in by_evaluation.values())
        for outcome in ("stable", "rollback-proposed", "quarantined")
    }
    return {
        "schemaVersion": 1,
        "promotionRef": promotion_ref,
        "requiredTasks": required_tasks,
        "observedTasks": observed,
        "remainingTasks": max(0, required_tasks - observed),
        "status": "mature" if observed >= required_tasks else "open",
        "outcomes": counts,
        "mutationPerformed": False,
    }


class MonitoringService:
    """Record one post-promotion comparison without mutating a target."""

    def __init__(self, store: EventStore) -> None:
        self.store = store

    def record(
        self,
        *,
        run_id: str,
        logical_operation_id: str,
        promotion_ref: str,
        evaluation_ref: str,
        baseline: Mapping[str, object],
        variant: Mapping[str, object],
        causal_attribution: str,
        expected_control_plane_version: str,
    ) -> dict[str, object]:
        baseline_record = MetricRecord.from_mapping(baseline)
        variant_record = MetricRecord.from_mapping(variant)
        assessment = evaluate_monitoring(
            baseline_record,
            variant_record,
            causal_attribution=causal_attribution,
            expected_control_plane_version=expected_control_plane_version,
        )
        events = self.store.read_events()
        by_id = _index(events)
        evaluation = _require_event(by_id, evaluation_ref, "evaluation.completed", "evaluationRef")
        if evaluation.run_id != run_id:
            raise LifecycleError("evaluationRef belongs to another monitoring run")
        resolution = _require_event(by_id, promotion_ref, "resolution.recorded", "promotionRef")
        if resolution.run_id == run_id:
            raise LifecycleError("monitoring requires a cross-run promotion reference")
        verification = _predecessor(by_id, resolution, "verification.completed")
        if not (
            verification.payload["liveReadback"] is True
            and verification.payload["tests"] == "passed"
            and verification.payload["attestationMatch"] is True
        ):
            raise LifecycleError("promotionRef is not an affirmatively verified promotion")
        completed = _predecessor(by_id, verification, "apply.completed")
        started = _predecessor(by_id, completed, "apply.started")
        snapshot = _predecessor(by_id, started, "snapshot.created")

        rollback_proposal: dict[str, object] | None = None
        if assessment["outcome"] == "rollback-proposed":
            rollback_proposal = {
                "schemaVersion": 1,
                "kind": "rollback-proposal",
                "promotionRef": promotion_ref,
                "snapshotPath": snapshot.payload["snapshotPath"],
                "expectedPostHash": started.payload["expectedPostHash"],
                "requiresApproval": True,
                "mutationPerformed": False,
            }
        report = {
            "schemaVersion": 1,
            "kind": "monitoring-report",
            "runId": run_id,
            "promotionRef": promotion_ref,
            "evaluationRef": evaluation_ref,
            "baseline": baseline_record.to_mapping(),
            "variant": variant_record.to_mapping(),
            "assessment": assessment,
            "rollbackProposal": rollback_proposal,
            "mutationPerformed": False,
        }
        report_ref, encoded, report_digest = _report_ref("monitoring", report)
        monitoring = append_event(
            self.store,
            event_type="monitoring.recorded",
            run_id=run_id,
            logical_operation_id=logical_operation_id + ":record",
            target_skill="rsi",
            causation_id=evaluation.event_id,
            payload={
                "promotionRef": promotion_ref,
                "evaluationId": evaluation_ref,
                "causalAttribution": causal_attribution,
                "outcome": assessment["outcome"],
            },
            correlation_id=report_digest,
            payload_ref=report_ref,
            sidecar_path=self.store.home / report_ref,
            sidecar_bytes=encoded,
        )
        event_ids = [monitoring.event_id]
        if assessment["outcome"] == "quarantined":
            incident_id = "incident_" + report_digest[7:39]
            incident = append_event(
                self.store,
                event_type="incident.latched",
                run_id=run_id,
                logical_operation_id=logical_operation_id + ":incident",
                target_skill="rsi",
                causation_id=monitoring.event_id,
                payload={
                    "incidentId": incident_id,
                    "reason": str(assessment["reason"]),
                    "quarantineTargets": [str(started.payload["targetSkill"])],
                },
                correlation_id=report_digest,
            )
            closed = _append_close(
                self.store,
                run_id=run_id,
                logical_operation_id=logical_operation_id + ":close",
                causation_id=incident.event_id,
                status="quarantined",
                linked_ids=[incident_id],
            )
            event_ids.extend((incident.event_id, closed.event_id))
        else:
            closed = _append_close(
                self.store,
                run_id=run_id,
                logical_operation_id=logical_operation_id + ":close",
                causation_id=monitoring.event_id,
                status="completed",
                linked_ids=[monitoring.event_id],
            )
            event_ids.append(closed.event_id)
        return {
            "schemaVersion": 1,
            "runId": run_id,
            "outcome": assessment["outcome"],
            "reason": assessment["reason"],
            "reportRef": report_ref,
            "reportDigest": report_digest,
            "rollbackProposal": rollback_proposal,
            "eventIds": event_ids,
            "mutationPerformed": False,
        }


def _markdown_report(report: Mapping[str, object]) -> bytes:
    aggregate = report["aggregate"]
    assert isinstance(aggregate, Mapping)
    summary = aggregate["summary"]
    assert isinstance(summary, Mapping)
    verified = summary["verifiedSuccessRate"]
    assert isinstance(verified, Mapping)
    uncertainty = report["uncertainty"]
    assert isinstance(uncertainty, Mapping)
    lines = [
        "# RSI global monitoring report",
        "",
        f"Conclusion: {report['conclusion']}",
        f"Reason: {report['reason']}",
        f"Unique task fingerprints: {aggregate['uniqueFingerprintCount']}",
        f"Duplicate task fingerprints: {aggregate['duplicateFingerprintCount']}",
        f"Verified success: {verified['numerator']}/{verified['denominator']}",
        (
            "95% Wilson interval: unknown"
            if uncertainty["verifiedSuccessWilson95"] is None
            else "95% Wilson interval: "
            + "..".join(str(value) for value in uncertainty["verifiedSuccessWilson95"])
        ),
        "",
        "This report is read-only; mutationPerformed=false.",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


class GlobalReportService:
    """Aggregate independent completed evaluations into one immutable global report."""

    def __init__(self, store: EventStore) -> None:
        self.store = store

    def generate(
        self,
        *,
        run_id: str,
        logical_operation_id: str,
        source_evaluation_refs: Iterable[str],
        records: Iterable[Mapping[str, object]],
        minimum_fingerprints: int = 3,
        minimum_skills: int = 2,
    ) -> dict[str, object]:
        references = tuple(source_evaluation_refs)
        parsed = tuple(MetricRecord.from_mapping(item) for item in records)
        if len(references) != len(parsed) or not references:
            raise MetricError("global records and source references must be nonempty and aligned")
        durable = self.store.read_events()
        by_id = _index(durable)
        source_events = [
            _require_event(by_id, ref, "evaluation.completed", "sourceEvaluationRef")
            for ref in references
        ]
        if len({event.event_id for event in source_events}) != len(source_events):
            raise LifecycleError("source evaluation references must be unique")
        for source, record in zip(source_events, parsed, strict=True):
            deltas = source.payload.get("metricDeltas")
            if not isinstance(deltas, Mapping) or deltas.get("taskFingerprint") != record.task_fingerprint:
                raise LifecycleError("source evaluation fingerprint does not match its metric record")

        aggregate = aggregate_global(
            parsed,
            minimum_fingerprints=minimum_fingerprints,
            minimum_skills=minimum_skills,
        )
        verified = aggregate["summary"]["verifiedSuccessRate"]  # type: ignore[index]
        assert isinstance(verified, Mapping)
        denominator = int(verified["denominator"])
        interval: list[float] | None = None
        if denominator:
            interval = list(wilson_interval(int(verified["numerator"]), denominator))
        unique_records: dict[str, MetricRecord] = {}
        for item in parsed:
            unique_records.setdefault(item.task_fingerprint, item)
        grouped: dict[str, list[MetricRecord]] = {}
        for item in unique_records.values():
            key = json.dumps(
                dict(item.baseline_key),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            grouped.setdefault(key, []).append(item)
        baseline_groups = [
            {
                "baselineKey": dict(items[0].baseline_key),
                "summary": summarize_records(items),
            }
            for _, items in sorted(grouped.items())
        ]
        report_core: dict[str, object] = {
            "schemaVersion": 1,
            "kind": "global-monitoring-report",
            "runId": run_id,
            "sourceEvaluationRefs": list(references),
            "records": [item.to_mapping() for item in parsed],
            "baselineGroups": baseline_groups,
            "aggregate": aggregate,
            "conclusion": aggregate["conclusion"],
            "reason": aggregate["reason"],
            "uncertainty": {"verifiedSuccessWilson95": interval},
            "mutationPerformed": False,
        }
        report_id = "global_" + canonical_digest(report_core)[7:39]
        report = {**report_core, "reportId": report_id}
        json_ref, json_bytes, report_digest = _report_ref("global", report)
        markdown_ref = f"reports/global-{report_digest[7:]}.md"
        markdown_bytes = _markdown_report(report)

        controls = sorted({item.control_plane_version for item in parsed})
        active = sorted(
            {
                f"{item.baseline_key['targetSkill']}@{item.baseline_key['targetSkillVersion']}"
                for item in parsed
            }
        )
        started = append_event(
            self.store,
            event_type="run.started",
            run_id=run_id,
            logical_operation_id=logical_operation_id + ":start",
            target_skill="rsi",
            causation_id=None,
            payload={
                "mode": "observe",
                "hookMode": "late-review",
                "activeSkills": active,
                "policyVersion": "1",
                "controlPlaneVersion": controls[0] if len(controls) == 1 else "mixed",
                "runKind": "global",
            },
            correlation_id=report_digest,
        )
        # Markdown is a deterministic derivative.  The JSON event is the
        # marker-last authority and retries complete an interrupted derivative.
        self.store.write_once(self.store.home / markdown_ref, markdown_bytes)
        generated = append_event(
            self.store,
            event_type="global.report.generated",
            run_id=run_id,
            logical_operation_id=logical_operation_id + ":report",
            target_skill="rsi",
            causation_id=started.event_id,
            payload={
                "sourceEvaluationRefs": list(references),
                "thresholds": {
                    "minimumFingerprints": minimum_fingerprints,
                    "minimumSkills": minimum_skills,
                },
                "reportDigest": report_digest,
                "mutationPerformed": False,
            },
            correlation_id=report_digest,
            payload_ref=json_ref,
            sidecar_path=self.store.home / json_ref,
            sidecar_bytes=json_bytes,
        )
        event_ids = [started.event_id, generated.event_id]
        conclusion = str(aggregate["conclusion"])
        if conclusion == "quarantined":
            incident_id = "incident_" + report_digest[7:39]
            incident = append_event(
                self.store,
                event_type="incident.latched",
                run_id=run_id,
                logical_operation_id=logical_operation_id + ":incident",
                target_skill="rsi",
                causation_id=generated.event_id,
                payload={
                    "incidentId": incident_id,
                    "reason": str(aggregate["reason"]),
                    "quarantineTargets": [],
                },
                correlation_id=report_digest,
            )
            closed = _append_close(
                self.store,
                run_id=run_id,
                logical_operation_id=logical_operation_id + ":close",
                causation_id=incident.event_id,
                status="quarantined",
                linked_ids=[incident_id],
            )
            event_ids.extend((incident.event_id, closed.event_id))
        else:
            closed = _append_close(
                self.store,
                run_id=run_id,
                logical_operation_id=logical_operation_id + ":close",
                causation_id=generated.event_id,
                status="completed" if conclusion == "supported" else "no-op",
                linked_ids=[generated.event_id],
            )
            event_ids.append(closed.event_id)
        return {
            "schemaVersion": 1,
            "runId": run_id,
            "reportId": report_id,
            "jsonReportRef": json_ref,
            "markdownReportRef": markdown_ref,
            "reportDigest": report_digest,
            "conclusion": conclusion,
            "reason": aggregate["reason"],
            "eventIds": event_ids,
            "mutationPerformed": False,
        }


def read_report(store: EventStore, report_ref: object) -> dict[str, object]:
    if type(report_ref) is not str:
        raise LifecycleError("reportRef is invalid")
    path = PurePosixPath(report_ref)
    if (
        len(path.parts) != 2
        or path.parts[0] != "reports"
        or not path.name.startswith("global-")
        or not path.name.endswith(".json")
    ):
        raise LifecycleError("reportRef is invalid")
    try:
        raw = store.read_sidecar(store.home / report_ref)
    except (OSError, StoreIntegrityError):
        raise LifecycleError("reportRef is unavailable") from None
    if len(raw) > _MAX_REPORT_BYTES or not raw.endswith(b"\n"):
        raise LifecycleError("report framing is invalid")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise LifecycleError("report framing is invalid") from None
    if (
        not isinstance(value, dict)
        or value.get("schemaVersion") != 1
        or value.get("kind") != "global-monitoring-report"
        or value.get("mutationPerformed") is not False
        or _canonical_bytes(value) != raw
    ):
        raise LifecycleError("report schema is invalid")
    expected = f"reports/global-{_raw_digest(raw)[7:]}.json"
    if report_ref != expected:
        raise LifecycleError("reportRef digest is invalid")
    markers = [
        event
        for event in store.read_events()
        if event.event_type == "global.report.generated"
        and event.payload_ref == report_ref
        and event.payload["reportDigest"] == _raw_digest(raw)
        and event.payload["mutationPerformed"] is False
    ]
    if len(markers) != 1:
        raise LifecycleError("report marker is missing or ambiguous")
    return value
