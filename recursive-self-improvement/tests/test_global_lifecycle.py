from __future__ import annotations

import importlib
import json
import os
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from rsi_core.events import EventValidationError, fold_run
from rsi_core.storage import EventStore, StoreIntegrityError
from test_events import EVENT_PAYLOADS, make_event, promotion_prefix

DIGEST = "sha256:" + "1" * 64


def _report_module():
    return importlib.import_module("rsi_core.report")


def _record(
    fingerprint: str,
    *,
    skill: str = "alpha-skill",
    success: bool | None = True,
    high: int = 0,
    latency: int | None = 100,
    control: str = "1.1.0",
) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "baselineKey": {
            "targetSkill": skill,
            "taskClass": "coding",
            "targetSkillVersion": DIGEST,
            "evaluatorVersion": "1.0.0",
            "harnessVersion": "harness-v1",
        },
        "taskFingerprint": fingerprint,
        "controlPlaneVersion": control,
        "hardInvariantViolations": {"critical": 0, "high": high},
        "verifiedSuccess": success,
        "userCorrection": False,
        "retryCount": 1,
        "testsPassed": 10,
        "testsTotal": 10,
        "latencyMs": latency,
        "toolCalls": 2,
    }


def _tree(root: Path) -> tuple[tuple[str, str, int, bytes], ...]:
    result: list[tuple[str, str, int, bytes]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        metadata = path.lstat()
        kind = "directory" if stat.S_ISDIR(metadata.st_mode) else "file"
        payload = b"" if kind == "directory" else path.read_bytes()
        result.append((path.relative_to(root).as_posix(), kind, stat.S_IMODE(metadata.st_mode), payload))
    return tuple(result)


def _promotion(store: EventStore) -> tuple[str, str]:
    prefix = promotion_prefix(mode="promote-safe", run_id="promotion-run")
    prefix[-1] = make_event(
        "apply.started",
        11,
        causation_id=prefix[-2].event_id,
        run_id="promotion-run",
        payload={**EVENT_PAYLOADS["apply.started"], "expectedPostHash": DIGEST},
    )
    completed = make_event(
        "apply.completed", 12, causation_id=prefix[-1].event_id, run_id="promotion-run"
    )
    verified = make_event(
        "verification.completed", 13, causation_id=completed.event_id, run_id="promotion-run"
    )
    resolved = make_event(
        "resolution.recorded", 14, causation_id=verified.event_id, run_id="promotion-run"
    )
    for event in [*prefix, completed, verified, resolved]:
        store.append(event)
    return "event:" + resolved.event_id, prefix[-2].payload["snapshotPath"]


def _monitor_run(store: EventStore, number: int, fingerprint: str) -> str:
    run_id = f"monitor-run-{number}"
    started = make_event("run.started", number * 10 + 1, run_id=run_id)
    observed = make_event(
        "task.observed", number * 10 + 2, causation_id=started.event_id, run_id=run_id
    )
    evaluation = make_event(
        "evaluation.completed",
        number * 10 + 3,
        causation_id=observed.event_id,
        run_id=run_id,
        payload={
            **EVENT_PAYLOADS["evaluation.completed"],
            "metricDeltas": {"taskFingerprint": fingerprint},
        },
    )
    for event in (started, observed, evaluation):
        store.append(event)
    return "event:" + evaluation.event_id


def test_monitoring_records_verified_cross_run_link_and_exact_rollback_proposal(
    tmp_path: Path,
) -> None:
    """A quality regression must propose, but never execute, the exact snapshot rollback."""
    module = _report_module()
    home, target = tmp_path / "rsi", tmp_path / "target"
    target.mkdir()
    (target / "SKILL.md").write_text("stable target\n", encoding="utf-8")
    before = _tree(target)
    store = EventStore(home)
    promotion_ref, snapshot_path = _promotion(store)
    evaluation_ref = _monitor_run(store, 20, "task-variant")

    result = module.MonitoringService(store).record(
        run_id="monitor-run-20",
        logical_operation_id="monitor-quality",
        promotion_ref=promotion_ref,
        evaluation_ref=evaluation_ref,
        baseline=_record("task-baseline", success=True, latency=500),
        variant=_record("task-variant", success=False, latency=1),
        causal_attribution="isolated",
        expected_control_plane_version="1.1.0",
    )

    assert result["outcome"] == "rollback-proposed"
    assert result["mutationPerformed"] is False
    assert result["rollbackProposal"] == {
        "schemaVersion": 1,
        "kind": "rollback-proposal",
        "promotionRef": promotion_ref,
        "snapshotPath": snapshot_path,
        "expectedPostHash": DIGEST,
        "requiresApproval": True,
        "mutationPerformed": False,
    }
    assert _tree(target) == before
    report = json.loads((home / result["reportRef"]).read_text(encoding="utf-8"))
    assert report["assessment"]["reason"] == "task-quality-regression"
    monitoring = [event for event in store.read_events() if event.event_type == "monitoring.recorded"]
    assert len(monitoring) == 1
    assert monitoring[0].payload["promotionRef"] == promotion_ref
    assert monitoring[0].payload["evaluationId"] == evaluation_ref


def test_monitoring_replay_is_byte_identical_and_does_not_duplicate_event(tmp_path: Path) -> None:
    """At-least-once retry must reuse one report and one monitoring event."""
    module = _report_module()
    store = EventStore(tmp_path / "rsi")
    promotion_ref, _ = _promotion(store)
    evaluation_ref = _monitor_run(store, 30, "task-stable")
    arguments = {
        "run_id": "monitor-run-30",
        "logical_operation_id": "monitor-stable",
        "promotion_ref": promotion_ref,
        "evaluation_ref": evaluation_ref,
        "baseline": _record("task-baseline"),
        "variant": _record("task-stable"),
        "causal_attribution": "isolated",
        "expected_control_plane_version": "1.1.0",
    }

    first = module.MonitoringService(store).record(**arguments)
    report_before = (store.home / first["reportRef"]).read_bytes()
    second = module.MonitoringService(store).record(**arguments)

    assert second == first
    assert (store.home / first["reportRef"]).read_bytes() == report_before
    assert len([event for event in store.read_events() if event.event_type == "monitoring.recorded"]) == 1


def test_global_report_deduplicates_sources_writes_json_and_markdown_and_is_idempotent(
    tmp_path: Path,
) -> None:
    """A global claim must retain exact denominators, uncertainty, provenance, and no mutation."""
    module = _report_module()
    home, target = tmp_path / "rsi", tmp_path / "target"
    target.mkdir()
    (target / "reference.md").write_text("unchanged\n", encoding="utf-8")
    before = _tree(target)
    store = EventStore(home)
    source_refs = [
        _monitor_run(store, 40, "task-a"),
        _monitor_run(store, 41, "task-b"),
        _monitor_run(store, 42, "task-c"),
        _monitor_run(store, 43, "task-a"),
    ]
    records = [
        _record("task-a", skill="alpha-skill"),
        _record("task-b", skill="alpha-skill"),
        _record("task-c", skill="beta-skill"),
        _record("task-a", skill="alpha-skill"),
    ]
    service = module.GlobalReportService(store)

    first = service.generate(
        run_id="global-run",
        logical_operation_id="global-review",
        source_evaluation_refs=source_refs,
        records=records,
        minimum_fingerprints=3,
        minimum_skills=2,
    )
    second = service.generate(
        run_id="global-run",
        logical_operation_id="global-review",
        source_evaluation_refs=source_refs,
        records=records,
        minimum_fingerprints=3,
        minimum_skills=2,
    )

    assert second == first
    assert first["conclusion"] == "supported"
    assert first["mutationPerformed"] is False
    assert first["eventIds"] == second["eventIds"]
    json_report = json.loads((home / first["jsonReportRef"]).read_text(encoding="utf-8"))
    markdown = (home / first["markdownReportRef"]).read_text(encoding="utf-8")
    assert json_report["aggregate"]["uniqueFingerprintCount"] == 3
    assert json_report["aggregate"]["duplicateFingerprintCount"] == 1
    assert json_report["aggregate"]["summary"]["verifiedSuccessRate"]["denominator"] == 3
    assert len(json_report["baselineGroups"]) == 2
    assert sorted(
        group["summary"]["verifiedSuccessRate"]["denominator"]
        for group in json_report["baselineGroups"]
    ) == [1, 2]
    assert "95% Wilson interval" in markdown
    assert _tree(target) == before
    events = store.read_events()
    global_events = [event for event in events if event.event_type == "global.report.generated"]
    assert len(global_events) == 1
    assert global_events[0].payload["mutationPerformed"] is False
    assert fold_run([event for event in events if event.run_id == "global-run"]).status == "completed"


def test_global_run_rejects_local_analysis_events() -> None:
    """Global reporting cannot silently become another local lifecycle or mutation path."""
    started = make_event(
        "run.started",
        1,
        run_id="global-run",
        payload={**EVENT_PAYLOADS["run.started"], "runKind": "global"},
    )
    observed = make_event(
        "task.observed", 2, run_id="global-run", causation_id=started.event_id
    )

    with pytest.raises(EventValidationError, match="global"):
        fold_run([started, observed])


def test_global_run_rejects_duplicate_report_terminal() -> None:
    """One global run cannot publish two competing aggregate conclusions."""
    started = make_event(
        "run.started",
        1,
        run_id="global-run",
        payload={**EVENT_PAYLOADS["run.started"], "runKind": "global"},
    )
    first = make_event(
        "global.report.generated", 2, run_id="global-run", causation_id=started.event_id
    )
    second = make_event(
        "global.report.generated", 3, run_id="global-run", causation_id=started.event_id
    )

    with pytest.raises(EventValidationError, match="global report"):
        fold_run([started, first, second])


def test_local_run_rejects_global_report_event() -> None:
    """The global report terminal is unavailable outside runKind=global."""
    started = make_event("run.started", 1, run_id="local-run")
    report = make_event(
        "global.report.generated", 2, run_id="local-run", causation_id=started.event_id
    )

    with pytest.raises(EventValidationError, match="global report"):
        fold_run([started, report])


def test_global_run_cannot_close_without_one_report() -> None:
    """A successful global close cannot hide a missing aggregate report."""
    started = make_event(
        "run.started",
        1,
        run_id="global-empty",
        payload={**EVENT_PAYLOADS["run.started"], "runKind": "global"},
    )
    closed = make_event("run.closed", 2, run_id="global-empty", causation_id=started.event_id)

    with pytest.raises(EventValidationError, match="global report"):
        fold_run([started, closed])


def test_store_rejects_global_report_with_nonexistent_source_event(tmp_path: Path) -> None:
    """Direct journal use cannot bypass immutable global provenance checks."""
    store = EventStore(tmp_path / "rsi")
    started = make_event(
        "run.started",
        1,
        run_id="global-counterfeit",
        payload={**EVENT_PAYLOADS["run.started"], "runKind": "global"},
    )
    report = make_event(
        "global.report.generated",
        2,
        run_id="global-counterfeit",
        causation_id=started.event_id,
        payload={
            **EVENT_PAYLOADS["global.report.generated"],
            "sourceEvaluationRefs": ["event:evt-missing"],
        },
    )
    store.append(started)

    with pytest.raises(StoreIntegrityError, match="source evaluation"):
        store.append(report)


def test_global_report_rejects_record_not_bound_to_source_fingerprint(tmp_path: Path) -> None:
    """A caller cannot attach strong metrics to an unrelated durable evaluation."""
    module = _report_module()
    store = EventStore(tmp_path / "rsi")
    source = _monitor_run(store, 45, "task-a")

    with pytest.raises(Exception, match="fingerprint"):
        module.GlobalReportService(store).generate(
            run_id="global-mismatch",
            logical_operation_id="global-mismatch",
            source_evaluation_refs=[source],
            records=[_record("task-substituted")],
        )


def test_global_review_cli_and_report_reader_are_stable_and_target_read_only(tmp_path: Path) -> None:
    """Both public commands must use structured input and expose the same durable report."""
    home, target = tmp_path / "rsi", tmp_path / "target"
    target.mkdir()
    (target / "SKILL.md").write_text("unchanged\n", encoding="utf-8")
    nested = target / "references" / "deep"
    nested.mkdir(parents=True)
    (nested / "binary.dat").write_bytes(bytes(range(256)))
    executable = target / "verify.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o750)
    (target / "references").chmod(0o750)
    before = _tree(target)
    store = EventStore(home)
    source_refs = [
        _monitor_run(store, 50, "task-a"),
        _monitor_run(store, 51, "task-b"),
        _monitor_run(store, 52, "task-c"),
    ]
    request = {
        "sourceEvaluationRefs": source_refs,
        "records": [
            _record("task-a", skill="alpha-skill"),
            _record("task-b", skill="alpha-skill"),
            _record("task-c", skill="beta-skill"),
        ],
        "minimumFingerprints": 3,
        "minimumSkills": 2,
    }
    request_path = tmp_path / "global.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    script = Path(__file__).parents[1] / "scripts" / "rsi.py"
    environment = {**os.environ, "PYTHONPATH": str(script.parent)}

    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "global-review",
            "--home",
            str(home),
            "--target-root",
            str(target),
            "--run-id",
            "global-cli-run",
            "--idempotency-key",
            "global-cli-operation",
            "--input-file",
            str(request_path),
            "--json",
        ],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout
    envelope = json.loads(completed.stdout)
    assert envelope["command"] == "global-review"
    assert envelope["mutationPerformed"] is False
    assert _tree(target) == before
    report_request = tmp_path / "report.json"
    report_request.write_text(
        json.dumps({"reportRef": envelope["jsonReportRef"]}), encoding="utf-8"
    )
    rendered = subprocess.run(
        [
            sys.executable,
            str(script),
            "report",
            "--home",
            str(home),
            "--run-id",
            "report-read-run",
            "--idempotency-key",
            "report-read-operation",
            "--input-file",
            str(report_request),
            "--json",
        ],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert rendered.returncode == 0, rendered.stdout
    report_envelope = json.loads(rendered.stdout)
    assert report_envelope["report"]["reportId"] == envelope["reportId"]
    assert report_envelope["mutationPerformed"] is False
    assert _tree(target) == before


def test_global_report_control_plane_mixture_is_quarantined(tmp_path: Path) -> None:
    """Cross-version aggregation must not publish a supported global conclusion."""
    module = _report_module()
    store = EventStore(tmp_path / "rsi")
    refs = [
        _monitor_run(store, 60, "task-a"),
        _monitor_run(store, 61, "task-b"),
        _monitor_run(store, 62, "task-c"),
    ]

    result = module.GlobalReportService(store).generate(
        run_id="global-version-drift",
        logical_operation_id="global-version-drift",
        source_evaluation_refs=refs,
        records=[
            _record("task-a", skill="alpha-skill"),
            _record("task-b", skill="alpha-skill", control="2.0.0"),
            _record("task-c", skill="beta-skill"),
        ],
        minimum_fingerprints=3,
        minimum_skills=2,
    )

    assert result["conclusion"] == "quarantined"
    assert result["reason"] == "control-plane-version-drift"


def test_monitoring_safety_regression_latches_named_target_without_restore(tmp_path: Path) -> None:
    """Safety regression is a durable target quarantine, never an automatic restore."""
    module = _report_module()
    store = EventStore(tmp_path / "rsi")
    promotion_ref, _ = _promotion(store)
    evaluation_ref = _monitor_run(store, 65, "task-unsafe")

    result = module.MonitoringService(store).record(
        run_id="monitor-run-65",
        logical_operation_id="monitor-safety",
        promotion_ref=promotion_ref,
        evaluation_ref=evaluation_ref,
        baseline=_record("task-baseline", high=0),
        variant=_record("task-unsafe", high=1),
        causal_attribution="isolated",
        expected_control_plane_version="1.1.0",
    )

    assert result["outcome"] == "quarantined"
    events = [event for event in store.read_events() if event.run_id == "monitor-run-65"]
    incident = next(event for event in events if event.event_type == "incident.latched")
    assert incident.payload["quarantineTargets"] == ("example",)
    assert not any(event.event_type in {"apply.started", "apply.reverted"} for event in events)


def test_concurrent_global_report_retry_has_one_marker_and_identical_result(tmp_path: Path) -> None:
    """Concurrent at-least-once delivery must converge on one immutable report marker."""
    module = _report_module()
    store = EventStore(tmp_path / "rsi")
    refs = [
        _monitor_run(store, 70, "task-a"),
        _monitor_run(store, 71, "task-b"),
        _monitor_run(store, 72, "task-c"),
    ]
    arguments = {
        "run_id": "global-concurrent",
        "logical_operation_id": "global-concurrent",
        "source_evaluation_refs": refs,
        "records": [
            _record("task-a", skill="alpha-skill"),
            _record("task-b", skill="alpha-skill"),
            _record("task-c", skill="beta-skill"),
        ],
        "minimum_fingerprints": 3,
        "minimum_skills": 2,
    }

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: module.GlobalReportService(store).generate(**arguments), range(2)))

    assert results[0] == results[1]
    events = store.read_events()
    assert len([event for event in events if event.event_type == "global.report.generated"]) == 1
    assert len([event for event in events if event.run_id == "global-concurrent" and event.event_type == "run.closed"]) == 1


def test_monitor_cli_records_only_a_rollback_proposal_and_preserves_target(tmp_path: Path) -> None:
    """The public monitoring command is structured, causal, and target read-only."""
    home, target = tmp_path / "rsi", tmp_path / "target"
    target.mkdir()
    (target / "SKILL.md").write_text("unchanged\n", encoding="utf-8")
    before = _tree(target)
    store = EventStore(home)
    promotion_ref, _ = _promotion(store)
    evaluation_ref = _monitor_run(store, 80, "task-variant")
    request = {
        "promotionRef": promotion_ref,
        "evaluationRef": evaluation_ref,
        "baseline": _record("task-baseline", success=True),
        "variant": _record("task-variant", success=False),
        "causalAttribution": "isolated",
        "expectedControlPlaneVersion": "1.1.0",
    }
    request_path = tmp_path / "monitor.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    script = Path(__file__).parents[1] / "scripts" / "rsi.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "monitor",
            "--home",
            str(home),
            "--target-root",
            str(target),
            "--run-id",
            "monitor-run-80",
            "--idempotency-key",
            "monitor-cli-operation",
            "--input-file",
            str(request_path),
            "--json",
        ],
        env={**os.environ, "PYTHONPATH": str(script.parent)},
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout
    result = json.loads(completed.stdout)
    assert result["command"] == "monitor"
    assert result["outcome"] == "rollback-proposed"
    assert result["rollbackProposal"]["requiresApproval"] is True
    assert result["mutationPerformed"] is False
    assert _tree(target) == before


def test_report_reader_rejects_unreferenced_content_addressed_orphan(tmp_path: Path) -> None:
    """A plausible file is not a report until the immutable journal marker exists."""
    module = _report_module()
    store = EventStore(tmp_path / "rsi")
    report = {
        "schemaVersion": 1,
        "kind": "global-monitoring-report",
        "reportId": "global_orphan",
        "mutationPerformed": False,
    }
    raw = json.dumps(
        report, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8") + b"\n"
    import hashlib

    reference = "reports/global-" + hashlib.sha256(raw).hexdigest() + ".json"
    store.write_once(store.home / reference, raw)

    with pytest.raises(Exception, match="marker"):
        module.read_report(store, reference)


def test_fixed_monitoring_window_counts_unique_later_tasks_and_exact_outcomes() -> None:
    """A promotion matures only after the configured number of distinct evaluations."""
    module = _report_module()
    promotion_ref = "event:evt-promotion"
    events = []
    for number in range(10):
        events.append(
            make_event(
                "monitoring.recorded",
                number + 1,
                run_id=f"later-run-{number}",
                causation_id=f"evt-evaluation-{number}",
                payload={
                    **EVENT_PAYLOADS["monitoring.recorded"],
                    "promotionRef": promotion_ref,
                    "evaluationId": f"event:evt-evaluation-{number}",
                    "outcome": "stable" if number < 9 else "rollback-proposed",
                },
            )
        )
    duplicate = make_event(
        "monitoring.recorded",
        20,
        run_id="duplicate-run",
        causation_id="evt-evaluation-0",
        payload={
            **EVENT_PAYLOADS["monitoring.recorded"],
            "promotionRef": promotion_ref,
            "evaluationId": "event:evt-evaluation-0",
            "outcome": "stable",
        },
    )

    open_window = module.summarize_monitoring_window(events[:9], promotion_ref, required_tasks=10)
    mature = module.summarize_monitoring_window([*events, duplicate], promotion_ref, required_tasks=10)

    assert open_window["status"] == "open"
    assert open_window["observedTasks"] == 9
    assert mature == {
        "schemaVersion": 1,
        "promotionRef": promotion_ref,
        "requiredTasks": 10,
        "observedTasks": 10,
        "remainingTasks": 0,
        "status": "mature",
        "outcomes": {"stable": 9, "rollback-proposed": 1, "quarantined": 0},
        "mutationPerformed": False,
    }
