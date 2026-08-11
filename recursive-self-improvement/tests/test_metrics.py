from __future__ import annotations

import importlib

import pytest


def _metrics():
    return importlib.import_module("rsi_core.metrics")


def _record(
    fingerprint: str,
    *,
    skill: str = "alpha-skill",
    task_class: str = "coding",
    version: str = "sha256:" + "1" * 64,
    evaluator: str = "1.0.0",
    harness: str = "harness-v1",
    control: str = "1.1.0",
    verified_success: bool | None = True,
    user_correction: bool | None = False,
    critical: int = 0,
    high: int = 0,
    retry_count: int | None = 1,
    tests_passed: int | None = 10,
    tests_total: int | None = 10,
    latency_ms: int | None = 100,
    tool_calls: int | None = 2,
) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "baselineKey": {
            "targetSkill": skill,
            "taskClass": task_class,
            "targetSkillVersion": version,
            "evaluatorVersion": evaluator,
            "harnessVersion": harness,
        },
        "taskFingerprint": fingerprint,
        "controlPlaneVersion": control,
        "hardInvariantViolations": {"critical": critical, "high": high},
        "verifiedSuccess": verified_success,
        "userCorrection": user_correction,
        "retryCount": retry_count,
        "testsPassed": tests_passed,
        "testsTotal": tests_total,
        "latencyMs": latency_ms,
        "toolCalls": tool_calls,
    }


def test_baseline_key_is_per_target_task_version_evaluator_and_harness() -> None:
    """Dropping any baseline dimension would compare causally different work."""
    module = _metrics()
    first = module.MetricRecord.from_mapping(_record("task-a"))
    changed = _record("task-b", harness="harness-v2")

    with pytest.raises(module.MetricError, match="baseline key"):
        module.evaluate_monitoring(
            first,
            module.MetricRecord.from_mapping(changed),
            causal_attribution="isolated",
            expected_control_plane_version="1.1.0",
        )


def test_missing_metrics_remain_unknown_and_never_become_zero() -> None:
    """A missing latency/tool measurement must not fabricate an improvement."""
    module = _metrics()
    baseline = module.MetricRecord.from_mapping(_record("task-a", latency_ms=None))
    variant = module.MetricRecord.from_mapping(_record("task-b", latency_ms=None))

    result = module.evaluate_monitoring(
        baseline,
        variant,
        causal_attribution="isolated",
        expected_control_plane_version="1.1.0",
    )

    assert result["metrics"]["latencyDeltaMs"] is None
    assert result["metrics"]["latencyStatus"] == "unknown"


def test_exact_rate_denominators_do_not_count_unknown_observations() -> None:
    """Unknown outcomes must be excluded from both numerator and denominator."""
    module = _metrics()
    summary = module.summarize_records(
        [
            module.MetricRecord.from_mapping(_record("task-a", verified_success=True)),
            module.MetricRecord.from_mapping(_record("task-b", verified_success=False)),
            module.MetricRecord.from_mapping(_record("task-c", verified_success=None)),
        ]
    )

    assert summary["verifiedSuccessRate"] == {
        "numerator": 1,
        "denominator": 2,
        "value": 0.5,
    }


def test_wilson_interval_uses_the_exact_observed_denominator() -> None:
    """Changing denominator handling must move the independently known interval."""
    module = _metrics()

    lower, upper = module.wilson_interval(0, 10)

    assert lower == pytest.approx(0.0, abs=1e-12)
    assert upper == pytest.approx(0.2775328, abs=1e-7)


def test_safety_regression_quarantines_before_quality_or_efficiency() -> None:
    """Latency gains cannot compensate for a newly introduced high violation."""
    module = _metrics()
    result = module.evaluate_monitoring(
        module.MetricRecord.from_mapping(_record("task-a", latency_ms=500)),
        module.MetricRecord.from_mapping(
            _record("task-b", high=1, verified_success=True, latency_ms=1)
        ),
        causal_attribution="isolated",
        expected_control_plane_version="1.1.0",
    )

    assert result["outcome"] == "quarantined"
    assert result["reason"] == "new-critical-or-high-violation"
    assert result["mutationPerformed"] is False


def test_quality_regression_proposes_rollback_even_when_efficiency_improves() -> None:
    """A faster failed task is still a regression under lexicographic policy."""
    module = _metrics()
    result = module.evaluate_monitoring(
        module.MetricRecord.from_mapping(_record("task-a", latency_ms=500)),
        module.MetricRecord.from_mapping(
            _record("task-b", verified_success=False, latency_ms=1)
        ),
        causal_attribution="isolated",
        expected_control_plane_version="1.1.0",
    )

    assert result["outcome"] == "rollback-proposed"
    assert result["reason"] == "task-quality-regression"


def test_control_plane_version_drift_is_quarantined() -> None:
    """Metrics computed under another control plane cannot authorize stability."""
    module = _metrics()
    result = module.evaluate_monitoring(
        module.MetricRecord.from_mapping(_record("task-a")),
        module.MetricRecord.from_mapping(_record("task-b", control="2.0.0")),
        causal_attribution="isolated",
        expected_control_plane_version="1.1.0",
    )

    assert result["outcome"] == "quarantined"
    assert result["reason"] == "control-plane-version-drift"


def test_global_evidence_deduplicates_fingerprints_and_requires_three_tasks_two_skills() -> None:
    """Repeated evidence from one task or skill cannot become a global claim."""
    module = _metrics()
    records = [
        module.MetricRecord.from_mapping(_record("task-a", skill="alpha-skill")),
        module.MetricRecord.from_mapping(_record("task-a", skill="alpha-skill")),
        module.MetricRecord.from_mapping(_record("task-b", skill="alpha-skill")),
        module.MetricRecord.from_mapping(_record("task-c", skill="beta-skill")),
    ]

    summary = module.aggregate_global(records, minimum_fingerprints=3, minimum_skills=2)

    assert summary["sourceRecordCount"] == 4
    assert summary["uniqueFingerprintCount"] == 3
    assert summary["duplicateFingerprintCount"] == 1
    assert summary["distinctSkillCount"] == 2
    assert summary["conclusion"] == "supported"


def test_global_evidence_below_either_independence_threshold_is_insufficient() -> None:
    """Meeting only the task count must not claim a cross-skill pattern."""
    module = _metrics()
    records = [
        module.MetricRecord.from_mapping(_record("task-a")),
        module.MetricRecord.from_mapping(_record("task-b")),
        module.MetricRecord.from_mapping(_record("task-c")),
    ]

    summary = module.aggregate_global(records, minimum_fingerprints=3, minimum_skills=2)

    assert summary["conclusion"] == "insufficient-evidence"
    assert summary["thresholds"] == {
        "minimumFingerprints": 3,
        "minimumSkills": 2,
    }


def test_duplicate_fingerprint_with_conflicting_evidence_is_rejected() -> None:
    """Deduplication cannot choose whichever contradictory duplicate appears first."""
    module = _metrics()
    records = [
        module.MetricRecord.from_mapping(_record("task-a", verified_success=True)),
        module.MetricRecord.from_mapping(_record("task-a", verified_success=False)),
    ]

    with pytest.raises(module.MetricError, match="conflicting duplicate"):
        module.aggregate_global(records)


def test_duplicate_fingerprint_cannot_hide_control_plane_drift() -> None:
    """A repeated fingerprint from another control plane is quarantine evidence."""
    module = _metrics()
    records = [
        module.MetricRecord.from_mapping(_record("task-a", control="1.1.0")),
        module.MetricRecord.from_mapping(_record("task-a", control="2.0.0")),
    ]

    summary = module.aggregate_global(records)

    assert summary["conclusion"] == "quarantined"
    assert summary["reason"] == "control-plane-version-drift"
