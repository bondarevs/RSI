"""Strict, read-only monitoring metrics for Task 9 RSI reports."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from statistics import NormalDist
from types import MappingProxyType
from typing import Any


class MetricError(ValueError):
    """A metric record cannot participate in a causal comparison."""


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SEMVER_RE = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\Z")
_RECORD_KEYS = frozenset(
    {
        "schemaVersion",
        "baselineKey",
        "taskFingerprint",
        "controlPlaneVersion",
        "hardInvariantViolations",
        "verifiedSuccess",
        "userCorrection",
        "retryCount",
        "testsPassed",
        "testsTotal",
        "latencyMs",
        "toolCalls",
    }
)
_BASELINE_KEYS = frozenset(
    {
        "targetSkill",
        "taskClass",
        "targetSkillVersion",
        "evaluatorVersion",
        "harnessVersion",
    }
)
_HARD_KEYS = frozenset({"critical", "high"})
_MAX_COUNT = 1_000_000
_MAX_LATENCY_MS = 7 * 24 * 60 * 60 * 1000


def _strict_mapping(value: object, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise MetricError(f"{label} has invalid fields")
    return dict(value)


def _bounded_string(value: object, label: str, *, maximum: int = 1024) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise MetricError(f"{label} is invalid")
    return value


def _optional_count(value: object, label: str, *, maximum: int = _MAX_COUNT) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0 or value > maximum:
        raise MetricError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class MetricRecord:
    baseline_key: Mapping[str, str]
    task_fingerprint: str
    control_plane_version: str
    critical_violations: int
    high_violations: int
    verified_success: bool | None
    user_correction: bool | None
    retry_count: int | None
    tests_passed: int | None
    tests_total: int | None
    latency_ms: int | None
    tool_calls: int | None

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> MetricRecord:
        record = _strict_mapping(value, _RECORD_KEYS, "metric record")
        if record["schemaVersion"] != 1 or type(record["schemaVersion"]) is not int:
            raise MetricError("metric record schema version is invalid")
        baseline = _strict_mapping(record["baselineKey"], _BASELINE_KEYS, "baseline key")
        for field in ("targetSkill", "taskClass", "evaluatorVersion", "harnessVersion"):
            baseline[field] = _bounded_string(baseline[field], f"baseline key {field}")
        version = _bounded_string(baseline["targetSkillVersion"], "target skill version")
        if _DIGEST_RE.fullmatch(version) is None:
            raise MetricError("baseline key target skill version is invalid")
        baseline["targetSkillVersion"] = version
        evaluator = str(baseline["evaluatorVersion"])
        if _SEMVER_RE.fullmatch(evaluator) is None:
            raise MetricError("baseline key evaluator version is invalid")
        control = _bounded_string(record["controlPlaneVersion"], "control plane version")
        if _SEMVER_RE.fullmatch(control) is None:
            raise MetricError("control plane version is invalid")
        hard = _strict_mapping(record["hardInvariantViolations"], _HARD_KEYS, "hard invariants")
        critical = _optional_count(hard["critical"], "critical violations")
        high = _optional_count(hard["high"], "high violations")
        assert critical is not None and high is not None
        for field in ("verifiedSuccess", "userCorrection"):
            if record[field] is not None and type(record[field]) is not bool:
                raise MetricError(f"{field} is invalid")
        passed = _optional_count(record["testsPassed"], "tests passed")
        total = _optional_count(record["testsTotal"], "tests total")
        if (passed is None) != (total is None) or (
            passed is not None and total is not None and passed > total
        ):
            raise MetricError("test numerator and denominator are inconsistent")
        return cls(
            MappingProxyType({key: str(baseline[key]) for key in sorted(baseline)}),
            _bounded_string(record["taskFingerprint"], "task fingerprint"),
            control,
            critical,
            high,
            record["verifiedSuccess"],  # type: ignore[arg-type]
            record["userCorrection"],  # type: ignore[arg-type]
            _optional_count(record["retryCount"], "retry count"),
            passed,
            total,
            _optional_count(record["latencyMs"], "latency", maximum=_MAX_LATENCY_MS),
            _optional_count(record["toolCalls"], "tool calls"),
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "baselineKey": dict(self.baseline_key),
            "taskFingerprint": self.task_fingerprint,
            "controlPlaneVersion": self.control_plane_version,
            "hardInvariantViolations": {
                "critical": self.critical_violations,
                "high": self.high_violations,
            },
            "verifiedSuccess": self.verified_success,
            "userCorrection": self.user_correction,
            "retryCount": self.retry_count,
            "testsPassed": self.tests_passed,
            "testsTotal": self.tests_total,
            "latencyMs": self.latency_ms,
            "toolCalls": self.tool_calls,
        }


def _rate(numerator: int, denominator: int) -> dict[str, int | float | None]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": numerator / denominator if denominator else None,
    }


def summarize_records(records: Iterable[MetricRecord]) -> dict[str, object]:
    owned = tuple(records)
    if any(type(item) is not MetricRecord for item in owned):
        raise MetricError("record collection is invalid")
    verified = [item.verified_success for item in owned if item.verified_success is not None]
    corrections = [item.user_correction for item in owned if item.user_correction is not None]
    passed = sum(item.tests_passed or 0 for item in owned if item.tests_passed is not None)
    total = sum(item.tests_total or 0 for item in owned if item.tests_total is not None)
    return {
        "recordCount": len(owned),
        "verifiedSuccessRate": _rate(sum(value is True for value in verified), len(verified)),
        "userCorrectionRate": _rate(sum(value is True for value in corrections), len(corrections)),
        "testPassRate": _rate(passed, total),
    }


def wilson_interval(successes: int, total: int, confidence: float = 0.95) -> tuple[float, float]:
    if type(successes) is not int or type(total) is not int or total < 1 or not 0 <= successes <= total:
        raise MetricError("confidence interval counts are invalid")
    if type(confidence) is not float or not 0.0 < confidence < 1.0:
        raise MetricError("confidence level is invalid")
    z = NormalDist().inv_cdf(1.0 - (1.0 - confidence) / 2.0)
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = z * math.sqrt(
        proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total)
    ) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def _delta(current: int | None, baseline: int | None) -> int | None:
    return None if current is None or baseline is None else current - baseline


def evaluate_monitoring(
    baseline: MetricRecord,
    variant: MetricRecord,
    *,
    causal_attribution: str,
    expected_control_plane_version: str,
) -> dict[str, object]:
    if type(baseline) is not MetricRecord or type(variant) is not MetricRecord:
        raise MetricError("monitoring records are invalid")
    if dict(baseline.baseline_key) != dict(variant.baseline_key):
        raise MetricError("baseline key mismatch")
    if causal_attribution not in {"isolated", "confounded", "unknown"}:
        raise MetricError("causal attribution is invalid")
    if _SEMVER_RE.fullmatch(expected_control_plane_version) is None:
        raise MetricError("expected control plane version is invalid")

    latency_delta = _delta(variant.latency_ms, baseline.latency_ms)
    retry_delta = _delta(variant.retry_count, baseline.retry_count)
    tool_delta = _delta(variant.tool_calls, baseline.tool_calls)
    baseline_test_rate = (
        baseline.tests_passed / baseline.tests_total
        if baseline.tests_passed is not None and baseline.tests_total
        else None
    )
    variant_test_rate = (
        variant.tests_passed / variant.tests_total
        if variant.tests_passed is not None and variant.tests_total
        else None
    )
    metrics = {
        "latencyDeltaMs": latency_delta,
        "latencyStatus": "unknown" if latency_delta is None else "known",
        "retryDelta": retry_delta,
        "toolCallDelta": tool_delta,
        "baselineTestPassRate": baseline_test_rate,
        "variantTestPassRate": variant_test_rate,
    }

    if (
        baseline.control_plane_version != expected_control_plane_version
        or variant.control_plane_version != expected_control_plane_version
    ):
        outcome, reason, regressions = "quarantined", "control-plane-version-drift", ["control-plane"]
    elif (
        variant.critical_violations > baseline.critical_violations
        or variant.high_violations > baseline.high_violations
    ):
        outcome, reason, regressions = "quarantined", "new-critical-or-high-violation", ["safety"]
    else:
        quality_regressions: list[str] = []
        if baseline.verified_success is True and variant.verified_success is False:
            quality_regressions.append("verified-success")
        if baseline.user_correction is False and variant.user_correction is True:
            quality_regressions.append("user-correction")
        if baseline_test_rate is not None and variant_test_rate is not None and variant_test_rate < baseline_test_rate:
            quality_regressions.append("test-pass-rate")
        if retry_delta is not None and retry_delta > 0:
            quality_regressions.append("retry-count")
        efficiency_regressions = [
            name
            for name, value in (("latency", latency_delta), ("tool-calls", tool_delta))
            if value is not None and value > 0
        ]
        if quality_regressions:
            outcome, reason, regressions = "rollback-proposed", "task-quality-regression", quality_regressions
        elif efficiency_regressions:
            outcome, reason, regressions = "rollback-proposed", "efficiency-regression", efficiency_regressions
        else:
            outcome, reason, regressions = "stable", "no-regression", []
        if regressions and causal_attribution != "isolated":
            outcome, reason = "stable", "insufficient-causal-evidence"

    return {
        "schemaVersion": 1,
        "outcome": outcome,
        "reason": reason,
        "causalAttribution": causal_attribution,
        "baselineKey": dict(baseline.baseline_key),
        "metrics": metrics,
        "regressions": regressions,
        "mutationPerformed": False,
    }


def aggregate_global(
    records: Iterable[MetricRecord],
    *,
    minimum_fingerprints: int = 3,
    minimum_skills: int = 2,
) -> dict[str, object]:
    if type(minimum_fingerprints) is not int or type(minimum_skills) is not int or minimum_fingerprints < 1 or minimum_skills < 1:
        raise MetricError("global thresholds are invalid")
    source = tuple(records)
    if any(type(item) is not MetricRecord for item in source):
        raise MetricError("global records are invalid")
    control_versions = sorted({item.control_plane_version for item in source})
    unique: dict[str, MetricRecord] = {}
    for item in source:
        prior = unique.setdefault(item.task_fingerprint, item)
        if (
            prior is not item
            and prior.control_plane_version == item.control_plane_version
            and prior.to_mapping() != item.to_mapping()
        ):
            raise MetricError("conflicting duplicate task fingerprint")
    skill_count = len({item.baseline_key["targetSkill"] for item in unique.values()})
    threshold_met = len(unique) >= minimum_fingerprints and skill_count >= minimum_skills
    if len(control_versions) > 1:
        conclusion, reason = "quarantined", "control-plane-version-drift"
    elif threshold_met:
        conclusion, reason = "supported", "independence-threshold-met"
    else:
        conclusion, reason = "insufficient-evidence", "independence-threshold-not-met"
    return {
        "schemaVersion": 1,
        "sourceRecordCount": len(source),
        "uniqueFingerprintCount": len(unique),
        "duplicateFingerprintCount": len(source) - len(unique),
        "distinctSkillCount": skill_count,
        "thresholds": {
            "minimumFingerprints": minimum_fingerprints,
            "minimumSkills": minimum_skills,
        },
        "controlPlaneVersions": control_versions,
        "conclusion": conclusion,
        "reason": reason,
        "summary": summarize_records(unique.values()),
        "mutationPerformed": False,
    }
