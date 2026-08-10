"""Pure, closed request schemas shared by the Task 4 CLI and lifecycle."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

from .sanitize import sanitize_evidence


class LifecycleError(ValueError):
    """A request cannot safely participate in the observe-only lifecycle."""


SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}(?::[a-z0-9][a-z0-9._-]{0,62})?\Z")
TASK_CLASS_RE = re.compile(r"[a-z][a-z0-9-]{0,31}(?:\.[a-z][a-z0-9-]{0,31}){0,7}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SCOPE_RE = re.compile(r"[a-z][a-z0-9]{0,31}(?:\.[a-z][a-z0-9-]{0,31}){0,7}\Z")
DEDUPE_RE = re.compile(r"[a-z][a-z0-9.-]{2,127}\Z")
MODES = frozenset({"off", "observe", "propose", "promote-safe"})
HOOK_MODES = frozenset({"coordinated", "late-review"})
OUTCOMES = frozenset({"verified-success", "verified-failure", "unverified"})
SIGNALS = frozenset({"retryCount", "toolFailureCount", "userCorrectionCount", "testPassed", "testFailed", "latencyMs"})
MAX_SIGNAL = 1_000_000
ZERO_DIGEST = "sha256:" + "0" * 64
OBSERVATION_FIELDS = frozenset(
    {
        "runId", "taskClass", "outcome", "targetSkills", "signalsByTarget", "evidence",
        "taskFingerprint", "artifactDigest", "requestDigest", "privacy", "draftCount",
        "canonicalCaptureAllowed", "verificationBindings",
    }
)


def _closed(value: object, fields: set[str] | frozenset[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise LifecycleError(f"{label} has an invalid schema")
    if any(not isinstance(key, str) for key in value):
        raise LifecycleError(f"{label} has an invalid schema")
    return value


def validate_cli_identifiers(run_id: object, logical_operation_id: object) -> tuple[str, str]:
    if not isinstance(run_id, str) or not IDENTIFIER_RE.fullmatch(run_id):
        raise LifecycleError("run id is invalid")
    if not isinstance(logical_operation_id, str) or not IDENTIFIER_RE.fullmatch(logical_operation_id):
        raise LifecycleError("idempotency key is invalid")
    return run_id, logical_operation_id


def validate_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise LifecycleError(f"{label} must be a sha256 digest")
    return value


def validate_task_class(value: object) -> str:
    if not isinstance(value, str) or len(value) > 128 or not TASK_CLASS_RE.fullmatch(value):
        raise LifecycleError("taskClass is invalid")
    return value


def target_identity(target: Mapping[str, str]) -> str:
    return target["name"] + "@" + target["versionHash"]


def validate_targets(value: object, label: str = "target skills") -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise LifecycleError(f"{label} must be a bounded non-empty array")
    result: list[dict[str, str]] = []
    for item in value:
        source = _closed(item, {"name", "versionHash"}, f"{label} entry")
        name = source["name"]
        version = source["versionHash"]
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise LifecycleError(f"{label} entry name is invalid")
        result.append({"name": name, "versionHash": validate_digest(version, f"{label} versionHash")})
    identities = [target_identity(item) for item in result]
    if len(set(identities)) != len(identities) or len({item["name"] for item in result}) != len(result):
        raise LifecycleError(f"{label} contains a duplicate")
    return result


def validate_signals(value: object, targets: list[dict[str, str]]) -> dict[str, dict[str, int]]:
    identities = [target_identity(item) for item in targets]
    if not isinstance(value, Mapping) or set(value) != set(identities) or any(not isinstance(key, str) for key in value):
        raise LifecycleError("signalsByTarget must exactly match target identities")
    result: dict[str, dict[str, int]] = {}
    for identity in identities:
        signals = value[identity]
        if not isinstance(signals, Mapping) or any(not isinstance(key, str) for key in signals) or set(signals) - SIGNALS:
            raise LifecycleError("signalsByTarget entry has an invalid schema")
        if len(signals) > len(SIGNALS):
            raise LifecycleError("signalsByTarget entry has an invalid schema")
        clean: dict[str, int] = {}
        for key, signal in signals.items():
            if type(signal) is not int or signal < 0 or signal > MAX_SIGNAL:
                raise LifecycleError("signal value is out of bounds")
            clean[key] = signal
        result[identity] = clean
    return result


def validate_evidence(value: object, label: str = "evidence", *, require_nonempty: bool = False) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 5 or (require_nonempty and not value):
        raise LifecycleError(f"{label} must be a bounded {'non-empty ' if require_nonempty else ''}array")
    raw: list[dict[str, str]] = []
    for item in value:
        source = _closed(item, {"kind", "summary"}, f"{label} entry")
        kind, summary = source["kind"], source["summary"]
        if not isinstance(kind, str) or not kind or len(kind) > 80:
            raise LifecycleError(f"{label} kind is invalid")
        if not isinstance(summary, str) or not summary or len(summary) > 1200:
            raise LifecycleError(f"{label} summary is invalid")
        raw.append({"kind": kind, "summary": summary})
    sanitized = sanitize_evidence(raw)
    if sanitized.rejected_count or sanitized.truncated_count or len(sanitized.accepted) != len(raw):
        raise LifecycleError(f"{label} contains unsafe or unrepresentable content")
    return [dict(item) for item in sanitized.accepted]


def validate_finding(value: object) -> dict[str, str]:
    source = _closed(value, {"proposedScope", "proposedDedupeKey", "summary"}, "finding draft")
    scope, dedupe, summary = source["proposedScope"], source["proposedDedupeKey"], source["summary"]
    if not isinstance(scope, str) or len(scope) > 128 or not SCOPE_RE.fullmatch(scope):
        raise LifecycleError("finding draft scope is invalid")
    if not isinstance(dedupe, str) or not DEDUPE_RE.fullmatch(dedupe):
        raise LifecycleError("finding draft dedupe key is invalid")
    admitted = validate_evidence([{"kind": "finding", "summary": summary}], "finding draft")
    return {"proposedScope": scope, "proposedDedupeKey": dedupe, "summary": admitted[0]["summary"]}


def validate_local_review(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise LifecycleError("local-review input must be an object")
    allowed = {"mode", "hookMode", "taskClass", "activeSkills", "signalsByTarget", "evidence", "taskFingerprint", "artifactDigest", "findings", "finalArtifacts"}
    if set(value) - allowed:
        raise LifecycleError("local-review input contains unknown fields")
    mode = value.get("mode", "observe")
    hook_mode = value.get("hookMode", "coordinated")
    if type(mode) is not str or mode not in MODES:
        raise LifecycleError("local-review mode is invalid")
    if type(hook_mode) is not str or hook_mode not in HOOK_MODES:
        raise LifecycleError("local-review hookMode is invalid")
    task_class = validate_task_class(value.get("taskClass"))
    targets = validate_targets(value.get("activeSkills"), "activeSkills")
    task_fingerprint = validate_digest(value.get("taskFingerprint", ZERO_DIGEST), "taskFingerprint")
    artifact_digest = validate_digest(value.get("artifactDigest", ZERO_DIGEST), "artifactDigest")
    result: dict[str, object] = {
        "mode": mode,
        "hookMode": hook_mode,
        "taskClass": task_class,
        "activeSkills": targets,
        "taskFingerprint": task_fingerprint,
        "artifactDigest": artifact_digest,
    }
    if hook_mode == "late-review":
        if {"findings", "signalsByTarget", "evidence"} & set(value) or "finalArtifacts" not in value:
            raise LifecycleError("late-review accepts only supplied finalArtifacts")
        result["finalArtifacts"] = validate_evidence(value["finalArtifacts"], "finalArtifacts", require_nonempty=True)
    else:
        if "finalArtifacts" in value:
            raise LifecycleError("coordinated local-review does not accept finalArtifacts")
        result["signalsByTarget"] = validate_signals(value.get("signalsByTarget", {target_identity(item): {} for item in targets}), targets)
        result["evidence"] = validate_evidence(value.get("evidence", []))
        findings = value.get("findings", [])
        if not isinstance(findings, list) or len(findings) > 3:
            raise LifecycleError("findings must be a bounded array")
        result["findings"] = [validate_finding(item) for item in findings]
    return result


def validate_observe(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise LifecycleError("observe input must be an object")
    allowed = {"taskClass", "targetSkills", "signalsByTarget", "evidence", "taskFingerprint", "artifactDigest"}
    if set(value) - allowed or not {"taskClass", "targetSkills", "signalsByTarget"} <= set(value):
        raise LifecycleError("observe input has an invalid schema")
    targets = validate_targets(value["targetSkills"])
    return {
        "taskClass": validate_task_class(value["taskClass"]),
        "targetSkills": targets,
        "signalsByTarget": validate_signals(value["signalsByTarget"], targets),
        "evidence": validate_evidence(value.get("evidence", [])),
        "taskFingerprint": validate_digest(value.get("taskFingerprint", ZERO_DIGEST), "taskFingerprint"),
        "artifactDigest": validate_digest(value.get("artifactDigest", ZERO_DIGEST), "artifactDigest"),
    }


def validate_observation(value: object) -> dict[str, object]:
    source = _closed(value, OBSERVATION_FIELDS, "observation")
    run_id = source["runId"]
    if not isinstance(run_id, str) or not IDENTIFIER_RE.fullmatch(run_id):
        raise LifecycleError("observation runId is invalid")
    outcome = source["outcome"]
    if type(outcome) is not str or outcome not in OUTCOMES:
        raise LifecycleError("observation outcome is invalid")
    targets = validate_targets(source["targetSkills"])
    privacy = _closed(source["privacy"], {"rawContentStored", "redactionApplied", "sensitiveContentDetected"}, "observation privacy")
    if any(type(privacy[key]) is not bool for key in privacy) or privacy["rawContentStored"] is not False:
        raise LifecycleError("observation privacy is invalid")
    draft_count = source["draftCount"]
    if type(draft_count) is not int or not 0 <= draft_count <= 3:
        raise LifecycleError("observation draftCount is invalid")
    capture = source["canonicalCaptureAllowed"]
    if type(capture) is not bool or capture is not (outcome != "unverified"):
        raise LifecycleError("observation canonicalCaptureAllowed is inconsistent")
    evidence = validate_evidence(source["evidence"])
    if evidence != source["evidence"]:
        raise LifecycleError("observation evidence is not in canonical admitted form")
    from .target_identity import admit_verification_bindings

    verification_bindings = admit_verification_bindings(source["verificationBindings"], targets)
    if outcome == "unverified" and verification_bindings["targetRoots"]:
        raise LifecycleError("unverified observation cannot carry trusted root bindings")
    return {
        "runId": run_id,
        "taskClass": validate_task_class(source["taskClass"]),
        "outcome": outcome,
        "targetSkills": targets,
        "signalsByTarget": validate_signals(source["signalsByTarget"], targets),
        "evidence": evidence,
        "taskFingerprint": validate_digest(source["taskFingerprint"], "taskFingerprint"),
        "artifactDigest": validate_digest(source["artifactDigest"], "artifactDigest"),
        "requestDigest": validate_digest(source["requestDigest"], "requestDigest"),
        "privacy": dict(privacy),
        "draftCount": draft_count,
        "canonicalCaptureAllowed": capture,
        "verificationBindings": verification_bindings,
    }


def observation_digest(value: Mapping[str, object]) -> str:
    semantic = {key: value[key] for key in sorted(OBSERVATION_FIELDS - {"requestDigest"})}
    encoded = json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_evaluate(value: object) -> dict[str, object]:
    source = _closed(value, {"observation", "observationEventId"}, "evaluate input")
    event_id = source["observationEventId"]
    if not isinstance(event_id, str) or not IDENTIFIER_RE.fullmatch(event_id):
        raise LifecycleError("observationEventId is invalid")
    return {"observation": validate_observation(source["observation"]), "observationEventId": event_id}
