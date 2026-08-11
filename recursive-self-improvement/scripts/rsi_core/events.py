"""Versioned RSI event envelopes and deterministic per-run lifecycle folding."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping


SCHEMA_VERSION = 1
TASK8_CONTROL_PLANE_VERSION = "1.1.0"
TASK8_ADDENDUM_DIGEST = "sha256:ef84059ca0df0d3804dc090616cef3e4abbe3ce7f11ec6f8535e74aa3afe02c0"
TASK8_ADDENDUM_MARKDOWN_DIGEST = "sha256:6fd2ab2a1d45e678f7eaf237c462c49e6dcf3ad133e30c41e28326b9d5f909b6"
TASK8_REGISTRY_ADDENDUM = {
    "controlPlaneVersion": TASK8_CONTROL_PLANE_VERSION,
    "domain": "rsi-task8-registry-addendum-v1",
    "event": {
        "eventType": "apply.reverted",
        "logicalOperationPhase": "rollback",
        "predecessorEventType": "verification.completed",
        "predecessorOutcome": "rollback-armed",
        "sidecarKind": "rollback-readback",
    },
    "normativeMarkdownRawSha256": TASK8_ADDENDUM_MARKDOWN_DIGEST,
    "schemaVersion": 1,
}
TASK8_REGISTRY_ADDENDUM_BYTES = (
    json.dumps(
        TASK8_REGISTRY_ADDENDUM,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    + b"\n"
)


class EventValidationError(ValueError):
    """An event cannot safely participate in the immutable lifecycle ledger."""


@dataclass(frozen=True, slots=True)
class EventRule:
    required_payload_keys: frozenset[str]
    predecessor_types: frozenset[str] | None
    additional_properties: bool = False


_ANY_PREDECESSOR = None
_COMMON_PAYLOAD_KEYS = frozenset({"logicalOperationId", "targetSkill"})
_EVENT_RULES: dict[str, EventRule] = {
    "run.started": EventRule(frozenset({"mode", "hookMode", "activeSkills", "policyVersion", "controlPlaneVersion"}), frozenset()),
    "finding.drafted": EventRule(frozenset({"draftId", "proposedScope", "summary"}), frozenset({"run.started", "finding.drafted"})),
    "task.observed": EventRule(frozenset({"taskOutcome", "verificationStatus", "targetSkillHashes"}), frozenset({"run.started", "finding.drafted"})),
    "evaluation.completed": EventRule(frozenset({"targetSkill", "baseline", "metricDeltas", "evidenceStatus"}), frozenset({"task.observed"})),
    "candidate.admission_decided": EventRule(frozenset({"decision", "hardReasons"}), frozenset({"evaluation.completed"})),
    "candidate.captured": EventRule(frozenset({"providerCandidateId", "captureOperationId", "owner"}), frozenset({"candidate.admission_decided"})),
    "promotion.gated": EventRule(frozenset({"decision", "requiredChecks"}), frozenset({"candidate.captured"})),
    "staging.completed": EventRule(frozenset({"diffDigest", "targetPreHash", "stagingRef"}), frozenset({"promotion.gated"})),
    "validation.completed": EventRule(frozenset({"attestationRef", "attestationDigest"}), frozenset({"staging.completed"})),
    "promotion.planned": EventRule(frozenset({"planRef", "planDigest", "candidateHash", "diffDigest", "targetHash", "contractHash", "providerOperationIds"}), frozenset({"validation.completed"})),
    "snapshot.created": EventRule(frozenset({"snapshotOperationId", "snapshotPath", "manifestDigest"}), frozenset({"promotion.planned"})),
    "apply.started": EventRule(frozenset({"transactionId", "expectedPreHash", "expectedPostHash"}), frozenset({"snapshot.created"})),
    "apply.completed": EventRule(frozenset({"actualPostHash"}), frozenset({"apply.started"})),
    "verification.completed": EventRule(frozenset({"liveReadback", "tests", "attestationMatch"}), frozenset({"apply.completed"})),
    "apply.reverted": EventRule(
        frozenset({"transactionId", "restoredPreHash", "restoredManifestPreHash", "displacedPostHash", "rollbackVerified", "rollbackDigest"}),
        frozenset({"verification.completed"}),
    ),
    "resolution.recorded": EventRule(frozenset({"providerOperationId", "resolutionId"}), frozenset({"verification.completed", "candidate.admission_decided", "promotion.gated", "validation.completed"})),
    "monitoring.recorded": EventRule(frozenset({"promotionRef", "evaluationId", "causalAttribution", "outcome"}), frozenset({"evaluation.completed"})),
    "report.generated": EventRule(frozenset({"reportKind", "pathDigest", "inputRefs", "mutationPerformed"}), frozenset({"task.observed", "evaluation.completed", "candidate.admission_decided", "candidate.captured", "promotion.gated", "validation.completed"})),
    "global.report.generated": EventRule(frozenset({"sourceEvaluationRefs", "thresholds", "reportDigest", "mutationPerformed"}), frozenset({"run.started"})),
    "defrag.audit.completed": EventRule(frozenset({"registrationDigest", "inventoryDigest", "findings", "mutationPerformed"}), frozenset({"run.started"})),
    "defrag.plan.built": EventRule(frozenset({"ruleInventoryDigest", "ledgerDigest", "umbrellaPlanDigest"}), frozenset({"defrag.audit.completed"})),
    "defrag.plan.validated": EventRule(frozenset({"coverage", "goldenValidation", "rollbackValidation", "mutationPerformed"}), frozenset({"defrag.plan.built"})),
    "payload.expired": EventRule(frozenset({"sourceEventId", "payloadRef", "originalDigest", "tombstoneAt"}), frozenset({"run.started"})),
    "incident.latched": EventRule(frozenset({"incidentId", "reason", "quarantineTargets"}), _ANY_PREDECESSOR),
    "run.closed": EventRule(frozenset({"status", "linkedIds"}), _ANY_PREDECESSOR),
}

_STRING_FIELDS = frozenset(
    {
        "logicalOperationId", "targetSkill", "mode", "hookMode", "policyVersion", "controlPlaneVersion",
        "draftId", "proposedScope", "summary", "taskOutcome", "verificationStatus", "baseline",
        "evidenceStatus", "providerCandidateId", "captureOperationId", "owner", "stagingRef",
        "attestationRef", "planRef", "snapshotOperationId", "snapshotPath", "transactionId", "tests",
        "providerOperationId", "resolutionId", "promotionRef", "evaluationId", "causalAttribution", "outcome",
        "reportKind", "coverage", "goldenValidation", "rollbackValidation", "sourceEventId", "payloadRef",
        "tombstoneAt", "incidentId", "reason", "status", "runKind", "decision",
    }
)
_DIGEST_FIELDS = frozenset(
    {
        "diffDigest", "targetPreHash", "attestationDigest", "planDigest", "candidateHash", "targetHash",
        "contractHash", "manifestDigest", "expectedPreHash", "expectedPostHash", "actualPostHash", "pathDigest",
        "reportDigest", "registrationDigest", "inventoryDigest", "ruleInventoryDigest", "ledgerDigest",
        "umbrellaPlanDigest", "originalDigest",
    }
)
_LIST_FIELDS = frozenset(
    {"activeSkills", "targetSkillHashes", "hardReasons", "requiredChecks", "providerOperationIds", "inputRefs",
     "sourceEvaluationRefs", "findings", "quarantineTargets", "linkedIds"}
)
_OBJECT_FIELDS = frozenset({"metricDeltas", "thresholds"})
_BOOLEAN_FIELDS = frozenset({"liveReadback", "attestationMatch", "mutationPerformed"})
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SEMVER_RE = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\Z")
_RUN_MODES = frozenset({"off", "observe", "propose", "promote-safe"})
_RUN_KINDS = frozenset({"local", "global", "defrag", "retention"})

_TASK8_PHASES = {
    "run.started": "run-start",
    "promotion.gated": "gate",
    "staging.completed": "staging",
    "validation.completed": "validation",
    "promotion.planned": "plan",
    "snapshot.created": "snapshot",
    "apply.started": "apply-start",
    "apply.completed": "apply-complete",
    "verification.completed": "verification",
    "resolution.recorded": "resolve",
    "apply.reverted": "rollback",
    "incident.latched": "incident",
    "run.closed": "close",
}
_TASK8_REQUIRED_CHECKS = (
    "allowlist", "artifact-store", "atomic-exchange", "attestation",
    "candidate-authority", "contract", "incident-latch", "namespace-lease",
    "policy", "provider", "target-hash", "ttl",
)
_TASK8_KEYS = {
    "run.started": frozenset({"logicalOperationId", "targetSkill", "mode", "hookMode", "runKind", "activeSkills", "policyVersion", "controlPlaneVersion"}),
    "promotion.gated": frozenset({"logicalOperationId", "targetSkill", "decision", "requiredChecks", "transactionId", "planDigest", "originDigest"}),
    "staging.completed": frozenset({"logicalOperationId", "targetSkill", "diffDigest", "targetPreHash", "stagingRef", "transactionId"}),
    "validation.completed": frozenset({"logicalOperationId", "targetSkill", "attestationRef", "attestationDigest", "transactionId"}),
    "promotion.planned": frozenset({"logicalOperationId", "targetSkill", "planRef", "planDigest", "candidateHash", "diffDigest", "targetHash", "contractHash", "providerOperationIds", "transactionId"}),
    "snapshot.created": frozenset({"logicalOperationId", "targetSkill", "snapshotOperationId", "snapshotPath", "manifestDigest", "transactionId", "snapshotDigest"}),
    "apply.started": frozenset({"logicalOperationId", "targetSkill", "transactionId", "expectedPreHash", "expectedPostHash", "intentDigest"}),
    "apply.reverted": frozenset({"logicalOperationId", "targetSkill", "transactionId", "restoredPreHash", "restoredManifestPreHash", "displacedPostHash", "rollbackVerified", "rollbackDigest"}),
    "resolution.recorded": frozenset({"logicalOperationId", "targetSkill", "transactionId", "providerOperationId", "resolutionId", "providerResolutionRequestDigest", "candidateFullRecordBeforeDigest", "providerAuthorityBindingBeforeDigest", "task7CandidateBindingDigest", "candidateCaptureLineageBindingDigest", "candidateStateBindingBeforeDigest", "candidateFullRecordAfterDigest", "providerAuthorityBindingAfterDigest", "candidateStateBindingAfterDigest", "providerResolutionRecordDigest", "resolutionDigest"}),
    "incident.latched": frozenset({"logicalOperationId", "targetSkill", "incidentId", "reason", "quarantineTargets", "transactionId", "incidentDigest", "quarantineRef", "quarantineDisposition", "blockingQuarantineDigest", "latchRef", "latchDisposition", "blockingLatchDigest"}),
    "run.closed": frozenset({"logicalOperationId", "targetSkill", "status", "linkedIds", "transactionId", "outcome", "terminalReasonCode", "closeStatus", "decisionDigest"}),
}
_TASK8_APPLY_KEYS = {
    "applied": frozenset({"logicalOperationId", "targetSkill", "transactionId", "outcome", "reasonCode", "actualPostHash", "actualManifestPostHash", "readbackDigest"}),
    "not-applied": frozenset({"logicalOperationId", "targetSkill", "transactionId", "outcome", "reasonCode", "actualPreHash", "actualManifestPreHash", "readbackDigest"}),
}
_TASK8_VERIFY_KEYS = frozenset({"logicalOperationId", "targetSkill", "transactionId", "outcome", "reasonCode", "verificationDigest", "liveReadback", "tests", "attestationMatch"})
_TASK8_OP_RE = re.compile(r"op_(snapshot|resolve)_[0-9a-f]{32}\Z")


def derive_idempotency_key(
    producer_version: str, event_type: str, run_id: str, logical_operation_id: str, target_skill: str
) -> str:
    """Return the normative, content-free V1 idempotency digest."""
    normalized = json.dumps(
        [producer_version, event_type, run_id, logical_operation_id, target_skill],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(normalized).hexdigest()


def _task8_digest(value: Mapping[str, Any]) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _task8_transaction_id(plan_digest: str) -> str:
    return "tx_" + _task8_digest(
        {"domain": "rsi-promotion-transaction-v1", "planDigest": plan_digest}
    )[7:]


def _task8_run_id(plan_digest: str) -> str:
    return "run_promote_" + _task8_digest(
        {"domain": "rsi-promotion-continuation-v1", "planDigest": plan_digest}
    )[7:]


def _task8_event_id(transaction_id: str, event_type: str) -> str:
    return "evt_" + _task8_digest(
        {"domain": "rsi-promotion-event-v1", "eventType": event_type, "transactionId": transaction_id}
    )[7:]


def _task8_incident_id(transaction_id: str) -> str:
    return "incident_" + _task8_digest(
        {"domain": "rsi-promotion-incident-v1", "transactionId": transaction_id}
    )[7:]


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _task8_exact_keys(payload: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = set(payload)
    if actual != expected:
        raise EventValidationError(
            f"{label} arm has invalid payload fields: missing={sorted(expected - actual)} "
            f"additional={sorted(actual - expected)}"
        )


def _task8_payload_digest(event_type: str, payload: Mapping[str, Any]) -> str | None:
    field = {
        "promotion.gated": "originDigest",
        "snapshot.created": "snapshotDigest",
        "apply.started": "intentDigest",
        "apply.completed": "readbackDigest",
        "verification.completed": "verificationDigest",
        "apply.reverted": "rollbackDigest",
        "resolution.recorded": "resolutionDigest",
        "run.closed": "decisionDigest",
    }.get(event_type)
    value = payload.get(field) if field else None
    return value if isinstance(value, str) else None


def _validate_task8_event(event: "EventEnvelope") -> None:
    payload = event.payload
    plan_digest = event.correlation_id
    if not _is_digest(plan_digest):
        raise EventValidationError("Task 8 correlationId must bind the plan digest")
    transaction_id = _task8_transaction_id(plan_digest)
    declared_transaction = payload.get("transactionId")
    if declared_transaction is not None and declared_transaction != transaction_id:
        raise EventValidationError("Task 8 transactionId is invalid for the plan correlation")
    if event.run_id != _task8_run_id(plan_digest):
        raise EventValidationError("Task 8 runId does not match the plan")
    if event.event_type not in _TASK8_PHASES:
        raise EventValidationError("event type is unavailable in a Task 8 continuation")
    if event.event_id != _task8_event_id(transaction_id, event.event_type):
        raise EventValidationError("Task 8 eventId is not deterministic")
    expected_logical = f"promote:{transaction_id}:{_TASK8_PHASES[event.event_type]}"
    if payload.get("logicalOperationId") != expected_logical:
        raise EventValidationError("Task 8 logical phase is invalid")
    if payload.get("targetSkill") is None or not isinstance(payload.get("targetSkill"), str):
        raise EventValidationError("Task 8 targetSkill is invalid")

    if event.event_type == "apply.completed":
        outcome = payload.get("outcome")
        expected = _TASK8_APPLY_KEYS.get(outcome)
        if expected is None:
            raise EventValidationError("apply.completed arm is invalid")
        _task8_exact_keys(payload, expected, f"apply.completed {outcome}")
        if outcome == "applied":
            if payload.get("reasonCode") is not None:
                raise EventValidationError("applied arm reasonCode must be null")
            digest_fields = ("actualPostHash", "actualManifestPostHash", "readbackDigest")
        else:
            if not isinstance(payload.get("reasonCode"), str) or not payload["reasonCode"]:
                raise EventValidationError("not-applied reasonCode is invalid")
            digest_fields = ("actualPreHash", "actualManifestPreHash", "readbackDigest")
    elif event.event_type == "verification.completed":
        _task8_exact_keys(payload, _TASK8_VERIFY_KEYS, "verification.completed")
        outcome = payload.get("outcome")
        reason = payload.get("reasonCode")
        tests = payload.get("tests")
        if not isinstance(tests, Mapping) or set(tests) != {
            "skillValidationPassed", "contractValidationPassed", "targetTestsPassed"
        }:
            raise EventValidationError("verification tests arm is invalid")
        values = tuple(tests.values())
        attestation = payload.get("attestationMatch")
        if outcome == "affirmed":
            if reason is not None or values != (True, True, True) or attestation is not True:
                raise EventValidationError("affirmed verification requires all tests and attestation")
        elif outcome == "rollback-armed":
            if reason == "verifier-unavailable":
                if values != (None, None, None) or attestation is not None:
                    raise EventValidationError("verifier-unavailable arm is invalid")
            elif reason == "attestation-mismatch":
                if attestation is not False:
                    raise EventValidationError("attestation-mismatch reason is required")
            elif reason == "verification-failed":
                if attestation is False:
                    raise EventValidationError("attestation-mismatch takes reason precedence")
                if all(value is True for value in values):
                    raise EventValidationError("verification-failed requires a failed test")
            elif reason == "authority-invalidated":
                if values != (True, True, True) or attestation is not True:
                    raise EventValidationError("authority-invalidated proof is invalid")
            else:
                raise EventValidationError("rollback-armed reason is invalid")
        else:
            raise EventValidationError("verification outcome is invalid")
        digest_fields = ("verificationDigest",)
    else:
        expected = _TASK8_KEYS[event.event_type]
        _task8_exact_keys(payload, expected, event.event_type)
        digest_fields = tuple(
            key for key in payload if key.endswith("Digest") or key.endswith("Hash")
        )

    if payload.get("transactionId", transaction_id) != transaction_id:
        raise EventValidationError("Task 8 transactionId is invalid")
    for key in digest_fields:
        value = payload.get(key)
        if key == "providerResolutionRequestDigest":
            valid = isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
        else:
            valid = _is_digest(value)
        if not valid:
            raise EventValidationError(f"payload.{key} must be a sha256 digest")

    if event.event_type == "run.started":
        if payload["mode"] != "promote-safe" or payload["hookMode"] != "coordinated":
            raise EventValidationError("Task 8 run must be promote-safe coordinated")
        if payload["runKind"] != "local":
            raise EventValidationError("Task 8 run must be local")
        if payload["controlPlaneVersion"] != TASK8_CONTROL_PLANE_VERSION:
            raise EventValidationError("Task 8 control plane version is invalid")
        active = payload["activeSkills"]
        if (
            not isinstance(active, tuple)
            or len(active) != 1
            or not isinstance(active[0], str)
            or not active[0].startswith(payload["targetSkill"] + "@sha256:")
            or _SHA256_RE.fullmatch(active[0].split("@", 1)[1]) is None
        ):
            raise EventValidationError("Task 8 activeSkills must identify exactly one target")
    elif event.event_type == "promotion.gated":
        if payload["decision"] != "allow":
            raise EventValidationError("Task 8 promotion gate must allow")
        if payload["requiredChecks"] != _TASK8_REQUIRED_CHECKS:
            raise EventValidationError("Task 8 requiredChecks must be the literal sorted check set")
        if payload["planDigest"] != plan_digest:
            raise EventValidationError("Task 8 gate plan digest mismatch")
    elif event.event_type == "promotion.planned":
        operations = payload["providerOperationIds"]
        if not isinstance(operations, Mapping) or set(operations) != {"snapshot", "resolve"}:
            raise EventValidationError("providerOperationIds must be the exact operation object")
        for name, prefix in (("snapshot", "op_snapshot_"), ("resolve", "op_resolve_")):
            value = operations[name]
            if not isinstance(value, str) or not value.startswith(prefix) or _TASK8_OP_RE.fullmatch(value) is None:
                raise EventValidationError("providerOperationIds contains an invalid operation")
    elif event.event_type == "apply.reverted":
        if payload["rollbackVerified"] is not True:
            raise EventValidationError("rollback proof must be verified")
        if payload["restoredPreHash"] == payload["rollbackDigest"]:
            raise EventValidationError("rollback digest must be independent")
    elif event.event_type == "incident.latched":
        if payload["incidentId"] != _task8_incident_id(transaction_id):
            raise EventValidationError("incident identifier is invalid")
        if payload["quarantineDisposition"] not in {"created", "preexisting"} or payload["latchDisposition"] not in {"created", "preexisting"}:
            raise EventValidationError("incident disposition is invalid")
    elif event.event_type == "run.closed":
        if payload["status"] != payload["closeStatus"]:
            raise EventValidationError("close status fields disagree")
        if payload["linkedIds"][0] != transaction_id:
            raise EventValidationError("close linked transaction is invalid")

    digest = _task8_payload_digest(event.event_type, payload)
    if event.event_type == "incident.latched":
        expected_ref = f"incidents/records/{_task8_incident_id(transaction_id)}.json"
    elif digest is None:
        expected_ref = None
    else:
        role = {
            "promotion.gated": "origin", "snapshot.created": "snapshot",
            "apply.started": "intent", "apply.completed": "readback",
            "verification.completed": "verification", "apply.reverted": "readback",
            "resolution.recorded": "resolution", "run.closed": "decision",
        }[event.event_type]
        expected_ref = f"transactions/{transaction_id}-{role}-{digest[7:]}.json"
    if event.payload_ref != expected_ref:
        raise EventValidationError("Task 8 payloadRef does not match its sidecar binding")


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    schema_version: int
    event_type: str
    event_id: str
    run_id: str
    correlation_id: str | None
    causation_id: str | None
    created_at: str
    idempotency_key: str
    producer_version: str
    payload: Mapping[str, Any] = field(repr=False)
    payload_ref: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", _freeze(self.payload))
        EventRegistry().validate(self)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "EventEnvelope":
        if not isinstance(raw, Mapping):
            raise EventValidationError("event envelope must be an object")
        expected = {
            "schemaVersion", "eventType", "eventId", "runId", "correlationId", "causationId",
            "createdAt", "idempotencyKey", "producerVersion", "payload", "payloadRef",
        }
        extra = set(raw) - expected
        missing = expected - set(raw)
        if extra or missing:
            raise EventValidationError(f"invalid envelope fields: missing={sorted(missing)} extra={sorted(extra)}")
        event = cls(
            schema_version=raw["schemaVersion"], event_type=raw["eventType"], event_id=raw["eventId"],
            run_id=raw["runId"], correlation_id=raw["correlationId"], causation_id=raw["causationId"],
            created_at=raw["createdAt"], idempotency_key=raw["idempotencyKey"],
            producer_version=raw["producerVersion"], payload=raw["payload"], payload_ref=raw["payloadRef"],
        )
        return event

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version, "eventType": self.event_type, "eventId": self.event_id,
            "runId": self.run_id, "correlationId": self.correlation_id, "causationId": self.causation_id,
            "createdAt": self.created_at, "idempotencyKey": self.idempotency_key,
            "producerVersion": self.producer_version, "payload": _thaw(self.payload), "payloadRef": self.payload_ref,
        }


class EventRegistry:
    """The closed V1 registry: unknown versions or types are never tolerated."""

    rules = MappingProxyType(_EVENT_RULES)

    def validate(self, event: EventEnvelope) -> None:
        if event.schema_version != SCHEMA_VERSION:
            raise EventValidationError(f"unsupported schema version: {event.schema_version}")
        rule = self.rules.get(event.event_type)
        if rule is None:
            raise EventValidationError(f"unknown event type: {event.event_type}")
        for field_name, value in (("eventId", event.event_id), ("runId", event.run_id), ("idempotencyKey", event.idempotency_key), ("producerVersion", event.producer_version)):
            if not isinstance(value, str) or not value or len(value) > 512:
                raise EventValidationError(f"{field_name} must be a non-empty string")
        if not _SEMVER_RE.fullmatch(event.producer_version):
            raise EventValidationError("producerVersion must be semver")
        if event.correlation_id is not None and not isinstance(event.correlation_id, str):
            raise EventValidationError("correlationId must be string or null")
        if event.causation_id is not None and not isinstance(event.causation_id, str):
            raise EventValidationError("causationId must be string or null")
        if event.payload_ref is not None and not isinstance(event.payload_ref, str):
            raise EventValidationError("payloadRef must be string or null")
        if not isinstance(event.payload, Mapping):
            raise EventValidationError("payload must be an object")
        try:
            parsed = event.created_at.replace("Z", "+00:00")
            if not event.created_at.endswith("Z") or datetime.fromisoformat(parsed).tzinfo is None:
                raise ValueError
        except (AttributeError, ValueError):
            raise EventValidationError("createdAt must be RFC3339 UTC") from None
        task8 = (
            event.run_id.startswith("run_promote_")
            and event.event_type in _TASK8_PHASES
            and isinstance(event.payload.get("logicalOperationId"), str)
            and event.payload["logicalOperationId"].startswith("promote:")
        )
        if task8:
            _validate_task8_event(event)
            expected_key = derive_idempotency_key(
                event.producer_version,
                event.event_type,
                event.run_id,
                event.payload["logicalOperationId"],
                event.payload["targetSkill"],
            )
            if event.idempotency_key != expected_key:
                raise EventValidationError("idempotencyKey does not match the normative tuple")
            return
        required = rule.required_payload_keys | _COMMON_PAYLOAD_KEYS
        absent = required - set(event.payload)
        if absent:
            raise EventValidationError(f"missing required payload keys: {sorted(absent)}")
        allowed = required | ({"runKind"} if event.event_type == "run.started" else set())
        extra_payload = set(event.payload) - allowed
        if extra_payload and not rule.additional_properties:
            raise EventValidationError(f"additional payload fields are forbidden: {sorted(extra_payload)}")
        for key, value in event.payload.items():
            self._validate_payload_field(key, value)
        expected_key = derive_idempotency_key(
            event.producer_version,
            event.event_type,
            event.run_id,
            event.payload["logicalOperationId"],
            event.payload["targetSkill"],
        )
        if event.idempotency_key != expected_key:
            raise EventValidationError("idempotencyKey does not match the normative tuple")
        if event.event_type == "run.closed" and event.payload["status"] not in {
            "completed", "no-op", "deferred", "rejected", "blocked", "failed", "ambiguous", "quarantined",
        }:
            raise EventValidationError("run.closed has an unsupported status")
        if event.event_type == "run.started":
            if event.payload["mode"] not in _RUN_MODES:
                raise EventValidationError("run.started has an unsupported mode")
            if event.payload.get("runKind", "local") not in _RUN_KINDS:
                raise EventValidationError("run.started has an unsupported runKind")
        if event.event_type == "candidate.admission_decided" and event.payload["decision"] not in {"allow", "reject"}:
            raise EventValidationError("candidate admission decision is invalid")
        if event.event_type == "promotion.gated" and event.payload["decision"] not in {"allow", "defer", "reject", "supersede"}:
            raise EventValidationError("promotion gate decision is invalid")
        if event.event_type in {"report.generated", "global.report.generated", "defrag.audit.completed", "defrag.plan.validated"} and event.payload["mutationPerformed"] is not False:
            raise EventValidationError("read-only event must declare mutationPerformed=false")
        if event.event_type == "monitoring.recorded":
            if not event.payload["promotionRef"].startswith("event:") or not event.payload["evaluationId"].startswith("event:"):
                raise EventValidationError("monitoring refs must use immutable event: references")

    @staticmethod
    def _validate_payload_field(key: str, value: Any) -> None:
        if key in _STRING_FIELDS:
            if not isinstance(value, str) or not value or len(value) > 1024:
                raise EventValidationError(f"payload.{key} must be a bounded non-empty string")
            return
        if key in _DIGEST_FIELDS:
            if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
                raise EventValidationError(f"payload.{key} must be a sha256 digest")
            return
        if key in _LIST_FIELDS:
            if not isinstance(value, tuple) or len(value) > 64:
                raise EventValidationError(f"payload.{key} must be a bounded array")
            for item in value:
                if not isinstance(item, str) or not item or len(item) > 1024:
                    raise EventValidationError(f"payload.{key} contains an invalid item")
            if key == "targetSkillHashes" and any(not _SHA256_RE.fullmatch(item) for item in value):
                raise EventValidationError("payload.targetSkillHashes must contain sha256 digests")
            return
        if key in _OBJECT_FIELDS:
            if not isinstance(value, Mapping) or len(value) > 64:
                raise EventValidationError(f"payload.{key} must be a bounded object")
            return
        if key in _BOOLEAN_FIELDS:
            if type(value) is not bool:
                raise EventValidationError(f"payload.{key} must be boolean")
            return
        raise EventValidationError(f"payload.{key} has no V1 schema")


@dataclass(frozen=True, slots=True)
class RunState:
    run_id: str
    mode: str
    run_kind: str
    status: str | None
    event_ids: tuple[str, ...]
    expired_payloads: Mapping[str, str]
    incident_latched: bool
    open_apply_transactions: frozenset[str]


def _allows_predecessor(event: EventEnvelope, predecessor: EventEnvelope) -> bool:
    rule = _EVENT_RULES[event.event_type]
    if rule.predecessor_types is None:
        return True
    return predecessor.event_type in rule.predecessor_types


def _fold_task8_run(
    sequence: list[EventEnvelope],
    external_predecessors: Mapping[str, EventEnvelope] | None,
) -> RunState:
    registry = EventRegistry()
    first = sequence[0]
    run_id = first.run_id
    by_id: dict[str, EventEnvelope] = {}
    external = dict(external_predecessors or {})
    transaction_id = _task8_transaction_id(first.correlation_id or "")
    status: str | None = None
    incident_latched = False
    open_apply = False
    applied = False
    reverted = False
    resolved = False

    for index, event in enumerate(sequence):
        registry.validate(event)
        if event.run_id != run_id:
            raise EventValidationError("fold_run accepts exactly one run")
        if event.event_id in by_id:
            raise EventValidationError(f"duplicate eventId: {event.event_id}")
        if status is not None:
            raise EventValidationError("terminal event already recorded")
        if index == 0:
            if event.event_type != "run.started" or event.causation_id is not None:
                raise EventValidationError("Task 8 run.started must be first without causation")
        else:
            if event.causation_id is None:
                raise EventValidationError(f"{event.event_type} requires causation")
            predecessor = by_id.get(event.causation_id)
            if predecessor is None:
                predecessor = external.get(event.causation_id)
                if not (
                    index == 1
                    and event.event_type == "promotion.gated"
                    and predecessor is not None
                    and predecessor.event_type == "candidate.captured"
                    and predecessor.run_id != run_id
                ):
                    raise EventValidationError("missing or illegal external causation predecessor")
            allowed = {
                "promotion.gated": {"candidate.captured"},
                "staging.completed": {"promotion.gated"},
                "validation.completed": {"staging.completed"},
                "promotion.planned": {"validation.completed"},
                "snapshot.created": {"promotion.planned"},
                "apply.started": {"snapshot.created"},
                "apply.completed": {"apply.started"},
                "verification.completed": {"apply.completed"},
                "resolution.recorded": {"verification.completed"},
                "apply.reverted": {"verification.completed"},
                "incident.latched": set(_TASK8_PHASES),
                "run.closed": {"promotion.planned", "snapshot.created", "apply.completed", "resolution.recorded", "apply.reverted", "incident.latched"},
            }.get(event.event_type, set())
            if predecessor.event_type not in allowed:
                raise EventValidationError(
                    f"illegal predecessor {predecessor.event_type} for {event.event_type}"
                )

            if event.event_type == "apply.started":
                if open_apply or applied:
                    raise EventValidationError("duplicate apply transaction")
                open_apply = True
            elif event.event_type == "apply.completed":
                if not open_apply or predecessor.payload["transactionId"] != transaction_id:
                    raise EventValidationError("apply.completed has no same-transaction open apply")
                open_apply = False
                applied = event.payload["outcome"] == "applied"
            elif event.event_type == "verification.completed":
                if predecessor.payload["outcome"] != "applied" or not applied:
                    raise EventValidationError("verification requires an applied transaction")
            elif event.event_type == "resolution.recorded":
                if predecessor.payload["outcome"] != "affirmed":
                    raise EventValidationError("resolution requires affirmed verification")
                resolved = True
            elif event.event_type == "apply.reverted":
                if predecessor.payload["outcome"] != "rollback-armed":
                    raise EventValidationError("apply.reverted requires rollback-armed verification")
                if predecessor.payload["transactionId"] != event.payload["transactionId"]:
                    raise EventValidationError("rollback transaction mismatch")
                reverted = True
            elif event.event_type == "incident.latched":
                incident_latched = True
            elif event.event_type == "run.closed":
                linked = event.payload["linkedIds"]
                if linked != (transaction_id, predecessor.event_id):
                    raise EventValidationError("close linkedIds do not match the terminal event")
                outcome = event.payload["outcome"]
                reason = event.payload["terminalReasonCode"]
                if predecessor.event_type == "resolution.recorded":
                    expected = ("promoted", "verified-promotion", "completed")
                    if not resolved:
                        raise EventValidationError("promoted close requires resolution")
                elif predecessor.event_type == "apply.reverted":
                    verification = by_id.get(predecessor.causation_id or "")
                    expected = ("rolled-back", verification.payload["reasonCode"] if verification else None, None)
                    try:
                        from .recovery import close_status_for
                        expected = (expected[0], expected[1], close_status_for(expected[0], expected[1]))
                    except (ImportError, ValueError):
                        raise EventValidationError("rolled-back close reason is invalid") from None
                    if not reverted:
                        raise EventValidationError("rolled-back close requires rollback")
                elif predecessor.event_type == "apply.completed":
                    expected = ("not-applied", predecessor.payload["reasonCode"], None)
                    try:
                        from .recovery import close_status_for
                        expected = (expected[0], expected[1], close_status_for(expected[0], expected[1]))
                    except (ImportError, ValueError):
                        raise EventValidationError("not-applied close reason is invalid") from None
                elif predecessor.event_type in {"promotion.planned", "snapshot.created"}:
                    expected = ("not-started", reason, None)
                    try:
                        from .recovery import close_status_for
                        expected = (expected[0], expected[1], close_status_for(expected[0], expected[1]))
                    except (ImportError, ValueError):
                        raise EventValidationError("not-started close reason is invalid") from None
                elif predecessor.event_type == "incident.latched":
                    expected = (event.payload["status"], predecessor.payload["reason"], event.payload["status"])
                    if expected[0] not in {"ambiguous", "quarantined"} or not incident_latched:
                        raise EventValidationError("incident close status is invalid")
                else:
                    raise EventValidationError("unsupported Task 8 close predecessor")
                actual = (outcome, reason, event.payload["closeStatus"])
                if actual != expected or event.payload["status"] != expected[2]:
                    raise EventValidationError("close status, reason, or outcome contradicts terminal evidence")
                status = event.payload["status"]
        by_id[event.event_id] = event

    return RunState(
        run_id, "promote-safe", "local", status, tuple(by_id),
        MappingProxyType({}), incident_latched,
        frozenset({transaction_id} if open_apply else set()),
    )


def fold_run(
    events: Iterable[EventEnvelope],
    *,
    external_predecessors: Mapping[str, EventEnvelope] | None = None,
) -> RunState:
    """Validate one run in recorded order and derive its stable, audit-only state."""
    sequence = list(events)
    if not sequence:
        raise EventValidationError("a run must contain events")
    if (
        sequence[0].event_type == "run.started"
        and sequence[0].payload.get("runKind", "local") in {"defrag", "retention"}
        and any(event.event_type == "apply.started" for event in sequence[1:])
    ):
        raise EventValidationError(
            "apply transaction is forbidden for this run mode or kind"
        )
    if sequence[0].run_id.startswith("run_promote_"):
        return _fold_task8_run(sequence, external_predecessors)
    if external_predecessors:
        raise EventValidationError("external predecessors are only valid for Task 8 continuations")
    registry = EventRegistry()
    run_id = sequence[0].run_id
    by_id: dict[str, EventEnvelope] = {}
    expired: dict[str, str] = {}
    status: str | None = None
    incident_latched = False
    open_applies: set[str] = set()
    completed_applies: set[str] = set()
    verified_applies: set[str] = set()
    verification_transactions: set[str] = set()
    resolved_applies: set[str] = set()
    resolution_ids: set[str] = set()
    provider_operation_ids: set[str] = set()
    captured_admissions: set[str] = set()
    mode = "off"
    run_kind = "local"
    global_report_generated = False
    defrag_audited = False
    defrag_planned = False
    defrag_validated = False

    for index, event in enumerate(sequence):
        registry.validate(event)
        if event.run_id != run_id:
            raise EventValidationError("fold_run accepts exactly one run")
        if event.event_id in by_id:
            raise EventValidationError(f"duplicate eventId: {event.event_id}")
        if event.event_type == "run.started":
            if index != 0:
                raise EventValidationError("run.started must be first")
            if event.causation_id is not None:
                raise EventValidationError("run.started cannot have causation")
            mode = event.payload["mode"]
            run_kind = event.payload.get("runKind", "local")
        else:
            if run_kind == "global" and event.event_type not in {
                "global.report.generated",
                "incident.latched",
                "run.closed",
            }:
                raise EventValidationError(
                    "global runs accept only global reporting and terminal events"
                )
            if run_kind == "defrag" and event.event_type not in {
                "defrag.audit.completed",
                "defrag.plan.built",
                "defrag.plan.validated",
                "incident.latched",
                "run.closed",
            }:
                if event.event_type == "apply.started":
                    raise EventValidationError(
                        "apply transaction is forbidden for this run mode or kind"
                    )
                raise EventValidationError(
                    "defrag runs accept only defragmentation and terminal events"
                )
            if event.causation_id is None:
                raise EventValidationError(f"{event.event_type} requires causation")
            predecessor = by_id.get(event.causation_id or "")
            if predecessor is None:
                raise EventValidationError("missing causation event")
            if not _allows_predecessor(event, predecessor):
                raise EventValidationError(f"illegal predecessor {predecessor.event_type} for {event.event_type}")
            if event.event_type == "global.report.generated" and run_kind != "global":
                raise EventValidationError("global report event requires a global run")
            if event.event_type.startswith("defrag.") and run_kind != "defrag":
                raise EventValidationError("defragmentation event requires a defrag run")
            if event.event_type == "candidate.captured" and predecessor.payload["decision"] != "allow":
                raise EventValidationError("candidate.captured requires admission allow")
            if event.event_type == "candidate.captured":
                assert event.causation_id is not None
                if event.causation_id in captured_admissions:
                    raise EventValidationError("duplicate candidate capture terminal")
                captured_admissions.add(event.causation_id)
            if event.event_type == "staging.completed" and predecessor.payload["decision"] != "allow":
                raise EventValidationError("staging.completed requires gate allow")
        if status is not None:
            raise EventValidationError("terminal event already recorded")
        if event.event_type == "apply.started":
            if mode != "promote-safe" or run_kind != "local":
                raise EventValidationError("apply transaction is forbidden for this run mode or kind")
            transaction_id = event.payload["transactionId"]
            if transaction_id in open_applies or transaction_id in completed_applies:
                raise EventValidationError("duplicate apply transaction")
            open_applies.add(transaction_id)
        elif event.event_type == "apply.completed":
            assert event.causation_id is not None
            transaction = by_id[event.causation_id].payload["transactionId"]
            if transaction not in open_applies:
                raise EventValidationError("apply.completed has no open transaction")
            open_applies.remove(transaction)
            completed_applies.add(transaction)
        elif event.event_type == "verification.completed":
            assert event.causation_id is not None
            transaction = by_id[by_id[event.causation_id].causation_id or ""].payload["transactionId"]
            if transaction not in completed_applies:
                raise EventValidationError("verification has no completed transaction")
            if transaction in verification_transactions:
                raise EventValidationError("duplicate verification terminal event")
            verification_transactions.add(transaction)
            if event.payload["liveReadback"] is True and event.payload["tests"] == "passed" and event.payload["attestationMatch"] is True:
                verified_applies.add(transaction)
        elif event.event_type == "resolution.recorded" and event.causation_id:
            resolution_id = event.payload["resolutionId"]
            if resolution_id in resolution_ids:
                raise EventValidationError("duplicate resolution terminal event")
            resolution_ids.add(resolution_id)
            provider_operation_id = event.payload["providerOperationId"]
            if provider_operation_id in provider_operation_ids:
                raise EventValidationError("duplicate provider operation terminal event")
            provider_operation_ids.add(provider_operation_id)
            predecessor = by_id[event.causation_id]
            if predecessor.event_type == "verification.completed":
                apply_completed = by_id[predecessor.causation_id or ""]
                apply_started = by_id[apply_completed.causation_id or ""]
                if apply_started.payload["transactionId"] not in verified_applies:
                    raise EventValidationError("resolution requires verified apply")
                if apply_started.payload["transactionId"] in resolved_applies:
                    raise EventValidationError("duplicate transaction terminal event")
                resolved_applies.add(apply_started.payload["transactionId"])
        elif event.event_type == "payload.expired":
            expired[event.payload["sourceEventId"]] = event.payload["originalDigest"]
        elif event.event_type == "global.report.generated":
            if global_report_generated:
                raise EventValidationError("duplicate global report terminal")
            global_report_generated = True
        elif event.event_type == "defrag.audit.completed":
            if defrag_audited or defrag_planned or defrag_validated:
                raise EventValidationError("duplicate or out-of-order defragmentation audit")
            defrag_audited = True
        elif event.event_type == "defrag.plan.built":
            if not defrag_audited or defrag_planned or defrag_validated:
                raise EventValidationError("duplicate or out-of-order defragmentation plan")
            defrag_planned = True
        elif event.event_type == "defrag.plan.validated":
            if not defrag_planned or defrag_validated:
                raise EventValidationError("duplicate or out-of-order defragmentation validation")
            defrag_validated = True
        elif event.event_type == "incident.latched":
            incident_latched = True
        elif event.event_type == "run.closed":
            if run_kind == "global" and not global_report_generated:
                raise EventValidationError("global run close requires one global report")
            if run_kind == "defrag" and not defrag_validated:
                raise EventValidationError("defrag run close requires a validated plan")
            closing_status = event.payload["status"]
            if run_kind == "defrag" and closing_status not in {
                "completed",
                "ambiguous",
                "quarantined",
            }:
                raise EventValidationError("defrag run close status is invalid")
            unresolved = open_applies | (completed_applies - resolved_applies)
            if closing_status not in {"ambiguous", "quarantined"} and unresolved:
                raise EventValidationError("unresolved apply blocks clean close")
            if closing_status in {"ambiguous", "quarantined"} and not incident_latched:
                raise EventValidationError("incident required before ambiguous or quarantined close")
            status = closing_status
        by_id[event.event_id] = event

    return RunState(run_id, mode, run_kind, status, tuple(by_id), MappingProxyType(expired), incident_latched, frozenset(open_applies))
