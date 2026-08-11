from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json

import pytest

from rsi_core.events import EventEnvelope, EventRegistry, EventValidationError, fold_run


DIGEST = "sha256:" + "a" * 64


EVENT_PAYLOADS = {
    "run.started": {"mode": "observe", "hookMode": "manual", "activeSkills": [], "policyVersion": "1", "controlPlaneVersion": "1"},
    "finding.drafted": {"draftId": "draft-1", "proposedScope": "example.scope", "summary": "sanitized"},
    "task.observed": {"taskOutcome": "verified-success", "verificationStatus": "verified", "targetSkillHashes": [DIGEST]},
    "evaluation.completed": {"targetSkill": "example", "baseline": "base-1", "metricDeltas": {}, "evidenceStatus": "verified"},
    "candidate.admission_decided": {"decision": "allow", "hardReasons": []},
    "candidate.captured": {"providerCandidateId": "candidate-1", "captureOperationId": "op-1", "owner": "example"},
    "promotion.gated": {"decision": "allow", "requiredChecks": []},
    "staging.completed": {"diffDigest": DIGEST, "targetPreHash": DIGEST, "stagingRef": "stage-1"},
    "validation.completed": {"attestationRef": "att-1", "attestationDigest": DIGEST},
    "promotion.planned": {"planRef": "plan-1", "planDigest": DIGEST, "candidateHash": DIGEST, "diffDigest": DIGEST, "targetHash": DIGEST, "contractHash": DIGEST, "providerOperationIds": ["op-1"]},
    "snapshot.created": {"snapshotOperationId": "op-snapshot", "snapshotPath": "snap-1", "manifestDigest": DIGEST},
    "apply.started": {"transactionId": "tx-1", "expectedPreHash": DIGEST, "expectedPostHash": DIGEST},
    "apply.completed": {"actualPostHash": DIGEST},
    "verification.completed": {"liveReadback": True, "tests": "passed", "attestationMatch": True},
    "resolution.recorded": {"providerOperationId": "op-resolution", "resolutionId": "review-1"},
    "monitoring.recorded": {"promotionRef": "event:evt-promotion", "evaluationId": "event:evt-evaluation", "causalAttribution": "direct", "outcome": "stable"},
    "report.generated": {"reportKind": "local", "pathDigest": DIGEST, "inputRefs": [], "mutationPerformed": False},
    "global.report.generated": {"sourceEvaluationRefs": [], "thresholds": {}, "reportDigest": DIGEST, "mutationPerformed": False},
    "defrag.audit.completed": {"registrationDigest": DIGEST, "inventoryDigest": DIGEST, "findings": [], "mutationPerformed": False},
    "defrag.plan.built": {"ruleInventoryDigest": DIGEST, "ledgerDigest": DIGEST, "umbrellaPlanDigest": DIGEST},
    "defrag.plan.validated": {"coverage": "passed", "goldenValidation": "passed", "rollbackValidation": "passed", "mutationPerformed": False},
    "payload.expired": {"sourceEventId": "evt-source", "payloadRef": "object-1", "originalDigest": DIGEST, "tombstoneAt": "2026-08-07T00:00:00Z"},
    "incident.latched": {"incidentId": "incident-1", "reason": "sanitized", "quarantineTargets": []},
    "run.closed": {"status": "no-op", "linkedIds": []},
}

NORMATIVE_PREDECESSORS = {
    "run.started": frozenset(),
    "finding.drafted": frozenset({"run.started", "finding.drafted"}),
    "task.observed": frozenset({"run.started", "finding.drafted"}),
    "evaluation.completed": frozenset({"task.observed"}),
    "candidate.admission_decided": frozenset({"evaluation.completed"}),
    "candidate.captured": frozenset({"candidate.admission_decided"}),
    "promotion.gated": frozenset({"candidate.captured"}),
    "staging.completed": frozenset({"promotion.gated"}),
    "validation.completed": frozenset({"staging.completed"}),
    "promotion.planned": frozenset({"validation.completed"}),
    "snapshot.created": frozenset({"promotion.planned"}),
    "apply.started": frozenset({"snapshot.created"}),
    "apply.completed": frozenset({"apply.started"}),
    "verification.completed": frozenset({"apply.completed"}),
    "resolution.recorded": frozenset({"verification.completed", "candidate.admission_decided", "promotion.gated", "validation.completed"}),
    "monitoring.recorded": frozenset({"evaluation.completed"}),
    "report.generated": frozenset({"task.observed", "evaluation.completed", "candidate.admission_decided", "candidate.captured", "promotion.gated", "validation.completed"}),
    "global.report.generated": frozenset({"run.started"}),
    "defrag.audit.completed": frozenset({"run.started"}),
    "defrag.plan.built": frozenset({"defrag.audit.completed"}),
    "defrag.plan.validated": frozenset({"defrag.plan.built"}),
    "payload.expired": frozenset({"run.started"}),
    "incident.latched": None,
    "run.closed": None,
}


def _idempotency_key(producer_version: str, event_type: str, run_id: str, logical_operation_id: str, target_skill: str) -> str:
    normalized = json.dumps(
        [producer_version, event_type, run_id, logical_operation_id, target_skill],
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def make_event(event_type: str, number: int, *, causation_id: str | None = None, payload: dict | None = None, run_id: str = "run-1") -> EventEnvelope:
    resolved_payload = dict(EVENT_PAYLOADS[event_type] if payload is None else payload)
    resolved_payload.setdefault("logicalOperationId", f"op-{number}-{event_type}")
    resolved_payload.setdefault("targetSkill", "example")
    return EventEnvelope.from_mapping(
        {
            "schemaVersion": 1,
            "eventType": event_type,
            "eventId": f"evt-{number}",
            "runId": run_id,
            "correlationId": None,
            "causationId": causation_id,
            "createdAt": "2026-08-07T00:00:00Z",
            "idempotencyKey": _idempotency_key("1.0.0", event_type, run_id, resolved_payload["logicalOperationId"], resolved_payload["targetSkill"]),
            "producerVersion": "1.0.0",
            "payload": resolved_payload,
            "payloadRef": None,
        }
    )


@pytest.mark.parametrize("event_type", sorted(EVENT_PAYLOADS))
def test_registry_validates_every_normative_event_type(event_type: str) -> None:
    """Removing a normative type or one of its required keys must fail."""
    event = make_event(event_type, 1)

    EventRegistry().validate(event)


@pytest.mark.parametrize("event_type", sorted(NORMATIVE_PREDECESSORS))
def test_every_event_declares_its_normative_legal_predecessors(event_type: str) -> None:
    """The complete registry cannot silently broaden or narrow a legal edge."""
    assert EventRegistry.rules[event_type].predecessor_types == NORMATIVE_PREDECESSORS[event_type]


def test_envelope_is_immutable_and_rejects_unknown_schema_or_event_type() -> None:
    """An altered, future, or unknown envelope must never enter a lifecycle."""
    event = make_event("run.started", 1)
    with pytest.raises(FrozenInstanceError):
        event.run_id = "other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        event.payload["mode"] = "promote-safe"  # type: ignore[index]

    unknown = event.to_dict()
    unknown["schemaVersion"] = 2
    with pytest.raises(EventValidationError, match="schema"):
        EventEnvelope.from_mapping(unknown)
    unknown["schemaVersion"] = 1
    unknown["eventType"] = "unknown.event"
    with pytest.raises(EventValidationError, match="event type"):
        EventEnvelope.from_mapping(unknown)


def test_registry_rejects_missing_required_payload_key() -> None:
    """A partial event must not be treated as a valid lifecycle record."""
    payload = dict(EVENT_PAYLOADS["evaluation.completed"])
    payload.pop("baseline")

    with pytest.raises(EventValidationError, match="baseline"):
        make_event("evaluation.completed", 1, payload=payload)


@pytest.mark.parametrize(
    ("event_type", "required_key"),
    [(event_type, required_key) for event_type, payload in sorted(EVENT_PAYLOADS.items()) for required_key in payload],
)
def test_every_normative_payload_field_is_required(event_type: str, required_key: str) -> None:
    """Dropping any documented per-event field must fail schema validation."""
    raw = make_event(event_type, 1).to_dict()
    raw["payload"].pop(required_key)

    with pytest.raises(EventValidationError, match=required_key):
        EventEnvelope.from_mapping(raw)


@pytest.mark.parametrize("event_type", sorted(EVENT_PAYLOADS))
@pytest.mark.parametrize("common_key", ["logicalOperationId", "targetSkill"])
def test_every_event_requires_each_common_idempotency_field(event_type: str, common_key: str) -> None:
    """The normative replay tuple is mandatory for every single event schema."""
    raw = make_event(event_type, 1).to_dict()
    raw["payload"].pop(common_key)

    with pytest.raises(EventValidationError, match=common_key):
        EventEnvelope.from_mapping(raw)


@pytest.mark.parametrize(
    "event_type",
    sorted(set(EVENT_PAYLOADS) - {"run.started", "incident.latched", "run.closed"}),
)
def test_every_restricted_predecessor_rejects_a_disallowed_prior_event(event_type: str) -> None:
    """Every non-wildcard predecessor policy is enforced by the fold, not just documented."""
    start = make_event("run.started", 1)
    task = make_event("task.observed", 2, causation_id=start.event_id)
    event = make_event(event_type, 3, causation_id=task.event_id)

    if event_type == "report.generated":
        event = make_event(event_type, 3, causation_id=start.event_id)
        sequence = [start, event]
    elif event_type == "monitoring.recorded":
        evaluation = make_event("evaluation.completed", 3, causation_id=task.event_id)
        admission = make_event("candidate.admission_decided", 4, causation_id=evaluation.event_id)
        captured = make_event("candidate.captured", 5, causation_id=admission.event_id)
        event = make_event(event_type, 6, causation_id=captured.event_id)
        sequence = [start, task, evaluation, admission, captured, event]
    elif "task.observed" in EventRegistry.rules[event_type].predecessor_types:
        predecessor = make_event("evaluation.completed", 3, causation_id=task.event_id)
        event = make_event(event_type, 4, causation_id=predecessor.event_id)
        sequence = [start, task, predecessor, event]
    else:
        sequence = [start, task, event]

    with pytest.raises(EventValidationError, match="illegal predecessor"):
        fold_run(sequence)


@pytest.mark.parametrize(
    ("event_type", "field", "bad_value"),
    [
        ("staging.completed", "diffDigest", "sha256:not-a-digest"),
        ("candidate.admission_decided", "decision", "maybe"),
        ("report.generated", "mutationPerformed", True),
        ("task.observed", "targetSkillHashes", "not-a-list"),
    ],
)
def test_schema_rejects_bad_field_values(event_type: str, field: str, bad_value: object) -> None:
    """Typed policy fields must not be accepted merely because their key exists."""
    raw = make_event(event_type, 1).to_dict()
    raw["payload"][field] = bad_value

    with pytest.raises(EventValidationError):
        EventEnvelope.from_mapping(raw)


def test_schema_rejects_undeclared_payload_fields_and_wrong_derived_idempotency_key() -> None:
    """A caller cannot smuggle unversioned data or choose an arbitrary replay key."""
    extra = make_event("run.started", 1).to_dict()
    extra["payload"]["surprise"] = "unreviewed"
    with pytest.raises(EventValidationError, match="additional"):
        EventEnvelope.from_mapping(extra)

    mismatched = make_event("run.started", 1).to_dict()
    mismatched["idempotencyKey"] = "sha256:" + "0" * 64
    with pytest.raises(EventValidationError, match="idempotency"):
        EventEnvelope.from_mapping(mismatched)


def test_fold_run_rejects_missing_or_illegal_causation() -> None:
    """A lifecycle event may only follow its declared predecessor in the same run."""
    start = make_event("run.started", 1)
    observation_without_cause = make_event("task.observed", 2)
    with pytest.raises(EventValidationError, match="causation"):
        fold_run([start, observation_without_cause])

    draft = make_event("finding.drafted", 2, causation_id=start.event_id)
    evaluation_after_draft = make_event("evaluation.completed", 3, causation_id=draft.event_id)
    with pytest.raises(EventValidationError, match="predecessor"):
        fold_run([start, draft, evaluation_after_draft])


def test_fold_run_rejects_duplicate_terminal_event() -> None:
    """A run may be closed exactly once."""
    start = make_event("run.started", 1)
    close = make_event("run.closed", 2, causation_id=start.event_id)
    another_close = make_event("run.closed", 3, causation_id=start.event_id)

    with pytest.raises(EventValidationError, match="terminal"):
        fold_run([start, close, another_close])


def test_clean_close_rejects_unresolved_apply_and_ambiguous_close_needs_incident() -> None:
    """An apply cannot be hidden by a normal close or an unsupported ambiguous close."""
    start = make_event("run.started", 1, payload={**EVENT_PAYLOADS["run.started"], "mode": "promote-safe"})
    observed = make_event("task.observed", 2, causation_id=start.event_id)
    evaluation = make_event("evaluation.completed", 3, causation_id=observed.event_id)
    admission = make_event("candidate.admission_decided", 4, causation_id=evaluation.event_id)
    captured = make_event("candidate.captured", 5, causation_id=admission.event_id)
    gated = make_event("promotion.gated", 6, causation_id=captured.event_id)
    staged = make_event("staging.completed", 7, causation_id=gated.event_id)
    validated = make_event("validation.completed", 8, causation_id=staged.event_id)
    planned = make_event("promotion.planned", 9, causation_id=validated.event_id)
    snapshot = make_event("snapshot.created", 10, causation_id=planned.event_id)
    apply_started = make_event("apply.started", 11, causation_id=snapshot.event_id)
    prefix = [start, observed, evaluation, admission, captured, gated, staged, validated, planned, snapshot, apply_started]
    clean_close = make_event("run.closed", 12, causation_id=apply_started.event_id, payload={"status": "completed", "linkedIds": []})
    with pytest.raises(EventValidationError, match="unresolved apply"):
        fold_run([*prefix, clean_close])

    ambiguous_close = make_event("run.closed", 12, causation_id=apply_started.event_id, payload={"status": "ambiguous", "linkedIds": []})
    with pytest.raises(EventValidationError, match="incident"):
        fold_run([*prefix, ambiguous_close])

    incident = make_event("incident.latched", 12, causation_id=apply_started.event_id)
    quarantined_close = make_event("run.closed", 13, causation_id=incident.event_id, payload={"status": "quarantined", "linkedIds": ["incident-1"]})
    assert fold_run([*prefix, incident, quarantined_close]).status == "quarantined"


def promotion_prefix(*, mode: str, run_kind: str = "local", run_id: str = "run-1", offset: int = 0) -> list[EventEnvelope]:
    start = make_event("run.started", offset + 1, payload={**EVENT_PAYLOADS["run.started"], "mode": mode, "runKind": run_kind}, run_id=run_id)
    observed = make_event("task.observed", offset + 2, causation_id=start.event_id, run_id=run_id)
    evaluation = make_event("evaluation.completed", offset + 3, causation_id=observed.event_id, run_id=run_id)
    admission = make_event("candidate.admission_decided", offset + 4, causation_id=evaluation.event_id, run_id=run_id)
    captured = make_event("candidate.captured", offset + 5, causation_id=admission.event_id, run_id=run_id)
    gated = make_event("promotion.gated", offset + 6, causation_id=captured.event_id, run_id=run_id)
    staged = make_event("staging.completed", offset + 7, causation_id=gated.event_id, run_id=run_id)
    validated = make_event("validation.completed", offset + 8, causation_id=staged.event_id, run_id=run_id)
    planned = make_event("promotion.planned", offset + 9, causation_id=validated.event_id, run_id=run_id)
    snapshot = make_event("snapshot.created", offset + 10, causation_id=planned.event_id, run_id=run_id)
    apply_started = make_event("apply.started", offset + 11, causation_id=snapshot.event_id, run_id=run_id)
    return [start, observed, evaluation, admission, captured, gated, staged, validated, planned, snapshot, apply_started]


def test_fold_run_exercises_every_alternate_legal_predecessor_edge() -> None:
    """All multi-edge registry transitions are accepted as real folded histories."""
    start = make_event("run.started", 1)
    draft = make_event("finding.drafted", 2, causation_id=start.event_id)
    repeated_draft = make_event("finding.drafted", 3, causation_id=draft.event_id)
    task_after_draft = make_event("task.observed", 4, causation_id=repeated_draft.event_id)
    evaluation = make_event("evaluation.completed", 5, causation_id=task_after_draft.event_id)
    admission = make_event("candidate.admission_decided", 6, causation_id=evaluation.event_id)
    captured = make_event("candidate.captured", 7, causation_id=admission.event_id)
    gated = make_event("promotion.gated", 8, causation_id=captured.event_id)
    staged = make_event("staging.completed", 9, causation_id=gated.event_id)
    validated = make_event("validation.completed", 10, causation_id=staged.event_id)
    histories = [
        [start, draft, repeated_draft, task_after_draft, evaluation, admission, make_event("resolution.recorded", 11, causation_id=admission.event_id)],
        [start, draft, repeated_draft, task_after_draft, evaluation, admission, captured, gated, make_event("resolution.recorded", 11, causation_id=gated.event_id)],
        [start, draft, repeated_draft, task_after_draft, evaluation, admission, captured, gated, staged, validated, make_event("resolution.recorded", 11, causation_id=validated.event_id)],
        [start, draft, repeated_draft, task_after_draft, make_event("report.generated", 11, causation_id=task_after_draft.event_id)],
        [start, draft, repeated_draft, task_after_draft, evaluation, make_event("report.generated", 11, causation_id=evaluation.event_id)],
        [start, draft, repeated_draft, task_after_draft, evaluation, admission, make_event("report.generated", 11, causation_id=admission.event_id)],
        [start, draft, repeated_draft, task_after_draft, evaluation, admission, captured, gated, make_event("report.generated", 11, causation_id=gated.event_id)],
        [start, draft, repeated_draft, task_after_draft, evaluation, admission, captured, gated, staged, validated, make_event("report.generated", 11, causation_id=validated.event_id)],
    ]

    for history in histories:
        assert fold_run(history).status is None


@pytest.mark.parametrize(
    ("mode", "run_kind"),
    [("observe", "local"), ("propose", "local"), ("promote-safe", "global"), ("promote-safe", "defrag"), ("promote-safe", "retention")],
)
def test_mode_and_run_kind_forbid_apply_transactions(mode: str, run_kind: str) -> None:
    """Only promote-safe local runs may create an apply transaction."""
    expected = "global" if run_kind == "global" else "apply transaction"
    with pytest.raises(EventValidationError, match=expected):
        fold_run(promotion_prefix(mode=mode, run_kind=run_kind))


@pytest.mark.parametrize("status", ["completed", "no-op", "failed", "blocked", "deferred", "rejected"])
def test_every_non_quarantine_close_rejects_unproven_apply(status: str) -> None:
    """No ordinary terminal status may conceal a transaction without proof."""
    prefix = promotion_prefix(mode="promote-safe")
    close = make_event("run.closed", 12, causation_id=prefix[-1].event_id, payload={"status": status, "linkedIds": []})

    with pytest.raises(EventValidationError, match="unresolved apply"):
        fold_run([*prefix, close])


def test_false_verification_cannot_resolve_an_apply_and_terminal_events_are_unique() -> None:
    """Verification must be affirmative and each transaction/provider operation ends once."""
    prefix = promotion_prefix(mode="promote-safe")
    completed = make_event("apply.completed", 12, causation_id=prefix[-1].event_id)
    failed_verification = make_event("verification.completed", 13, causation_id=completed.event_id, payload={**EVENT_PAYLOADS["verification.completed"], "liveReadback": False})
    resolution = make_event("resolution.recorded", 14, causation_id=failed_verification.event_id)
    with pytest.raises(EventValidationError, match="verified"):
        fold_run([*prefix, completed, failed_verification, resolution])

    verified = make_event("verification.completed", 13, causation_id=completed.event_id)
    duplicate_verification = make_event("verification.completed", 14, causation_id=completed.event_id)
    with pytest.raises(EventValidationError, match="verification terminal"):
        fold_run([*prefix, completed, verified, duplicate_verification])

    first_resolution = make_event("resolution.recorded", 14, causation_id=verified.event_id)
    second_resolution = make_event("resolution.recorded", 15, causation_id=verified.event_id, payload={"providerOperationId": "op-resolution", "resolutionId": "review-2"})
    with pytest.raises(EventValidationError, match="provider operation"):
        fold_run([*prefix, completed, verified, first_resolution, second_resolution])


def test_payload_expired_is_foldable_audit_tombstone() -> None:
    """Retention preserves the source event identity after its payload expires."""
    start = make_event("run.started", 1)
    expired = make_event("payload.expired", 2, causation_id=start.event_id)
    close = make_event("run.closed", 3, causation_id=expired.event_id)

    state = fold_run([start, expired, close])

    assert state.expired_payloads == {"evt-source": DIGEST}
    assert state.status == "no-op"


# Task 8 architecture REDs.  These fixtures deliberately derive identifiers and
# references without calling a production Task 8 builder.
TASK8_CONTROL_PLANE_VERSION = "1.1.0"
TASK8_ADDENDUM_DIGEST = "sha256:ef84059ca0df0d3804dc090616cef3e4abbe3ce7f11ec6f8535e74aa3afe02c0"
TASK8_ADDENDUM_MARKDOWN_DIGEST = "sha256:6fd2ab2a1d45e678f7eaf237c462c49e6dcf3ad133e30c41e28326b9d5f909b6"
TASK8_PLAN_DIGEST = "sha256:" + "b" * 64
TASK8_PRE_HASH = "sha256:" + "1" * 64
TASK8_POST_HASH = "sha256:" + "2" * 64
TASK8_MANIFEST_PRE_HASH = "sha256:" + "3" * 64
TASK8_MANIFEST_POST_HASH = "sha256:" + "4" * 64
TASK8_ORIGIN_DIGEST = "sha256:" + "5" * 64
TASK8_ATTESTATION_DIGEST = "sha256:" + "6" * 64
TASK8_PLAN_OBJECT_DIGEST = TASK8_PLAN_DIGEST
TASK8_SNAPSHOT_DIGEST = "sha256:" + "7" * 64
TASK8_INTENT_DIGEST = "sha256:" + "8" * 64
TASK8_READBACK_DIGEST = "sha256:" + "9" * 64
TASK8_VERIFICATION_DIGEST = "sha256:" + "a" * 64
TASK8_ROLLBACK_DIGEST = "sha256:" + "c" * 64
TASK8_RESOLUTION_DIGEST = "sha256:" + "d" * 64
TASK8_DECISION_DIGEST = "sha256:" + "e" * 64
TASK8_INCIDENT_DIGEST = "sha256:" + "f" * 64
TASK8_PROVIDER_REQUEST_DIGEST = "0" * 64
TASK8_SNAPSHOT_OPERATION_ID = "op_snapshot_" + "1" * 32
TASK8_RESOLVE_OPERATION_ID = "op_resolve_" + "2" * 32
TASK8_REQUIRED_CHECKS = [
    "allowlist",
    "artifact-store",
    "atomic-exchange",
    "attestation",
    "candidate-authority",
    "contract",
    "incident-latch",
    "namespace-lease",
    "policy",
    "provider",
    "target-hash",
    "ttl",
]


def _task8_canonical_no_lf(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _task8_prefixed_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_task8_canonical_no_lf(value)).hexdigest()


def _task8_transaction_id(plan_digest: str = TASK8_PLAN_DIGEST) -> str:
    preimage = {"domain": "rsi-promotion-transaction-v1", "planDigest": plan_digest}
    return "tx_" + _task8_prefixed_digest(preimage)[7:]


def _task8_run_id(plan_digest: str = TASK8_PLAN_DIGEST) -> str:
    preimage = {"domain": "rsi-promotion-continuation-v1", "planDigest": plan_digest}
    return "run_promote_" + _task8_prefixed_digest(preimage)[7:]


def _task8_event_id(event_type: str, transaction_id: str | None = None) -> str:
    preimage = {
        "domain": "rsi-promotion-event-v1",
        "eventType": event_type,
        "transactionId": transaction_id or _task8_transaction_id(),
    }
    return "evt_" + _task8_prefixed_digest(preimage)[7:]


def _task8_incident_id(transaction_id: str | None = None) -> str:
    preimage = {
        "domain": "rsi-promotion-incident-v1",
        "transactionId": transaction_id or _task8_transaction_id(),
    }
    return "incident_" + _task8_prefixed_digest(preimage)[7:]


TASK8_PHASES = {
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


def _task8_payload(event_type: str, *, arm: str = "rollback") -> dict[str, object]:
    transaction_id = _task8_transaction_id()
    common: dict[str, object] = {
        "logicalOperationId": f"promote:{transaction_id}:{TASK8_PHASES[event_type]}",
        "targetSkill": "example",
    }
    event_specific: dict[str, dict[str, object]] = {
        "run.started": {
            "mode": "promote-safe",
            "hookMode": "coordinated",
            "runKind": "local",
            "activeSkills": [f"example@{TASK8_MANIFEST_PRE_HASH}"],
            "policyVersion": "policy-v1",
            "controlPlaneVersion": TASK8_CONTROL_PLANE_VERSION,
        },
        "promotion.gated": {
            "decision": "allow",
            "requiredChecks": list(TASK8_REQUIRED_CHECKS),
            "transactionId": transaction_id,
            "planDigest": TASK8_PLAN_DIGEST,
            "originDigest": TASK8_ORIGIN_DIGEST,
        },
        "staging.completed": {
            "diffDigest": "sha256:" + "0" * 64,
            "targetPreHash": TASK8_MANIFEST_PRE_HASH,
            "stagingRef": "experiments/op-1/bundle.json",
            "transactionId": transaction_id,
        },
        "validation.completed": {
            "attestationRef": "experiments/op-1/attestation.json",
            "attestationDigest": TASK8_ATTESTATION_DIGEST,
            "transactionId": transaction_id,
        },
        "promotion.planned": {
            "planRef": "experiments/op-1/plan.json",
            "planDigest": TASK8_PLAN_OBJECT_DIGEST,
            "candidateHash": "sha256:" + "1" * 64,
            "diffDigest": "sha256:" + "0" * 64,
            "targetHash": TASK8_MANIFEST_PRE_HASH,
            "contractHash": "sha256:" + "2" * 64,
            "providerOperationIds": {
                "snapshot": TASK8_SNAPSHOT_OPERATION_ID,
                "resolve": TASK8_RESOLVE_OPERATION_ID,
            },
            "transactionId": transaction_id,
        },
        "snapshot.created": {
            "snapshotOperationId": TASK8_SNAPSHOT_OPERATION_ID,
            "snapshotPath": "snapshots/example/" + "1" * 64,
            "manifestDigest": "sha256:" + "3" * 64,
            "transactionId": transaction_id,
            "snapshotDigest": TASK8_SNAPSHOT_DIGEST,
        },
        "apply.started": {
            "transactionId": transaction_id,
            "expectedPreHash": TASK8_PRE_HASH,
            "expectedPostHash": TASK8_POST_HASH,
            "intentDigest": TASK8_INTENT_DIGEST,
        },
        "apply.reverted": {
            "transactionId": transaction_id,
            "restoredPreHash": TASK8_PRE_HASH,
            "restoredManifestPreHash": TASK8_MANIFEST_PRE_HASH,
            "displacedPostHash": TASK8_POST_HASH,
            "rollbackVerified": True,
            "rollbackDigest": TASK8_ROLLBACK_DIGEST,
        },
        "resolution.recorded": {
            "transactionId": transaction_id,
            "providerOperationId": TASK8_RESOLVE_OPERATION_ID,
            "resolutionId": "review-1",
            "providerResolutionRequestDigest": TASK8_PROVIDER_REQUEST_DIGEST,
            "candidateFullRecordBeforeDigest": "sha256:" + "1" * 64,
            "providerAuthorityBindingBeforeDigest": "sha256:" + "2" * 64,
            "task7CandidateBindingDigest": "sha256:" + "3" * 64,
            "candidateCaptureLineageBindingDigest": "sha256:" + "4" * 64,
            "candidateStateBindingBeforeDigest": "sha256:" + "5" * 64,
            "candidateFullRecordAfterDigest": "sha256:" + "6" * 64,
            "providerAuthorityBindingAfterDigest": "sha256:" + "7" * 64,
            "candidateStateBindingAfterDigest": "sha256:" + "8" * 64,
            "providerResolutionRecordDigest": "sha256:" + "9" * 64,
            "resolutionDigest": TASK8_RESOLUTION_DIGEST,
        },
        "incident.latched": {
            "incidentId": _task8_incident_id(),
            "reason": "provider-state-unknown",
            "quarantineTargets": [
                {
                    "rootIdentityDigest": "sha256:" + "1" * 64,
                    "artifactPath": "references/knowledge.md",
                }
            ],
            "transactionId": transaction_id,
            "incidentDigest": TASK8_INCIDENT_DIGEST,
            "quarantineRef": "incidents/quarantine/" + "1" * 64 + ".json",
            "quarantineDisposition": (
                "preexisting" if arm == "preexisting-incident" else "created"
            ),
            "blockingQuarantineDigest": "sha256:" + "2" * 64,
            "latchRef": "incidents/latch.json",
            "latchDisposition": (
                "preexisting" if arm == "preexisting-incident" else "created"
            ),
            "blockingLatchDigest": "sha256:" + "3" * 64,
        },
    }
    if event_type == "apply.completed":
        if arm == "applied":
            event_specific[event_type] = {
                "transactionId": transaction_id,
                "outcome": "applied",
                "reasonCode": None,
                "actualPostHash": TASK8_POST_HASH,
                "actualManifestPostHash": TASK8_MANIFEST_POST_HASH,
                "readbackDigest": TASK8_READBACK_DIGEST,
            }
        else:
            event_specific[event_type] = {
                "transactionId": transaction_id,
                "outcome": "not-applied",
                "reasonCode": "candidate-drift",
                "actualPreHash": TASK8_PRE_HASH,
                "actualManifestPreHash": TASK8_MANIFEST_PRE_HASH,
                "readbackDigest": TASK8_READBACK_DIGEST,
            }
    elif event_type == "verification.completed":
        affirmed = arm == "affirmed"
        unavailable = arm == "unavailable"
        attestation_mismatch = arm == "attestation-mismatch"
        authority_invalidated = arm == "authority-invalidated"
        if affirmed:
            reason_code = None
        elif unavailable:
            reason_code = "verifier-unavailable"
        elif attestation_mismatch:
            reason_code = "attestation-mismatch"
        elif authority_invalidated:
            reason_code = "authority-invalidated"
        else:
            reason_code = "verification-failed"
        event_specific[event_type] = {
            "transactionId": transaction_id,
            "outcome": "affirmed" if affirmed else "rollback-armed",
            "reasonCode": reason_code,
            "verificationDigest": TASK8_VERIFICATION_DIGEST,
            "liveReadback": True,
            "tests": {
                "skillValidationPassed": None if unavailable else True,
                "contractValidationPassed": None if unavailable else True,
                "targetTestsPassed": (
                    None
                    if unavailable
                    else not (arm in {"rollback", "attestation-mismatch"})
                ),
            },
            "attestationMatch": None if unavailable else not attestation_mismatch,
        }
    elif event_type == "run.closed":
        if arm == "promoted":
            terminal_event_id = _task8_event_id("resolution.recorded")
            event_specific[event_type] = {
                "status": "completed",
                "linkedIds": [transaction_id, terminal_event_id],
                "transactionId": transaction_id,
                "outcome": "promoted",
                "terminalReasonCode": "verified-promotion",
                "closeStatus": "completed",
                "decisionDigest": TASK8_DECISION_DIGEST,
            }
        elif arm == "not-started":
            terminal_event_id = _task8_event_id("promotion.planned")
            event_specific[event_type] = {
                "status": "blocked",
                "linkedIds": [transaction_id, terminal_event_id],
                "transactionId": transaction_id,
                "outcome": "not-started",
                "terminalReasonCode": "eligibility-blocked",
                "closeStatus": "blocked",
                "decisionDigest": TASK8_DECISION_DIGEST,
            }
        elif arm == "not-applied":
            terminal_event_id = _task8_event_id("apply.completed")
            event_specific[event_type] = {
                "status": "deferred",
                "linkedIds": [transaction_id, terminal_event_id],
                "transactionId": transaction_id,
                "outcome": "not-applied",
                "terminalReasonCode": "candidate-drift",
                "closeStatus": "deferred",
                "decisionDigest": TASK8_DECISION_DIGEST,
            }
        elif arm in {"ambiguous", "quarantined"}:
            terminal_event_id = _task8_event_id("incident.latched")
            reason_code = (
                "provider-state-unknown"
                if arm == "ambiguous"
                else "post-state-drift"
            )
            event_specific[event_type] = {
                "status": arm,
                "linkedIds": [transaction_id, terminal_event_id],
                "transactionId": transaction_id,
                "outcome": arm,
                "terminalReasonCode": reason_code,
                "closeStatus": arm,
                "decisionDigest": TASK8_DECISION_DIGEST,
            }
        else:
            terminal_event_id = _task8_event_id("apply.reverted")
            event_specific[event_type] = {
                "status": "failed",
                "linkedIds": [transaction_id, terminal_event_id],
                "transactionId": transaction_id,
                "outcome": "rolled-back",
                "terminalReasonCode": "verification-failed",
                "closeStatus": "failed",
                "decisionDigest": TASK8_DECISION_DIGEST,
            }
    return {**common, **event_specific[event_type]}


def _task8_payload_ref(event_type: str) -> str | None:
    transaction_id = _task8_transaction_id()
    digest_by_event = {
        "promotion.gated": ("origin", TASK8_ORIGIN_DIGEST),
        "snapshot.created": ("snapshot", TASK8_SNAPSHOT_DIGEST),
        "apply.started": ("intent", TASK8_INTENT_DIGEST),
        "apply.completed": ("readback", TASK8_READBACK_DIGEST),
        "verification.completed": ("verification", TASK8_VERIFICATION_DIGEST),
        "apply.reverted": ("readback", TASK8_ROLLBACK_DIGEST),
        "resolution.recorded": ("resolution", TASK8_RESOLUTION_DIGEST),
        "run.closed": ("decision", TASK8_DECISION_DIGEST),
    }
    if event_type == "incident.latched":
        return f"incidents/records/{_task8_incident_id()}.json"
    binding = digest_by_event.get(event_type)
    if binding is None:
        return None
    role, digest = binding
    return f"transactions/{transaction_id}-{role}-{digest[7:]}.json"


def _task8_event_raw(
    event_type: str,
    *,
    causation_id: str | None = None,
    arm: str = "rollback",
    created_at: str = "2026-08-09T00:00:00Z",
) -> dict[str, object]:
    payload = _task8_payload(event_type, arm=arm)
    run_id = _task8_run_id()
    logical_operation_id = str(payload["logicalOperationId"])
    return {
        "schemaVersion": 1,
        "eventType": event_type,
        "eventId": _task8_event_id(event_type),
        "runId": run_id,
        "correlationId": TASK8_PLAN_DIGEST,
        "causationId": causation_id,
        "createdAt": created_at,
        "idempotencyKey": _idempotency_key(
            "1.0.0", event_type, run_id, logical_operation_id, "example"
        ),
        "producerVersion": "1.0.0",
        "payload": payload,
        "payloadRef": _task8_payload_ref(event_type),
    }


def _task8_event(
    event_type: str,
    *,
    causation_id: str | None = None,
    arm: str = "rollback",
    created_at: str = "2026-08-09T00:00:00Z",
) -> EventEnvelope:
    return EventEnvelope.from_mapping(
        _task8_event_raw(
            event_type,
            causation_id=causation_id,
            arm=arm,
            created_at=created_at,
        )
    )


def _task8_chain(*, terminal: str = "rollback") -> tuple[EventEnvelope, list[EventEnvelope]]:
    origin = make_event(
        "candidate.captured",
        900,
        causation_id="evt-origin-admission",
        run_id="run-origin",
    )
    start = _task8_event("run.started")
    gate = _task8_event("promotion.gated", causation_id=origin.event_id)
    staged = _task8_event("staging.completed", causation_id=gate.event_id)
    validated = _task8_event("validation.completed", causation_id=staged.event_id)
    planned = _task8_event("promotion.planned", causation_id=validated.event_id)
    snapshot = _task8_event("snapshot.created", causation_id=planned.event_id)
    started = _task8_event("apply.started", causation_id=snapshot.event_id)
    applied = _task8_event("apply.completed", causation_id=started.event_id, arm="applied")
    if terminal == "promoted":
        verified = _task8_event(
            "verification.completed", causation_id=applied.event_id, arm="affirmed"
        )
        resolved = _task8_event("resolution.recorded", causation_id=verified.event_id)
        closed = _task8_event("run.closed", causation_id=resolved.event_id, arm="promoted")
        return origin, [
            start,
            gate,
            staged,
            validated,
            planned,
            snapshot,
            started,
            applied,
            verified,
            resolved,
            closed,
        ]
    verified = _task8_event(
        "verification.completed", causation_id=applied.event_id, arm="rollback"
    )
    reverted = _task8_event("apply.reverted", causation_id=verified.event_id)
    closed = _task8_event("run.closed", causation_id=reverted.event_id, arm="rollback")
    return origin, [
        start,
        gate,
        staged,
        validated,
        planned,
        snapshot,
        started,
        applied,
        verified,
        reverted,
        closed,
    ]


def test_task8_registry_is_exactly_baseline_plus_bound_apply_reverted() -> None:
    """A second new event type or a direct-apply rollback edge reopens the approved registry."""
    assert set(EventRegistry.rules) == set(EVENT_PAYLOADS) | {"apply.reverted"}
    assert EventRegistry.rules["apply.reverted"].predecessor_types == frozenset(
        {"verification.completed"}
    )


def test_task8_exports_the_frozen_addendum_and_control_plane_bindings() -> None:
    """A build cannot silently load a different rollback addendum under version 1.1.0."""
    from rsi_core import events as events_module

    assert events_module.TASK8_CONTROL_PLANE_VERSION == TASK8_CONTROL_PLANE_VERSION
    assert events_module.TASK8_ADDENDUM_DIGEST == TASK8_ADDENDUM_DIGEST
    assert (
        events_module.TASK8_ADDENDUM_MARKDOWN_DIGEST
        == TASK8_ADDENDUM_MARKDOWN_DIGEST
    )
    expected_registry = {
        "controlPlaneVersion": "1.1.0",
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
    expected_bytes = _task8_canonical_no_lf(expected_registry) + b"\n"
    assert events_module.TASK8_REGISTRY_ADDENDUM == expected_registry
    assert events_module.TASK8_REGISTRY_ADDENDUM_BYTES == expected_bytes
    assert (
        "sha256:" + hashlib.sha256(expected_bytes).hexdigest()
        == TASK8_ADDENDUM_DIGEST
    )


@pytest.mark.parametrize(
    ("event_type", "arm"),
    [
        ("run.started", "rollback"),
        ("promotion.gated", "rollback"),
        ("staging.completed", "rollback"),
        ("validation.completed", "rollback"),
        ("promotion.planned", "rollback"),
        ("snapshot.created", "rollback"),
        ("apply.started", "rollback"),
        ("apply.completed", "applied"),
        ("apply.completed", "not-applied"),
        ("verification.completed", "affirmed"),
        ("verification.completed", "rollback"),
        ("verification.completed", "attestation-mismatch"),
        ("verification.completed", "unavailable"),
        ("verification.completed", "authority-invalidated"),
        ("resolution.recorded", "rollback"),
        ("apply.reverted", "rollback"),
        ("incident.latched", "rollback"),
        ("incident.latched", "preexisting-incident"),
        ("run.closed", "promoted"),
        ("run.closed", "not-started"),
        ("run.closed", "not-applied"),
        ("run.closed", "rollback"),
        ("run.closed", "ambiguous"),
        ("run.closed", "quarantined"),
    ],
)
def test_task8_registry_admits_each_exact_closed_payload_arm(
    event_type: str, arm: str
) -> None:
    """Deleting a closed union arm strands a durable Task 8 terminal."""
    EventEnvelope.from_mapping(_task8_event_raw(event_type, arm=arm))


@pytest.mark.parametrize(
    "field",
    [
        "transactionId",
        "restoredPreHash",
        "restoredManifestPreHash",
        "displacedPostHash",
        "rollbackVerified",
        "rollbackDigest",
    ],
)
def test_apply_reverted_requires_every_addendum_field(field: str) -> None:
    """A partial rollback envelope cannot discharge a live transaction."""
    raw = _task8_event_raw("apply.reverted")
    raw["payload"].pop(field)  # type: ignore[union-attr]

    with pytest.raises(EventValidationError, match=field):
        EventEnvelope.from_mapping(raw)


@pytest.mark.parametrize(
    ("event_type", "arm"),
    [
        ("promotion.gated", "rollback"),
        ("apply.completed", "applied"),
        ("verification.completed", "rollback"),
        ("resolution.recorded", "rollback"),
        ("apply.reverted", "rollback"),
        ("incident.latched", "rollback"),
        ("run.closed", "rollback"),
    ],
)
def test_task8_payload_arms_reject_every_undeclared_field(
    event_type: str, arm: str
) -> None:
    """An optional-looking field must not turn a closed Task 8 arm into an open bag."""
    raw = _task8_event_raw(event_type, arm=arm)
    raw["payload"]["unreviewed"] = True  # type: ignore[index]

    with pytest.raises(EventValidationError, match="additional|unreviewed"):
        EventEnvelope.from_mapping(raw)


def test_apply_completed_rejects_mixed_applied_and_not_applied_hash_arms() -> None:
    """A caller cannot claim both exact-post and typed non-application."""
    raw = _task8_event_raw("apply.completed", arm="applied")
    raw["payload"]["actualPreHash"] = TASK8_PRE_HASH  # type: ignore[index]
    raw["payload"]["actualManifestPreHash"] = TASK8_MANIFEST_PRE_HASH  # type: ignore[index]

    with pytest.raises(EventValidationError, match="arm|additional|applied"):
        EventEnvelope.from_mapping(raw)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("outcome", "affirmed"),
        ("reasonCode", None),
        ("rollbackVerified", False),
        ("restoredPreHash", "1" * 64),
        ("restoredManifestPreHash", "sha256:" + "A" * 64),
        ("rollbackDigest", TASK8_VERIFICATION_DIGEST),
    ],
)
def test_apply_reverted_rejects_wrong_outcome_hash_or_proof(
    field: str, bad_value: object
) -> None:
    """Hash-shaped or affirmative evidence cannot be relabelled as rollback proof."""
    raw = _task8_event_raw("apply.reverted")
    raw["payload"][field] = bad_value  # type: ignore[index]

    with pytest.raises(EventValidationError):
        EventEnvelope.from_mapping(raw)


@pytest.mark.parametrize(
    "event_type",
    [
        "promotion.gated",
        "snapshot.created",
        "apply.started",
        "apply.completed",
        "verification.completed",
        "resolution.recorded",
        "apply.reverted",
        "incident.latched",
        "run.closed",
    ],
)
def test_task8_event_to_sidecar_binding_rejects_null_wrong_kind_or_wrong_digest(
    event_type: str,
) -> None:
    """A ref cannot redirect one phase to another transaction object."""
    raw = _task8_event_raw(
        event_type,
        arm="applied" if event_type == "apply.completed" else "rollback",
    )
    wrong_refs = [
        None,
        f"transactions/{_task8_transaction_id()}-origin-{'0' * 64}.json",
        str(raw["payloadRef"])[:-6] + "0.json",
    ]
    if event_type == "incident.latched":
        wrong_refs[1] = f"incidents/records/incident_{'0' * 64}.json"
    for wrong_ref in wrong_refs:
        changed = dict(raw)
        changed["payloadRef"] = wrong_ref
        with pytest.raises(EventValidationError, match="ref|sidecar|payload"):
            EventEnvelope.from_mapping(changed)


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("eventId", "evt_" + "0" * 64),
        ("runId", "run_promote_" + "0" * 64),
        ("correlationId", "sha256:" + "0" * 64),
    ],
)
def test_task8_envelope_recomputes_deterministic_ids_and_plan_binding(
    mutation: str, value: str
) -> None:
    """Caller-selected IDs would split one plan into multiple transactions or runs."""
    raw = _task8_event_raw("apply.reverted")
    raw[mutation] = value

    with pytest.raises(EventValidationError, match="event|run|plan|correlation"):
        EventEnvelope.from_mapping(raw)


@pytest.mark.parametrize(
    ("event_type", "arm"),
    [
        ("run.started", "rollback"),
        ("promotion.gated", "rollback"),
        ("staging.completed", "rollback"),
        ("validation.completed", "rollback"),
        ("promotion.planned", "rollback"),
        ("snapshot.created", "rollback"),
        ("apply.started", "rollback"),
        ("apply.completed", "applied"),
        ("verification.completed", "affirmed"),
        ("resolution.recorded", "rollback"),
        ("apply.reverted", "rollback"),
        ("incident.latched", "rollback"),
        ("run.closed", "rollback"),
    ],
)
def test_every_task8_phase_rejects_a_caller_selected_event_id(
    event_type: str, arm: str
) -> None:
    """Determinism applies to start, close, and every phase between them."""
    raw = _task8_event_raw(event_type, arm=arm)
    raw["eventId"] = "evt_" + "0" * 64

    with pytest.raises(EventValidationError, match="eventId|deterministic|event id"):
        EventEnvelope.from_mapping(raw)


def test_task8_gate_requires_the_literal_sorted_twelve_check_set() -> None:
    """Reordering or omitting one gate check cannot produce an allow event."""
    for required_checks in (
        list(reversed(TASK8_REQUIRED_CHECKS)),
        TASK8_REQUIRED_CHECKS[:-1],
        [*TASK8_REQUIRED_CHECKS, "unreviewed"],
    ):
        raw = _task8_event_raw("promotion.gated")
        raw["payload"]["requiredChecks"] = required_checks  # type: ignore[index]
        with pytest.raises(EventValidationError, match="requiredChecks|check|sorted"):
            EventEnvelope.from_mapping(raw)


def test_task8_plan_rejects_legacy_provider_operation_array_and_wrong_prefix_length() -> None:
    """The continuation uses the exact snapshot/resolve object, not the legacy tuple."""
    for provider_operations in (
        [TASK8_SNAPSHOT_OPERATION_ID, TASK8_RESOLVE_OPERATION_ID],
        {
            "snapshot": "op_snapshot_" + "1" * 64,
            "resolve": TASK8_RESOLVE_OPERATION_ID,
        },
        {
            "snapshot": TASK8_SNAPSHOT_OPERATION_ID,
            "resolve": "op_snapshot_" + "2" * 32,
        },
    ):
        raw = _task8_event_raw("promotion.planned")
        raw["payload"]["providerOperationIds"] = provider_operations  # type: ignore[index]
        with pytest.raises(EventValidationError, match="providerOperationIds|operation"):
            EventEnvelope.from_mapping(raw)


def test_verification_reason_precedence_and_affirmed_truth_table_are_closed() -> None:
    """Attestation mismatch wins over test failure; affirmation requires every proof true."""
    mismatch = _task8_event_raw("verification.completed", arm="rollback")
    mismatch["payload"]["attestationMatch"] = False  # type: ignore[index]
    mismatch["payload"]["reasonCode"] = "verification-failed"  # type: ignore[index]
    with pytest.raises(EventValidationError, match="attestation-mismatch|reason"):
        EventEnvelope.from_mapping(mismatch)

    false_affirmed = _task8_event_raw("verification.completed", arm="affirmed")
    false_affirmed["payload"]["tests"]["targetTestsPassed"] = False  # type: ignore[index]
    with pytest.raises(EventValidationError, match="affirmed|tests|rollback"):
        EventEnvelope.from_mapping(false_affirmed)


def test_task8_run_start_rejects_legacy_or_nonlocal_identity() -> None:
    """The external bridge is unavailable outside the exact promote-safe local continuation."""
    for field, value in (
        ("mode", "propose"),
        ("hookMode", "manual"),
        ("runKind", "global"),
        ("controlPlaneVersion", "1.0.0"),
        ("activeSkills", ["example"]),
    ):
        raw = _task8_event_raw("run.started")
        raw["payload"][field] = value  # type: ignore[index]
        with pytest.raises(EventValidationError, match="promote-safe|local|control|active|hook"):
            EventEnvelope.from_mapping(raw)


def test_task8_event_id_is_independent_of_audit_timestamp_but_not_event_type() -> None:
    """Transport time may vary on replay; phase identity may not."""
    first = _task8_event(
        "apply.reverted", created_at="2026-08-09T00:00:00Z"
    )
    retry = _task8_event(
        "apply.reverted", created_at="2026-08-10T23:59:59Z"
    )

    assert first.event_id == retry.event_id == _task8_event_id("apply.reverted")
    assert first.idempotency_key == retry.idempotency_key
    assert first.event_id != _task8_event_id("verification.completed")


def test_task8_phase_and_idempotency_are_both_recomputed() -> None:
    """Re-keying an alternate logical phase cannot turn it into a valid rollback."""
    raw = _task8_event_raw("apply.reverted")
    payload = raw["payload"]
    assert isinstance(payload, dict)
    payload["logicalOperationId"] = f"promote:{_task8_transaction_id()}:resolve"
    raw["idempotencyKey"] = _idempotency_key(
        "1.0.0",
        "apply.reverted",
        str(raw["runId"]),
        str(payload["logicalOperationId"]),
        "example",
    )

    with pytest.raises(EventValidationError, match="phase|logical"):
        EventEnvelope.from_mapping(raw)


def test_promote_safe_fold_accepts_only_the_index_one_external_capture_bridge() -> None:
    """The explicit bridge is needed for the closed Task 6 capture and nowhere else."""
    origin = make_event(
        "candidate.captured",
        900,
        causation_id="evt-origin-admission",
        run_id="run-origin",
    )
    started = _task8_event("run.started")
    gated = _task8_event("promotion.gated", causation_id=origin.event_id)

    state = fold_run(
        [started, gated],
        external_predecessors={origin.event_id: origin},
    )
    assert state.mode == "promote-safe"
    assert state.run_kind == "local"
    assert state.event_ids == (started.event_id, gated.event_id)
    with pytest.raises(EventValidationError, match="external|causation|missing"):
        fold_run([started, gated])


def test_external_bridge_rejects_same_run_wrong_type_and_late_gate() -> None:
    """A generic external predecessor map would bypass the lifecycle FSM."""
    origin = make_event(
        "candidate.captured",
        900,
        causation_id="evt-origin-admission",
        run_id="run-origin",
    )
    started = _task8_event("run.started")
    gated = _task8_event("promotion.gated", causation_id=origin.event_id)
    staged = _task8_event("staging.completed", causation_id=gated.event_id)

    same_run = make_event(
        "candidate.captured",
        901,
        causation_id="evt-origin-admission",
        run_id=started.run_id,
    )
    same_run_gate_raw = _task8_event_raw(
        "promotion.gated", causation_id=same_run.event_id
    )
    same_run_gate = EventEnvelope.from_mapping(same_run_gate_raw)
    with pytest.raises(EventValidationError, match="different run|external"):
        fold_run(
            [started, same_run_gate],
            external_predecessors={same_run.event_id: same_run},
        )

    wrong_type = make_event(
        "task.observed", 902, causation_id="evt-origin-start", run_id="run-origin"
    )
    wrong_gate = _task8_event("promotion.gated", causation_id=wrong_type.event_id)
    with pytest.raises(EventValidationError, match="candidate.captured|external"):
        fold_run(
            [started, wrong_gate],
            external_predecessors={wrong_type.event_id: wrong_type},
        )

    with pytest.raises(EventValidationError, match="unique|index|first|duplicate"):
        fold_run(
            [started, gated, staged, gated],
            external_predecessors={origin.event_id: origin},
        )


def test_exact_negative_verification_rollback_and_close_fold_to_one_failed_terminal() -> None:
    """Removing any rollback terminal proof must leave the completed apply unresolved."""
    origin, events = _task8_chain(terminal="rollback")

    state = fold_run(
        events,
        external_predecessors={origin.event_id: origin},
    )

    assert state.status == "failed"
    assert state.event_ids[-2:] == (
        _task8_event_id("apply.reverted"),
        _task8_event_id("run.closed"),
    )


def test_apply_reverted_rejects_direct_apply_affirmed_cross_run_cross_transaction_and_duplicate() -> None:
    """Only one same-run, same-transaction rollback-armed verification may cause rollback."""
    origin, events = _task8_chain(terminal="rollback")
    reverted_index = next(
        index for index, event in enumerate(events) if event.event_type == "apply.reverted"
    )
    applied = next(event for event in events if event.event_type == "apply.completed")
    verified = next(
        event for event in events if event.event_type == "verification.completed"
    )

    direct = _task8_event("apply.reverted", causation_id=applied.event_id)
    with pytest.raises(EventValidationError, match="verification|predecessor"):
        fold_run(
            [*events[:reverted_index], direct],
            external_predecessors={origin.event_id: origin},
        )

    affirmative = _task8_event(
        "verification.completed", causation_id=applied.event_id, arm="affirmed"
    )
    after_affirmative = _task8_event(
        "apply.reverted", causation_id=affirmative.event_id
    )
    with pytest.raises(EventValidationError, match="rollback-armed|affirmative|affirmed"):
        fold_run(
            [*events[: reverted_index - 1], affirmative, after_affirmative],
            external_predecessors={origin.event_id: origin},
        )

    foreign_verification = make_event(
        "verification.completed",
        910,
        causation_id="evt-foreign-apply",
        run_id="run-foreign",
    )
    cross_run = _task8_event(
        "apply.reverted", causation_id=foreign_verification.event_id
    )
    with pytest.raises(EventValidationError, match="external|cross-run|same run|causation"):
        fold_run(
            [events[0], cross_run],
            external_predecessors={foreign_verification.event_id: foreign_verification},
        )

    other_transaction = "tx_" + "0" * 64
    cross_raw = _task8_event_raw("apply.reverted", causation_id=verified.event_id)
    cross_payload = cross_raw["payload"]
    assert isinstance(cross_payload, dict)
    cross_payload["transactionId"] = other_transaction
    cross_payload["logicalOperationId"] = f"promote:{other_transaction}:rollback"
    cross_raw["eventId"] = _task8_event_id("apply.reverted", other_transaction)
    cross_raw["payloadRef"] = (
        f"transactions/{other_transaction}-readback-{TASK8_ROLLBACK_DIGEST[7:]}.json"
    )
    cross_raw["idempotencyKey"] = _idempotency_key(
        "1.0.0",
        "apply.reverted",
        str(cross_raw["runId"]),
        str(cross_payload["logicalOperationId"]),
        "example",
    )
    with pytest.raises(EventValidationError, match="transaction"):
        cross = EventEnvelope.from_mapping(cross_raw)
        fold_run(
            [*events[:reverted_index], cross],
            external_predecessors={origin.event_id: origin},
        )

    reverted = events[reverted_index]
    with pytest.raises(EventValidationError, match="duplicate|terminal|event"):
        fold_run(
            [*events[: reverted_index + 1], reverted],
            external_predecessors={origin.event_id: origin},
        )


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("status", "deferred"),
        ("closeStatus", "deferred"),
        ("terminalReasonCode", "verifier-unavailable"),
        ("outcome", "not-applied"),
        ("linkedIds", [_task8_transaction_id(), _task8_event_id("verification.completed")]),
    ],
)
def test_rolled_back_close_recomputes_status_reason_outcome_and_link_order(
    field: str, bad_value: object
) -> None:
    """An allowed-looking close label cannot contradict its causal verification."""
    origin, events = _task8_chain(terminal="rollback")
    close_raw = events[-1].to_dict()
    close_raw["payload"][field] = bad_value

    with pytest.raises(EventValidationError, match="close|status|reason|outcome|linked"):
        changed = EventEnvelope.from_mapping(close_raw)
        fold_run(
            [*events[:-1], changed],
            external_predecessors={origin.event_id: origin},
        )


def test_affirmed_resolution_and_close_are_the_only_promoted_terminal() -> None:
    """A promoted close must follow the exact affirmative resolution arm."""
    origin, events = _task8_chain(terminal="promoted")

    state = fold_run(
        events,
        external_predecessors={origin.event_id: origin},
    )

    assert state.status == "completed"
    resolution = events[-2]
    assert resolution.event_type == "resolution.recorded"
    assert resolution.payload_ref == _task8_payload_ref("resolution.recorded")
    assert len(_task8_canonical_no_lf(resolution.to_dict()) + b"\n") < 64 * 1024
