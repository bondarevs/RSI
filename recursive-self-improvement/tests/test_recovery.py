from __future__ import annotations

from dataclasses import FrozenInstanceError
import inspect

import pytest

from task8_support import DIGEST_A, DIGEST_B, lazy_module


def _recovery():
    return lazy_module("rsi_core.recovery")


def test_recovery_public_boundary_is_diagnostic_and_transaction_selective() -> None:
    module = _recovery()
    assert module.PromotionRecovery
    assert module.RecoveryReport
    assert module.RecoveryError
    parameters = inspect.signature(module.PromotionRecovery.inspect).parameters
    assert tuple(parameters) == ("self", "transaction_id")
    assert parameters["transaction_id"].default is None


def test_recovery_report_is_deeply_immutable() -> None:
    module = _recovery()
    report = module.RecoveryReport(
        transaction_id="tx_" + "a" * 64,
        state="not-started",
        recommendation="resume",
        last_durable_event_id="evt_" + "b" * 64,
        state_changing=False,
    )
    with pytest.raises((FrozenInstanceError, AttributeError)):
        report.recommendation = "mutate"


def test_recovery_open_existing_has_no_creating_default_constructor_fallback() -> None:
    module = _recovery()
    signature = inspect.signature(module.PromotionRecovery.open_existing)
    assert "create" not in signature.parameters
    assert "repair" not in signature.parameters
    assert "initialize" not in signature.parameters


def test_recovery_public_object_exposes_no_mutating_command_surface() -> None:
    module = _recovery()
    public_methods = {
        name
        for name, member in inspect.getmembers(module.PromotionRecovery)
        if not name.startswith("_")
        and callable(member)
    }
    assert public_methods == {"open_existing", "inspect"}


@pytest.mark.parametrize(
    ("outcome", "reason", "expected_status"),
    [
        ("promoted", "verified-promotion", "completed"),
        ("not-started", "eligibility-blocked", "blocked"),
        ("not-started", "control-disabled", "blocked"),
        ("not-started", "capability-lost", "blocked"),
        ("not-started", "target-stale-external", "failed"),
        ("not-started", "snapshot-failed", "failed"),
        ("not-started", "intent-publication-failed", "failed"),
        ("not-started", "authority-expired", "deferred"),
        ("not-started", "candidate-drift", "deferred"),
        ("not-started", "provider-authority-drift", "deferred"),
        ("not-applied", "authority-expired", "deferred"),
        ("not-applied", "candidate-drift", "deferred"),
        ("not-applied", "temp-create-failed", "failed"),
        ("not-applied", "pre-exchange-check-failed", "failed"),
        ("rolled-back", "verifier-unavailable", "deferred"),
        ("rolled-back", "authority-invalidated", "deferred"),
        ("rolled-back", "verification-failed", "failed"),
        ("rolled-back", "attestation-mismatch", "failed"),
        ("ambiguous", "preapply-provider-unknown", "ambiguous"),
        ("ambiguous", "partial-apply-authority", "ambiguous"),
        ("ambiguous", "prepared-temp-unknown", "ambiguous"),
        ("ambiguous", "prepared-temp-sync-failed", "ambiguous"),
        ("ambiguous", "prepared-temp-cleanup-absent-unsynced", "ambiguous"),
        ("ambiguous", "retained-preimage-cleanup-absent-unsynced", "ambiguous"),
        ("ambiguous", "displaced-post-cleanup-absent-unsynced", "ambiguous"),
        ("ambiguous", "pre-state-unreadable", "ambiguous"),
        ("ambiguous", "post-state-unreadable", "ambiguous"),
        ("ambiguous", "provider-state-unknown", "ambiguous"),
        ("ambiguous", "verifier-state-unknown", "ambiguous"),
        ("ambiguous", "namespace-lease-unavailable", "ambiguous"),
        ("ambiguous", "namespace-enforcer-lost", "ambiguous"),
        ("ambiguous", "forward-exchange-ambiguous", "ambiguous"),
        ("ambiguous", "emergency-reverse-ambiguous", "ambiguous"),
        ("ambiguous", "rollback-exchange-ambiguous", "ambiguous"),
        ("ambiguous", "ancestry-lost", "ambiguous"),
        ("quarantined", "post-state-drift", "quarantined"),
        ("quarantined", "retained-preimage-drift", "quarantined"),
    ],
)
def test_terminal_reason_has_one_total_close_status(
    outcome: str, reason: str, expected_status: str
) -> None:
    module = _recovery()
    assert module.close_status_for(outcome, reason) == expected_status


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        ("promoted", "candidate-drift"),
        ("not-started", "verification-failed"),
        ("not-applied", "verified-promotion"),
        ("rolled-back", "temp-write-failed"),
        ("ambiguous", "post-state-drift"),
        ("quarantined", "forward-exchange-ambiguous"),
        ("caller-outcome", "candidate-drift"),
    ],
)
def test_status_mapper_rejects_cross_arm_or_unknown_pairs(
    outcome: str, reason: str
) -> None:
    module = _recovery()
    with pytest.raises(module.RecoveryError, match="outcome|reason|status"):
        module.close_status_for(outcome, reason)


def _observation(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "transactionId": "tx_" + "a" * 64,
        "lastDurableEvent": "apply.started",
        "targetClassification": "exact-pre",
        "reservedNameClassification": "absent",
        "providerClassification": "unresolved",
        "verificationClassification": "not-reached",
        "authorityCurrent": True,
        "causalCleanupEvent": None,
        "orphanIntentPresent": False,
        "orphanBackendEvidencePresent": False,
    }
    value.update(changes)
    return value


@pytest.mark.parametrize(
    ("observation", "branch", "reason", "preserve_reserved"),
    [
        (
            _observation(
                lastDurableEvent="snapshot.created",
                orphanIntentPresent=True,
                targetClassification="exact-pre",
            ),
            "not-started",
            "orphan-intent",
            True,
        ),
        (
            _observation(),
            "resume-apply",
            "never-created-authority-current",
            True,
        ),
        (
            _observation(authorityCurrent=False),
            "not-applied",
            "never-created",
            True,
        ),
        (
            _observation(reservedNameClassification="unbound-present"),
            "incident",
            "prepared-temp-unknown",
            True,
        ),
        (
            _observation(
                targetClassification="exact-post",
                reservedNameClassification="expected-preimage",
            ),
            "incident",
            "forward-exchange-ambiguous",
            True,
        ),
        (
            _observation(
                lastDurableEvent="apply.completed:applied",
                targetClassification="exact-post",
            ),
            "resume-verification",
            "applied-unverified",
            True,
        ),
        (
            _observation(
                lastDurableEvent="verification.completed:rollback-armed",
                targetClassification="exact-post",
                reservedNameClassification="retained-preimage",
                verificationClassification="rollback-armed",
            ),
            "rollback",
            "rollback-authorized",
            True,
        ),
        (
            _observation(
                lastDurableEvent="verification.completed:rollback-armed",
                targetClassification="exact-pre",
                reservedNameClassification="displaced-post",
                verificationClassification="rollback-armed",
            ),
            "incident",
            "rollback-exchange-ambiguous",
            True,
        ),
        (
            _observation(
                lastDurableEvent="verification.completed:affirmed",
                targetClassification="exact-post",
                providerClassification="promoted-exact",
                verificationClassification="affirmed",
            ),
            "reconcile-resolution-event",
            "provider-commit-local-event-missing",
            True,
        ),
        (
            _observation(
                lastDurableEvent="resolution.recorded",
                targetClassification="exact-post",
                providerClassification="promoted-exact",
                verificationClassification="affirmed",
                reservedNameClassification="event-bound-retained-preimage",
                causalCleanupEvent="resolution.recorded",
            ),
            "cleanup-retained-preimage",
            "event-authorized-cleanup",
            False,
        ),
        (
            _observation(
                lastDurableEvent="resolution.recorded",
                targetClassification="other",
                providerClassification="promoted-exact",
                verificationClassification="affirmed",
                reservedNameClassification="event-bound-retained-preimage",
                causalCleanupEvent="resolution.recorded",
            ),
            "incident",
            "resolved-target-not-post",
            True,
        ),
        (
            _observation(
                lastDurableEvent="apply.completed:applied",
                targetClassification="exact-post",
                providerClassification="unknown",
            ),
            "incident",
            "provider-state-unknown",
            True,
        ),
    ],
)
def test_recovery_crash_cut_classifier_is_phase_exact_and_conservative(
    observation: dict[str, object],
    branch: str,
    reason: str,
    preserve_reserved: bool,
) -> None:
    module = _recovery()
    classification = module.classify_promotion_recovery(observation)
    assert classification.branch == branch
    assert classification.reason == reason
    assert classification.preserve_reserved_name is preserve_reserved
    assert classification.state_changing is False


@pytest.mark.parametrize("orphan_field", ["orphanIntentPresent", "orphanBackendEvidencePresent"])
def test_orphan_evidence_never_reconstructs_a_missing_mutation_event(
    orphan_field: str,
) -> None:
    module = _recovery()
    baseline = _observation(
        targetClassification="exact-post",
        reservedNameClassification="expected-preimage",
    )
    orphan = {**baseline, orphan_field: True}
    first = module.classify_promotion_recovery(baseline)
    second = module.classify_promotion_recovery(orphan)
    assert first.branch == second.branch == "incident"
    assert first.reason == second.reason == "forward-exchange-ambiguous"


def test_recovery_never_infers_ownership_from_expected_temp_bytes_or_inode_shape() -> None:
    module = _recovery()
    observation = _observation(
        reservedNameClassification="unbound-present",
        orphanBackendEvidencePresent=True,
        observedReservedDigest=DIGEST_A,
        expectedPostDigest=DIGEST_A,
        observedReservedMetadata={"type": "regular-file", "nlink": 1},
    )
    classification = module.classify_promotion_recovery(observation)
    assert classification.branch == "incident"
    assert classification.reason == "prepared-temp-unknown"
    assert classification.preserve_reserved_name is True


def test_rollback_requires_durable_same_transaction_negative_verification() -> None:
    module = _recovery()
    observation = _observation(
        lastDurableEvent="apply.completed:applied",
        targetClassification="exact-post",
        reservedNameClassification="retained-preimage",
        verificationClassification="rollback-armed-orphan-sidecar",
    )
    classification = module.classify_promotion_recovery(observation)
    assert classification.branch == "incident"
    assert classification.reason == "rollback-authority-blocked"


@pytest.mark.parametrize(
    ("last_event", "reserved", "authority_event", "expected"),
    [
        ("apply.started", "absent", None, False),
        ("apply.started", "unbound-present", None, False),
        (
            "apply.completed:not-applied",
            "event-bound-prepared-post",
            "apply.completed:not-applied",
            True,
        ),
        ("resolution.recorded", "event-bound-retained-preimage", "resolution.recorded", True),
        ("apply.reverted", "event-bound-displaced-post", "apply.reverted", True),
        ("resolution.recorded", "unbound-present", "resolution.recorded", False),
    ],
)
def test_cleanup_authority_requires_exact_event_bound_name_identity(
    last_event: str, reserved: str, authority_event: str | None, expected: bool
) -> None:
    module = _recovery()
    assert (
        module.cleanup_is_authorized(
            last_durable_event=last_event,
            reserved_name_classification=reserved,
            authority_event=authority_event,
        )
        is expected
    )


def test_unlink_crash_cut_requires_absence_parent_sync_and_terminal_readback() -> None:
    module = _recovery()
    cut = {
        "authorityEvent": "resolution.recorded",
        "reservedName": "absent",
        "parentSynced": False,
        "targetClassification": "exact-post",
        "providerClassification": "promoted-exact",
    }
    classification = module.classify_cleanup_recovery(cut)
    assert classification.branch == "resume-parent-sync"
    assert classification.may_unlink is False

    reappeared = {**cut, "reservedName": "different-present"}
    classification = module.classify_cleanup_recovery(reappeared)
    assert classification.branch == "incident"
    assert classification.may_unlink is False


def test_incident_publication_is_acyclic_marker_last_and_first_latch_wins() -> None:
    module = _recovery()
    local_incident = DIGEST_A
    blocking_latch = DIGEST_B
    created = module.validate_incident_publication_trace(
        [
            "transaction-stop",
            "incident-record",
            "quarantine-cas",
            "latch-cas",
            "incident.latched",
            "decision",
            "run.closed",
        ],
        local_incident_digest=local_incident,
        latch_disposition="created",
        blocking_latch_digest=local_incident,
    )
    assert created is None
    preexisting = module.validate_incident_publication_trace(
        [
            "transaction-stop",
            "incident-record",
            "quarantine-cas",
            "latch-cas",
            "incident.latched",
            "decision",
            "run.closed",
        ],
        local_incident_digest=local_incident,
        latch_disposition="preexisting",
        blocking_latch_digest=blocking_latch,
    )
    assert preexisting is None


@pytest.mark.parametrize(
    "trace",
    [
        ["latch-cas", "incident-record", "incident.latched"],
        ["incident-record", "incident.latched", "latch-cas"],
        ["transaction-stop", "incident-record", "quarantine-cas", "latch-cas", "run.closed"],
        [
            "transaction-stop",
            "incident-record",
            "quarantine-cas",
            "latch-cas",
            "decision",
            "incident.latched",
        ],
        [
            "incident-record",
            "quarantine-cas",
            "latch-cas",
            "incident.latched",
            "decision",
            "run.closed",
        ],
    ],
)
def test_incident_publication_rejects_reorder_partial_close_or_future_binding(
    trace: list[str],
) -> None:
    module = _recovery()
    with pytest.raises(module.RecoveryError, match="incident|order|event|close"):
        module.validate_incident_publication_trace(
            trace,
            local_incident_digest=DIGEST_A,
            latch_disposition="created",
            blocking_latch_digest=DIGEST_A,
        )


def test_recovery_report_can_flag_double_scan_drift_without_becoming_a_mutator() -> None:
    module = _recovery()
    report = module.RecoveryReport(
        transaction_id="tx_" + "a" * 64,
        state="state-changing",
        recommendation="operator-restore",
        last_durable_event_id="evt_" + "b" * 64,
        state_changing=True,
    )
    assert report.state_changing is True
    assert report.recommendation == "operator-restore"
    assert {
        name
        for name, member in inspect.getmembers(module.PromotionRecovery)
        if not name.startswith("_")
        and callable(member)
    } == {"open_existing", "inspect"}
