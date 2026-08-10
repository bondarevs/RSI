"""Read-only, conservative Task 8 recovery classification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Mapping, Sequence

from .storage import EventStore, StoreIntegrityError


class RecoveryError(ValueError):
    """Recovery evidence cannot be classified safely."""


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    transaction_id: str
    state: str
    recommendation: str
    last_durable_event_id: str
    state_changing: bool


@dataclass(frozen=True, slots=True)
class RecoveryClassification:
    branch: str
    reason: str
    preserve_reserved_name: bool
    state_changing: bool = False
    may_unlink: bool = False


_STATUS: dict[str, dict[str, str]] = {
    "promoted": {"verified-promotion": "completed"},
    "not-started": {
        "eligibility-blocked": "blocked",
        "control-disabled": "blocked",
        "capability-lost": "blocked",
        "target-stale-external": "failed",
        "snapshot-failed": "failed",
        "intent-publication-failed": "failed",
        "authority-expired": "deferred",
        "candidate-drift": "deferred",
        "provider-authority-drift": "deferred",
    },
    "not-applied": {
        "authority-expired": "deferred",
        "candidate-drift": "deferred",
        "temp-create-failed": "failed",
        "pre-exchange-check-failed": "failed",
    },
    "rolled-back": {
        "verifier-unavailable": "deferred",
        "authority-invalidated": "deferred",
        "verification-failed": "failed",
        "attestation-mismatch": "failed",
    },
    "ambiguous": {
        reason: "ambiguous"
        for reason in (
            "preapply-provider-unknown", "partial-apply-authority", "prepared-temp-unknown",
            "prepared-temp-sync-failed", "prepared-temp-cleanup-absent-unsynced",
            "retained-preimage-cleanup-absent-unsynced", "displaced-post-cleanup-absent-unsynced",
            "pre-state-unreadable", "post-state-unreadable", "provider-state-unknown",
            "verifier-state-unknown", "namespace-lease-unavailable", "namespace-enforcer-lost",
            "forward-exchange-ambiguous", "emergency-reverse-ambiguous",
            "rollback-exchange-ambiguous", "ancestry-lost",
        )
    },
    "quarantined": {
        "post-state-drift": "quarantined",
        "retained-preimage-drift": "quarantined",
    },
}


def close_status_for(outcome: str, reason: str) -> str:
    try:
        return _STATUS[outcome][reason]
    except (KeyError, TypeError):
        raise RecoveryError("outcome/reason has no deterministic close status") from None


def _classification(branch: str, reason: str, preserve: bool, *, may_unlink: bool = False) -> RecoveryClassification:
    return RecoveryClassification(branch, reason, preserve, False, may_unlink)


def classify_promotion_recovery(observation: Mapping[str, object]) -> RecoveryClassification:
    if not isinstance(observation, Mapping):
        raise RecoveryError("recovery observation is invalid")
    event = observation.get("lastDurableEvent")
    target = observation.get("targetClassification")
    reserved = observation.get("reservedNameClassification")
    provider = observation.get("providerClassification")
    verification = observation.get("verificationClassification")

    if event == "snapshot.created":
        return _classification("not-started", "orphan-intent", True)

    if event == "apply.started":
        if reserved == "unbound-present":
            return _classification("incident", "prepared-temp-unknown", True)
        if target == "exact-post" and reserved == "expected-preimage":
            return _classification("incident", "forward-exchange-ambiguous", True)
        if observation.get("authorityCurrent") is False:
            return _classification("not-applied", "never-created", True)
        if target == "exact-pre" and reserved == "absent":
            return _classification("resume-apply", "never-created-authority-current", True)

    if event == "apply.completed:applied":
        if provider == "unknown":
            return _classification("incident", "provider-state-unknown", True)
        if verification == "rollback-armed-orphan-sidecar":
            return _classification("incident", "rollback-authority-blocked", True)
        if target == "exact-post":
            return _classification("resume-verification", "applied-unverified", True)

    if event == "verification.completed:rollback-armed":
        if verification != "rollback-armed":
            return _classification("incident", "rollback-authority-blocked", True)
        if target == "exact-pre" and reserved == "displaced-post":
            return _classification("incident", "rollback-exchange-ambiguous", True)
        if target == "exact-post" and reserved == "retained-preimage":
            return _classification("rollback", "rollback-authorized", True)

    if event == "verification.completed:affirmed":
        if target == "exact-post" and provider == "promoted-exact" and verification == "affirmed":
            return _classification("reconcile-resolution-event", "provider-commit-local-event-missing", True)

    if event == "resolution.recorded":
        if target != "exact-post":
            return _classification("incident", "resolved-target-not-post", True)
        if (
            provider == "promoted-exact"
            and reserved == "event-bound-retained-preimage"
            and observation.get("causalCleanupEvent") == "resolution.recorded"
        ):
            return _classification("cleanup-retained-preimage", "event-authorized-cleanup", False)

    # Once a durable apply intent exists, an unclassified state is never a clean inference.
    return _classification("incident", "partial-apply-authority", True)


def cleanup_is_authorized(
    *, last_durable_event: str, reserved_name_classification: str,
    authority_event: str | None,
) -> bool:
    expected = {
        "apply.completed:not-applied": "event-bound-prepared-post",
        "resolution.recorded": "event-bound-retained-preimage",
        "apply.reverted": "event-bound-displaced-post",
    }
    return (
        authority_event == last_durable_event
        and expected.get(last_durable_event) == reserved_name_classification
    )


def classify_cleanup_recovery(cut: Mapping[str, object]) -> RecoveryClassification:
    if cut.get("reservedName") == "absent":
        if cut.get("parentSynced") is True:
            return _classification("terminal-readback", "authorized-absence-synced", True)
        return _classification("resume-parent-sync", "authorized-absence-unsynced", True)
    return _classification("incident", "cleanup-name-reappeared", True)


_INCIDENT_TRACE = (
    "transaction-stop", "incident-record", "quarantine-cas", "latch-cas",
    "incident.latched", "decision", "run.closed",
)


def validate_incident_publication_trace(
    trace: Sequence[str], *, local_incident_digest: str,
    latch_disposition: str, blocking_latch_digest: str,
) -> None:
    if tuple(trace) != _INCIDENT_TRACE:
        raise RecoveryError("incident publication/event/close order is invalid")
    if latch_disposition not in {"created", "preexisting"}:
        raise RecoveryError("incident latch disposition is invalid")
    if latch_disposition == "created" and blocking_latch_digest != local_incident_digest:
        raise RecoveryError("created incident latch does not bind the local incident")


class PromotionRecovery:
    __slots__ = ("_root", "_store")

    def __init__(self, root: Path, store: EventStore) -> None:
        self._root = Path(root)
        self._store = store

    @classmethod
    def open_existing(cls, root: Path) -> "PromotionRecovery":
        path = Path(root)
        try:
            store = EventStore.open_existing(path)
        except (OSError, StoreIntegrityError) as error:
            raise RecoveryError("recovery root is unavailable or invalid") from error
        return cls(path, store)

    def inspect(self, transaction_id=None) -> RecoveryReport:
        if transaction_id is not None and (
            type(transaction_id) is not str
            or re.fullmatch(r"tx_[0-9a-f]{64}", transaction_id) is None
        ):
            raise RecoveryError("transaction identifier is invalid")
        try:
            events = self._store.read_events()
        except (OSError, StoreIntegrityError) as error:
            raise RecoveryError("durable promotion journal is unreadable") from error
        by_transaction: dict[str, list[object]] = {}
        for event in events:
            value = event.payload.get("transactionId")
            if isinstance(value, str) and re.fullmatch(r"tx_[0-9a-f]{64}", value):
                by_transaction.setdefault(value, []).append(event)
        if transaction_id is None:
            if len(by_transaction) != 1:
                raise RecoveryError(
                    "recovery inspection requires one explicit transaction selector"
                )
            transaction_id = next(iter(by_transaction))
        sequence = by_transaction.get(transaction_id)
        if not sequence:
            raise RecoveryError("promotion transaction is not present")
        last = sequence[-1]
        event_type = last.event_type
        outcome = last.payload.get("outcome")
        if event_type == "run.closed":
            state, recommendation = str(last.payload.get("status")), "none"
        elif event_type in {
            "run.started", "promotion.gated", "staging.completed",
            "validation.completed", "promotion.planned", "snapshot.created",
        }:
            state, recommendation = "not-started", "resume"
        elif event_type == "apply.started":
            state, recommendation = "state-changing", "quarantine"
        elif event_type == "apply.completed" and outcome == "not-applied":
            state, recommendation = "not-applied", "event-reconciliation"
        elif event_type == "apply.completed":
            state, recommendation = "applied-unverified", "resume-verification"
        elif event_type == "verification.completed" and outcome == "rollback-armed":
            state, recommendation = "rollback-armed", "rollback"
        elif event_type == "verification.completed":
            state, recommendation = "verified", "resume-resolution"
        elif event_type == "apply.reverted":
            state, recommendation = "rolled-back", "event-reconciliation"
        elif event_type == "resolution.recorded":
            state, recommendation = "resolved", "event-reconciliation"
        elif event_type == "incident.latched":
            state, recommendation = "incident", "operator-restore"
        else:
            raise RecoveryError("durable promotion phase cannot be classified")
        return RecoveryReport(
            transaction_id=transaction_id,
            state=state,
            recommendation=recommendation,
            last_durable_event_id=last.event_id,
            state_changing=state in {
                "state-changing", "applied-unverified", "verified",
                "rollback-armed", "resolved", "incident",
            },
        )
