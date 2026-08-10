from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import sys

import pytest

from task8_support import (
    DIGEST_A,
    DIGEST_B,
    lazy_module,
    prefixed_digest,
    task8_event_id,
    task8_incident_id,
    task8_run_id,
    task8_transaction_id,
)


def _promotion():
    return lazy_module("rsi_core.promotion")


def test_task8_ids_are_full_width_domain_separated_and_deterministic() -> None:
    module = _promotion()
    transaction_id = task8_transaction_id(DIGEST_A)
    assert module.derive_promotion_transaction_id(DIGEST_A) == transaction_id
    assert module.derive_promotion_run_id(DIGEST_A) == task8_run_id(DIGEST_A)
    assert (
        module.derive_promotion_event_id(transaction_id, "apply.started")
        == task8_event_id(transaction_id, "apply.started")
    )
    assert len(transaction_id.removeprefix("tx_")) == 64


def test_incident_and_cli_command_ids_use_their_exact_distinct_preimages() -> None:
    module = _promotion()
    transaction_id = task8_transaction_id(DIGEST_A)
    expected_command_id = "promote_" + prefixed_digest(
        {"domain": "rsi-promote-cli-v1", "planDigest": DIGEST_A},
        final_lf=False,
    )[7:]
    assert module.derive_promotion_incident_id(transaction_id) == task8_incident_id(
        transaction_id
    )
    assert module.derive_promotion_command_id(DIGEST_A) == expected_command_id
    assert task8_incident_id(transaction_id).removeprefix(
        "incident_"
    ) != transaction_id.removeprefix("tx_")


def test_same_plan_derivation_converges_across_concurrent_callers() -> None:
    module = _promotion()
    with ThreadPoolExecutor(max_workers=16) as executor:
        values = tuple(
            executor.map(module.derive_promotion_transaction_id, [DIGEST_A] * 64)
        )
    assert values == (task8_transaction_id(DIGEST_A),) * 64


def test_different_plans_cannot_share_transaction_run_or_event_ids() -> None:
    module = _promotion()
    first = module.derive_promotion_transaction_id(DIGEST_A)
    second = module.derive_promotion_transaction_id(DIGEST_B)
    assert first != second
    assert module.derive_promotion_run_id(DIGEST_A) != module.derive_promotion_run_id(
        DIGEST_B
    )
    assert module.derive_promotion_event_id(
        first, "run.closed"
    ) != module.derive_promotion_event_id(second, "run.closed")


def test_promotion_conflict_is_a_typed_public_error() -> None:
    module = _promotion()
    assert issubclass(module.PromotionConflict, module.PromotionError)


LOCK_ORDER = (
    "namespace-lease",
    "transaction",
    "global",
    "target",
    "provider",
    "event-store",
)


def _acquire_release_trace(*locks: str) -> list[tuple[str, str]]:
    return [
        *(("acquire", lock) for lock in locks),
        *(("release", lock) for lock in reversed(locks)),
    ]


def test_protected_lock_order_is_one_exact_outermost_sequence() -> None:
    module = _promotion()
    assert tuple(module.TASK8_PROTECTED_LOCK_ORDER) == LOCK_ORDER
    module.validate_task8_lock_trace(_acquire_release_trace(*LOCK_ORDER))


@pytest.mark.parametrize(
    ("earlier", "later"),
    [
        ("namespace-lease", "transaction"),
        ("transaction", "global"),
        ("global", "target"),
        ("target", "provider"),
        ("provider", "event-store"),
        ("namespace-lease", "provider"),
        ("transaction", "event-store"),
    ],
)
def test_every_lock_order_inversion_is_rejected(earlier: str, later: str) -> None:
    module = _promotion()
    trace = _acquire_release_trace(later, earlier)
    with pytest.raises(module.PromotionConflict, match="lock|order|inversion"):
        module.validate_task8_lock_trace(trace)


@pytest.mark.parametrize(
    "inner_lock",
    ["transaction", "global", "target", "provider", "event-store"],
)
def test_lease_acquisition_is_forbidden_while_any_inner_lock_is_held(
    inner_lock: str,
) -> None:
    module = _promotion()
    trace = [
        ("acquire", inner_lock),
        ("acquire", "namespace-lease"),
        ("release", "namespace-lease"),
        ("release", inner_lock),
    ]
    with pytest.raises(module.PromotionConflict, match="lease|outer|held"):
        module.validate_task8_lock_trace(trace)


def test_full_manifest_scan_releases_all_inner_locks_but_retains_lease() -> None:
    module = _promotion()
    trace = [
        ("acquire", "namespace-lease"),
        ("heavy", "full-manifest-readback"),
        ("acquire", "transaction"),
        ("acquire", "global"),
        ("acquire", "target"),
        ("acquire", "provider"),
        ("acquire", "event-store"),
        ("release", "event-store"),
        ("release", "provider"),
        ("release", "target"),
        ("release", "global"),
        ("release", "transaction"),
        ("release", "namespace-lease"),
    ]
    module.validate_task8_lock_trace(trace)


def test_long_verifier_window_keeps_only_the_outer_lease() -> None:
    module = _promotion()
    trace = [
        ("acquire", "namespace-lease"),
        ("heavy", "full-manifest-readback"),
        ("heavy", "trusted-verifier"),
        ("acquire", "transaction"),
        ("acquire", "global"),
        ("acquire", "target"),
        ("acquire", "provider"),
        ("acquire", "event-store"),
        ("release", "event-store"),
        ("release", "provider"),
        ("release", "target"),
        ("release", "global"),
        ("release", "transaction"),
        ("release", "namespace-lease"),
    ]
    module.validate_task8_lock_trace(trace)


@pytest.mark.parametrize(
    ("heavy_operation", "forbidden_lock"),
    [
        ("full-manifest-readback", "global"),
        ("full-manifest-readback", "provider"),
        ("full-manifest-readback", "event-store"),
        ("trusted-verifier", "global"),
        ("trusted-verifier", "provider"),
        ("trusted-verifier", "event-store"),
        ("provider-snapshot", "event-store"),
        ("provider-resolve", "event-store"),
    ],
)
def test_heavy_or_provider_operation_cannot_span_forbidden_inner_lock(
    heavy_operation: str, forbidden_lock: str
) -> None:
    module = _promotion()
    trace = [
        ("acquire", "namespace-lease"),
        ("acquire", forbidden_lock),
        ("heavy", heavy_operation),
        ("release", forbidden_lock),
        ("release", "namespace-lease"),
    ]
    with pytest.raises(module.PromotionConflict, match="heavy|provider|lock"):
        module.validate_task8_lock_trace(trace)


def test_guard_a_releases_the_preapply_suffix_before_acquiring_lease_and_temp_io() -> None:
    module = _promotion()
    trace = [
        ("acquire", "transaction"),
        ("acquire", "global"),
        ("acquire", "target"),
        ("acquire", "provider"),
        ("acquire", "event-store"),
        ("callback", "apply.started"),
        ("release", "event-store"),
        ("release", "provider"),
        ("release", "target"),
        ("release", "global"),
        ("release", "transaction"),
        ("acquire", "namespace-lease"),
        ("heavy", "prepared-post-io"),
        ("release", "namespace-lease"),
    ]
    module.validate_task8_lock_trace(trace)


def test_guard_b_never_appends_event_or_builds_historical_batch() -> None:
    module = _promotion()
    for forbidden in ("event-store-append", "historical-batch"):
        trace = [
            ("acquire", "namespace-lease"),
            ("acquire", "transaction"),
            ("acquire", "global"),
            ("acquire", "target"),
            ("acquire", "provider"),
            ("guard-b", forbidden),
        ]
        with pytest.raises(module.PromotionConflict, match="Guard B|append|batch"):
            module.validate_task8_lock_trace(trace)


def test_forward_apply_keeps_lease_across_guard_b_readback_and_apply_event() -> None:
    module = _promotion()
    trace = [
        "acquire:namespace-lease",
        "acquire:transaction",
        "acquire:global",
        "acquire:target",
        "acquire:provider:guard-b",
        "backend:forward-exchange",
        "release:provider:guard-b",
        "release:target",
        "release:global",
        "release:transaction",
        "heavy:full-manifest-readback",
        "acquire:transaction",
        "acquire:global",
        "acquire:target",
        "acquire:provider:rollback-mode",
        "acquire:event-store",
        "append:apply.completed:applied",
        "release:event-store",
        "release:provider:rollback-mode",
        "release:target",
        "release:global",
        "release:transaction",
        "release:namespace-lease",
    ]
    module.validate_task8_phase_trace("forward-apply", trace)


def test_rollback_keeps_one_lease_across_reverse_full_readback_and_revert_event() -> None:
    module = _promotion()
    trace = [
        "acquire:namespace-lease",
        "heavy:full-manifest-readback:exact-post",
        "acquire:transaction",
        "acquire:global",
        "acquire:target",
        "acquire:provider:rollback",
        "backend:rollback-exchange",
        "release:provider:rollback",
        "release:target",
        "release:global",
        "release:transaction",
        "heavy:full-manifest-readback:exact-pre",
        "acquire:transaction",
        "acquire:global",
        "acquire:target",
        "acquire:provider:rollback",
        "acquire:event-store",
        "append:apply.reverted",
        "release:event-store",
        "release:provider:rollback",
        "release:target",
        "release:global",
        "release:transaction",
        "release:namespace-lease",
    ]
    module.validate_task8_phase_trace("rollback-apply", trace)


def test_cleanup_provider_guard_is_continuous_from_name_check_through_close() -> None:
    module = _promotion()
    trace = [
        "acquire:namespace-lease",
        "heavy:full-manifest-readback",
        "acquire:transaction",
        "acquire:global",
        "acquire:target",
        "acquire:provider:unresolved-terminal",
        "bounded:reserved-name-check",
        "backend:unlink",
        "backend:parent-sync",
        "bounded:protected-postcheck",
        "acquire:event-store",
        "append:transaction-decision",
        "release:event-store",
        "acquire:event-store",
        "append:run.closed",
        "release:event-store",
        "release:provider:unresolved-terminal",
        "release:target",
        "release:global",
        "release:transaction",
        "release:namespace-lease",
    ]
    module.validate_task8_phase_trace("prepared-post-cleanup", trace)

    broken = list(trace)
    index = broken.index("backend:parent-sync")
    broken.insert(index, "release:provider:unresolved-terminal")
    broken.insert(index + 1, "acquire:provider:unresolved-terminal")
    with pytest.raises(module.PromotionConflict, match="continuous|cleanup|guard"):
        module.validate_task8_phase_trace("prepared-post-cleanup", broken)


def test_provider_to_eventstore_callback_allowlist_is_closed() -> None:
    module = _promotion()
    expected = frozenset(
        {
            "historical-gate",
            "all-origin-batch",
            "guard-a:apply.started",
            "rollback:apply.completed:applied",
            "new-apply:verification.completed:affirmed",
            "rollback:verification.completed:rollback-armed",
            "not-started-terminal",
            "not-applied-terminal",
            "rollback:apply.reverted",
            "rollback-terminal",
            "terminal-readback:resolution.recorded",
            "promoted-terminal",
            "incident-publication",
            "incident-close",
        }
    )
    assert frozenset(module.PROVIDER_EVENTSTORE_CALLBACKS) == expected
    for callback in expected:
        module.validate_provider_eventstore_callback(callback)
    with pytest.raises(module.PromotionConflict, match="callback|provider|event"):
        module.validate_provider_eventstore_callback("guard-b:apply.completed")


@pytest.mark.parametrize(
    ("operation_class", "required_windows"),
    [
        (
            "forward-apply",
            {
                "create-write",
                "exchange",
                "emergency-reverse",
                "parent-sync",
                "full-readback",
                "event-callback",
            },
        ),
        (
            "rollback-apply",
            {"reverse-exchange", "parent-sync", "full-readback", "event-callback"},
        ),
        (
            "verifier-readback",
            {"full-readback", "trusted-verifier", "event-callback"},
        ),
        (
            "promoted-terminal",
            {"full-readback", "provider-resolve", "event-callback"},
        ),
        (
            "unresolved-terminal",
            {"full-readback", "event-callback"},
        ),
        (
            "incident-classification",
            {"full-readback", "event-callback"},
        ),
        (
            "prepared-post-cleanup",
            {"full-readback", "unlink", "parent-sync", "event-callback"},
        ),
        (
            "retained-preimage-cleanup",
            {"full-readback", "unlink", "parent-sync", "event-callback"},
        ),
        (
            "displaced-post-cleanup",
            {"full-readback", "unlink", "parent-sync", "event-callback"},
        ),
    ],
)
def test_operation_lease_spans_every_required_protected_window(
    operation_class: str, required_windows: set[str]
) -> None:
    module = _promotion()
    assert set(module.lease_required_windows(operation_class)) == required_windows


def test_backend_callback_may_not_reenter_rsi_lock_graph() -> None:
    module = _promotion()
    for lock in LOCK_ORDER[1:]:
        trace = [
            ("acquire", "namespace-lease"),
            ("backend-callback-acquire", lock),
        ]
        with pytest.raises(module.PromotionConflict, match="backend|callback|lock"):
            module.validate_task8_lock_trace(trace)


def test_builtin_local_namespace_backend_is_unavailable_on_ordinary_hosts() -> None:
    module = _promotion()
    backend = module.LocalTrustedNamespaceMutationLeaseBackend()
    assert backend.available is False
    assert backend.failure_code == "unsupported"
    assert sys.platform in {"darwin", "linux"} or backend.available is False


def test_constructor_registry_rejects_caller_supplied_backend_or_capability_boolean() -> None:
    module = _promotion()
    registry = module.TrustedNamespaceMutationLeaseRegistry.empty()
    public_methods = {
        name
        for name in dir(registry)
        if not name.startswith("_") and callable(getattr(registry, name))
    }
    assert not {
        "register",
        "register_from_caller",
        "add_backend",
        "accept_backend",
    }.intersection(public_methods)
    with pytest.raises(
        (TypeError, module.PromotionError), match="capability|boolean|attest|keyword"
    ):
        registry.resolve(backend_identity_digest=DIGEST_A, capability=True)


@pytest.mark.parametrize(
    ("event", "expected_state"),
    [
        ("holder-died", "released"),
        ("enforcer-died", "fail-closed"),
        ("watchdog-expired", "released"),
    ],
)
def test_lease_liveness_never_returns_an_unprotected_live_holder(
    event: str, expected_state: str
) -> None:
    module = _promotion()
    liveness = module.NamespaceLeaseLiveness(initial_state="protected-live")
    liveness.apply(event)
    assert liveness.state == expected_state
    assert not (liveness.holder_live and not liveness.protection_live)


def test_guard_b_race_before_exchange_is_not_applied_and_after_exchange_is_incident() -> None:
    module = _promotion()
    before = module.classify_guard_b_race(
        exchange_performed=False,
        provider_precheck="drift",
        provider_postcheck="not-run",
    )
    assert (before.outcome, before.reason, before.exchange_count) == (
        "not-applied",
        "pre-exchange-check-failed",
        0,
    )
    after = module.classify_guard_b_race(
        exchange_performed=True,
        provider_precheck="exact",
        provider_postcheck="drift",
    )
    assert (after.outcome, after.reason, after.exchange_count) == (
        "incident",
        "provider-state-unknown",
        1,
    )


def test_same_transaction_incident_cas_converges_on_one_fixed_winner() -> None:
    module = _promotion()
    incident_id = module.derive_promotion_incident_id(
        module.derive_promotion_transaction_id(DIGEST_A)
    )
    contenders = [DIGEST_A, DIGEST_B] * 32
    cas = module.InMemoryIncidentRecordCAS(incident_id)
    with ThreadPoolExecutor(max_workers=16) as executor:
        dispositions = tuple(executor.map(cas.publish, contenders))
    winner = cas.read_digest()
    assert winner in {DIGEST_A, DIGEST_B}
    assert sum(item.disposition == "created" for item in dispositions) == 1
    assert all(item.blocking_digest == winner for item in dispositions)


def test_incompatible_plan_for_same_root_conflicts_before_snapshot_or_apply() -> None:
    module = _promotion()
    gate = module.InMemoryPromotionAdmissionGate()
    first = gate.claim(root_identity_digest=DIGEST_A, plan_digest=DIGEST_A)
    replay = gate.claim(root_identity_digest=DIGEST_A, plan_digest=DIGEST_A)
    assert replay == first
    with pytest.raises(module.PromotionConflict, match="root|plan|conflict"):
        gate.claim(root_identity_digest=DIGEST_A, plan_digest=DIGEST_B)
    assert gate.snapshot_call_count == 0
    assert gate.apply_call_count == 0
