from __future__ import annotations

from pathlib import Path

from rsi_core.hooks import RunCoordinator, VerificationResult
from rsi_core.hooks import LifecycleError
from rsi_core.storage import EventStore


def test_coordinated_hooks_are_exactly_once_and_merge_then_cap_drafts(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")
    coordinator = RunCoordinator(store)

    started = coordinator.start(
        run_id="run-hooks", active_skills=[{"name": "mail", "versionHash": "sha256:" + "a" * 64}],
        task_class="code.change", logical_operation_id="start-1", mode="observe", hook_mode="coordinated",
    )
    assert coordinator.start(
        run_id="run-hooks", active_skills=[{"name": "mail", "versionHash": "sha256:" + "a" * 64}],
        task_class="code.change", logical_operation_id="start-1", mode="observe", hook_mode="coordinated",
    ) == started

    first = coordinator.note_finding("run-hooks", {"proposedScope": "mail.smtp", "proposedDedupeKey": "mail.smtp.retry", "summary": "Retry evidence is recorded."}, "note-1")
    merged = coordinator.note_finding("run-hooks", {"proposedScope": "mail.smtp", "proposedDedupeKey": "mail.smtp.retry", "summary": "A later wording is not a new draft."}, "note-2")
    assert merged["draftId"] == first["draftId"]
    assert merged["merged"] is True
    for number in range(2, 5):
        coordinator.note_finding("run-hooks", {"proposedScope": f"mail.scope{number}", "proposedDedupeKey": f"mail.key{number}", "summary": f"Finding number {number} is recorded."}, f"note-{number + 1}")
    capped = coordinator.note_finding("run-hooks", {"proposedScope": "mail.extra", "proposedDedupeKey": "mail.extra", "summary": "This must not be persisted."}, "note-cap")
    assert capped["status"] == "no-op"
    assert capped["reason"] == "draft-cap-reached"
    assert len([event for event in store.read_events() if event.event_type == "finding.drafted"]) == 3


def test_late_review_is_explicit_and_discloses_missing_in_dialog_signals(tmp_path: Path) -> None:
    coordinator = RunCoordinator(EventStore(tmp_path / "rsi"))
    result = coordinator.start(
        run_id="late", active_skills=[{"name": "mail", "versionHash": "sha256:" + "b" * 64}],
        task_class="code.change", logical_operation_id="late-start", mode="observe", hook_mode="late-review",
        final_artifacts=[{"kind": "test-result", "summary": "The final deterministic test passed."}],
    )

    assert result["status"] == "completed"
    assert result["warnings"] == ["late-review: in-dialog-only signals were unavailable"]
    assert result["coordinatedCapture"] is False
    try:
        coordinator.note_finding("late", {"proposedScope": "mail.smtp", "proposedDedupeKey": "mail.smtp", "summary": "This was not captured in dialog."}, "late-note")
    except LifecycleError as error:
        assert str(error) == "late-review does not accept in-dialog drafts"
    else:
        raise AssertionError("late review accepted an in-dialog draft")


def test_reused_logical_operation_key_with_different_request_fails_closed(tmp_path: Path) -> None:
    coordinator = RunCoordinator(EventStore(tmp_path / "rsi"))
    request = dict(run_id="conflict", active_skills=[{"name": "mail", "versionHash": "sha256:" + "b" * 64}], task_class="code.change", logical_operation_id="start", hook_mode="coordinated")
    coordinator.start(**request, mode="observe")

    try:
        coordinator.start(**request, mode="propose")
    except LifecycleError as error:
        assert str(error) == "logical operation id conflicts with its recorded request"
    else:
        raise AssertionError("conflicting replay returned a prior operation")


def test_no_rsi_legacy_case_writes_no_events_or_claimed_guarantees(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")

    result = RunCoordinator.no_rsi(store)

    assert result == {"status": "no-rsi", "rsiGuarantees": False, "eventIds": []}
    assert store.read_events() == []


def test_close_requires_one_verified_observation_and_all_target_evaluations(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")
    coordinator = RunCoordinator(store)
    target = {"name": "mail", "versionHash": "sha256:" + "a" * 64}
    coordinator.start(run_id="ordered", active_skills=[target], task_class="code.change", logical_operation_id="start", mode="observe", hook_mode="coordinated")

    try:
        coordinator.close(run_id="ordered", logical_operation_id="close")
    except LifecycleError as error:
        assert str(error) == "close requires observation and all target evaluations"
    else:
        raise AssertionError("close before verification succeeded")


def test_verification_result_must_be_literal_and_bound_to_the_run(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")
    target = {"name": "mail", "versionHash": "sha256:" + "b" * 64}
    coordinator = RunCoordinator(store, verification_authority=lambda **_: VerificationResult.success("other", "sha256:" + "1" * 64, [target], "sha256:" + "2" * 64))
    coordinator.start(run_id="bound", active_skills=[target], task_class="code.change", logical_operation_id="start", mode="observe", hook_mode="coordinated")

    try:
        coordinator.verify_primary_task(run_id="bound", logical_operation_id="verify", task_class="code.change", target_skills=[target], task_fingerprint="sha256:" + "1" * 64, artifact_digest="sha256:" + "2" * 64, signals_by_target={"mail@sha256:" + "b" * 64: {}})
    except LifecycleError as error:
        assert str(error) == "verification result is not bound to this task"
    else:
        raise AssertionError("unbound verifier result was accepted")
