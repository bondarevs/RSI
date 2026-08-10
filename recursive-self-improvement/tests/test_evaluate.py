from __future__ import annotations

from pathlib import Path

import pytest

from rsi_core.evaluate import Evaluator
from rsi_core.hooks import LifecycleError, RunCoordinator
from rsi_core.observe import Observer
from rsi_core.storage import EventStore


def _observation(store: EventStore, targets: list[dict[str, str]]) -> dict:
    RunCoordinator(store).start(run_id="run-eval", active_skills=targets, task_class="code.change", logical_operation_id="start", mode="observe", hook_mode="coordinated")
    return Observer(store).observe(run_id="run-eval", logical_operation_id="observe", task_class="code.change", outcome="verified-success", target_skills=targets, signals={"verificationPassed": True}, evidence=[])


def test_evaluation_uses_independent_baselines_for_two_targets(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")
    first = {"name": "mail", "versionHash": "sha256:" + "a" * 64}
    second = {"name": "calendar", "versionHash": "sha256:" + "b" * 64}
    observed = _observation(store, [first, second])
    calls: list[tuple[str, str, str]] = []

    def baseline(name: str, task_class: str, version_hash: str, evaluator_version: str) -> dict | None:
        calls.append((name, task_class, version_hash))
        return {"ref": f"baseline:{name}", "signals": {"retryCount": 1}} if name == "mail" else None

    results = Evaluator(store, baseline_lookup=baseline).evaluate_per_target(
        run_id="run-eval", observation=observed["observation"], observation_event_id=observed["eventIds"][0], logical_operation_id="evaluate",
    )

    assert [result["targetSkill"] for result in results] == ["mail", "calendar"]
    assert results[0]["baselineRef"] == "baseline:mail"
    assert results[1]["baselineRef"] == "unknown"
    assert results[1]["metricDeltas"]["baselineStatus"] == "unknown"
    assert calls == [("mail", "code.change", first["versionHash"]), ("calendar", "code.change", second["versionHash"])]


def test_no_finding_and_stale_baseline_are_not_treated_as_zero(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")
    observed = _observation(store, [{"name": "mail", "versionHash": "sha256:" + "c" * 64}])

    results = Evaluator(store, baseline_lookup=lambda *_: {"ref": "old", "stale": True}).evaluate_per_target(
        run_id="run-eval", observation=observed["observation"], observation_event_id=observed["eventIds"][0], logical_operation_id="evaluate",
    )

    assert results[0]["decision"] == "unknown"
    assert results[0]["baselineRef"] == "unknown"
    assert results[0]["metricDeltas"]["baselineStatus"] == "unknown"


def test_evaluation_replay_binds_observation_and_baseline_request(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")
    observed = _observation(store, [{"name": "mail", "versionHash": "sha256:" + "d" * 64}])
    evaluator = Evaluator(store, baseline_lookup=lambda *_: {"ref": "baseline:one", "signals": {"retryCount": 1}})
    evaluator.evaluate_per_target(run_id="run-eval", observation=observed["observation"], observation_event_id=observed["eventIds"][0], logical_operation_id="evaluate")

    changed = {**observed["observation"], "taskClass": "different.task"}
    try:
        evaluator.evaluate_per_target(run_id="run-eval", observation=changed, observation_event_id=observed["eventIds"][0], logical_operation_id="evaluate")
    except Exception as error:
        assert "conflicts" in str(error)
    else:
        raise AssertionError("changed evaluation replay succeeded")


def test_public_evaluator_rejects_undeclared_target_before_append(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")
    observed = _observation(store, [{"name": "mail", "versionHash": "sha256:" + "e" * 64}])
    poisoned = {**observed["observation"], "targetSkills": [{"name": "other", "versionHash": "sha256:" + "f" * 64}]}

    try:
        Evaluator(store).evaluate_per_target(run_id="run-eval", observation=poisoned, observation_event_id=observed["eventIds"][0], logical_operation_id="poison")
    except Exception as error:
        assert "durable" in str(error) or "undeclared" in str(error)
    else:
        raise AssertionError("public evaluator accepted an undeclared target")


@pytest.mark.parametrize("poisoned", [float("inf"), float("nan"), True, -1, 1_000_001])
def test_baseline_metric_values_must_be_finite_bounded_integers_before_persistence(tmp_path: Path, poisoned: object) -> None:
    store = EventStore(tmp_path / "rsi")
    target = {"name": "mail", "versionHash": "sha256:" + "9" * 64}
    identity = target["name"] + "@" + target["versionHash"]
    RunCoordinator(store).start(run_id="run-eval", active_skills=[target], task_class="code.change", logical_operation_id="start", mode="propose", hook_mode="coordinated")
    observed = Observer(store).observe(
        run_id="run-eval",
        logical_operation_id="observe",
        task_class="code.change",
        outcome="unverified",
        target_skills=[target],
        signals_by_target={identity: {"retryCount": 1}},
        evidence=[],
    )

    with pytest.raises(LifecycleError, match="baseline|metric|signal|finite|bounds"):
        Evaluator(
            store,
            baseline_lookup=lambda *_: {"ref": "baseline:known", "signals": {"retryCount": poisoned}, "hardInvariantsPassed": True},
        ).evaluate_per_target(
            run_id="run-eval",
            observation=observed["observation"],
            observation_event_id=observed["eventIds"][0],
            logical_operation_id="evaluate",
        )

    assert not any(event.event_type == "evaluation.completed" for event in store.read_events())


def test_evaluation_sidecar_failure_never_commits_event_before_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EventStore(tmp_path / "rsi")
    target = {"name": "mail", "versionHash": "sha256:" + "8" * 64}
    observed = _observation(store, [target])
    original = store.write_once

    def fail_evaluation(path: Path, data: bytes) -> None:
        if "evaluations" in path.parts:
            raise OSError("injected-evaluation-sidecar-failure")
        original(path, data)

    monkeypatch.setattr(store, "write_once", fail_evaluation)

    with pytest.raises(LifecycleError, match="evaluation"):
        Evaluator(
            store,
            baseline_lookup=lambda *_: {
                "ref": "baseline:known",
                "signals": {},
                "hardInvariantsPassed": True,
            },
        ).evaluate_per_target(
            run_id="run-eval",
            observation=observed["observation"],
            observation_event_id=observed["eventIds"][0],
            logical_operation_id="evaluate",
        )

    assert not any(event.event_type == "evaluation.completed" for event in store.read_events())
