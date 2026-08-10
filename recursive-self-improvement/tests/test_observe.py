from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from rsi_core.hooks import RunCoordinator, VerificationResult, LifecycleError
from rsi_core.observe import Observer
from rsi_core.storage import EventStore


TARGET = {"name": "mail", "versionHash": "sha256:" + "c" * 64}


def _tree_manifest(root: Path) -> list[tuple[str, str, int, bytes]]:
    result = []
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        stat = path.lstat()
        if path.is_symlink():
            kind, content = "symlink", os.readlink(path).encode()
        elif path.is_dir():
            kind, content = "directory", b""
        else:
            kind, content = "file", path.read_bytes()
        result.append((relative, kind, stat.st_mode & 0o7777, content))
    return result


def _started(store: EventStore, run_id: str = "run-observe") -> None:
    RunCoordinator(store).start(run_id=run_id, active_skills=[TARGET], task_class="code.change", logical_operation_id="start", mode="observe", hook_mode="coordinated")


def test_observe_distinguishes_verified_success_failure_and_unverified(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")
    for number, outcome in enumerate(("verified-success", "verified-failure", "unverified"), start=1):
        run_id = f"run-{number}"
        _started(store, run_id)
        def authority(**kwargs: object) -> VerificationResult:
            targets = kwargs["target_skills"]
            return VerificationResult(outcome, str(kwargs["run_id"]), str(kwargs["task_fingerprint"]), tuple((item["name"], item["versionHash"]) for item in targets), str(kwargs["artifact_digest"]))
        observer = Observer(store, verification_authority=authority)
        result = observer.observe(
            run_id=run_id, logical_operation_id=f"observe-{number}", task_class="code.change", outcome=outcome,
            target_skills=[TARGET], signals_by_target={"mail@" + TARGET["versionHash"]: {}}, task_fingerprint="sha256:" + "1" * 64, artifact_digest="sha256:" + "2" * 64,
            evidence=[{"kind": "test-result", "summary": "The deterministic test suite completed."}],
        )
        assert result["observation"]["outcome"] == outcome
        assert result["observation"]["canonicalCaptureAllowed"] is (outcome != "unverified")


def test_unverified_observation_keeps_audit_drafts_but_blocks_capture(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")
    _started(store)
    coordinator = RunCoordinator(store)
    coordinator.note_finding("run-observe", {"proposedScope": "mail.smtp", "proposedDedupeKey": "mail.smtp.readback", "summary": "Readback is useful."}, "note")

    result = Observer(store).observe(
        run_id="run-observe", logical_operation_id="observe", task_class="code.change", outcome="unverified",
        target_skills=[TARGET], signals={}, evidence=[],
    )

    assert result["candidateIds"] == []
    assert result["observation"]["canonicalCaptureAllowed"] is False
    assert result["observation"]["draftCount"] == 1


def test_observe_replay_returns_identical_envelope_without_extra_jsonl_line(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")
    _started(store)
    observer = Observer(store)
    request = dict(run_id="run-observe", logical_operation_id="observe", task_class="code.change", outcome="unverified", target_skills=[TARGET], signals_by_target={"mail@" + TARGET["versionHash"]: {}}, evidence=[])

    first = observer.observe(**request)
    before = store.events_path.read_bytes()
    assert observer.observe(**request) == first
    assert store.events_path.read_bytes() == before


def test_observation_sidecar_failure_never_commits_event_before_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EventStore(tmp_path / "rsi")
    _started(store)
    original = store.write_once

    def fail_observation(path: Path, data: bytes) -> None:
        if "observations" in path.parts:
            raise OSError("injected-observation-sidecar-failure")
        original(path, data)

    monkeypatch.setattr(store, "write_once", fail_observation)

    with pytest.raises(LifecycleError, match="observation"):
        Observer(store).observe(
            run_id="run-observe",
            logical_operation_id="observe",
            task_class="code.change",
            outcome="unverified",
            target_skills=[TARGET],
            signals_by_target={"mail@" + TARGET["versionHash"]: {}},
            evidence=[],
        )

    assert not any(event.event_type == "task.observed" for event in store.read_events())


def test_cli_local_review_replays_stably_and_never_mutates_target(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    cli = root / "scripts" / "rsi.py"
    home = tmp_path / "rsi-home"
    target = tmp_path / "target"
    target.mkdir()
    (target / "SKILL.md").write_bytes(b"unchanged target bytes\n")
    (target / "references").mkdir()
    (target / "references" / "facts.md").write_bytes(b"immutable facts\n")
    (target / "link").symlink_to("SKILL.md")
    payload = tmp_path / "review.json"
    payload.write_text(json.dumps({"mode": "observe", "hookMode": "coordinated", "taskClass": "code.change", "activeSkills": [TARGET], "signalsByTarget": {"mail@" + TARGET["versionHash"]: {}}, "evidence": [], "findings": [{"proposedScope": "mail.smtp", "proposedDedupeKey": "mail.smtp.readback", "summary": "Readback is recorded."}]}), encoding="utf-8")
    command = [sys.executable, str(cli), "local-review", "--home", str(home), "--run-id", "run-cli", "--idempotency-key", "review-1", "--input-file", str(payload), "--target-root", str(target), "--json"]
    environment = {**os.environ, "PYTHONPATH": str(root / "scripts")}

    before_tree = _tree_manifest(target)
    first = subprocess.run(command, check=False, capture_output=True, text=True, env=environment)
    before_events = (home / "events.jsonl").read_bytes()
    second = subprocess.run(command, check=False, capture_output=True, text=True, env=environment)

    assert first.returncode == second.returncode == 0
    assert json.loads(first.stdout) == json.loads(second.stdout)
    assert (home / "events.jsonl").read_bytes() == before_events
    assert _tree_manifest(target) == before_tree
    envelope = json.loads(first.stdout)
    assert envelope["candidateIds"] == []
    assert envelope["mutationPerformed"] is False


def test_cli_uses_stable_typed_error_envelope(tmp_path: Path) -> None:
    cli = Path(__file__).resolve().parents[1] / "scripts" / "rsi.py"
    completed = subprocess.run([sys.executable, str(cli), "observe", "--home", str(tmp_path / "rsi"), "--json"], check=False, capture_output=True, text=True)

    assert completed.returncode == 2
    assert json.loads(completed.stdout) == {"schemaVersion": 1, "command": "observe", "runId": None, "status": "failed", "error": {"code": "invalid-arguments", "message": "--run-id, --idempotency-key, and --input-file are required", "retryable": False, "details": {}}}


def test_untrusted_caller_cannot_self_assert_verified_and_targets_must_match_start(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")
    _started(store)
    result = Observer(store).observe(run_id="run-observe", logical_operation_id="observe", task_class="code.change", outcome="verified-success", target_skills=[TARGET], signals_by_target={"mail@" + TARGET["versionHash"]: {}}, evidence=[], task_fingerprint="sha256:" + "1" * 64, artifact_digest="sha256:" + "2" * 64)
    assert result["observation"]["outcome"] == "unverified"


def test_observation_replay_conflict_and_signal_scope_are_rejected(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "rsi")
    _started(store)
    request = dict(run_id="run-observe", logical_operation_id="observe", task_class="code.change", outcome="unverified", target_skills=[TARGET], signals_by_target={"mail@" + TARGET["versionHash"]: {"retryCount": 1}}, evidence=[], task_fingerprint="sha256:" + "1" * 64, artifact_digest="sha256:" + "2" * 64)
    Observer(store).observe(**request)
    try:
        Observer(store).observe(**{**request, "signals_by_target": {"mail@" + TARGET["versionHash"]: {"retryCount": 2}}})
    except LifecycleError as error:
        assert str(error) == "logical operation id conflicts with its recorded request"
    else:
        raise AssertionError("changed observation replay succeeded")

    _started(store, "wrong-target")
    try:
        Observer(store).observe(run_id="wrong-target", logical_operation_id="observe", task_class="code.change", outcome="unverified", target_skills=[{"name": "other", "versionHash": TARGET["versionHash"]}], signals_by_target={"other@" + TARGET["versionHash"]: {}}, evidence=[], task_fingerprint="sha256:" + "1" * 64, artifact_digest="sha256:" + "2" * 64)
    except LifecycleError as error:
        assert str(error) == "observed targets do not match run start"
    else:
        raise AssertionError("undeclared target was accepted")


def test_cli_rejects_home_inside_target_before_creating_entries(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    target = tmp_path / "target"
    target.mkdir()
    (target / "SKILL.md").write_text("identity", encoding="utf-8")
    payload = tmp_path / "input.json"
    payload.write_text(json.dumps({"mode": "observe", "hookMode": "coordinated", "taskClass": "code.change", "activeSkills": [TARGET], "signalsByTarget": {"mail@" + TARGET["versionHash"]: {}}}), encoding="utf-8")
    completed = subprocess.run([sys.executable, str(root / "scripts" / "rsi.py"), "local-review", "--home", str(target / "state"), "--target-root", str(target), "--run-id", "overlap", "--idempotency-key", "one", "--input-file", str(payload), "--json"], check=False, capture_output=True, text=True)

    assert completed.returncode == 2
    assert json.loads(completed.stdout)["error"]["code"] == "invalid-arguments"
    assert not (target / "state").exists()
