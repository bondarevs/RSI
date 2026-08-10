from __future__ import annotations

import copy
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys

import pytest

import rsi_core.storage as storage
from rsi_core.evaluate import Evaluator
from rsi_core.hooks import RunCoordinator, append_event, canonical_digest
from rsi_core.observe import Observer
from rsi_core.storage import EventStore, StoreIntegrityError


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
TARGET = {"name": "mail", "versionHash": DIGEST_A}
IDENTITY = "mail@" + DIGEST_A
STATE_DIRECTORIES = (
    "locks",
    "objects",
    "objects/observations",
    "objects/post-images",
    "baselines",
    "experiments",
    "reports",
    "defragmentation",
    "rejected",
    "incidents",
)
STATE_FILES = ("events.jsonl", "locks/events.lock", "index.sqlite")


def _cli_path() -> Path:
    return Path(__file__).resolve().parents[1] / "scripts" / "rsi.py"


def _tree_manifest(root: Path) -> list[tuple[str, str, int, bytes]]:
    result: list[tuple[str, str, int, bytes]] = []
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if path.is_symlink():
            kind, content = "symlink", os.readlink(path).encode("utf-8")
        elif path.is_dir():
            kind, content = "directory", b""
        else:
            kind, content = "file", path.read_bytes()
        result.append((str(path.relative_to(root)), kind, metadata.st_mode & 0o7777, content))
    return result


def _target_tree(root: Path) -> Path:
    target = root / "target"
    target.mkdir()
    (target / "SKILL.md").write_bytes(b"target bytes\n")
    (target / "references").mkdir()
    (target / "references" / "facts.md").write_bytes(b"facts\n")
    return target


def _local_body(*, hook_mode: str = "coordinated") -> dict[str, object]:
    common: dict[str, object] = {
        "mode": "observe",
        "hookMode": hook_mode,
        "taskClass": "code.change",
        "activeSkills": [dict(TARGET)],
        "taskFingerprint": DIGEST_A,
        "artifactDigest": DIGEST_B,
    }
    if hook_mode == "late-review":
        common["finalArtifacts"] = [{"kind": "test-result", "summary": "The final test passed."}]
    else:
        common.update({"signalsByTarget": {IDENTITY: {}}, "evidence": [], "findings": []})
    return common


def _observe_body() -> dict[str, object]:
    return {
        "taskClass": "code.change",
        "targetSkills": [dict(TARGET)],
        "signalsByTarget": {IDENTITY: {"retryCount": 1}},
        "evidence": [{"kind": "test-result", "summary": "The deterministic test passed."}],
        "taskFingerprint": DIGEST_A,
        "artifactDigest": DIGEST_B,
    }


def _observation_body() -> dict[str, object]:
    return {
        "runId": "run-evaluate",
        "taskClass": "code.change",
        "outcome": "unverified",
        "targetSkills": [dict(TARGET)],
        "signalsByTarget": {IDENTITY: {}},
        "evidence": [],
        "taskFingerprint": DIGEST_A,
        "artifactDigest": DIGEST_B,
        "requestDigest": DIGEST_A,
        "privacy": {"rawContentStored": False, "redactionApplied": False, "sensitiveContentDetected": False},
        "draftCount": 0,
        "canonicalCaptureAllowed": False,
    }


def _run_cli(
    tmp_path: Path,
    command: str,
    body: dict[str, object],
    *,
    home: Path | None = None,
    target: Path | None = None,
    run_id: str | None = None,
    operation: str = "operation-one",
) -> subprocess.CompletedProcess[str]:
    payload = tmp_path / (command + "-input.json")
    payload.write_text(json.dumps(body), encoding="utf-8")
    state = home or (tmp_path / "state")
    argv = [
        sys.executable,
        str(_cli_path()),
        command,
        "--home",
        str(state),
        "--run-id",
        run_id or ("run-evaluate" if command == "evaluate" else "run-cli"),
        "--idempotency-key",
        operation,
        "--input-file",
        str(payload),
        "--json",
    ]
    if command == "local-review":
        argv.extend(["--target-root", str(target or _target_tree(tmp_path))])
    return subprocess.run(argv, check=False, capture_output=True, text=True)


def _invalid_cli_cases() -> list[tuple[str, dict[str, object]]]:
    cases: list[tuple[str, dict[str, object]]] = []

    local_mutations = [
        ("mode", True),
        ("mode", "OBSERVE"),
        ("hookMode", "manual"),
        ("taskClass", ""),
        ("taskClass", ["code.change"]),
        ("activeSkills", []),
        ("activeSkills", [{"name": f"skill-{number}", "versionHash": DIGEST_A} for number in range(33)]),
        ("activeSkills", [{"name": "mail", "versionHash": DIGEST_A, "ignored": True}]),
        ("activeSkills", [{"name": "Mail", "versionHash": DIGEST_A}]),
        ("activeSkills", [{"name": "mail", "versionHash": DIGEST_A}, {"name": "mail", "versionHash": DIGEST_B}]),
        ("activeSkills", [{"name": "mail", "versionHash": "sha256:" + "A" * 64}]),
        ("signalsByTarget", {IDENTITY: {"retryCount": True}}),
        ("signalsByTarget", {IDENTITY: {"retryCount": -1}}),
        ("signalsByTarget", {IDENTITY: {"retryCount": 1_000_001}}),
        ("signalsByTarget", {IDENTITY: {"unknownSignal": 1}}),
        ("evidence", [{"kind": "test", "summary": "passed", "ignored": "value"}]),
        ("evidence", [{"kind": "test", "summary": 1}]),
        ("evidence", [{"kind": "test", "summary": "passed"} for _ in range(6)]),
        ("findings", [{"proposedScope": "mail.smtp", "proposedDedupeKey": "mail.smtp.retry", "summary": "safe", "ignored": True}]),
        ("findings", [{"proposedScope": "Mail.SMTP", "proposedDedupeKey": "mail.smtp.retry", "summary": "safe"}]),
        ("taskFingerprint", "sha256:" + "1" * 63),
        ("artifactDigest", 7),
    ]
    for field, value in local_mutations:
        body = _local_body()
        body[field] = value
        cases.append(("local-review", body))
    coordinated_final = _local_body()
    coordinated_final["finalArtifacts"] = []
    cases.append(("local-review", coordinated_final))
    late = _local_body(hook_mode="late-review")
    late["finalArtifacts"] = [{"kind": "test", "summary": "passed", "ignored": "value"}]
    cases.append(("local-review", late))
    too_many_findings = _local_body()
    too_many_findings["findings"] = [{"proposedScope": f"mail.scope{number}", "proposedDedupeKey": f"mail.retry{number}", "summary": "safe"} for number in range(4)]
    cases.append(("local-review", too_many_findings))
    too_many_artifacts = _local_body(hook_mode="late-review")
    too_many_artifacts["finalArtifacts"] = [{"kind": "test", "summary": "passed"} for _ in range(6)]
    cases.append(("local-review", too_many_artifacts))

    observe_mutations = [
        ("taskClass", False),
        ("targetSkills", [{"name": "mail", "versionHash": DIGEST_A, "ignored": 1}]),
        ("targetSkills", [{"name": "mail", "versionHash": "bad"}]),
        ("signalsByTarget", {IDENTITY: {"latencyMs": 1.5}}),
        ("signalsByTarget", {"other@" + DIGEST_A: {}}),
        ("evidence", ["not-an-object"]),
        ("taskFingerprint", "not-a-digest"),
        ("artifactDigest", None),
    ]
    for field, value in observe_mutations:
        body = _observe_body()
        body[field] = value
        cases.append(("observe", body))

    finding = {"proposedScope": "mail.smtp", "proposedDedupeKey": "mail.smtp.retry", "summary": "A bounded safe finding."}
    for body in (
        {**finding, "ignored": 1},
        {**finding, "proposedScope": "mail..smtp"},
        {**finding, "proposedDedupeKey": "x"},
        {**finding, "summary": 1},
    ):
        cases.append(("note-finding", body))

    observation = _observation_body()
    for mutation in (
        {"observationEventId": 1, "observation": observation},
        {"observationEventId": "evt_test", "observation": {**observation, "ignored": True}},
        {"observationEventId": "evt_test", "observation": {**observation, "privacy": {"rawContentStored": False}}},
        {"observationEventId": "evt_test", "observation": {**observation, "draftCount": True}},
        {"observationEventId": "evt_test", "observation": {**observation, "canonicalCaptureAllowed": True}},
    ):
        cases.append(("evaluate", mutation))
    return cases


@pytest.mark.parametrize(("command", "body"), _invalid_cli_cases())
def test_malformed_cli_request_is_rejected_before_state_exists(
    tmp_path: Path, command: str, body: dict[str, object]
) -> None:
    """Deleting pre-store validation must make this create the forbidden home."""
    state = tmp_path / "never-created"
    target = _target_tree(tmp_path) if command == "local-review" else None
    before = _tree_manifest(target) if target else None

    completed = _run_cli(tmp_path, command, body, home=state, target=target)

    assert completed.returncode != 0, completed.stdout
    assert not state.exists()
    if target:
        assert _tree_manifest(target) == before


@pytest.mark.parametrize(
    ("command", "body"),
    [
        ("observe", {**_observe_body(), "artifactDigest": "bad"}),
        ("note-finding", {"proposedScope": "Bad.Scope", "proposedDedupeKey": "mail.retry", "summary": "safe"}),
        ("evaluate", {"observationEventId": "evt_test", "observation": {**_observation_body(), "draftCount": True}}),
        ("local-review", {**_local_body(), "activeSkills": [{"name": "mail", "versionHash": DIGEST_A, "ignored": True}]}),
    ],
)
def test_malformed_cli_request_leaves_existing_home_byte_and_mode_identical(
    tmp_path: Path, command: str, body: dict[str, object]
) -> None:
    home = tmp_path / "existing-state"
    home.mkdir()
    sentinel = home / "events.jsonl"
    sentinel.write_bytes(b"sentinel bytes that are intentionally not a ledger\n")
    sentinel.chmod(0o644)
    target = _target_tree(tmp_path) if command == "local-review" else None
    before = _tree_manifest(home)

    completed = _run_cli(tmp_path, command, body, home=home, target=target)

    assert completed.returncode != 0
    assert _tree_manifest(home) == before


@pytest.mark.parametrize(("run_id", "operation"), [("bad run", "safe-key"), ("safe-run", "x" * 300)])
def test_invalid_cli_identifiers_leave_existing_home_untouched(tmp_path: Path, run_id: str, operation: str) -> None:
    home = tmp_path / "existing-state"
    home.mkdir()
    sentinel = home / "events.jsonl"
    sentinel.write_bytes(b"unchanged\n")
    sentinel.chmod(0o644)
    before = _tree_manifest(home)

    completed = _run_cli(tmp_path, "observe", _observe_body(), home=home, run_id=run_id, operation=operation)

    assert completed.returncode != 0
    assert _tree_manifest(home) == before


def _process_cli(command: list[str], gate: multiprocessing.synchronize.Event, output: multiprocessing.queues.Queue) -> None:
    gate.wait(timeout=30)
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    output.put((completed.returncode, completed.stdout, completed.stderr))


def _race_cli(command: list[str], contenders: int = 8) -> list[tuple[int, str, str]]:
    context = multiprocessing.get_context("spawn")
    gate = context.Event()
    output = context.Queue()
    processes = [context.Process(target=_process_cli, args=(command, gate, output)) for _ in range(contenders)]
    for process in processes:
        process.start()
    gate.set()
    results = [output.get(timeout=60) for _ in processes]
    for process in processes:
        process.join(timeout=60)
        assert process.exitcode == 0
    return results


def test_real_process_observation_race_has_one_logical_effect_and_complete_sidecar(tmp_path: Path) -> None:
    home = tmp_path / "state"
    RunCoordinator(EventStore(home)).start(
        run_id="run-race", active_skills=[TARGET], task_class="code.change",
        logical_operation_id="start", mode="observe", hook_mode="coordinated",
    )
    payload = tmp_path / "observe.json"
    payload.write_text(json.dumps(_observe_body()), encoding="utf-8")
    command = [sys.executable, str(_cli_path()), "observe", "--home", str(home), "--run-id", "run-race", "--idempotency-key", "observe-race", "--input-file", str(payload), "--json"]

    results = _race_cli(command)

    assert {code for code, _, _ in results} == {0}, "\n".join(stdout for code, stdout, _ in results if code)
    envelopes = [json.loads(stdout) for _, stdout, _ in results]
    assert all(envelope == envelopes[0] for envelope in envelopes)
    events = EventStore(home).read_events()
    assert [event.event_type for event in events].count("task.observed") == 1
    observation_id = envelopes[0]["eventIds"][0]
    sidecar = home / "objects" / "observations" / (observation_id + ".json")
    assert json.loads(sidecar.read_text(encoding="utf-8")) == envelopes[0]["observation"]


def test_real_process_local_review_race_returns_identical_complete_results(tmp_path: Path) -> None:
    home = tmp_path / "state"
    target = _target_tree(tmp_path)
    before = _tree_manifest(target)
    payload = tmp_path / "review.json"
    payload.write_text(json.dumps(_local_body()), encoding="utf-8")
    command = [sys.executable, str(_cli_path()), "local-review", "--home", str(home), "--target-root", str(target), "--run-id", "run-race-review", "--idempotency-key", "review-race", "--input-file", str(payload), "--json"]

    results = _race_cli(command)

    assert {code for code, _, _ in results} == {0}, "\n".join(stdout for code, stdout, _ in results if code)
    envelopes = [json.loads(stdout) for _, stdout, _ in results]
    assert all(envelope == envelopes[0] for envelope in envelopes)
    assert _tree_manifest(target) == before
    events = EventStore(home).read_events()
    assert len(events) == len({event.idempotency_key for event in events}) == 5
    reports = list((home / "reports").glob("local-review-*.json"))
    observations = list((home / "objects" / "observations").glob("*.json"))
    assert len(reports) == len(observations) == 1
    json.loads(reports[0].read_text(encoding="utf-8"))
    json.loads(observations[0].read_text(encoding="utf-8"))


def test_real_process_different_observation_requests_with_one_key_fail_closed(tmp_path: Path) -> None:
    home = tmp_path / "state"
    RunCoordinator(EventStore(home)).start(
        run_id="run-conflict", active_skills=[TARGET], task_class="code.change",
        logical_operation_id="start", mode="observe", hook_mode="coordinated",
    )
    commands: list[list[str]] = []
    for number, retry_count in enumerate((1, 2)):
        body = _observe_body()
        body["signalsByTarget"] = {IDENTITY: {"retryCount": retry_count}}
        payload = tmp_path / f"observe-{number}.json"
        payload.write_text(json.dumps(body), encoding="utf-8")
        commands.append([sys.executable, str(_cli_path()), "observe", "--home", str(home), "--run-id", "run-conflict", "--idempotency-key", "same-key", "--input-file", str(payload), "--json"])
    context = multiprocessing.get_context("spawn")
    gate = context.Event()
    output = context.Queue()
    processes = [context.Process(target=_process_cli, args=(command, gate, output)) for command in commands]
    for process in processes:
        process.start()
    gate.set()
    results = [output.get(timeout=60) for _ in processes]
    for process in processes:
        process.join(timeout=60)
        assert process.exitcode == 0

    codes = sorted(code for code, _, _ in results)
    assert codes[0] == 0 and codes[1] in {2, 4}
    events = EventStore(home).read_events()
    assert [event.event_type for event in events].count("task.observed") == 1
    assert len(list((home / "objects" / "observations").glob("*.json"))) == 1


def test_write_once_handles_short_writes_and_stale_temp_residue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = EventStore(tmp_path / "state")
    destination = store.home / "reports" / "report.json"
    stale = destination.parent / ("." + destination.name + ".tmp")
    stale.write_bytes(b"crash residue")
    real_write = os.write

    def short_write(descriptor: int, data: bytes) -> int:
        return real_write(descriptor, data[: max(1, len(data) // 3)])

    monkeypatch.setattr("rsi_core.storage.os.write", short_write)
    store.write_once(destination, b"complete payload\n")

    assert destination.read_bytes() == b"complete payload\n"
    assert stale.read_bytes() == b"crash residue"


def test_write_once_publish_failure_exposes_no_partial_and_retry_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = EventStore(tmp_path / "state")
    destination = store.home / "reports" / "report.json"
    real_publish = storage._rename_noreplace_at
    calls = 0

    def crash_once(parent_fd: int, source: str, target: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected publish crash")
        real_publish(parent_fd, source, target)

    monkeypatch.setattr(storage, "_rename_noreplace_at", crash_once)
    with pytest.raises(OSError, match="injected publish crash"):
        store.write_once(destination, b"complete payload\n")
    assert not destination.exists()

    store.write_once(destination, b"complete payload\n")
    assert destination.read_bytes() == b"complete payload\n"


def test_write_once_post_publish_cleanup_failure_replays_complete_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = EventStore(tmp_path / "state")
    destination = store.home / "reports" / "report.json"
    real_unlink = os.unlink
    calls = 0

    def crash_once(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected pre-cleanup crash")
        real_unlink(*args, **kwargs)

    monkeypatch.setattr("rsi_core.storage.os.unlink", crash_once)
    with pytest.raises(OSError, match="injected pre-cleanup crash"):
        store.write_once(destination, b"complete payload\n")
    assert destination.read_bytes() == b"complete payload\n"

    store.write_once(destination, b"complete payload\n")
    assert destination.read_bytes() == b"complete payload\n"


@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink"])
def test_write_once_rejects_sidecar_alias_without_touching_target(tmp_path: Path, unsafe_kind: str) -> None:
    store = EventStore(tmp_path / "state")
    target = tmp_path / "outside"
    target.write_bytes(b"unchanged")
    destination = store.home / "reports" / "report.json"
    if unsafe_kind == "symlink":
        destination.symlink_to(target)
    else:
        os.link(target, destination)
    before = target.read_bytes(), target.stat().st_mode

    with pytest.raises(StoreIntegrityError):
        store.write_once(destination, b"new bytes")

    assert (target.read_bytes(), target.stat().st_mode) == before


def test_write_once_never_accepts_conflicting_complete_bytes(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "state")
    destination = store.home / "reports" / "report.json"
    store.write_once(destination, b"first\n")

    with pytest.raises(StoreIntegrityError, match="conflicts"):
        store.write_once(destination, b"second\n")

    assert destination.read_bytes() == b"first\n"


def _durable_observation(tmp_path: Path) -> tuple[EventStore, dict[str, object], str]:
    store = EventStore(tmp_path / "state")
    RunCoordinator(store).start(
        run_id="run-tamper", active_skills=[TARGET], task_class="code.change",
        logical_operation_id="start", mode="observe", hook_mode="coordinated",
    )
    result = Observer(store).observe(
        run_id="run-tamper", logical_operation_id="observe", task_class="code.change",
        outcome="unverified", target_skills=[TARGET], signals_by_target={IDENTITY: {"retryCount": 1}},
        evidence=[{"kind": "test-result", "summary": "The deterministic test passed."}],
        task_fingerprint=DIGEST_A, artifact_digest=DIGEST_B,
    )
    return store, result["observation"], result["eventIds"][0]


def _tamper(field: str, observation: dict[str, object]) -> None:
    if field == "outcome":
        observation[field] = "verified-success"
    elif field == "taskClass":
        observation[field] = "different.task"
    elif field == "targetSkills":
        observation[field] = [{"name": "mail", "versionHash": DIGEST_B}]
    elif field == "signalsByTarget":
        observation[field] = {IDENTITY: {"retryCount": 99}}
    elif field == "evidence":
        observation[field] = [{"kind": "test-result", "summary": "A different test passed."}]
    elif field == "taskFingerprint":
        observation[field] = DIGEST_B
    elif field == "artifactDigest":
        observation[field] = DIGEST_A
    elif field == "privacy":
        observation[field] = {"rawContentStored": False, "redactionApplied": False, "sensitiveContentDetected": True}
    elif field == "draftCount":
        observation[field] = 1
    elif field == "canonicalCaptureAllowed":
        observation[field] = True
    else:
        raise AssertionError(field)


@pytest.mark.parametrize(
    "field",
    ["outcome", "taskClass", "targetSkills", "signalsByTarget", "evidence", "taskFingerprint", "artifactDigest", "privacy", "draftCount", "canonicalCaptureAllowed"],
)
def test_evaluator_recomputes_durable_observation_digest_for_every_semantic_category(tmp_path: Path, field: str) -> None:
    store, observation, event_id = _durable_observation(tmp_path)
    poisoned = copy.deepcopy(observation)
    _tamper(field, poisoned)
    sidecar = store.home / "objects" / "observations" / (event_id + ".json")
    sidecar.write_text(json.dumps(poisoned, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    with pytest.raises(Exception, match="digest|binding|inconsistent|conflicts|invalid|exactly match"):
        Evaluator(store).evaluate_per_target(
            run_id="run-tamper", observation=poisoned,
            observation_event_id=event_id, logical_operation_id="evaluate",
        )
    assert not any(event.event_type == "evaluation.completed" for event in store.read_events())


@pytest.mark.parametrize(("name", "version"), [("other", DIGEST_A), ("mail", DIGEST_B)])
def test_store_lock_rejects_evaluation_name_or_version_not_declared_by_start(tmp_path: Path, name: str, version: str) -> None:
    store, observation, event_id = _durable_observation(tmp_path)
    observation_digest = observation["requestDigest"]

    with pytest.raises(StoreIntegrityError, match="declared"):
        append_event(
            store,
            event_type="evaluation.completed",
            run_id="run-tamper",
            logical_operation_id="evaluate:" + name + ":" + version,
            target_skill=name,
            causation_id=event_id,
            payload={"baseline": "unknown", "metricDeltas": {"baselineStatus": "unknown"}, "evidenceStatus": "unverified"},
            correlation_id=canonical_digest({"observationDigest": observation_digest}),
        )

    assert not any(event.event_type == "evaluation.completed" for event in store.read_events())


def test_namespaced_skill_identity_remains_unambiguous_in_store_binding(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "state")
    target = {"name": "plugin:mail", "versionHash": DIGEST_A}
    identity = "plugin:mail@" + DIGEST_A
    RunCoordinator(store).start(
        run_id="run-namespaced", active_skills=[target], task_class="code.change",
        logical_operation_id="start", mode="observe", hook_mode="coordinated",
    )
    observed = Observer(store).observe(
        run_id="run-namespaced", logical_operation_id="observe", task_class="code.change",
        outcome="unverified", target_skills=[target], signals_by_target={identity: {}},
        evidence=[], task_fingerprint=DIGEST_A, artifact_digest=DIGEST_B,
    )

    results = Evaluator(store).evaluate_per_target(
        run_id="run-namespaced", observation=observed["observation"],
        observation_event_id=observed["eventIds"][0], logical_operation_id="evaluate",
    )

    assert [result["targetSkill"] for result in results] == ["plugin:mail"]


def _prepare_internal_parent(home: Path, relative: str) -> Path:
    path = home / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@pytest.mark.parametrize("relative", STATE_DIRECTORIES)
@pytest.mark.parametrize("unsafe_kind", ["symlink", "non-directory"])
def test_event_store_rejects_every_unsafe_internal_directory_component(
    tmp_path: Path, relative: str, unsafe_kind: str
) -> None:
    home = tmp_path / "state"
    home.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker"
    marker.write_bytes(b"unchanged")
    path = _prepare_internal_parent(home, relative)
    if unsafe_kind == "symlink":
        path.symlink_to(outside, target_is_directory=True)
    else:
        path.write_bytes(b"not a directory")
    before = _tree_manifest(outside)

    with pytest.raises(StoreIntegrityError, match="topology"):
        EventStore(home)

    assert _tree_manifest(outside) == before


@pytest.mark.parametrize("relative", STATE_FILES)
@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink", "non-regular"])
def test_event_store_rejects_every_unsafe_critical_file(
    tmp_path: Path, relative: str, unsafe_kind: str
) -> None:
    home = tmp_path / "state"
    home.mkdir()
    outside = tmp_path / "outside-file"
    outside.write_bytes(b"unchanged")
    path = _prepare_internal_parent(home, relative)
    if unsafe_kind == "symlink":
        path.symlink_to(outside)
    elif unsafe_kind == "hardlink":
        os.link(outside, path)
    else:
        path.mkdir()
    before = outside.read_bytes(), outside.stat().st_mode

    with pytest.raises(StoreIntegrityError, match="topology"):
        EventStore(home)

    assert (outside.read_bytes(), outside.stat().st_mode) == before


@pytest.mark.parametrize("relative", STATE_FILES)
def test_critical_file_permission_fallback_cannot_race_chmod_onto_external_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    """A same-user replacement at the old chmod boundary must leave its target untouched."""
    home = tmp_path / "state"
    home.mkdir()
    critical = _prepare_internal_parent(home, relative)
    critical.write_bytes(b"state")
    critical.chmod(0o004)
    target = tmp_path / "target"
    target.mkdir()
    external = target / "external"
    external.write_bytes(b"external")
    external.chmod(0o640)
    before = _tree_manifest(target), external.stat().st_nlink
    real_chmod = os.chmod

    def swap_before_chmod(
        path: str | bytes | int,
        requested_mode: int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        if path == critical.name and dir_fd is not None:
            os.unlink(path, dir_fd=dir_fd)
            os.link(external, path, dst_dir_fd=dir_fd, follow_symlinks=False)
        real_chmod(path, requested_mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(storage.os, "chmod", swap_before_chmod)

    with pytest.raises(StoreIntegrityError):
        EventStore(home)

    assert (_tree_manifest(target), external.stat().st_nlink) == before


def test_event_store_rejects_home_root_symlink_without_touching_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "marker").write_bytes(b"unchanged")
    home = tmp_path / "state"
    home.symlink_to(outside, target_is_directory=True)
    before = _tree_manifest(outside)

    with pytest.raises(StoreIntegrityError, match="topology"):
        EventStore(home)

    assert _tree_manifest(outside) == before


@pytest.mark.parametrize("relation", ["equal", "home-inside-target", "target-inside-home", "root-alias"])
def test_local_review_rejects_all_home_target_alias_relations_before_mutation(tmp_path: Path, relation: str) -> None:
    target = _target_tree(tmp_path)
    if relation == "equal":
        home = target
    elif relation == "home-inside-target":
        home = target / "state"
    elif relation == "target-inside-home":
        home = tmp_path
    else:
        home = tmp_path / "state-alias"
        home.symlink_to(target, target_is_directory=True)
    before = _tree_manifest(target)

    completed = _run_cli(tmp_path, "local-review", _local_body(), home=home, target=target)

    assert completed.returncode != 0
    assert json.loads(completed.stdout)["error"]["code"] in {"invalid-arguments", "store-integrity"}
    assert _tree_manifest(target) == before


@pytest.mark.parametrize("relative", STATE_DIRECTORIES)
def test_local_review_rejects_internal_directory_alias_into_target_before_mutation(tmp_path: Path, relative: str) -> None:
    target = _target_tree(tmp_path)
    home = tmp_path / "state"
    home.mkdir()
    path = _prepare_internal_parent(home, relative)
    path.symlink_to(target, target_is_directory=True)
    before = _tree_manifest(target)

    completed = _run_cli(tmp_path, "local-review", _local_body(), home=home, target=target)

    assert completed.returncode != 0
    assert _tree_manifest(target) == before


@pytest.mark.parametrize("relative", STATE_FILES)
@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink"])
def test_local_review_rejects_internal_file_alias_into_target_before_mutation(
    tmp_path: Path, relative: str, unsafe_kind: str
) -> None:
    target = _target_tree(tmp_path)
    home = tmp_path / "state"
    home.mkdir()
    path = _prepare_internal_parent(home, relative)
    if unsafe_kind == "symlink":
        path.symlink_to(target / "SKILL.md")
    else:
        os.link(target / "SKILL.md", path)
    before = _tree_manifest(target)

    completed = _run_cli(tmp_path, "local-review", _local_body(), home=home, target=target)

    assert completed.returncode != 0
    assert _tree_manifest(target) == before


def test_local_review_accepts_a_secure_existing_home(tmp_path: Path) -> None:
    target = _target_tree(tmp_path)
    home = tmp_path / "state"
    EventStore(home)

    completed = _run_cli(tmp_path, "local-review", _local_body(), home=home, target=target)

    assert completed.returncode == 0, completed.stdout
    assert json.loads(completed.stdout)["status"] == "completed"
