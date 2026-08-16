from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import shutil
import stat
import subprocess
import sys
import time

import pytest


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CODEX = shutil.which("codex")
NPX = shutil.which("npx")
RUN_LATEST_CODEX = os.environ.get("RSI_TEST_LATEST_CODEX") == "1"
CATALOG_PROMPT = (
    "Report only whether the model-visible skill catalog contains "
    "recursive-self-improvement. Do not invoke any skill."
)
SKILL_BODY_SENTINEL = (
    "Operate as the control plane for evidence-backed role-skill improvement."
)
EXPECTED_SKILL_DESCRIPTION = (
    "Use only during or after a completed, verified skill-driven task to preserve "
    "and evaluate evidence-backed reusable findings without changing role goals or "
    "weakening safeguards. Use for recurring role-skill evidence, validated "
    "improvements, ownership audits, defragmentation, or cross-skill RSI reports. "
    "Do not use for ordinary conversation, status questions, one-off facts, tasks "
    "without reusable evidence, or RSI/skill-learning deployment and maintenance."
)


def _pid_exists(process_id: int) -> bool:
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_pid_absent(process_id: int, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_exists(process_id):
            return True
        time.sleep(0.01)
    return not _pid_exists(process_id)


def _kill_pid_for_test(process_id: int) -> None:
    if not _pid_exists(process_id):
        return
    try:
        os.kill(process_id, signal.SIGKILL)
    except ProcessLookupError:
        return
    _wait_pid_absent(process_id)


def _open_descriptor_names() -> set[str]:
    descriptor_root = (
        Path("/dev/fd") if Path("/dev/fd").is_dir() else Path("/proc/self/fd")
    )
    return {entry.name for entry in descriptor_root.iterdir()}


def _tree_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    result: list[tuple[object, ...]] = []
    for path in sorted((root, *root.rglob("*")), key=lambda item: os.fsencode(item)):
        metadata = os.lstat(path)
        relative = "." if path == root else path.relative_to(root).as_posix()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISREG(metadata.st_mode):
            payload = path.read_bytes()
            kind = "regular"
            evidence: object = (len(payload), hashlib.sha256(payload).hexdigest())
        elif stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
            evidence = None
        elif stat.S_ISLNK(metadata.st_mode):
            kind = "symlink"
            evidence = os.readlink(path)
        else:
            kind = "special"
            evidence = None
        result.append((relative, kind, mode, metadata.st_nlink, evidence))
    return tuple(result)


def _install_catalog_surface(package_root: Path, installed: Path) -> None:
    (installed / "agents").mkdir(parents=True)
    shutil.copy2(package_root / "SKILL.md", installed / "SKILL.md")
    shutil.copy2(
        package_root / "agents/openai.yaml",
        installed / "agents/openai.yaml",
    )


def _attested_catalog_surface(tmp_path: Path) -> tuple[object, Path, Path]:
    from rsi_core.deployment import DeploymentPaths, GlobalRsiDeployer
    from rsi_core.global_rollout import attest_installed_snapshot

    repo = tmp_path / "source-repository"
    package = repo / "recursive-self-improvement"
    shutil.copytree(
        PACKAGE_ROOT,
        package,
        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc"),
    )
    subprocess.run(["git", "init", "-q", os.fspath(repo)], check=True)
    environment = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    for arguments in (
        ("config", "user.email", "rsi-catalog@example.invalid"),
        ("config", "user.name", "RSI Catalog Tests"),
        ("add", "recursive-self-improvement"),
        ("commit", "-q", "-m", "fixture"),
    ):
        subprocess.run(
            ["git", "-C", os.fspath(repo), *arguments],
            check=True,
            capture_output=True,
            env=environment,
        )
    protected_home = tmp_path / "protected-codex-home"
    paths = DeploymentPaths.for_testing(protected_home)
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo, "deploy-catalog-fixture")
    snapshot = attest_installed_snapshot(paths.installed_root, deployer)
    return snapshot, protected_home, paths.installed_root


def _render_fresh_catalog(
    package_root: Path,
    run_root: Path,
    *,
    command: tuple[str, ...] | None = None,
) -> tuple[str, Path]:
    selected = (CODEX,) if command is None else command
    assert selected and all(type(item) is str and item for item in selected)
    run_root.mkdir(parents=True)
    codex_home = run_root / "codex-home"
    installed = codex_home / "skills" / "recursive-self-improvement"
    _install_catalog_surface(package_root, installed)
    isolated_home = run_root / "isolated-home"
    isolated_home.mkdir()
    environment = {
        "CODEX_HOME": os.fspath(codex_home),
        "HOME": os.fspath(isolated_home),
        "PATH": os.environ["PATH"],
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
    }
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    completed = catalog_probe._run_client(
        tuple(selected),
        ("debug", "prompt-input", CATALOG_PROMPT),
        run_root=run_root,
        environment=environment,
    )
    payload = json.loads(completed.stdout)
    assert type(payload) is list
    rendered = "\n".join(
        item["text"]
        for message in payload
        for item in message.get("content", [])
        if item.get("type") == "input_text" and type(item.get("text")) is str
    )
    return rendered, codex_home


def test_catalog_client_timeout_reaps_its_entire_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    child_pid_path = tmp_path / "child.pid"
    client = tmp_path / "timeout-client.py"
    client.write_text(
        "\n".join(
            (
                "import pathlib, signal, subprocess, sys, time",
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'], "
                "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
                f"pathlib.Path({os.fspath(child_pid_path)!r}).write_text(str(child.pid))",
                "time.sleep(60)",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(catalog_probe, "_CLIENT_TIMEOUT_SECONDS", 0.2)
    environment = {"PATH": os.environ.get("PATH", os.defpath)}
    try:
        with pytest.raises(catalog_probe.CatalogProbeError, match="unavailable|timed out"):
            catalog_probe._run_client(
                (sys.executable, os.fspath(client)),
                (),
                run_root=tmp_path,
                environment=environment,
            )
        process_id = int(child_pid_path.read_text(encoding="utf-8"))
        assert _wait_pid_absent(process_id), "timed-out catalog child survived"
    finally:
        if child_pid_path.exists():
            _kill_pid_for_test(int(child_pid_path.read_text(encoding="utf-8")))


def test_catalog_client_closed_pipes_still_returns_bounded_timeout_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    client = tmp_path / "closed-pipe-client.py"
    client.write_text(
        "import os, time\nos.close(1)\nos.close(2)\ntime.sleep(60)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(catalog_probe, "_CLIENT_TIMEOUT_SECONDS", 0.2)
    with pytest.raises(catalog_probe.CatalogProbeError, match="timed out"):
        catalog_probe._run_client(
            (sys.executable, os.fspath(client)),
            (),
            run_root=tmp_path,
            environment={"PATH": os.environ.get("PATH", os.defpath)},
        )


def test_catalog_client_output_bound_is_enforced_while_streaming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    marker = tmp_path / "after-flood"
    client = tmp_path / "flood-client.py"
    client.write_text(
        "\n".join(
            (
                "import os, pathlib",
                "os.write(1, b'x' * (1024 * 1024))",
                f"pathlib.Path({os.fspath(marker)!r}).write_bytes(b'reached')",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(catalog_probe, "_MAX_CLIENT_OUTPUT_BYTES", 4096)
    with pytest.raises(catalog_probe.CatalogProbeError, match="output exceeded"):
        catalog_probe._run_client(
            (sys.executable, os.fspath(client)),
            (),
            run_root=tmp_path,
            environment={"PATH": os.environ.get("PATH", os.defpath)},
        )
    assert not marker.exists(), "client completed before its output was rejected"


def test_catalog_client_reaps_descendants_after_leader_exit(
    tmp_path: Path,
) -> None:
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    child_pid_path = tmp_path / "child.pid"
    client = tmp_path / "lingering-client.py"
    client.write_text(
        "\n".join(
            (
                "import pathlib, signal, subprocess, sys",
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'], "
                "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
                f"pathlib.Path({os.fspath(child_pid_path)!r}).write_text(str(child.pid))",
            )
        ),
        encoding="utf-8",
    )
    try:
        with pytest.raises(catalog_probe.CatalogProbeError, match="lingering"):
            catalog_probe._run_client(
                (sys.executable, os.fspath(client)),
                (),
                run_root=tmp_path,
                environment={"PATH": os.environ.get("PATH", os.defpath)},
            )
        process_id = int(child_pid_path.read_text(encoding="utf-8"))
        assert _wait_pid_absent(process_id), "catalog descendant survived leader exit"
    finally:
        if child_pid_path.exists():
            _kill_pid_for_test(int(child_pid_path.read_text(encoding="utf-8")))


def test_disposable_tree_inventory_is_bounded_before_state_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    (tmp_path / "one").write_bytes(b"one")
    (tmp_path / "two").write_bytes(b"two")
    monkeypatch.setattr(
        catalog_probe,
        "_MAX_CLIENT_TREE_ENTRIES",
        2,
        raising=False,
    )

    with pytest.raises(catalog_probe.CatalogProbeError, match="entry bound"):
        catalog_probe._tree_snapshot(tmp_path)


def test_disposable_tree_inventory_stops_before_materializing_large_fanout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    for index in range(20):
        (tmp_path / f"entry-{index:02d}.bin").write_bytes(b"entry")
    real_scandir = os.scandir
    consumed = 0

    class CountingScandir:
        def __init__(self, directory: object) -> None:
            self._iterator = real_scandir(directory)  # type: ignore[arg-type]

        def __enter__(self) -> CountingScandir:
            return self

        def __exit__(self, *_args: object) -> None:
            self._iterator.close()

        def __iter__(self) -> CountingScandir:
            return self

        def __next__(self) -> os.DirEntry[str]:
            nonlocal consumed
            entry = next(self._iterator)
            consumed += 1
            return entry

    descriptors_before = _open_descriptor_names()
    with monkeypatch.context() as patch:
        patch.setattr(catalog_probe, "_MAX_CLIENT_TREE_ENTRIES", 2)
        patch.setattr(catalog_probe.os, "scandir", CountingScandir)
        with pytest.raises(catalog_probe.CatalogProbeError, match="entry bound"):
            catalog_probe._tree_snapshot(tmp_path)
        consumed_before_descriptor_check = consumed

    assert _open_descriptor_names() == descriptors_before
    assert consumed_before_descriptor_check <= 3


@pytest.mark.parametrize(
    ("bound_name", "bound", "fixture_kind", "message"),
    [
        ("_MAX_CLIENT_TREE_DEPTH", 0, "nested", "depth bound"),
        ("_MAX_CLIENT_TREE_PATH_BYTES", 1, "regular", "path bound"),
        ("_MAX_CLIENT_TREE_NAME_BYTES", 1, "regular", "name bound"),
        ("_MAX_CLIENT_TREE_METADATA_BYTES", 8, "regular", "metadata bound"),
        ("_MAX_CLIENT_TREE_SYMLINK_BYTES", 1, "symlink", "symlink byte bound"),
        ("_MAX_CLIENT_TREE_FILE_BYTES", 3, "regular", "file byte bound"),
        (
            "_MAX_CLIENT_TREE_TOTAL_FILE_BYTES",
            7,
            "regular-pair",
            "file byte bound",
        ),
    ],
)
def test_disposable_tree_inventory_enforces_every_structural_and_payload_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bound_name: str,
    bound: int,
    fixture_kind: str,
    message: str,
) -> None:
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    if fixture_kind == "nested":
        (tmp_path / "nested").mkdir()
    elif fixture_kind == "symlink":
        (tmp_path / "alias").symlink_to("long-target")
    else:
        (tmp_path / "payload.bin").write_bytes(b"four")
        if fixture_kind == "regular-pair":
            (tmp_path / "second.bin").write_bytes(b"four")
    real_open = os.open
    real_pread = os.pread
    real_readlink = os.readlink
    descendant_opens = 0
    content_reads = 0
    link_reads = 0

    def count_descendant_open(
        path: object, flags: int, *args: object, **kwargs: object
    ) -> int:
        nonlocal descendant_opens
        if path in {"nested", "payload.bin", "second.bin"} and kwargs.get(
            "dir_fd"
        ) is not None:
            descendant_opens += 1
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    def count_content_read(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal content_reads
        content_reads += 1
        return real_pread(descriptor, size, offset)

    def count_link_read(path: object, *args: object, **kwargs: object):
        nonlocal link_reads
        link_reads += 1
        return real_readlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(catalog_probe, bound_name, bound, raising=False)
    monkeypatch.setattr(catalog_probe.os, "open", count_descendant_open)
    monkeypatch.setattr(catalog_probe.os, "pread", count_content_read)
    monkeypatch.setattr(catalog_probe.os, "readlink", count_link_read)
    descriptors_before = _open_descriptor_names()

    with pytest.raises(catalog_probe.CatalogProbeError, match=message):
        catalog_probe._tree_snapshot(tmp_path)

    assert _open_descriptor_names() == descriptors_before
    assert descendant_opens == 0
    assert content_reads == 0
    assert link_reads == 0


def test_disposable_tree_inventory_is_deterministic_and_never_follows_links(
    tmp_path: Path,
) -> None:
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    external = tmp_path.parent / "external.bin"
    external.write_bytes(b"outside-one")
    (tmp_path / "z-directory").mkdir()
    (tmp_path / "z-directory" / "payload.bin").write_bytes(b"nested")
    (tmp_path / "a-link").symlink_to(external)
    os.mkfifo(tmp_path / "m-fifo")
    descriptors_before = _open_descriptor_names()

    before = catalog_probe._tree_snapshot(tmp_path)
    external.write_bytes(b"outside-two")
    after = catalog_probe._tree_snapshot(tmp_path)

    assert after == before
    assert [row[0] for row in before] == sorted(
        (row[0] for row in before), key=os.fsencode
    )
    assert {str(row[0]): row[1] for row in before}["a-link"] == "symlink"
    assert {str(row[0]): row[1] for row in before}["m-fifo"] == "fifo"
    assert _open_descriptor_names() == descriptors_before


def test_disposable_tree_inventory_rejects_duplicate_directory_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    (tmp_path / "payload.bin").write_bytes(b"payload")
    real_scandir = os.scandir

    class DuplicateScandir:
        def __init__(self, directory: object) -> None:
            self._iterator = real_scandir(directory)  # type: ignore[arg-type]
            self._first: os.DirEntry[str] | None = None
            self._state = 0

        def __enter__(self) -> DuplicateScandir:
            return self

        def __exit__(self, *_args: object) -> None:
            self._iterator.close()

        def __iter__(self) -> DuplicateScandir:
            return self

        def __next__(self) -> os.DirEntry[str]:
            if self._state == 0:
                self._first = next(self._iterator)
                self._state = 1
                return self._first
            if self._state == 1:
                self._state = 2
                assert self._first is not None
                return self._first
            raise StopIteration

    descriptors_before = _open_descriptor_names()
    with monkeypatch.context() as patch:
        patch.setattr(catalog_probe.os, "scandir", DuplicateScandir)
        with pytest.raises(catalog_probe.CatalogProbeError, match="duplicate"):
            catalog_probe._tree_snapshot(tmp_path)

    assert _open_descriptor_names() == descriptors_before


def test_disposable_tree_inventory_rejects_directory_rebind_without_fd_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "payload.bin").write_bytes(b"payload")
    real_open = os.open
    rebound = False
    descriptors_before = _open_descriptor_names()

    def rebind_before_open(
        path: object, flags: int, *args: object, **kwargs: object
    ) -> int:
        nonlocal rebound
        if path == "nested" and kwargs.get("dir_fd") is not None and not rebound:
            rebound = True
            nested.rename(tmp_path / "nested-displaced")
            nested.mkdir()
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    with monkeypatch.context() as patch:
        patch.setattr(catalog_probe.os, "open", rebind_before_open)
        with pytest.raises(catalog_probe.CatalogProbeError, match="identity|changed"):
            catalog_probe._tree_snapshot(tmp_path)

    assert rebound is True
    assert _open_descriptor_names() == descriptors_before


@pytest.mark.parametrize(
    "fault",
    ["scandir", "stat", "open", "fstat", "pread", "readlink"],
)
def test_disposable_tree_inventory_syscall_faults_are_bounded_and_fd_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    (tmp_path / "payload.bin").write_bytes(b"payload")
    (tmp_path / "alias").symlink_to("payload.bin")
    real_scandir = os.scandir
    real_stat = os.stat
    real_open = os.open
    real_fstat = os.fstat
    real_pread = os.pread
    real_readlink = os.readlink
    payload_descriptor: int | None = None
    injected = False

    def fail_scandir(directory: object):
        nonlocal injected
        if not injected:
            injected = True
            raise OSError("injected scandir failure")
        return real_scandir(directory)  # type: ignore[arg-type]

    def fail_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        nonlocal injected
        if path == "payload.bin" and kwargs.get("dir_fd") is not None:
            injected = True
            raise OSError("injected stat failure")
        return real_stat(path, *args, **kwargs)  # type: ignore[arg-type]

    def fail_open(
        path: object, flags: int, *args: object, **kwargs: object
    ) -> int:
        nonlocal injected, payload_descriptor
        if path == "payload.bin" and kwargs.get("dir_fd") is not None:
            if fault == "open":
                injected = True
                raise OSError("injected open failure")
            descriptor = real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]
            payload_descriptor = descriptor
            return descriptor
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    def fail_fstat(descriptor: int) -> os.stat_result:
        nonlocal injected
        if descriptor == payload_descriptor:
            injected = True
            raise OSError("injected fstat failure")
        return real_fstat(descriptor)

    def fail_pread(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal injected
        if descriptor == payload_descriptor:
            injected = True
            raise OSError("injected pread failure")
        return real_pread(descriptor, size, offset)

    def fail_readlink(path: object, *args: object, **kwargs: object):
        nonlocal injected
        if path in {"alias", b"alias"} and kwargs.get("dir_fd") is not None:
            injected = True
            raise OSError("injected readlink failure")
        return real_readlink(path, *args, **kwargs)  # type: ignore[arg-type]

    descriptors_before = _open_descriptor_names()
    with monkeypatch.context() as patch:
        if fault == "scandir":
            patch.setattr(catalog_probe.os, "scandir", fail_scandir)
        elif fault == "stat":
            patch.setattr(catalog_probe.os, "stat", fail_stat)
        elif fault in {"open", "fstat", "pread"}:
            patch.setattr(catalog_probe.os, "open", fail_open)
            if fault == "fstat":
                patch.setattr(catalog_probe.os, "fstat", fail_fstat)
            elif fault == "pread":
                patch.setattr(catalog_probe.os, "pread", fail_pread)
        else:
            patch.setattr(catalog_probe.os, "readlink", fail_readlink)
        with pytest.raises(catalog_probe.CatalogProbeError, match="cannot|changed"):
            catalog_probe._tree_snapshot(tmp_path)

    assert injected is True
    assert _open_descriptor_names() == descriptors_before


@pytest.mark.parametrize(
    ("client_name", "command"),
    [
        pytest.param(
            "local",
            (CODEX,),
            marks=pytest.mark.skipif(CODEX is None, reason="Codex CLI is unavailable"),
        ),
        pytest.param(
            "latest",
            (NPX, "--yes", "@openai/codex@latest"),
            marks=pytest.mark.skipif(
                NPX is None or not RUN_LATEST_CODEX,
                reason="set RSI_TEST_LATEST_CODEX=1 for the mandatory network gate",
            ),
        ),
    ],
)
def test_catalog_probe_confines_real_client_system_sync(
    tmp_path: Path,
    client_name: str,
    command: tuple[str, ...],
) -> None:
    assert all(item is not None for item in command)
    exact_command = tuple(str(item) for item in command)
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")
    resolved_latest: str | None = None
    if client_name == "latest":
        resolution_root = tmp_path / "latest-resolution"
        resolution_root.mkdir()
        exact_command, resolved_latest = catalog_probe._latest_command(
            exact_command[0], resolution_root
        )

    unsafe_home = tmp_path / "unsafe-codex-home"
    unsafe_installed = unsafe_home / "skills" / "recursive-self-improvement"
    _install_catalog_surface(PACKAGE_ROOT, unsafe_installed)
    unsafe_before = _tree_snapshot(unsafe_home)

    _render_fresh_catalog(
        PACKAGE_ROOT,
        tmp_path / "unsafe-run",
        command=exact_command,
    )
    direct_run_home = tmp_path / "unsafe-run" / "codex-home"
    direct_after_client = _tree_snapshot(direct_run_home)
    assert direct_after_client != unsafe_before
    assert (direct_run_home / "skills" / ".system").is_dir()

    probe_module = PACKAGE_ROOT / "scripts" / "rsi_core" / "catalog_probe.py"
    assert probe_module.is_file(), (
        f"real {client_name} catalog rendering synchronized .system inside its "
        "active CODEX_HOME, but the isolated catalog probe is missing"
    )
    snapshot, protected_home, protected_installed = _attested_catalog_surface(
        tmp_path / "attested"
    )
    protected_before = _tree_snapshot(protected_home)

    try:
        result = catalog_probe.probe_catalog_client(
            snapshot.catalog_surface(),
            tmp_path / "isolated-probe",
            command=exact_command,
            client_name=client_name,
        )
    finally:
        snapshot.close()

    assert _tree_snapshot(protected_home) == protected_before
    assert result.client_name == client_name
    assert result.catalog_entry_count == 1
    assert result.verified_locator == protected_installed / "SKILL.md"
    assert result.model_locator != result.verified_locator
    assert result.isolated_home_change_count > 0
    assert result.skill_body_absent is True
    if resolved_latest is not None:
        assert catalog_probe._VERSION.findall(result.version) == [resolved_latest]


@pytest.mark.skipif(CODEX is None, reason="Codex CLI is unavailable")
def test_fresh_codex_catalog_lists_rsi_without_invoking_it(tmp_path: Path) -> None:
    rendered, codex_home = _render_fresh_catalog(PACKAGE_ROOT, tmp_path / "visible")

    assert "### Available skills" in rendered
    assert rendered.count("- recursive-self-improvement:") == 1
    assert f"- recursive-self-improvement: {EXPECTED_SKILL_DESCRIPTION}" in rendered
    assert os.fspath(
        codex_home / "skills/recursive-self-improvement/SKILL.md"
    ) in rendered
    assert SKILL_BODY_SENTINEL not in rendered


@pytest.mark.skipif(CODEX is None, reason="Codex CLI is unavailable")
def test_disabled_policy_is_not_model_visible(tmp_path: Path) -> None:
    disabled = tmp_path / "disabled-package"
    _install_catalog_surface(PACKAGE_ROOT, disabled)
    metadata_path = disabled / "agents/openai.yaml"
    metadata = metadata_path.read_text(encoding="utf-8")
    assert metadata.count("allow_implicit_invocation: true") == 1
    metadata_path.write_text(
        metadata.replace(
            "allow_implicit_invocation: true",
            "allow_implicit_invocation: false",
        ),
        encoding="utf-8",
    )

    rendered, codex_home = _render_fresh_catalog(disabled, tmp_path / "disabled")

    assert "- recursive-self-improvement:" not in rendered
    assert os.fspath(
        codex_home / "skills/recursive-self-improvement/SKILL.md"
    ) not in rendered


@pytest.mark.skipif(CODEX is None, reason="Codex CLI is unavailable")
def test_catalog_probe_preserves_source_and_creates_no_rsi_state(tmp_path: Path) -> None:
    protected = tmp_path / "protected" / "witness.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"protected-before\n")
    package_before = _tree_snapshot(PACKAGE_ROOT)

    _render_fresh_catalog(PACKAGE_ROOT, tmp_path / "zero-write")

    assert _tree_snapshot(PACKAGE_ROOT) == package_before
    assert protected.read_bytes() == b"protected-before\n"
    assert not list(tmp_path.rglob("events.jsonl"))
    assert not list(tmp_path.rglob("observations.jsonl"))
    assert not list(tmp_path.rglob("reports.jsonl"))
    assert not list(tmp_path.rglob("rsi-deployments-v1"))
