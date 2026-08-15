from __future__ import annotations

import builtins
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import fcntl
import hashlib
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import threading
import time
import pytest

import rsi_core.deployment as deployment_module
from rsi_core.deployment import (
    DeploymentError,
    DeploymentOperationConflict,
    DeploymentPaths,
    DeploymentUnsupported,
    GlobalRsiDeployer,
)
from rsi_core.deployment_schema import (
    DeploymentManifest,
    DeploymentReceipt,
    MANIFEST_RELATIVE_PATH,
    canonical_json_bytes,
)
from rsi_core.deployment_fs import DeploymentIntegrityError, scan_package
from rsi_core.global_instructions import MANAGED_BLOCK


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", os.fspath(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"},
    )
    return completed.stdout.strip()


def _write_repository(root: Path, *, version: str = "v1") -> Path:
    repo = root / f"repo-{version}"
    package = repo / "recursive-self-improvement"
    (package / "profiles").mkdir(parents=True)
    (package / "agents").mkdir()
    (package / "scripts").mkdir()
    (package / "payload.txt").write_text(version + "\n", encoding="utf-8")
    (package / "SKILL.md").write_text(
        "---\n"
        "name: recursive-self-improvement\n"
        "description: Safely review verified reusable findings.\n"
        "---\n\n"
        "# Recursive Self-Improvement\n",
        encoding="utf-8",
    )
    (package / "profiles" / "default.json").write_text(
        '{"schemaVersion":1,"mode":"observe","orchestration":{"hookMode":"late-review"}}\n',
        encoding="utf-8",
    )
    (package / "profiles" / "production.json").write_text(
        '{"schemaVersion":1,"activation":{"allowedTargets":[]}}\n',
        encoding="utf-8",
    )
    (package / "agents" / "openai.yaml").write_text(
        "interface:\n  display_name: Recursive Self-Improvement\n",
        encoding="utf-8",
    )
    (package / "scripts" / "rsi.py").write_text(
        "#!/usr/bin/env python3\nprint('observe')\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q", os.fspath(repo)], check=True)
    _git(repo, "config", "user.email", "rsi-tests@example.invalid")
    _git(repo, "config", "user.name", "RSI Tests")
    _git(repo, "add", "recursive-self-improvement")
    _git(repo, "commit", "-q", "-m", version)
    return repo


def _snapshot_tree(root: Path) -> tuple[object, ...]:
    if not root.exists():
        return ("absent",)
    result: list[object] = []
    for path in sorted([root, *root.rglob("*")], key=lambda item: os.fsencode(item)):
        metadata = os.lstat(path)
        relative = "." if path == root else path.relative_to(root).as_posix()
        kind = "directory" if stat.S_ISDIR(metadata.st_mode) else "file"
        payload = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
        result.append(
            (
                relative,
                kind,
                metadata.st_dev,
                metadata.st_ino,
                stat.S_IMODE(metadata.st_mode),
                metadata.st_nlink,
                metadata.st_uid,
                payload,
            )
        )
    return tuple(result)


def _trap_writes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def forbidden(name: str):
        def call(*_args: object, **_kwargs: object) -> None:
            calls.append(name)
            raise AssertionError(f"read-only deployment operation called {name}")

        return call

    for name in ("mkdir", "chmod", "rename", "replace", "link", "unlink"):
        monkeypatch.setattr(os, name, forbidden(name))

    real_open = builtins.open

    def checked_open(file: object, mode: str = "r", *args: object, **kwargs: object):
        if any(flag in mode for flag in "wax+"):
            calls.append("writable-open")
            raise AssertionError("read-only deployment operation opened a writable file")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", checked_open)

    real_os_open = os.open

    def checked_os_open(path: object, flags: int, *args: object, **kwargs: object):
        writable = flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        if writable:
            calls.append("writable-os-open")
            raise AssertionError("read-only deployment operation called writable os.open")
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", checked_os_open)
    for name in ("fchmod", "write", "fsync"):
        monkeypatch.setattr(os, name, forbidden(name))
    return calls


def _package_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"), key=lambda item: os.fsencode(item))
        if path.is_file() and path.name != MANIFEST_RELATIVE_PATH
    }


def _installed_modes(root: Path) -> dict[str, int]:
    return {
        path.relative_to(root).as_posix(): stat.S_IMODE(os.lstat(path).st_mode)
        for path in sorted(root.rglob("*"), key=lambda item: os.fsencode(item))
        if path.is_file()
    }


def test_plan_is_zero_write_and_admits_a_clean_observe_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _write_repository(tmp_path)
    codex_home = tmp_path / "codex"
    codex_home.mkdir(mode=0o700)
    agents = codex_home / "AGENTS.md"
    agents.write_bytes("prefix\nпользовательский текст\n".encode("utf-8"))
    before = _snapshot_tree(codex_home)
    deployer = GlobalRsiDeployer(DeploymentPaths.for_testing(codex_home))
    calls = _trap_writes(monkeypatch)

    planned = deployer.plan(repo)

    assert planned.eligible is True
    assert planned.action == "install"
    assert planned.mode == "observe"
    assert planned.hook_mode == "late-review"
    assert planned.production_allowlist_entry_count == 0
    assert calls == []
    assert _snapshot_tree(codex_home) == before


@pytest.mark.parametrize("method_name", ["verify", "status"])
def test_verify_and_status_report_typed_not_installed_without_creating_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method_name: str
) -> None:
    codex_home = tmp_path / "missing-codex-home"
    deployer = GlobalRsiDeployer(DeploymentPaths.for_testing(codex_home))
    calls = _trap_writes(monkeypatch)

    status = getattr(deployer, method_name)()

    assert status.state == "not-installed"
    assert status.installed is False
    assert status.verified is False
    assert calls == []
    assert not codex_home.exists()


def test_initial_deploy_is_exact_private_and_marker_last(tmp_path: Path) -> None:
    repo = _write_repository(tmp_path)
    source_package = repo / "recursive-self-improvement"
    codex_home = tmp_path / "codex"
    codex_home.mkdir(mode=0o700)
    agents = codex_home / "AGENTS.md"
    unmanaged = "prefix\nмногобайтный пользовательский текст\n".encode("utf-8")
    agents.write_bytes(unmanaged)
    agents.chmod(0o640)
    deployer = GlobalRsiDeployer(DeploymentPaths.for_testing(codex_home))

    receipt = deployer.deploy(repo, "deploy-v1")

    status = deployer.verify()
    assert type(receipt) is DeploymentReceipt
    assert receipt.operation_id == "deploy-v1"
    assert status.state == "verified"
    assert status.manifest_digest == receipt.manifest_digest
    assert _package_bytes(deployer.paths.installed_root) == _package_bytes(source_package)
    modes = _installed_modes(deployer.paths.installed_root)
    assert modes[MANIFEST_RELATIVE_PATH] == 0o600
    assert set(modes.values()) <= {0o600, 0o700}
    assert agents.read_bytes() == unmanaged + MANAGED_BLOCK
    assert stat.S_IMODE(os.lstat(agents).st_mode) == 0o640

    installed_manifest = (deployer.paths.installed_root / MANIFEST_RELATIVE_PATH).read_bytes()
    receipt_manifest = (
        deployer.paths.receipts_root / "deploy-v1.manifest.json"
    ).read_bytes()
    marker = (deployer.paths.receipts_root / "deploy-v1.json").read_bytes()
    assert receipt_manifest == installed_manifest
    assert DeploymentManifest.from_bytes(installed_manifest).operation_id == "deploy-v1"
    assert DeploymentReceipt.from_bytes(marker) == receipt


def test_exact_replay_returns_same_receipt_without_any_inode_or_byte_change(
    tmp_path: Path,
) -> None:
    repo = _write_repository(tmp_path)
    codex_home = tmp_path / "codex"
    deployer = GlobalRsiDeployer(DeploymentPaths.for_testing(codex_home))
    first = deployer.deploy(repo, "same-op")
    before = _snapshot_tree(codex_home)

    replay = deployer.deploy(repo, "same-op")

    assert replay == first
    assert _snapshot_tree(codex_home) == before


def test_reused_operation_id_with_different_source_conflicts_without_mutation(
    tmp_path: Path,
) -> None:
    first_repo = _write_repository(tmp_path, version="v1")
    second_repo = _write_repository(tmp_path, version="v2")
    codex_home = tmp_path / "codex"
    deployer = GlobalRsiDeployer(DeploymentPaths.for_testing(codex_home))
    deployer.deploy(first_repo, "same-op")
    before = _snapshot_tree(codex_home)

    with pytest.raises(DeploymentOperationConflict):
        deployer.deploy(second_repo, "same-op")

    assert _snapshot_tree(codex_home) == before


def test_plan_verify_and_status_are_zero_write_on_a_verified_installation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _write_repository(tmp_path)
    codex_home = tmp_path / "codex"
    deployer = GlobalRsiDeployer(DeploymentPaths.for_testing(codex_home))
    deployer.deploy(repo, "read-only-v1")
    before = _snapshot_tree(codex_home)
    calls = _trap_writes(monkeypatch)

    assert deployer.plan(repo).action == "no-op"
    assert deployer.verify().verified is True
    assert deployer.status().verified is True

    assert calls == []
    assert _snapshot_tree(codex_home) == before


def test_byte_identical_new_operation_is_a_complete_noop(tmp_path: Path) -> None:
    repo = _write_repository(tmp_path)
    deployer = GlobalRsiDeployer(
        DeploymentPaths.for_testing(tmp_path / "codex")
    )
    active = deployer.deploy(repo, "first-op")
    before = _snapshot_tree(deployer.paths.codex_home)

    result = deployer.deploy(repo, "second-op")

    assert result == active
    assert result.operation_id == "first-op"
    assert _snapshot_tree(deployer.paths.codex_home) == before


def test_v1_to_v2_update_and_v2_to_v1_rollback_restore_exact_agents_bytes_and_mode(
    tmp_path: Path,
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    deployer = GlobalRsiDeployer(
        DeploymentPaths.for_testing(tmp_path / "codex")
    )
    deployer.deploy(repo_v1, "deploy-v1")
    exact_prior_agents = (
        "до блока\n".encode("utf-8")
        + MANAGED_BLOCK
        + "после блока без LF".encode("utf-8")
    )
    deployer.paths.agents_file.write_bytes(exact_prior_agents)
    deployer.paths.agents_file.chmod(0o640)
    assert deployer.verify().verified is True

    updated = deployer.deploy(repo_v2, "deploy-v2")

    assert updated.operation_id == "deploy-v2"
    assert deployer.verify().operation_id == "deploy-v2"
    assert _package_bytes(deployer.paths.installed_root) == _package_bytes(
        repo_v2 / "recursive-self-improvement"
    )

    changed_current_agents = b"current-user-change\n" + MANAGED_BLOCK
    deployer.paths.agents_file.write_bytes(changed_current_agents)
    deployer.paths.agents_file.chmod(0o600)
    assert deployer.verify().verified is True

    rolled_back = deployer.rollback("deploy-v2", "rollback-to-v1")

    assert rolled_back.operation_id == "rollback-to-v1"
    assert deployer.verify().operation_id == "rollback-to-v1"
    assert _package_bytes(deployer.paths.installed_root) == _package_bytes(
        repo_v1 / "recursive-self-improvement"
    )
    assert deployer.paths.agents_file.read_bytes() == exact_prior_agents
    assert stat.S_IMODE(os.lstat(deployer.paths.agents_file).st_mode) == 0o640


def test_rollback_semantically_revalidates_backup_before_exchange(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo_v1, "semantic-backup-v1")
    deployer.deploy(repo_v2, "semantic-backup-v2")
    before = _snapshot_tree(paths.codex_home)
    real_validate = deployment_module._validate_package_documents
    backup_validation_seen = False

    def validate(package: Path, snapshot: object) -> str:
        nonlocal backup_validation_seen
        if paths.backups_root in package.parents:
            backup_validation_seen = True
            raise deployment_module.DeploymentSourceError(
                "test backup semantic admission failed"
            )
        return real_validate(package, snapshot)  # type: ignore[arg-type]

    monkeypatch.setattr(deployment_module, "_validate_package_documents", validate)

    with pytest.raises(deployment_module.DeploymentSourceError, match="semantic"):
        deployer.rollback("semantic-backup-v2", "semantic-backup-rollback")

    assert backup_validation_seen is True
    assert _snapshot_tree(paths.codex_home) == before


def test_rollback_accepts_the_immediately_preceding_verified_receipt(
    tmp_path: Path,
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo_v1, "target-v1")
    deployer.deploy(repo_v2, "active-v2")

    result = deployer.rollback("target-v1", "rollback-by-target")

    assert result.operation_id == "rollback-by-target"
    assert deployer.verify().operation_id == "rollback-by-target"
    assert _package_bytes(paths.installed_root) == _package_bytes(
        repo_v1 / "recursive-self-improvement"
    )


def test_backup_identity_binds_unmanaged_agents_bytes_not_only_package_tree(
    tmp_path: Path,
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    deployer = GlobalRsiDeployer(
        DeploymentPaths.for_testing(tmp_path / "codex")
    )
    deployer.deploy(repo_v1, "base-v1")
    deployer.paths.agents_file.write_bytes(b"unmanaged-a\n" + MANAGED_BLOCK)
    deployer.deploy(repo_v2, "first-v2")
    first_backups = {
        path.name for path in deployer.paths.backups_root.iterdir() if path.is_dir()
    }
    deployer.rollback("first-v2", "return-v1")
    deployer.paths.agents_file.write_bytes(b"unmanaged-b\n" + MANAGED_BLOCK)

    deployer.deploy(repo_v2, "second-v2")

    second_backups = {
        path.name for path in deployer.paths.backups_root.iterdir() if path.is_dir()
    }
    assert len(first_backups) >= 1
    assert len(second_backups - first_backups) >= 1


def test_rollback_rejects_unlisted_backup_member_without_changing_active_version(
    tmp_path: Path,
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo_v1, "backup-exact-v1")
    deployer.deploy(repo_v2, "backup-exact-v2")
    request = deployment_module._canonical_mapping(
        (paths.receipts_root / "backup-exact-v2.request.json").read_bytes(),
        label="backup exact request",
    )
    backup = paths.backups_root / str(request["priorStateBackupDigest"])
    (backup / "unlisted.bin").write_bytes(b"not-bound")
    before = _snapshot_tree(paths.codex_home)

    with pytest.raises(DeploymentIntegrityError):
        deployer.rollback("backup-exact-v2", "reject-extra-backup")

    assert _snapshot_tree(paths.codex_home) == before
    status = deployer.verify()
    assert status.verified is False
    assert status.state == "invalid"


def test_invalid_utf8_agents_file_blocks_initial_deploy_without_any_mutation(
    tmp_path: Path,
) -> None:
    repo = _write_repository(tmp_path)
    codex_home = tmp_path / "codex"
    codex_home.mkdir(mode=0o700)
    (codex_home / "AGENTS.md").write_bytes(b"invalid-utf8:\xff")
    before = _snapshot_tree(codex_home)
    deployer = GlobalRsiDeployer(DeploymentPaths.for_testing(codex_home))

    with pytest.raises(DeploymentError):
        deployer.deploy(repo, "reject-invalid-agents")

    assert _snapshot_tree(codex_home) == before


def test_unsupported_atomic_exchange_leaves_verified_v1_byte_exact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    deployer = GlobalRsiDeployer(
        DeploymentPaths.for_testing(tmp_path / "codex")
    )
    deployer.deploy(repo_v1, "supported-v1")
    before = _snapshot_tree(deployer.paths.codex_home)

    def unsupported(*_args: object, **_kwargs: object) -> None:
        raise DeploymentUnsupported("test host has no atomic exchange")

    monkeypatch.setattr(deployment_module, "_renameatx", unsupported)

    with pytest.raises(DeploymentUnsupported):
        deployer.deploy(repo_v2, "unsupported-v2")

    assert _snapshot_tree(deployer.paths.codex_home) == before
    assert deployer.verify().operation_id == "supported-v1"


def test_non_darwin_backend_is_rejected_before_any_deployment_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _write_repository(tmp_path)
    codex_home = tmp_path / "codex"
    deployer = GlobalRsiDeployer(DeploymentPaths.for_testing(codex_home))
    before = _snapshot_tree(codex_home)
    monkeypatch.setattr(deployment_module.sys, "platform", "linux")
    calls = _trap_writes(monkeypatch)

    with pytest.raises(DeploymentUnsupported):
        deployer.deploy(repo, "unsupported-host")

    assert calls == []
    assert _snapshot_tree(codex_home) == before


def test_non_darwin_update_is_rejected_before_any_deployment_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo_v1, "unsupported-update-base")
    before = _snapshot_tree(paths.codex_home)
    monkeypatch.setattr(deployment_module.sys, "platform", "linux")
    calls = _trap_writes(monkeypatch)

    with pytest.raises(DeploymentUnsupported):
        deployer.deploy(repo_v2, "unsupported-update")

    assert calls == []
    assert _snapshot_tree(paths.codex_home) == before


@pytest.mark.parametrize("kind", ["manifest", "marker"])
def test_failed_immutable_noreplace_cleans_exact_unpublished_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    parent = tmp_path / "receipts"
    parent.mkdir(mode=0o700)

    def unsupported(*_args: object, **_kwargs: object) -> None:
        raise DeploymentUnsupported("test publication is unsupported")

    monkeypatch.setattr(deployment_module, "_rename_noreplace", unsupported)

    with pytest.raises(DeploymentUnsupported):
        deployment_module._publish_immutable_file(
            parent / f"receipt-{kind}.json",
            b"immutable\n",
            operation_id="cleanup-temp",
            kind=kind,
        )

    assert list(parent.iterdir()) == []


class InjectedFault(OSError):
    pass


INITIAL_DURABLE_CUTS = (
    "package.staging.create",
    "package.file.write",
    "package.file.fsync",
    "package.manifest.write",
    "package.manifest.fsync",
    "package.directory.fsync",
    "package.staging.readback",
    "package.rename",
    "package.parent.fsync",
    "instruction.temp.write",
    "instruction.temp.fsync",
    "instruction.replace",
    "instruction.parent.fsync",
    "instruction.readback",
    "receipt.manifest.write",
    "receipt.manifest.fsync",
    "receipt.manifest.parent_fsync",
    "receipt.manifest.readback",
    "receipt.marker.write",
    "receipt.marker.fsync",
)


@pytest.mark.parametrize("cut", INITIAL_DURABLE_CUTS)
def test_every_initial_durable_fault_cut_restores_exact_predeployment_authority(
    tmp_path: Path, cut: str
) -> None:
    repo = _write_repository(tmp_path)
    codex_home = tmp_path / "codex"
    codex_home.mkdir(mode=0o700)
    agents = codex_home / "AGENTS.md"
    prior_agents = "точные исходные инструкции без LF".encode("utf-8")
    agents.write_bytes(prior_agents)
    agents.chmod(0o640)
    observed: list[str] = []

    def inject(boundary: str) -> None:
        observed.append(boundary)
        if boundary == cut:
            raise InjectedFault(cut)

    deployer = GlobalRsiDeployer(
        DeploymentPaths.for_testing(codex_home), fault_injector=inject
    )

    with pytest.raises((InjectedFault, DeploymentError)):
        deployer.deploy(repo, "faulted-initial")

    assert cut in observed
    assert deployer.verify().state == "not-installed"
    assert not deployer.paths.installed_root.exists()
    assert agents.read_bytes() == prior_agents
    assert stat.S_IMODE(os.lstat(agents).st_mode) == 0o640
    if deployer.paths.receipts_root.exists():
        assert not list(deployer.paths.receipts_root.glob("faulted-initial*"))
    assert not list(deployer.paths.skills_root.glob(".rsi-package-stage*"))
    assert not list(codex_home.glob(".rsi-agents*"))


def test_complete_write_retries_eintr_and_short_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "complete-write.bin"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    real_write = os.write
    attempts = 0

    def interrupted_then_short(fd: int, payload: object) -> int:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise InterruptedError
        data = bytes(payload)  # type: ignore[arg-type]
        return real_write(fd, data[: max(1, len(data) // 2)])

    monkeypatch.setattr(deployment_module.os, "write", interrupted_then_short)
    try:
        deployment_module._write_all(descriptor, b"0123456789abcdef")
    finally:
        os.close(descriptor)

    assert destination.read_bytes() == b"0123456789abcdef"
    assert attempts >= 3


def test_drift_before_package_exchange_is_detected_without_overwriting_racer(
    tmp_path: Path,
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    GlobalRsiDeployer(paths).deploy(repo_v1, "drift-base")
    displaced = paths.skills_root / "displaced-by-test"

    def drift(boundary: str) -> None:
        if boundary != "package.exchange":
            return
        os.rename(paths.installed_root, displaced)
        paths.installed_root.mkdir(mode=0o700)
        (paths.installed_root / "racer.txt").write_bytes(b"external-racer")

    deployer = GlobalRsiDeployer(paths, fault_injector=drift)

    with pytest.raises((DeploymentError, DeploymentIntegrityError), match="drift"):
        deployer.deploy(repo_v2, "drifted-update")

    assert (paths.installed_root / "racer.txt").read_bytes() == b"external-racer"
    assert _package_bytes(displaced) == _package_bytes(
        repo_v1 / "recursive-self-improvement"
    )
    assert not (paths.receipts_root / "drifted-update.json").exists()


def test_drift_during_backup_preflight_cleans_exact_backup_staging(
    tmp_path: Path,
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    GlobalRsiDeployer(paths).deploy(repo_v1, "backup-drift-base")

    def drift(boundary: str) -> None:
        if boundary == "backup.staging.create":
            (paths.installed_root / "payload.txt").write_bytes(b"external-racer\n")

    deployer = GlobalRsiDeployer(paths, fault_injector=drift)

    with pytest.raises(DeploymentIntegrityError, match="drift"):
        deployer.deploy(repo_v2, "backup-drift-update")

    assert (paths.installed_root / "payload.txt").read_bytes() == b"external-racer\n"
    assert not list(paths.backups_root.glob(".rsi-backup-stage*"))
    assert not list(paths.skills_root.glob(".rsi-package-stage*"))


def test_drift_before_instruction_replace_reverses_package_without_overwriting_racer(
    tmp_path: Path,
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo_v1, "instruction-base")
    prior = b"prior-unmanaged\n" + MANAGED_BLOCK
    paths.agents_file.write_bytes(prior)
    deployer.deploy(repo_v2, "instruction-v2")
    target_backup_bytes = prior
    current = b"current-before-rollback\n" + MANAGED_BLOCK
    paths.agents_file.write_bytes(current)
    racer = b"external-racer\n" + MANAGED_BLOCK

    def drift(boundary: str) -> None:
        if boundary == "instruction.replace":
            replacement = paths.codex_home / "racer-agents"
            replacement.write_bytes(racer)
            os.replace(replacement, paths.agents_file)

    faulted = GlobalRsiDeployer(paths, fault_injector=drift)

    with pytest.raises((DeploymentError, DeploymentIntegrityError), match="drift"):
        faulted.rollback("instruction-v2", "drifted-rollback")

    assert paths.agents_file.read_bytes() == racer
    assert _package_bytes(paths.installed_root) == _package_bytes(
        repo_v2 / "recursive-self-improvement"
    )
    assert target_backup_bytes != racer
    assert not (paths.receipts_root / "drifted-rollback.json").exists()


@pytest.mark.parametrize(
    ("boundary", "occurrence"),
    [
        *(("package.file.write", number) for number in range(1, 7)),
        *(("package.file.fsync", number) for number in range(1, 7)),
        *(("package.directory.fsync", number) for number in range(1, 5)),
    ],
)
def test_each_repeated_package_write_fsync_and_directory_fsync_cut_is_cleaned(
    tmp_path: Path, boundary: str, occurrence: int
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    count = 0

    def inject(observed: str) -> None:
        nonlocal count
        if observed == boundary:
            count += 1
            if count == occurrence:
                raise InjectedFault(f"{boundary}:{occurrence}")

    deployer = GlobalRsiDeployer(paths, fault_injector=inject)

    with pytest.raises((InjectedFault, DeploymentError)):
        deployer.deploy(repo, "repeated-cut")

    assert count == occurrence
    assert deployer.verify().state == "not-installed"
    assert not list(paths.skills_root.glob(".rsi-package-stage*"))


@pytest.mark.parametrize(
    "cut",
    [
        "package.exchange",
        "package.parent.fsync",
        "receipt.manifest.write",
        "receipt.manifest.fsync",
        "receipt.marker.write",
        "receipt.marker.fsync",
    ],
)
def test_update_fault_cuts_reverse_exchange_to_exact_verified_v1(
    tmp_path: Path, cut: str
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    GlobalRsiDeployer(paths).deploy(repo_v1, "update-cut-v1")
    before = _snapshot_tree(paths.codex_home)

    def inject(boundary: str) -> None:
        if boundary == cut:
            raise InjectedFault(cut)

    faulted = GlobalRsiDeployer(paths, fault_injector=inject)

    with pytest.raises((InjectedFault, DeploymentError)):
        faulted.deploy(repo_v2, "update-cut-v2")

    assert _snapshot_tree(paths.codex_home) == before
    assert faulted.verify().operation_id == "update-cut-v1"


@pytest.mark.parametrize(
    "cut",
    [
        "instruction.temp.write",
        "instruction.temp.fsync",
        "instruction.replace",
        "instruction.parent.fsync",
        "instruction.readback",
    ],
)
def test_rollback_instruction_fault_reverses_package_and_restores_current_agents(
    tmp_path: Path, cut: str
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo_v1, "rollback-cut-v1")
    paths.agents_file.write_bytes(b"prior-v1\n" + MANAGED_BLOCK)
    deployer.deploy(repo_v2, "rollback-cut-v2")
    paths.agents_file.write_bytes(b"current-v2\n" + MANAGED_BLOCK)
    paths.agents_file.chmod(0o640)
    before = _snapshot_tree(paths.codex_home)

    def inject(boundary: str) -> None:
        if boundary == cut:
            raise InjectedFault(cut)

    faulted = GlobalRsiDeployer(paths, fault_injector=inject)

    with pytest.raises((InjectedFault, DeploymentError)):
        faulted.rollback("rollback-cut-v2", "faulted-rollback")

    assert _snapshot_tree(paths.codex_home) == before
    assert faulted.verify().operation_id == "rollback-cut-v2"


def test_initial_failure_after_agents_publication_restores_absent_agents_file(
    tmp_path: Path,
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")

    def inject(boundary: str) -> None:
        if boundary == "receipt.manifest.write":
            raise InjectedFault(boundary)

    deployer = GlobalRsiDeployer(paths, fault_injector=inject)

    with pytest.raises((InjectedFault, DeploymentError)):
        deployer.deploy(repo, "absent-agents-cut")

    assert deployer.verify().state == "not-installed"
    assert not paths.agents_file.exists()
    assert not list(paths.codex_home.glob(".rsi-agents*"))


@pytest.mark.parametrize(
    "pause_boundary", ["package.staging.readback", "package.parent.fsync"]
)
def test_verify_serializes_behind_staging_and_post_exchange_publication(
    tmp_path: Path, pause_boundary: str
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    GlobalRsiDeployer(paths).deploy(repo_v1, "verify-race-v1")
    entered = threading.Event()
    release = threading.Event()

    def pause(boundary: str) -> None:
        if boundary == pause_boundary:
            entered.set()
            assert release.wait(timeout=5)

    updating = GlobalRsiDeployer(paths, fault_injector=pause)
    reading = GlobalRsiDeployer(paths)
    with ThreadPoolExecutor(max_workers=2) as executor:
        update_future = executor.submit(updating.deploy, repo_v2, "verify-race-v2")
        assert entered.wait(timeout=5)
        verify_future = executor.submit(reading.verify)
        time.sleep(0.1)
        assert not verify_future.done()
        release.set()
        assert update_future.result(timeout=5).operation_id == "verify-race-v2"
        observed = verify_future.result(timeout=5)

    assert observed.verified is True
    assert observed.operation_id == "verify-race-v2"


def test_concurrent_identical_deploys_have_one_serialized_winner_and_exact_replay(
    tmp_path: Path,
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(GlobalRsiDeployer(paths).deploy, repo, "concurrent-same")
            for _ in range(2)
        ]
        receipts = [future.result(timeout=10) for future in futures]

    assert receipts[0] == receipts[1]
    assert receipts[0].operation_id == "concurrent-same"
    assert GlobalRsiDeployer(paths).verify().operation_id == "concurrent-same"
    assert len(list(paths.receipts_root.glob("concurrent-same.json"))) == 1


def test_concurrent_conflicting_deploys_publish_exactly_one_authority(
    tmp_path: Path,
) -> None:
    repos = [
        _write_repository(tmp_path, version="v1"),
        _write_repository(tmp_path, version="v2"),
    ]
    paths = DeploymentPaths.for_testing(tmp_path / "codex")

    def attempt(repo: Path) -> str:
        try:
            GlobalRsiDeployer(paths).deploy(repo, "concurrent-conflict")
        except DeploymentOperationConflict:
            return "conflict"
        return "winner"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(attempt, repos))

    assert sorted(outcomes) == ["conflict", "winner"]
    assert GlobalRsiDeployer(paths).verify().verified is True
    assert len(list(paths.receipts_root.glob("concurrent-conflict.json"))) == 1


def test_lock_wait_is_bounded_and_does_not_change_active_authority(
    tmp_path: Path,
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    GlobalRsiDeployer(paths).deploy(repo, "lock-base")
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import fcntl,os,sys,time; "
                "fd=os.open(sys.argv[1],os.O_RDWR); "
                "fcntl.flock(fd,fcntl.LOCK_EX); print('ready',flush=True); time.sleep(10)"
            ),
            os.fspath(paths.lock_file),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "ready"
        before = _snapshot_tree(paths.codex_home)
        started = time.monotonic()

        with pytest.raises(deployment_module.DeploymentLockTimeout):
            GlobalRsiDeployer(paths, lock_timeout=0.15).deploy(repo, "blocked-op")

        assert time.monotonic() - started < 1.5
        assert _snapshot_tree(paths.codex_home) == before
    finally:
        holder.kill()
        holder.wait(timeout=5)


def test_killed_lock_holder_releases_automatically_for_next_deploy(
    tmp_path: Path,
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    active = GlobalRsiDeployer(paths).deploy(repo, "killed-lock-base")
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import fcntl,os,sys,time; "
                "fd=os.open(sys.argv[1],os.O_RDWR); "
                "fcntl.flock(fd,fcntl.LOCK_EX); print('ready',flush=True); time.sleep(30)"
            ),
            os.fspath(paths.lock_file),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert holder.stdout is not None
    assert holder.stdout.readline().strip() == "ready"
    holder.kill()
    holder.wait(timeout=5)

    started = time.monotonic()
    replay = GlobalRsiDeployer(paths).deploy(repo, "killed-lock-base")

    assert replay == active
    assert time.monotonic() - started < 2


def test_rollback_and_deploy_are_serialized_without_partial_authority(
    tmp_path: Path,
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    repo_v3 = _write_repository(tmp_path, version="v3")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo_v1, "serialized-v1")
    deployer.deploy(repo_v2, "serialized-v2")

    def rollback() -> str:
        try:
            GlobalRsiDeployer(paths).rollback("serialized-v2", "serialized-rollback")
        except DeploymentOperationConflict:
            return "conflict"
        return "rollback"

    def deploy() -> str:
        GlobalRsiDeployer(paths).deploy(repo_v3, "serialized-v3")
        return "deploy"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = [
            executor.submit(rollback),
            executor.submit(deploy),
        ]
        results = [future.result(timeout=15) for future in outcomes]

    assert "deploy" in results
    status = GlobalRsiDeployer(paths).verify()
    assert status.verified is True
    assert status.operation_id in {"serialized-v3", "serialized-rollback"}
    expected_repo = repo_v3 if status.operation_id == "serialized-v3" else repo_v2
    assert _package_bytes(paths.installed_root) == _package_bytes(
        expected_repo / "recursive-self-improvement"
    )


def test_live_paths_ignore_ambient_home_and_only_factories_can_construct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", os.fspath(tmp_path / "attacker-home"))
    monkeypatch.setenv("CODEX_HOME", os.fspath(tmp_path / "attacker-codex"))
    monkeypatch.setenv("CODEX_RSI_HOME", os.fspath(tmp_path / "attacker-rsi"))
    expected = Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".codex"

    live = DeploymentPaths.live()

    assert live.codex_home == expected
    assert live.installed_root == expected / "skills/recursive-self-improvement"
    with pytest.raises(DeploymentError):
        DeploymentPaths.for_testing(expected)
    with pytest.raises(DeploymentError):
        DeploymentPaths(
            codex_home=tmp_path,
            skills_root=tmp_path / "skills",
            installed_root=tmp_path / "elsewhere",
            agents_file=tmp_path / "AGENTS.md",
            state_root=tmp_path / "state",
            lock_file=tmp_path / "lock",
            receipts_root=tmp_path / "receipts",
            backups_root=tmp_path / "backups",
            testing=False,
        )


def test_test_path_factory_rejects_private_bypass_live_alias_and_symlink_ancestor(
    tmp_path: Path,
) -> None:
    live = Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".codex"
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(tmp_path)

    with pytest.raises(DeploymentError):
        DeploymentPaths._from_home(tmp_path / "direct", testing=True)
    with pytest.raises(DeploymentError):
        DeploymentPaths.for_testing(live / "nested")
    with pytest.raises(DeploymentError):
        DeploymentPaths.for_testing(alias_parent / "codex")


def test_deployer_rejects_forged_descriptor_roots(tmp_path: Path) -> None:
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    object.__setattr__(paths, "receipts_root", tmp_path / "escaped-receipts")

    with pytest.raises(DeploymentError):
        GlobalRsiDeployer(paths)


def test_source_admission_ignores_git_environment_and_compares_head_blob_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = _write_repository(tmp_path, version="trusted")
    other = _write_repository(tmp_path, version="other")
    monkeypatch.setenv("GIT_DIR", os.fspath(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", os.fspath(trusted))
    planned = GlobalRsiDeployer(
        DeploymentPaths.for_testing(tmp_path / "codex")
    ).plan(trusted)
    monkeypatch.delenv("GIT_DIR")
    monkeypatch.delenv("GIT_WORK_TREE")
    assert planned.source_commit == _git(trusted, "rev-parse", "HEAD")

    payload = trusted / "recursive-self-improvement/payload.txt"
    _git(trusted, "update-index", "--assume-unchanged", payload.relative_to(trusted).as_posix())
    payload.write_text("forged-working-tree\n", encoding="utf-8")
    with pytest.raises(
        (deployment_module.DeploymentSourceError, DeploymentIntegrityError),
        match="drift|HEAD blob",
    ):
        GlobalRsiDeployer(DeploymentPaths.for_testing(tmp_path / "codex-2")).plan(trusted)


def test_plan_and_deploy_share_exact_noop_request_equivalence(tmp_path: Path) -> None:
    repo_v1 = _write_repository(tmp_path, version="same")
    repo_copy = tmp_path / "copy-root"
    repo_copy.mkdir()
    copied = _write_repository(repo_copy, version="same")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo_v1, "exact-noop-v1")

    assert deployer.plan(repo_v1).action == "no-op"
    assert deployer.plan(copied).action == "update"


def test_cleanup_preserves_replaced_member_against_closed_identity_ledger(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    member = root / "member"
    member.write_bytes(b"ours")
    ledger = deployment_module._capture_cleanup_ledger(root)
    member.unlink()
    member.write_bytes(b"foreign")

    with pytest.raises(deployment_module.DeploymentAmbiguousError):
        deployment_module._remove_tree_exact(root, ledger.root_identity, ledger)

    assert member.read_bytes() == b"foreign"


@pytest.mark.parametrize("prior_agents", [None, b"exact prior bytes\n"])
def test_initial_deployment_can_rollback_to_exact_absent_package_and_agents(
    tmp_path: Path, prior_agents: bytes | None
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    if prior_agents is not None:
        paths.codex_home.mkdir(mode=0o700)
        paths.agents_file.write_bytes(prior_agents)
        paths.agents_file.chmod(0o640)
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo, "initial-rollback-source")

    receipt = deployer.rollback("initial-rollback-source", "initial-rollback-op")

    assert receipt.operation_id == "initial-rollback-op"
    assert not paths.installed_root.exists()
    assert deployer.verify().state == "not-installed"
    assert deployer.rollback("initial-rollback-source", "initial-rollback-op") == receipt
    with pytest.raises(DeploymentOperationConflict):
        deployer.rollback("different-receipt", "initial-rollback-op")
    if prior_agents is None:
        assert not paths.agents_file.exists()
    else:
        assert paths.agents_file.read_bytes() == prior_agents
        assert stat.S_IMODE(os.lstat(paths.agents_file).st_mode) == 0o640


def test_rollback_replay_binds_requested_receipt_id(tmp_path: Path) -> None:
    repo_v1 = _write_repository(tmp_path, version="replay-v1")
    repo_v2 = _write_repository(tmp_path, version="replay-v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo_v1, "replay-bind-v1")
    deployer.deploy(repo_v2, "replay-bind-v2")
    first = deployer.rollback("replay-bind-v2", "replay-bind-rollback")

    assert deployer.rollback("replay-bind-v2", "replay-bind-rollback") == first

    with pytest.raises(DeploymentOperationConflict):
        deployer.rollback("replay-bind-v1", "replay-bind-rollback")


def test_missing_lock_is_invalid_once_receipt_authority_exists(tmp_path: Path) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo, "missing-lock-authority")
    paths.lock_file.unlink()

    status = deployer.verify()

    assert status.verified is False
    assert status.state in {"invalid", "ambiguous"}


def test_source_head_bytes_are_rechecked_immediately_before_publication(
    tmp_path: Path,
) -> None:
    repo = _write_repository(tmp_path)
    payload = repo / "recursive-self-improvement/payload.txt"
    _git(repo, "update-index", "--assume-unchanged", payload.relative_to(repo).as_posix())
    paths = DeploymentPaths.for_testing(tmp_path / "codex")

    def drift(boundary: str) -> None:
        if boundary == "package.rename":
            payload.write_text("late-source-drift\n", encoding="utf-8")

    with pytest.raises(
        (deployment_module.DeploymentSourceError, DeploymentIntegrityError),
        match="drift|HEAD blob",
    ):
        GlobalRsiDeployer(paths, fault_injector=drift).deploy(repo, "late-head-drift")

    assert not paths.installed_root.exists()
    assert not list(paths.skills_root.glob(".rsi-package-stage*"))
    assert not list(paths.backups_root.glob("sha256:*"))


def test_late_symlink_ancestor_is_rejected_before_operation(tmp_path: Path) -> None:
    repo = _write_repository(tmp_path)
    alias = tmp_path / "late-alias"
    paths = DeploymentPaths.for_testing(alias / "codex")
    deployer = GlobalRsiDeployer(paths)
    target = tmp_path / "late-target"
    target.mkdir()
    alias.symlink_to(target)

    with pytest.raises(DeploymentError, match="symlink"):
        deployer.plan(repo)


def test_lock_name_replacement_after_flock_is_rejected_and_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    real_flock = fcntl.flock
    replaced = False

    def replace_after_lock(descriptor: int, operation: int) -> None:
        nonlocal replaced
        real_flock(descriptor, operation)
        if replaced or not (operation & fcntl.LOCK_EX) or (operation & fcntl.LOCK_UN):
            return
        replaced = True
        displaced = paths.state_root / "displaced-lock"
        os.rename(paths.lock_file, displaced)
        replacement = os.open(paths.lock_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(replacement)

    monkeypatch.setattr(deployment_module.fcntl, "flock", replace_after_lock)

    with pytest.raises(DeploymentIntegrityError, match="changed after locking"):
        GlobalRsiDeployer(paths).deploy(repo, "replaced-lock")

    assert replaced is True
    assert paths.lock_file.exists()
    assert (paths.state_root / "displaced-lock").exists()
    assert not paths.installed_root.exists()


def test_lock_is_acquired_before_transaction_layout_is_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    real_ensure = deployment_module._ensure_directory
    observed: list[str] = []

    def checked(path: Path, *, exact_private: bool) -> None:
        if path in {paths.skills_root, paths.receipts_root, paths.backups_root}:
            assert paths.lock_file.exists()
            observed.append(path.name)
        real_ensure(path, exact_private=exact_private)

    monkeypatch.setattr(deployment_module, "_ensure_directory", checked)
    GlobalRsiDeployer(paths).deploy(repo, "lock-before-layout")

    assert set(observed) == {"skills", "receipts", "backups"}


def test_stage_cleanup_preserves_member_replaced_during_fault_cut(tmp_path: Path) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    preserved: Path | None = None

    def replace(boundary: str) -> None:
        nonlocal preserved
        if boundary != "package.staging.readback":
            return
        stage = next(paths.skills_root.glob(".rsi-package-stage*"))
        preserved = stage / "payload.txt"
        preserved.unlink()
        preserved.write_bytes(b"foreign-replacement")
        raise InjectedFault(boundary)

    with pytest.raises(deployment_module.DeploymentAmbiguousError):
        GlobalRsiDeployer(paths, fault_injector=replace).deploy(
            repo, "preserve-foreign-stage"
        )

    assert preserved is not None
    assert preserved.read_bytes() == b"foreign-replacement"


def test_operation_request_acyclically_binds_exact_prior_backup_and_receipt(
    tmp_path: Path,
) -> None:
    repo_v1 = _write_repository(tmp_path, version="request-v1")
    repo_v2 = _write_repository(tmp_path, version="request-v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo_v1, "request-bind-v1")
    deployer.deploy(repo_v2, "request-bind-v2")

    request_bytes = (paths.receipts_root / "request-bind-v2.request.json").read_bytes()
    request = deployment_module._canonical_mapping(
        request_bytes, label="test operation request"
    )
    manifest = DeploymentManifest.from_bytes(
        (paths.receipts_root / "request-bind-v2.manifest.json").read_bytes()
    )
    assert request["operationKind"] == "deploy"
    assert request["requestReceiptId"] is None
    assert request["priorStateBackupDigest"] in {
        path.name for path in paths.backups_root.iterdir()
    }
    assert manifest.operation_request_digest == (
        "sha256:" + hashlib.sha256(request_bytes).hexdigest()
    )


def test_substituted_canonical_backup_is_rejected_before_rollback_mutation(
    tmp_path: Path,
) -> None:
    repos = {
        name: _write_repository(tmp_path, version=name)
        for name in ("sub-v1", "sub-v2", "sub-v3", "sub-v4")
    }
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repos["sub-v1"], "sub-target-v1")
    deployer.deploy(repos["sub-v2"], "sub-active-v2")
    request = deployment_module._canonical_mapping(
        (paths.receipts_root / "sub-active-v2.request.json").read_bytes(),
        label="test request",
    )
    exact = paths.backups_root / str(request["priorStateBackupDigest"])

    other_paths = DeploymentPaths.for_testing(tmp_path / "other-codex")
    other = GlobalRsiDeployer(other_paths)
    other.deploy(repos["sub-v3"], "other-v3")
    other.deploy(repos["sub-v4"], "other-v4")
    other_request = deployment_module._canonical_mapping(
        (other_paths.receipts_root / "other-v4.request.json").read_bytes(),
        label="other request",
    )
    source = other_paths.backups_root / str(other_request["priorStateBackupDigest"])
    forged_stage = paths.backups_root / "forged-stage"
    shutil.copytree(source, forged_stage)
    metadata = deployment_module._canonical_mapping(
        (forged_stage / "backup.json").read_bytes(), label="forged backup"
    )
    metadata["successorOperationId"] = "sub-active-v2"
    forged_bytes = canonical_json_bytes(metadata)
    (forged_stage / "backup.json").write_bytes(forged_bytes)
    forged_name = "sha256:" + hashlib.sha256(forged_bytes).hexdigest()
    forged = paths.backups_root / forged_name
    forged_stage.rename(forged)
    shutil.rmtree(exact)
    before = _snapshot_tree(paths.codex_home)

    with pytest.raises((DeploymentIntegrityError, DeploymentOperationConflict)):
        deployer.rollback("sub-active-v2", "reject-substituted-backup")

    assert _snapshot_tree(paths.codex_home) == before


def test_private_factory_token_cannot_forge_nonlive_production_descriptor(
    tmp_path: Path,
) -> None:
    with pytest.raises(DeploymentError):
        DeploymentPaths._from_home(
            tmp_path / "forged-live",
            testing=False,
        )


def test_install_rollback_reinstall_rollback_uses_versioned_absent_authority(
    tmp_path: Path,
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo, "cycle-install-1")
    deployer.rollback("cycle-install-1", "cycle-absent-1")
    assert deployer.verify().state == "not-installed"

    deployer.deploy(repo, "cycle-install-2")
    second = deployer.rollback("cycle-install-2", "cycle-absent-2")

    assert second.operation_id == "cycle-absent-2"
    assert deployer.verify().state == "not-installed"
    active = deployment_module._canonical_mapping(
        (paths.state_root / "active.json").read_bytes(), label="active authority"
    )
    assert active["operationId"] == "cycle-absent-2"
    assert (paths.state_root / "authorities/cycle-absent-1.absent.json").is_file()
    assert (paths.state_root / "authorities/cycle-absent-2.absent.json").is_file()


def test_backup_cleanup_preserves_foreign_member_added_at_readback(tmp_path: Path) -> None:
    repo_v1 = _write_repository(tmp_path, version="foreign-backup-v1")
    repo_v2 = _write_repository(tmp_path, version="foreign-backup-v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    GlobalRsiDeployer(paths).deploy(repo_v1, "foreign-backup-base")
    preserved: Path | None = None

    def inject(boundary: str) -> None:
        nonlocal preserved
        if boundary != "backup.readback":
            return
        backup = next(
            path
            for path in paths.backups_root.iterdir()
            if path.is_dir()
            and deployment_module._canonical_mapping(
                (path / "backup.json").read_bytes(), label="candidate backup"
            ).get("successorOperationId")
            == "foreign-backup-update"
        )
        preserved = backup / "foreign.bin"
        preserved.write_bytes(b"foreign-evidence")
        raise InjectedFault(boundary)

    with pytest.raises(deployment_module.DeploymentAmbiguousError):
        GlobalRsiDeployer(paths, fault_injector=inject).deploy(
            repo_v2, "foreign-backup-update"
        )

    assert preserved is not None
    assert preserved.read_bytes() == b"foreign-evidence"


def test_late_codex_ancestor_swap_after_lock_never_redirects_transaction_writes(
    tmp_path: Path,
) -> None:
    repo = _write_repository(tmp_path)
    parent = tmp_path / "owned-parent"
    parent.mkdir()
    paths = DeploymentPaths.for_testing(parent / "codex")
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    redirected_codex = redirected / "codex"
    (redirected_codex / "skills").mkdir(parents=True)
    (redirected_codex / "rsi-deployments-v1/backups").mkdir(parents=True)
    (redirected_codex / "rsi-deployments-v1/receipts").mkdir(parents=True)
    for directory in (
        redirected_codex,
        redirected_codex / "skills",
        redirected_codex / "rsi-deployments-v1",
        redirected_codex / "rsi-deployments-v1/backups",
        redirected_codex / "rsi-deployments-v1/receipts",
    ):
        directory.chmod(0o700)
    def swap(boundary: str) -> None:
        if boundary != "backup.staging.create":
            return
        parent.rename(tmp_path / "displaced-parent")
        parent.symlink_to(redirected)

    with pytest.raises((DeploymentError, deployment_module.DeploymentAmbiguousError)):
        GlobalRsiDeployer(paths, fault_injector=swap).deploy(repo, "late-root-swap")

    assert not any(
        path.name.startswith(("sha256:", ".rsi-"))
        for path in redirected.rglob("*")
    )


@pytest.mark.parametrize("relative", ["skills/recursive-self-improvement", "AGENTS.md"])
def test_dangling_destination_symlink_is_rejected_without_following(
    tmp_path: Path, relative: str
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    destination = paths.codex_home / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.symlink_to(tmp_path / "missing-target")

    with pytest.raises((DeploymentError, DeploymentIntegrityError)):
        GlobalRsiDeployer(paths).deploy(repo, "dangling-destination")

    assert destination.is_symlink()


@pytest.mark.parametrize(
    "cut",
    [
        "receipt.authority.write",
        "receipt.authority.fsync",
        "receipt.authority.parent_fsync",
        "receipt.authority.readback",
        "authority.pointer.write",
        "authority.pointer.fsync",
        "authority.pointer.replace",
        "authority.pointer.parent_fsync",
        "authority.pointer.readback",
    ],
)
def test_initial_authority_fault_cuts_never_claim_partial_install_verified(
    tmp_path: Path, cut: str
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")

    def inject(boundary: str) -> None:
        if boundary == cut:
            raise InjectedFault(cut)

    with pytest.raises((InjectedFault, DeploymentError)):
        GlobalRsiDeployer(paths, fault_injector=inject).deploy(
            repo, "authority-cut-install"
        )

    status = GlobalRsiDeployer(paths).verify()
    assert status.verified is False
    assert status.state in {"invalid", "ambiguous", "not-installed"}


@pytest.mark.parametrize(
    "cut",
    [
        "uninstall.package.rename",
        "uninstall.package.parent_fsync",
        "uninstall.agents.rename",
        "uninstall.agents.parent_fsync",
        "uninstall.agents.readback",
        "receipt.authority.write",
        "receipt.authority.fsync",
        "receipt.authority.parent_fsync",
        "receipt.authority.readback",
        "authority.pointer.write",
        "authority.pointer.fsync",
        "authority.pointer.replace",
        "authority.pointer.parent_fsync",
        "authority.pointer.readback",
    ],
)
def test_initial_uninstall_authority_fault_cuts_restore_exact_present_authority(
    tmp_path: Path, cut: str
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    GlobalRsiDeployer(paths).deploy(repo, "uninstall-cut-install")
    before_package = _package_bytes(paths.installed_root)
    before_agents = paths.agents_file.read_bytes()

    def inject(boundary: str) -> None:
        if boundary == cut:
            raise InjectedFault(cut)

    with pytest.raises((InjectedFault, DeploymentError)):
        GlobalRsiDeployer(paths, fault_injector=inject).rollback(
            "uninstall-cut-install", "uninstall-cut-rollback"
        )

    status = GlobalRsiDeployer(paths).verify()
    assert status.verified is True
    assert status.operation_id == "uninstall-cut-install"
    assert _package_bytes(paths.installed_root) == before_package
    assert paths.agents_file.read_bytes() == before_agents


@pytest.mark.parametrize(
    ("boundary", "occurrence"),
    [
        *(("backup.package.file.write", number) for number in range(1, 7)),
        *(("backup.package.file.fsync", number) for number in range(1, 7)),
        *(("backup.package.directory.fsync", number) for number in range(1, 5)),
    ],
)
def test_each_repeated_backup_write_and_fsync_cut_preserves_active_authority(
    tmp_path: Path, boundary: str, occurrence: int
) -> None:
    repo_v1 = _write_repository(tmp_path, version="backup-repeat-v1")
    repo_v2 = _write_repository(tmp_path, version="backup-repeat-v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    GlobalRsiDeployer(paths).deploy(repo_v1, "backup-repeat-base")
    before = _snapshot_tree(paths.codex_home)
    count = 0

    def inject(observed: str) -> None:
        nonlocal count
        if observed == boundary:
            count += 1
            if count == occurrence:
                raise InjectedFault(f"{boundary}:{occurrence}")

    with pytest.raises((InjectedFault, DeploymentError)):
        GlobalRsiDeployer(paths, fault_injector=inject).deploy(
            repo_v2, "backup-repeat-update"
        )

    assert count == occurrence
    assert _snapshot_tree(paths.codex_home) == before
    assert GlobalRsiDeployer(paths).verify().operation_id == "backup-repeat-base"


@pytest.mark.parametrize("first", ["rollback", "deploy"])
def test_rollback_and_deploy_serialize_correctly_in_both_lock_orders(
    tmp_path: Path, first: str
) -> None:
    repo_v1 = _write_repository(tmp_path, version=f"ordered-{first}-v1")
    repo_v2 = _write_repository(tmp_path, version=f"ordered-{first}-v2")
    repo_v3 = _write_repository(tmp_path, version=f"ordered-{first}-v3")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    base = GlobalRsiDeployer(paths)
    base.deploy(repo_v1, f"ordered-{first}-v1")
    base.deploy(repo_v2, f"ordered-{first}-v2")
    entered = threading.Event()
    release = threading.Event()

    def pause(boundary: str) -> None:
        if boundary == "package.staging.readback":
            entered.set()
            assert release.wait(timeout=5)

    rollback_deployer = GlobalRsiDeployer(
        paths, fault_injector=pause if first == "rollback" else None
    )
    deploy_deployer = GlobalRsiDeployer(
        paths, fault_injector=pause if first == "deploy" else None
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        if first == "rollback":
            first_future = executor.submit(
                rollback_deployer.rollback,
                f"ordered-{first}-v2",
                f"ordered-{first}-rollback",
            )
            assert entered.wait(timeout=5)
            second_future = executor.submit(
                deploy_deployer.deploy, repo_v3, f"ordered-{first}-v3"
            )
        else:
            first_future = executor.submit(
                deploy_deployer.deploy, repo_v3, f"ordered-{first}-v3"
            )
            assert entered.wait(timeout=5)
            second_future = executor.submit(
                rollback_deployer.rollback,
                f"ordered-{first}-v2",
                f"ordered-{first}-rollback",
            )
        time.sleep(0.05)
        assert not second_future.done()
        release.set()
        first_future.result(timeout=10)
        second_future.result(timeout=10)

    status = GlobalRsiDeployer(paths).verify()
    assert status.verified is True
    expected = f"ordered-{first}-v3" if first == "rollback" else f"ordered-{first}-rollback"
    assert status.operation_id == expected


def test_deployment_service_is_exported_from_rsi_core_without_eager_storage_import() -> None:
    from rsi_core import DeploymentPaths as ExportedPaths
    from rsi_core import GlobalRsiDeployer as ExportedDeployer

    assert ExportedPaths is DeploymentPaths
    assert ExportedDeployer is GlobalRsiDeployer


@pytest.mark.parametrize(
    "mutation",
    [
        "dirty-tracked",
        "untracked-package-member",
        "unsafe-source-mode",
        "invalid-default-mode",
        "nonempty-production-allowlist",
        "duplicate-json-key",
        "float-json-value",
        "duplicate-yaml-key",
        "invalid-skill-package",
        "tracked-symlink",
    ],
)
def test_source_admission_rejects_every_nonexact_or_unsafe_committed_arm_without_writes(
    tmp_path: Path, mutation: str
) -> None:
    repo = _write_repository(tmp_path)
    package = repo / "recursive-self-improvement"
    commit_required = False
    if mutation == "dirty-tracked":
        (package / "payload.txt").write_text("dirty\n", encoding="utf-8")
    elif mutation == "untracked-package-member":
        (package / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    elif mutation == "unsafe-source-mode":
        (package / "payload.txt").chmod(0o664)
    elif mutation == "invalid-default-mode":
        (package / "profiles/default.json").write_text(
            '{"schemaVersion":1,"mode":"propose","orchestration":{"hookMode":"late-review"}}\n',
            encoding="utf-8",
        )
        commit_required = True
    elif mutation == "nonempty-production-allowlist":
        (package / "profiles/production.json").write_text(
            '{"schemaVersion":1,"activation":{"allowedTargets":["target"]}}\n',
            encoding="utf-8",
        )
        commit_required = True
    elif mutation == "duplicate-json-key":
        (package / "profiles/default.json").write_text(
            '{"schemaVersion":1,"mode":"observe","mode":"observe",'
            '"orchestration":{"hookMode":"late-review"}}\n',
            encoding="utf-8",
        )
        commit_required = True
    elif mutation == "float-json-value":
        (package / "profiles/default.json").write_text(
            '{"schemaVersion":1,"mode":"observe","ratio":1.5,'
            '"orchestration":{"hookMode":"late-review"}}\n',
            encoding="utf-8",
        )
        commit_required = True
    elif mutation == "duplicate-yaml-key":
        (package / "agents/openai.yaml").write_text(
            "interface:\n  display_name: One\n  display_name: Two\n",
            encoding="utf-8",
        )
        commit_required = True
    elif mutation == "invalid-skill-package":
        (package / "SKILL.md").write_text(
            "---\nname: INVALID_NAME\ndescription: invalid\n---\n",
            encoding="utf-8",
        )
        commit_required = True
    elif mutation == "tracked-symlink":
        (package / "linked-payload").symlink_to("payload.txt")
        commit_required = True
    else:  # pragma: no cover - closed parameter table
        raise AssertionError(mutation)
    if commit_required:
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", mutation)
    codex_home = tmp_path / "missing-codex"
    deployer = GlobalRsiDeployer(DeploymentPaths.for_testing(codex_home))

    with pytest.raises((deployment_module.DeploymentSourceError, DeploymentIntegrityError)):
        deployer.plan(repo)

    assert not codex_home.exists()


def test_verify_rejects_semantically_invalid_but_self_consistent_profile_authority(
    tmp_path: Path,
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo, "semantic-profile")
    profile = paths.installed_root / "profiles/default.json"
    profile.write_text(
        '{"schemaVersion":1,"mode":"propose","orchestration":{"hookMode":"late-review"}}\n',
        encoding="utf-8",
    )
    old = DeploymentManifest.from_bytes(
        (paths.installed_root / MANIFEST_RELATIVE_PATH).read_bytes()
    )
    snapshot = scan_package(paths.installed_root, exclude_manifest=True)
    forged = replace(
        old,
        file_entries=snapshot.entries,
        source_tree_digest=snapshot.tree_digest,
        installed_tree_digest=snapshot.tree_digest,
    )
    manifest_bytes = forged.to_bytes()
    (paths.installed_root / MANIFEST_RELATIVE_PATH).write_bytes(manifest_bytes)
    (paths.receipts_root / "semantic-profile.manifest.json").write_bytes(
        manifest_bytes
    )
    receipt = DeploymentReceipt(
        operation_id="semantic-profile",
        manifest_byte_length=len(manifest_bytes),
        manifest_digest="sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
    )
    (paths.receipts_root / "semantic-profile.json").write_bytes(receipt.to_bytes())

    status = deployer.verify()

    assert status.state == "invalid"
    assert status.verified is False


def test_partial_receipt_authority_is_typed_ambiguous_and_never_repaired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    deployer = GlobalRsiDeployer(paths)
    deployer.deploy(repo, "partial-authority")
    (paths.receipts_root / "partial-authority.json").unlink()
    before = _snapshot_tree(paths.codex_home)
    calls = _trap_writes(monkeypatch)

    status = deployer.verify()

    assert status.state == "ambiguous"
    assert status.verified is False
    assert calls == []
    assert _snapshot_tree(paths.codex_home) == before


@pytest.mark.parametrize(
    "cut", ["receipt.marker.parent_fsync", "receipt.marker.readback"]
)
def test_receipt_marker_failure_before_active_pointer_preserves_typed_ambiguity(
    tmp_path: Path, cut: str
) -> None:
    repo = _write_repository(tmp_path)
    paths = DeploymentPaths.for_testing(tmp_path / "codex")

    def inject(boundary: str) -> None:
        if boundary == cut:
            raise InjectedFault(boundary)

    deployer = GlobalRsiDeployer(paths, fault_injector=inject)

    with pytest.raises(deployment_module.DeploymentAmbiguousError):
        deployer.deploy(repo, "ambiguous-marker")

    status = GlobalRsiDeployer(paths).verify()
    assert status.verified is False
    assert status.state in {"invalid", "ambiguous"}
    assert (paths.receipts_root / "ambiguous-marker.json").exists()


@pytest.mark.parametrize(
    "cut",
    [
        "backup.staging.create",
        "backup.package.staging.create",
        "backup.package.file.write",
        "backup.package.file.fsync",
        "backup.package.manifest.write",
        "backup.package.manifest.fsync",
        "backup.package.directory.fsync",
        "backup.package.staging.readback",
        "backup.manifest.write",
        "backup.manifest.fsync",
        "backup.agents.write",
        "backup.agents.fsync",
        "backup.metadata.write",
        "backup.metadata.fsync",
        "backup.directory.fsync",
        "backup.rename",
        "backup.parent.fsync",
        "backup.readback",
    ],
)
def test_every_backup_durable_fault_cut_preserves_exact_verified_active_version(
    tmp_path: Path, cut: str
) -> None:
    repo_v1 = _write_repository(tmp_path, version="v1")
    repo_v2 = _write_repository(tmp_path, version="v2")
    paths = DeploymentPaths.for_testing(tmp_path / "codex")
    GlobalRsiDeployer(paths).deploy(repo_v1, "backup-cut-v1")
    before = _snapshot_tree(paths.codex_home)

    def inject(boundary: str) -> None:
        if boundary == cut:
            raise InjectedFault(cut)

    faulted = GlobalRsiDeployer(paths, fault_injector=inject)

    with pytest.raises((InjectedFault, DeploymentError)):
        faulted.deploy(repo_v2, "backup-cut-v2")

    assert _snapshot_tree(paths.codex_home) == before
    assert faulted.verify().operation_id == "backup-cut-v1"
