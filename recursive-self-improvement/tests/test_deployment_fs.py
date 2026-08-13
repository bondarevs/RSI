from __future__ import annotations

from dataclasses import FrozenInstanceError
import os
from pathlib import Path
import unicodedata

import pytest

from rsi_core.deployment_fs import (
    DeploymentIntegrityError,
    scan_package,
    verify_package_snapshot,
)


def safe_package(root: Path) -> Path:
    root.mkdir(mode=0o700)
    (root / "SKILL.md").write_bytes(b"skill\n")
    scripts = root / "scripts"
    scripts.mkdir(mode=0o700)
    runner = scripts / "run.py"
    runner.write_bytes(b"run\n")
    runner.chmod(0o700)
    return root


def install_unsafe_member(root: Path, unsafe: str) -> None:
    if unsafe == "symlink":
        (root / "unsafe").symlink_to("SKILL.md")
    elif unsafe == "fifo":
        os.mkfifo(root / "unsafe")
    elif unsafe == "hardlink":
        os.link(root / "SKILL.md", root / "unsafe")
    elif unsafe == "world-write":
        path = root / "unsafe"
        path.write_bytes(b"unsafe")
        path.chmod(0o602)
    elif unsafe == "group-write":
        path = root / "unsafe"
        path.write_bytes(b"unsafe")
        path.chmod(0o620)
    elif unsafe == "setuid":
        path = root / "unsafe"
        path.write_bytes(b"unsafe")
        path.chmod(0o4600)
    elif unsafe == "setgid":
        path = root / "unsafe"
        path.write_bytes(b"unsafe")
        path.chmod(0o2600)
    elif unsafe == "sticky":
        path = root / "unsafe"
        path.write_bytes(b"unsafe")
        path.chmod(0o1600)
    else:  # pragma: no cover - a broken test fixture should be loud
        raise AssertionError(unsafe)


@pytest.mark.parametrize(
    "unsafe",
    [
        "symlink",
        "fifo",
        "hardlink",
        "world-write",
        "group-write",
        "setuid",
        "setgid",
        "sticky",
    ],
)
def test_scan_package_rejects_unsafe_topology(tmp_path: Path, unsafe: str) -> None:
    root = safe_package(tmp_path / "package")
    install_unsafe_member(root, unsafe)

    with pytest.raises(DeploymentIntegrityError):
        scan_package(root, exclude_manifest=True)


def test_scan_package_accepts_directory_link_counts_but_not_file_hardlinks(
    tmp_path: Path,
) -> None:
    root = safe_package(tmp_path / "package")
    (root / "scripts" / "nested").mkdir()
    assert root.stat().st_nlink >= 2

    snapshot = scan_package(root, exclude_manifest=True)

    assert snapshot.relative_paths == ("SKILL.md", "scripts/run.py")


def test_scan_package_excludes_only_the_exact_root_manifest_path(tmp_path: Path) -> None:
    root = safe_package(tmp_path / "package")
    (root / ".rsi-deployment-manifest.json").write_bytes(b"ignored")
    (root / ".rsi-deployment-manifest.json.bak").write_bytes(b"included")
    (root / "scripts" / ".rsi-deployment-manifest.json").write_bytes(b"nested")

    snapshot = scan_package(root, exclude_manifest=True)

    assert snapshot.relative_paths == (
        ".rsi-deployment-manifest.json.bak",
        "SKILL.md",
        "scripts/.rsi-deployment-manifest.json",
        "scripts/run.py",
    )


def test_scan_package_includes_manifest_when_exclusion_is_disabled(tmp_path: Path) -> None:
    root = safe_package(tmp_path / "package")
    (root / ".rsi-deployment-manifest.json").write_bytes(b"manifest")

    snapshot = scan_package(root, exclude_manifest=False)

    assert ".rsi-deployment-manifest.json" in snapshot.relative_paths


def test_scan_package_has_immutable_deterministic_identity(tmp_path: Path) -> None:
    root = safe_package(tmp_path / "package")

    first = scan_package(root, exclude_manifest=True)
    second = scan_package(root, exclude_manifest=True)

    assert first == second
    assert first.tree_digest == "sha256:b75ff7b724c195d9b7f4117c8b074c487dc91215b22483b784ae439ffc7e4d07"
    assert first.root_identity.device == root.stat().st_dev
    assert first.root_identity.inode == root.stat().st_ino
    with pytest.raises(FrozenInstanceError):
        first.tree_digest = "sha256:" + "0" * 64  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        first.root_identity.inode = 0  # type: ignore[misc]


def test_scan_package_records_any_repository_execute_bit(tmp_path: Path) -> None:
    root = safe_package(tmp_path / "package")
    path = root / "SKILL.md"
    path.chmod(0o610)

    snapshot = scan_package(root, exclude_manifest=True)

    skill_entry = next(entry for entry in snapshot.entries if entry.relative_path == "SKILL.md")
    assert skill_entry.executable is True


def test_verify_package_snapshot_rejects_byte_mode_membership_and_root_drift(
    tmp_path: Path,
) -> None:
    root = safe_package(tmp_path / "package")
    expected = scan_package(root, exclude_manifest=True)

    (root / "SKILL.md").write_bytes(b"changed\n")
    with pytest.raises(DeploymentIntegrityError, match="changed|match|drift"):
        verify_package_snapshot(root, expected)
    (root / "SKILL.md").write_bytes(b"skill\n")

    (root / "SKILL.md").chmod(0o700)
    with pytest.raises(DeploymentIntegrityError, match="changed|match|drift"):
        verify_package_snapshot(root, expected)
    (root / "SKILL.md").chmod(0o600)

    (root / "extra").write_bytes(b"extra")
    with pytest.raises(DeploymentIntegrityError, match="changed|match|drift"):
        verify_package_snapshot(root, expected)
    (root / "extra").unlink()

    replacement = tmp_path / "replacement"
    root.rename(replacement)
    safe_package(root)
    with pytest.raises(DeploymentIntegrityError, match="changed|match|drift"):
        verify_package_snapshot(root, expected)


def test_scan_package_rejects_non_nfc_path(tmp_path: Path) -> None:
    root = safe_package(tmp_path / "package")
    nfd_name = unicodedata.normalize("NFD", "café.txt")
    path = root / nfd_name
    path.write_bytes(b"text")
    if path.name != unicodedata.normalize("NFC", path.name):
        with pytest.raises(DeploymentIntegrityError, match="NFC|canonical|path"):
            scan_package(root, exclude_manifest=True)


def test_scan_package_rejects_depth_over_32(tmp_path: Path) -> None:
    root = safe_package(tmp_path / "package")
    current = root
    for index in range(33):
        current = current / f"d{index}"
        current.mkdir()

    with pytest.raises(DeploymentIntegrityError, match="depth|bound"):
        scan_package(root, exclude_manifest=True)


def test_scan_package_rejects_file_over_16_mib(tmp_path: Path) -> None:
    root = safe_package(tmp_path / "package")
    oversized = root / "oversized"
    with oversized.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)

    with pytest.raises(DeploymentIntegrityError, match="file|size|bound"):
        scan_package(root, exclude_manifest=True)


def test_scan_package_rejects_more_than_4096_members(tmp_path: Path) -> None:
    root = safe_package(tmp_path / "package")
    for index in range(4_095):
        (root / f"member-{index:04d}").write_bytes(b"")

    with pytest.raises(DeploymentIntegrityError, match="entry count|bound"):
        scan_package(root, exclude_manifest=True)


def test_scan_package_rejects_more_than_64_mib_aggregate(tmp_path: Path) -> None:
    root = safe_package(tmp_path / "package")
    for index in range(4):
        with (root / f"blob-{index}").open("wb") as stream:
            stream.truncate(16 * 1024 * 1024)

    with pytest.raises(DeploymentIntegrityError, match="aggregate|bytes|bound"):
        scan_package(root, exclude_manifest=True)


def test_scan_package_rejects_non_directory_and_symlink_roots(tmp_path: Path) -> None:
    regular = tmp_path / "regular"
    regular.write_bytes(b"x")
    target = safe_package(tmp_path / "target")
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(DeploymentIntegrityError):
        scan_package(regular, exclude_manifest=True)
    with pytest.raises(DeploymentIntegrityError):
        scan_package(link, exclude_manifest=True)


def test_scan_package_requires_boolean_manifest_switch(tmp_path: Path) -> None:
    root = safe_package(tmp_path / "package")
    with pytest.raises(DeploymentIntegrityError):
        scan_package(root, exclude_manifest=1)  # type: ignore[arg-type]
