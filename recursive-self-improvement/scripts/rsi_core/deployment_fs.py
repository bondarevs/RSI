"""Descriptor-relative, read-only package identity scanning."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import unicodedata

from .deployment_schema import (
    FileEntry,
    MANIFEST_RELATIVE_PATH,
    PACKAGE_TREE_DOMAIN,
    canonical_json_bytes,
)


class DeploymentIntegrityError(ValueError):
    """A package tree is unsafe, unstable, over bounds, or has drifted."""


_MAX_ENTRIES = 4_096
_MAX_DEPTH = 32
_MAX_PATH_BYTES = 4 * 1024 * 1024
_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_READ_SIZE = 1024 * 1024

_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


@dataclass(frozen=True, slots=True)
class RootIdentity:
    device: int
    inode: int

    def __post_init__(self) -> None:
        if type(self.device) is not int or self.device < 0:
            raise DeploymentIntegrityError("package root device identity is invalid")
        if type(self.inode) is not int or self.inode < 0:
            raise DeploymentIntegrityError("package root inode identity is invalid")


def _digest_entries(entries: tuple[FileEntry, ...]) -> str:
    payload = canonical_json_bytes(
        {
            "schemaVersion": 1,
            "domain": PACKAGE_TREE_DOMAIN,
            "fileEntries": [entry.to_mapping() for entry in entries],
        }
    )
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class PackageSnapshot:
    entries: tuple[FileEntry, ...]
    tree_digest: str
    root_identity: RootIdentity
    exclude_manifest: bool

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple or any(
            type(entry) is not FileEntry for entry in self.entries
        ):
            raise DeploymentIntegrityError("package snapshot entries are invalid")
        paths = tuple(entry.relative_path for entry in self.entries)
        if paths != tuple(sorted(paths, key=lambda item: item.encode("utf-8"))):
            raise DeploymentIntegrityError("package snapshot entries are not UTF-8 sorted")
        if len(paths) != len(set(paths)):
            raise DeploymentIntegrityError("package snapshot contains duplicate paths")
        if type(self.root_identity) is not RootIdentity:
            raise DeploymentIntegrityError("package root identity is invalid")
        if type(self.exclude_manifest) is not bool:
            raise DeploymentIntegrityError("package manifest exclusion is invalid")
        if _digest_entries(self.entries) != self.tree_digest:
            raise DeploymentIntegrityError("package tree digest is invalid")
        if self.exclude_manifest and MANIFEST_RELATIVE_PATH in paths:
            raise DeploymentIntegrityError("excluded manifest is present in the package snapshot")

    @property
    def relative_paths(self) -> tuple[str, ...]:
        return tuple(entry.relative_path for entry in self.entries)


@dataclass(slots=True)
class _ScanState:
    entries: list[FileEntry]
    entry_count: int = 0
    path_bytes: int = 0
    total_bytes: int = 0


def _stat_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _require_same_identity(
    *values: os.stat_result, label: str
) -> None:
    signatures = {_stat_signature(value) for value in values}
    if len(signatures) != 1:
        raise DeploymentIntegrityError(f"{label} changed during package scan")


def _require_safe_member(value: os.stat_result, *, directory: bool, label: str) -> None:
    kind_ok = stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)
    if not kind_ok:
        raise DeploymentIntegrityError(f"{label} is not a permitted package member")
    if value.st_uid != os.geteuid():
        raise DeploymentIntegrityError(f"{label} is not owned by the current user")
    if value.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise DeploymentIntegrityError(f"{label} has an unsafe writable mode")
    if value.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise DeploymentIntegrityError(f"{label} has unsafe special mode bits")
    if not directory and value.st_nlink != 1:
        raise DeploymentIntegrityError(f"{label} is a hard-linked regular file")


def _relative_path(parent: str, name: str, *, depth: int, state: _ScanState) -> str:
    if type(name) is not str:
        raise DeploymentIntegrityError("package path is not text")
    try:
        name_bytes = name.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise DeploymentIntegrityError("package path is not valid UTF-8") from None
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or unicodedata.normalize("NFC", name) != name
    ):
        raise DeploymentIntegrityError("package path is not NFC canonical")
    if depth > _MAX_DEPTH:
        raise DeploymentIntegrityError("package depth exceeds its bound")
    relative = f"{parent}/{name}" if parent else name
    relative_bytes = relative.encode("utf-8", "strict")
    state.entry_count += 1
    state.path_bytes += len(relative_bytes)
    if state.entry_count > _MAX_ENTRIES:
        raise DeploymentIntegrityError("package entry count exceeds its bound")
    if state.path_bytes > _MAX_PATH_BYTES:
        raise DeploymentIntegrityError("package path bytes exceed their bound")
    # Retain the direct-name encoding calculation above as an explicit check
    # against surrogate-containing names returned by the host filesystem.
    if not name_bytes:
        raise DeploymentIntegrityError("package path is invalid")
    return relative


def _named_stat(directory_fd: int, name: str, *, label: str) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except (OSError, ValueError):
        raise DeploymentIntegrityError(f"cannot inspect {label} safely") from None


def _open_directory(directory_fd: int, name: str, *, label: str) -> int:
    try:
        return os.open(
            name,
            os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
            dir_fd=directory_fd,
        )
    except OSError:
        raise DeploymentIntegrityError(f"cannot open {label} as a nofollow directory") from None


def _open_regular(directory_fd: int, name: str, *, label: str) -> int:
    try:
        return os.open(
            name,
            os.O_RDONLY | _NOFOLLOW | _CLOEXEC | _NONBLOCK,
            dir_fd=directory_fd,
        )
    except OSError:
        raise DeploymentIntegrityError(f"cannot open {label} as a nofollow regular file") from None


def _scan_regular(
    directory_fd: int,
    name: str,
    relative: str,
    named_before: os.stat_result,
    *,
    include: bool,
    state: _ScanState,
) -> None:
    _require_safe_member(named_before, directory=False, label=relative)
    if named_before.st_size > _MAX_FILE_BYTES:
        raise DeploymentIntegrityError(f"{relative} file size exceeds its bound")
    file_fd = _open_regular(directory_fd, name, label=relative)
    try:
        opened_before = os.fstat(file_fd)
        _require_safe_member(opened_before, directory=False, label=relative)
        _require_same_identity(named_before, opened_before, label=relative)

        digest = hashlib.sha256()
        byte_length = 0
        while True:
            chunk = os.read(file_fd, _READ_SIZE)
            if not chunk:
                break
            byte_length += len(chunk)
            if byte_length > _MAX_FILE_BYTES:
                raise DeploymentIntegrityError(f"{relative} file size exceeds its bound")
            digest.update(chunk)

        opened_after = os.fstat(file_fd)
        named_after = _named_stat(directory_fd, name, label=relative)
        _require_safe_member(opened_after, directory=False, label=relative)
        _require_safe_member(named_after, directory=False, label=relative)
        _require_same_identity(
            named_before,
            opened_before,
            opened_after,
            named_after,
            label=relative,
        )
        if byte_length != opened_after.st_size:
            raise DeploymentIntegrityError(f"{relative} changed during package scan")
    finally:
        os.close(file_fd)

    state.total_bytes += byte_length
    if state.total_bytes > _MAX_TOTAL_BYTES:
        raise DeploymentIntegrityError("package bytes exceed their aggregate bound")
    if include:
        state.entries.append(
            FileEntry(
                relative_path=relative,
                byte_length=byte_length,
                executable=bool(opened_after.st_mode & 0o111),
                digest="sha256:" + digest.hexdigest(),
            )
        )


def _scan_directory(
    directory_fd: int,
    parent: str,
    *,
    depth: int,
    exclude_manifest: bool,
    state: _ScanState,
) -> None:
    prepared: list[tuple[bytes, str, str, os.stat_result]] = []
    try:
        with os.scandir(directory_fd) as iterator:
            for directory_entry in iterator:
                name = directory_entry.name
                relative = _relative_path(parent, name, depth=depth, state=state)
                named_before = _named_stat(directory_fd, name, label=relative)
                prepared.append(
                    (name.encode("utf-8", "strict"), name, relative, named_before)
                )
    except OSError:
        raise DeploymentIntegrityError("cannot enumerate package directory safely") from None

    for _, name, relative, named_before in sorted(prepared, key=lambda item: item[0]):
        if stat.S_ISDIR(named_before.st_mode):
            _require_safe_member(named_before, directory=True, label=relative)
            child_fd = _open_directory(directory_fd, name, label=relative)
            try:
                opened_before = os.fstat(child_fd)
                _require_safe_member(opened_before, directory=True, label=relative)
                _require_same_identity(named_before, opened_before, label=relative)
                entries_before = len(state.entries)
                _scan_directory(
                    child_fd,
                    relative,
                    depth=depth + 1,
                    exclude_manifest=exclude_manifest,
                    state=state,
                )
                opened_after = os.fstat(child_fd)
                named_after = _named_stat(directory_fd, name, label=relative)
                _require_safe_member(opened_after, directory=True, label=relative)
                _require_safe_member(named_after, directory=True, label=relative)
                _require_same_identity(
                    named_before,
                    opened_before,
                    opened_after,
                    named_after,
                    label=relative,
                )
                if len(state.entries) == entries_before:
                    raise DeploymentIntegrityError(
                        f"{relative} directory has no included regular file descendant"
                    )
            finally:
                os.close(child_fd)
            continue

        if not stat.S_ISREG(named_before.st_mode):
            raise DeploymentIntegrityError(f"{relative} is not a directory or regular file")
        _scan_regular(
            directory_fd,
            name,
            relative,
            named_before,
            include=not (exclude_manifest and relative == MANIFEST_RELATIVE_PATH),
            state=state,
        )


def scan_package(root: Path, *, exclude_manifest: bool) -> PackageSnapshot:
    """Return a bounded immutable identity without following or writing members."""

    if not isinstance(root, Path) or type(exclude_manifest) is not bool:
        raise DeploymentIntegrityError("package scan arguments are invalid")
    try:
        named_before = os.lstat(root)
    except (OSError, ValueError):
        raise DeploymentIntegrityError("package root is unavailable") from None
    _require_safe_member(named_before, directory=True, label="package root")
    try:
        root_fd = os.open(root, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
    except OSError:
        raise DeploymentIntegrityError("package root is not a nofollow directory") from None
    try:
        opened_before = os.fstat(root_fd)
        _require_safe_member(opened_before, directory=True, label="package root")
        _require_same_identity(named_before, opened_before, label="package root")
        state = _ScanState(entries=[])
        _scan_directory(
            root_fd,
            "",
            depth=1,
            exclude_manifest=exclude_manifest,
            state=state,
        )
        opened_after = os.fstat(root_fd)
        try:
            named_after = os.lstat(root)
        except OSError:
            raise DeploymentIntegrityError("package root changed during scan") from None
        _require_safe_member(opened_after, directory=True, label="package root")
        _require_safe_member(named_after, directory=True, label="package root")
        _require_same_identity(
            named_before,
            opened_before,
            opened_after,
            named_after,
            label="package root",
        )
        if not state.entries:
            raise DeploymentIntegrityError(
                "package root directory has no included regular file descendant"
            )
    finally:
        os.close(root_fd)

    entries = tuple(
        sorted(state.entries, key=lambda entry: entry.relative_path.encode("utf-8"))
    )
    return PackageSnapshot(
        entries=entries,
        tree_digest=_digest_entries(entries),
        root_identity=RootIdentity(opened_after.st_dev, opened_after.st_ino),
        exclude_manifest=exclude_manifest,
    )


def verify_package_snapshot(root: Path, expected: PackageSnapshot) -> None:
    """Fail closed unless a fresh scan exactly reproduces an immutable snapshot."""

    if type(expected) is not PackageSnapshot:
        raise DeploymentIntegrityError("expected package snapshot is invalid")
    actual = scan_package(root, exclude_manifest=expected.exclude_manifest)
    if actual != expected:
        raise DeploymentIntegrityError("package snapshot does not match; package drift detected")


__all__ = [
    "DeploymentIntegrityError",
    "PackageSnapshot",
    "RootIdentity",
    "scan_package",
    "verify_package_snapshot",
]
