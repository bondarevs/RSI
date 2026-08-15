"""Transactional global deployment of one pinned RSI observe package.

The public read-only operations in this module deliberately avoid every repair
or setup action.  Mutation helpers are added below only for ``deploy`` and
``rollback``; live paths always come from the current user's passwd entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from typing import Callable

from .deployment_fs import (
    DeploymentIntegrityError,
    PackageSnapshot,
    scan_package,
    verify_package_snapshot,
)
from .deployment_schema import (
    DeploymentManifest,
    DeploymentReceipt,
    DeploymentSchemaError,
    MANIFEST_RELATIVE_PATH,
    PACKAGE_RELATIVE_PATH,
    canonical_json_bytes,
)
from .global_instructions import (
    GlobalInstructionsError,
    MANAGED_BLOCK_DIGEST,
    plan_agents_update,
    verify_agents_bytes,
)


class DeploymentError(RuntimeError):
    """Base class for bounded global deployment failures."""


class DeploymentSourceError(DeploymentError):
    """The repository is not an exact, clean, admissible release source."""


class DeploymentOperationConflict(DeploymentError):
    """An immutable operation ID was reused for a different request."""


class DeploymentUnsupported(DeploymentError):
    """The host lacks an atomic primitive required by the transaction."""


class DeploymentAmbiguousError(DeploymentError):
    """A durable boundary failed after publication and evidence was preserved."""


class DeploymentLockTimeout(DeploymentError):
    """The private deployment lock could not be acquired before its deadline."""


_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_ALLOWLIST_DOMAIN = "rsi-global-production-allowlist-v1"
_FaultInjector = Callable[[str], None]
_PATH_FACTORY_TOKEN = object()


def _cut(fault_injector: _FaultInjector | None, boundary: str) -> None:
    if fault_injector is not None:
        fault_injector(boundary)


def _actual_user_home() -> Path:
    try:
        value = pwd.getpwuid(os.geteuid()).pw_dir
    except (KeyError, OSError):
        raise DeploymentError("current-user home is unavailable") from None
    path = Path(value)
    if not path.is_absolute():
        raise DeploymentError("current-user home is not absolute")
    return path


@dataclass(frozen=True, slots=True, init=False)
class DeploymentPaths:
    """Constructor-fixed paths for one live or explicitly injected test home."""

    codex_home: Path
    skills_root: Path
    installed_root: Path
    agents_file: Path
    state_root: Path
    lock_file: Path
    receipts_root: Path
    backups_root: Path
    testing: bool
    _factory_provenance: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise DeploymentError(
            "deployment paths must be created by live() or for_testing()"
        )

    @classmethod
    def _from_home(
        cls,
        codex_home: Path,
        *,
        testing: bool,
        _factory_token: object | None = None,
    ) -> "DeploymentPaths":
        if _factory_token is not _PATH_FACTORY_TOKEN:
            raise DeploymentError("deployment paths require an approved factory")
        if not isinstance(codex_home, Path) or not codex_home.is_absolute():
            raise DeploymentError("Codex home must be an absolute Path")
        skills_root = codex_home / "skills"
        state_root = codex_home / "rsi-deployments-v1"
        instance = object.__new__(cls)
        values = {
            "codex_home": codex_home,
            "skills_root": skills_root,
            "installed_root": skills_root / PACKAGE_RELATIVE_PATH,
            "agents_file": codex_home / "AGENTS.md",
            "state_root": state_root,
            "lock_file": state_root / "lock",
            "receipts_root": state_root / "receipts",
            "backups_root": state_root / "backups",
            "testing": testing,
            "_factory_provenance": _PATH_FACTORY_TOKEN,
        }
        for name, value in values.items():
            object.__setattr__(instance, name, value)
        return instance

    @classmethod
    def live(cls) -> "DeploymentPaths":
        """Return fixed live paths; ``HOME`` and deployment env vars are ignored."""

        return cls._from_home(
            _actual_user_home() / ".codex",
            testing=False,
            _factory_token=_PATH_FACTORY_TOKEN,
        )

    @classmethod
    def for_testing(cls, codex_home: Path) -> "DeploymentPaths":
        """Inject a direct temporary Codex home for tests only."""

        if not isinstance(codex_home, Path):
            raise DeploymentError("test Codex home must be a Path")
        injected = Path(os.path.abspath(codex_home))
        if injected != codex_home:
            raise DeploymentError("test Codex home must be lexically canonical")
        live = _actual_user_home() / ".codex"
        try:
            injected.relative_to(live)
        except ValueError:
            pass
        else:
            raise DeploymentError("test path injection cannot target the live Codex tree")
        current = injected
        while True:
            try:
                metadata = os.lstat(current)
            except FileNotFoundError:
                pass
            except OSError:
                raise DeploymentError("test Codex home ancestry is unavailable") from None
            else:
                if stat.S_ISLNK(metadata.st_mode):
                    raise DeploymentError("test Codex home ancestry contains a symlink")
            if current.parent == current:
                break
            current = current.parent
        return cls._from_home(
            injected,
            testing=True,
            _factory_token=_PATH_FACTORY_TOKEN,
        )


def _validate_deployment_paths(paths: DeploymentPaths) -> None:
    if paths._factory_provenance is not _PATH_FACTORY_TOKEN:
        raise DeploymentError("deployment path provenance is invalid")
    home = paths.codex_home
    expected = {
        "skills_root": home / "skills",
        "installed_root": home / "skills" / PACKAGE_RELATIVE_PATH,
        "agents_file": home / "AGENTS.md",
        "state_root": home / "rsi-deployments-v1",
        "lock_file": home / "rsi-deployments-v1" / "lock",
        "receipts_root": home / "rsi-deployments-v1" / "receipts",
        "backups_root": home / "rsi-deployments-v1" / "backups",
    }
    if any(getattr(paths, name) != value for name, value in expected.items()):
        raise DeploymentError("deployment descriptor roots are not confined")
    current = home
    while True:
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            pass
        except OSError:
            raise DeploymentError("deployment root ancestry is unavailable") from None
        else:
            if stat.S_ISLNK(metadata.st_mode):
                raise DeploymentError("deployment root ancestry contains a symlink")
        if current.parent == current:
            break
        current = current.parent


@dataclass(frozen=True, slots=True)
class DeploymentPlan:
    eligible: bool
    action: str
    source_repository: str
    source_commit: str
    source_tree_digest: str
    managed_instruction_block_digest: str
    mode: str = "observe"
    hook_mode: str = "late-review"
    production_allowlist_entry_count: int = 0


@dataclass(frozen=True, slots=True)
class DeploymentStatus:
    state: str
    installed: bool
    verified: bool
    operation_id: str | None = None
    source_commit: str | None = None
    tree_digest: str | None = None
    manifest_digest: str | None = None
    receipt_digest: str | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class _AdmittedSource:
    repository: Path
    commit: str
    package_root: Path
    snapshot: PackageSnapshot
    allowlist_digest: str


@dataclass(frozen=True, slots=True)
class _AgentsFile:
    data: bytes | None
    mode: int | None
    device: int | None
    inode: int | None


@dataclass(frozen=True, slots=True)
class _PublishedInstruction:
    changed: bool
    prior: _AgentsFile
    temporary: Path | None
    active_identity: tuple[int, int] | None
    old_identity: tuple[int, int] | None


@dataclass(frozen=True, slots=True)
class _PublishedFile:
    path: Path
    identity: tuple[int, int]


@dataclass(frozen=True, slots=True)
class _BackupRecord:
    path: Path
    identity_payload: bytes
    root_identity: tuple[int, int]
    created: bool
    prior_manifest: DeploymentManifest | None
    agents: _AgentsFile
    cleanup_ledger: "_CleanupLedger | None" = None


@dataclass(frozen=True, slots=True)
class _CleanupLedger:
    root_identity: tuple[int, int]
    members: tuple[tuple[str, str, int, int], ...]


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _safe_directory(path: Path, *, exact_private: bool) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError:
        raise DeploymentIntegrityError(f"deployment directory is unavailable: {path.name}") from None
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise DeploymentIntegrityError(f"deployment directory is unsafe: {path.name}")
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise DeploymentIntegrityError(f"deployment directory mode is unsafe: {path.name}")
    if exact_private and mode != 0o700:
        raise DeploymentIntegrityError(f"private deployment directory mode is invalid: {path.name}")
    return metadata


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW | _CLOEXEC,
        )
    except OSError:
        raise DeploymentIntegrityError(f"cannot open directory for durability: {path.name}") from None
    try:
        os.fsync(descriptor)
    except OSError:
        raise DeploymentError(f"cannot fsync directory: {path.name}") from None
    finally:
        os.close(descriptor)


def _ensure_directory(path: Path, *, exact_private: bool) -> None:
    created = False
    try:
        os.mkdir(path, 0o700)
        created = True
    except FileExistsError:
        pass
    except OSError:
        raise DeploymentError(f"cannot create deployment directory: {path.name}") from None
    metadata = _safe_directory(path, exact_private=exact_private)
    if created:
        try:
            os.chmod(path, 0o700, follow_symlinks=False)
        except OSError:
            raise DeploymentError(f"cannot make deployment directory private: {path.name}") from None
        _safe_directory(path, exact_private=True)
        _fsync_directory(path)
        _fsync_directory(path.parent)
    elif exact_private and stat.S_IMODE(metadata.st_mode) != 0o700:
        raise DeploymentIntegrityError(f"private deployment directory mode is invalid: {path.name}")


def _ensure_lock_root(paths: DeploymentPaths) -> None:
    """Create only the ancestry required to publish and acquire the lock."""

    _ensure_directory(paths.codex_home, exact_private=False)
    _ensure_directory(paths.state_root, exact_private=True)


@contextmanager
def _exclusive_lock(paths: DeploymentPaths, *, timeout: float = 5.0):
    _ensure_lock_root(paths)
    flags = os.O_RDWR | os.O_CLOEXEC | _NOFOLLOW
    created = False
    try:
        named = os.lstat(paths.lock_file)
    except FileNotFoundError:
        try:
            descriptor = os.open(paths.lock_file, flags | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
        except FileExistsError:
            try:
                named = os.lstat(paths.lock_file)
                if (
                    not stat.S_ISREG(named.st_mode)
                    or named.st_uid != os.geteuid()
                    or named.st_nlink != 1
                    or stat.S_IMODE(named.st_mode) != 0o600
                ):
                    raise DeploymentIntegrityError("deployment lock identity is unsafe")
                descriptor = os.open(paths.lock_file, flags)
            except DeploymentIntegrityError:
                raise
            except OSError:
                raise DeploymentError("cannot open the raced deployment lock safely") from None
        except OSError:
            raise DeploymentError("cannot create the deployment lock safely") from None
        if created:
            try:
                os.fsync(descriptor)
                _fsync_directory(paths.state_root)
            except Exception:
                os.close(descriptor)
                raise
    except OSError:
        raise DeploymentIntegrityError("cannot inspect the deployment lock safely") from None
    else:
        if (
            not stat.S_ISREG(named.st_mode)
            or named.st_uid != os.geteuid()
            or named.st_nlink != 1
            or stat.S_IMODE(named.st_mode) != 0o600
        ):
            raise DeploymentIntegrityError("deployment lock identity is unsafe")
        try:
            descriptor = os.open(paths.lock_file, flags)
        except OSError:
            raise DeploymentError("cannot open the deployment lock safely") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise DeploymentIntegrityError("deployment lock identity is unsafe")
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise DeploymentLockTimeout("deployment lock deadline expired") from None
                time.sleep(0.01)
            except InterruptedError:
                continue
        try:
            named_after = os.lstat(paths.lock_file)
        except OSError:
            raise DeploymentIntegrityError("deployment lock disappeared after locking") from None
        if _identity(named_after) != _identity(metadata) or named_after.st_mode != metadata.st_mode:
            raise DeploymentIntegrityError("deployment lock changed after locking")
        _ensure_directory(paths.skills_root, exact_private=False)
        _ensure_directory(paths.receipts_root, exact_private=True)
        _ensure_directory(paths.backups_root, exact_private=True)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(descriptor)


@contextmanager
def _shared_lock(paths: DeploymentPaths, *, timeout: float = 5.0):
    """Acquire the existing lock read-only, without creating or repairing it."""

    try:
        named = os.lstat(paths.lock_file)
    except FileNotFoundError:
        authority = paths.installed_root.exists()
        if not authority:
            try:
                authority = any(os.scandir(paths.receipts_root))
            except FileNotFoundError:
                authority = False
            except OSError:
                authority = True
        if authority:
            raise DeploymentIntegrityError("deployment lock is missing with authority")
        yield
        return
    except OSError:
        raise DeploymentIntegrityError("cannot inspect the deployment lock") from None
    if (
        not stat.S_ISREG(named.st_mode)
        or named.st_uid != os.geteuid()
        or named.st_nlink != 1
        or stat.S_IMODE(named.st_mode) != 0o600
    ):
        raise DeploymentIntegrityError("deployment lock identity is unsafe")
    try:
        descriptor = os.open(paths.lock_file, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
    except OSError:
        raise DeploymentIntegrityError("cannot open the deployment lock read-only") from None
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(named) or opened.st_mode != named.st_mode:
            raise DeploymentIntegrityError("deployment lock changed while opening")
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise DeploymentLockTimeout("deployment read lock deadline expired") from None
                time.sleep(0.01)
            except InterruptedError:
                continue
        try:
            named_after = os.lstat(paths.lock_file)
        except OSError:
            raise DeploymentIntegrityError("deployment lock disappeared after locking") from None
        if _identity(named_after) != _identity(opened) or named_after.st_mode != opened.st_mode:
            raise DeploymentIntegrityError("deployment lock changed after locking")
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(descriptor, view[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise DeploymentError("deployment file write made no progress")
        offset += written


def _write_new_file(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    fault_injector: _FaultInjector | None = None,
    write_boundary: str | None = None,
    fsync_boundary: str | None = None,
) -> tuple[int, int]:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
            0o600,
        )
    except OSError:
        raise DeploymentError(f"cannot create private deployment file: {path.name}") from None
    try:
        opened_identity = _identity(os.fstat(descriptor))
        if write_boundary is not None:
            _cut(fault_injector, write_boundary)
        _write_all(descriptor, payload)
        os.fchmod(descriptor, mode)
        if fsync_boundary is not None:
            _cut(fault_injector, fsync_boundary)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.geteuid() or metadata.st_nlink != 1:
            raise DeploymentIntegrityError(f"new deployment file identity is unsafe: {path.name}")
        return _identity(metadata)
    except Exception as original_error:
        try:
            named = os.lstat(path)
            if (
                not stat.S_ISREG(named.st_mode)
                or _identity(named) != opened_identity
                or named.st_uid != os.geteuid()
                or named.st_nlink != 1
            ):
                raise DeploymentAmbiguousError(
                    f"new deployment file changed before cleanup: {path.name}"
                )
            os.unlink(path)
        except FileNotFoundError:
            pass
        except DeploymentAmbiguousError:
            raise
        except OSError:
            raise DeploymentAmbiguousError(
                f"new deployment file cleanup failed: {path.name}"
            ) from original_error
        if isinstance(original_error, OSError):
            raise DeploymentError(f"cannot durably write deployment file: {path.name}") from None
        raise
    finally:
        os.close(descriptor)


def _open_parent(path: Path) -> int:
    try:
        return os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW | _CLOEXEC,
        )
    except OSError:
        raise DeploymentIntegrityError(f"cannot retain deployment parent: {path.name}") from None


def _renameatx(parent_fd: int, source: str, destination: str, flags: int) -> None:
    if sys.platform != "darwin":
        raise DeploymentUnsupported("atomic Darwin rename capability is unavailable")
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renameatx_np
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    result = rename(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        flags,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS}:
            raise DeploymentUnsupported("atomic rename capability is unsupported")
        raise OSError(error_number, os.strerror(error_number))


def _require_atomic_backend() -> None:
    """Fail read-only before transaction setup when Darwin rename is unavailable."""

    if sys.platform != "darwin":
        raise DeploymentUnsupported("atomic Darwin rename capability is unavailable")
    try:
        getattr(ctypes.CDLL(None, use_errno=True), "renameatx_np")
    except (AttributeError, OSError):
        raise DeploymentUnsupported("atomic Darwin rename capability is unavailable") from None


def _rename_noreplace(source: Path, destination: Path) -> tuple[int, int]:
    if source.parent != destination.parent:
        raise DeploymentUnsupported("atomic publication requires one parent directory")
    parent_fd = _open_parent(source.parent)
    try:
        before = os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise DeploymentIntegrityError("publication destination unexpectedly exists")
        try:
            _renameatx(parent_fd, source.name, destination.name, 0x00000004)
        except OSError as error:
            if error.errno == errno.EEXIST:
                raise DeploymentIntegrityError("publication destination raced into existence") from None
            raise DeploymentError("atomic no-replace publication failed") from None
        after = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        if _identity(after) != _identity(before):
            raise DeploymentAmbiguousError("atomic publication identity is ambiguous")
        try:
            os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise DeploymentAmbiguousError("atomic publication retained both names")
        return _identity(after)
    finally:
        os.close(parent_fd)


def _exchange(source: Path, destination: Path) -> tuple[tuple[int, int], tuple[int, int]]:
    if source.parent != destination.parent:
        raise DeploymentUnsupported("atomic exchange requires one parent directory")
    parent_fd = _open_parent(source.parent)
    try:
        source_before = os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
        destination_before = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        try:
            _renameatx(parent_fd, source.name, destination.name, 0x00000002)
        except OSError:
            raise DeploymentError("atomic exchange failed") from None
        source_after = os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
        destination_after = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            _identity(source_after) != _identity(destination_before)
            or _identity(destination_after) != _identity(source_before)
        ):
            raise DeploymentAmbiguousError("atomic exchange identity is ambiguous")
        return _identity(destination_after), _identity(source_after)
    finally:
        os.close(parent_fd)


def _new_temporary(parent: Path, *, label: str, operation_id: str) -> Path:
    return parent / f".{label}.{operation_id}.{secrets.token_hex(12)}"


def _stage_package(
    admitted: _AdmittedSource,
    manifest: DeploymentManifest,
    destination: Path,
    *,
    fault_injector: _FaultInjector | None = None,
    boundary_prefix: str = "package",
) -> tuple[int, int]:
    _cut(fault_injector, f"{boundary_prefix}.staging.create")
    try:
        os.mkdir(destination, 0o700)
        os.chmod(destination, 0o700, follow_symlinks=False)
    except OSError:
        raise DeploymentError("cannot create private package staging directory") from None
    root_identity = _identity(_safe_directory(destination, exact_private=True))
    ledger_members: dict[str, tuple[str, int, int]] = {}
    try:
        created_directories: set[Path] = {destination}
        for entry in admitted.snapshot.entries:
            target = destination / entry.relative_path
            parents: list[Path] = []
            current = target.parent
            while current != destination and current not in created_directories:
                parents.append(current)
                current = current.parent
            for parent in reversed(parents):
                try:
                    os.mkdir(parent, 0o700)
                    os.chmod(parent, 0o700, follow_symlinks=False)
                except OSError:
                    raise DeploymentError("cannot create private package staging member") from None
                created_directories.add(parent)
                parent_identity = _identity(os.lstat(parent))
                ledger_members[parent.relative_to(destination).as_posix()] = (
                    "directory",
                    parent_identity[0],
                    parent_identity[1],
                )
            payload, _ = _read_regular_file(
                admitted.package_root / entry.relative_path,
                label=f"source package member {entry.relative_path}",
            )
            if len(payload) != entry.byte_length or _sha256(payload) != entry.digest:
                raise DeploymentSourceError("source package changed during staging")
            file_identity = _write_new_file(
                target,
                payload,
                mode=0o700 if entry.executable else 0o600,
                fault_injector=fault_injector,
                write_boundary=f"{boundary_prefix}.file.write",
                fsync_boundary=f"{boundary_prefix}.file.fsync",
            )
            ledger_members[entry.relative_path] = (
                "file",
                file_identity[0],
                file_identity[1],
            )

        manifest_path = destination / MANIFEST_RELATIVE_PATH
        manifest_identity = _write_new_file(
            manifest_path,
            manifest.to_bytes(),
            mode=0o600,
            fault_injector=fault_injector,
            write_boundary=f"{boundary_prefix}.manifest.write",
            fsync_boundary=f"{boundary_prefix}.manifest.fsync",
        )
        ledger_members[MANIFEST_RELATIVE_PATH] = (
            "file",
            manifest_identity[0],
            manifest_identity[1],
        )
        for directory in sorted(
            created_directories,
            key=lambda item: len(item.relative_to(destination).parts),
            reverse=True,
        ):
            _cut(fault_injector, f"{boundary_prefix}.directory.fsync")
            _fsync_directory(directory)
        _cut(fault_injector, f"{boundary_prefix}.staging.readback")
        snapshot = scan_package(destination, exclude_manifest=True)
        if snapshot.entries != manifest.file_entries or snapshot.tree_digest != manifest.installed_tree_digest:
            raise DeploymentIntegrityError("staged package readback does not match its manifest")
        _verify_installed_modes(destination, manifest)
        manifest_readback, _ = _read_regular_file(manifest_path, label="staged deployment manifest")
        if manifest_readback != manifest.to_bytes():
            raise DeploymentIntegrityError("staged deployment manifest readback differs")
        return root_identity
    except Exception as original_error:
        try:
            ledger = _CleanupLedger(
                root_identity,
                tuple(
                    (relative, *value)
                    for relative, value in sorted(
                        ledger_members.items(), key=lambda item: os.fsencode(item[0])
                    )
                ),
            )
            _remove_tree_exact(destination, root_identity, ledger)
        except Exception:
            raise DeploymentAmbiguousError(
                "package staging cleanup failed; evidence was preserved"
            ) from original_error
        raise


def _capture_cleanup_ledger(path: Path) -> _CleanupLedger:
    root = os.lstat(path)
    if not stat.S_ISDIR(root.st_mode) or root.st_uid != os.geteuid():
        raise DeploymentAmbiguousError("private transaction root is unsafe")
    members: list[tuple[str, str, int, int]] = []
    for member in sorted(path.rglob("*"), key=lambda item: os.fsencode(item)):
        metadata = os.lstat(member)
        if metadata.st_uid != os.geteuid() or stat.S_ISLNK(metadata.st_mode):
            raise DeploymentAmbiguousError("private transaction member is unsafe")
        if stat.S_ISREG(metadata.st_mode):
            kind = "file"
            if metadata.st_nlink != 1:
                raise DeploymentAmbiguousError("private transaction file topology is unsafe")
        elif stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
        else:
            raise DeploymentAmbiguousError("private transaction member type is unsafe")
        members.append(
            (
                member.relative_to(path).as_posix(),
                kind,
                metadata.st_dev,
                metadata.st_ino,
            )
        )
    return _CleanupLedger(_identity(root), tuple(members))


def _remove_tree_exact(
    path: Path,
    expected_identity: tuple[int, int],
    ledger: _CleanupLedger | None = None,
) -> None:
    try:
        root = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError:
        raise DeploymentAmbiguousError("cannot inspect private transaction evidence") from None
    if not stat.S_ISDIR(root.st_mode) or _identity(root) != expected_identity:
        raise DeploymentAmbiguousError("private transaction evidence changed identity")
    if ledger is not None:
        actual = _capture_cleanup_ledger(path)
        if actual != ledger or ledger.root_identity != expected_identity:
            raise DeploymentAmbiguousError(
                "private transaction membership changed; evidence was preserved"
            )
    for current_root, directory_names, file_names in os.walk(path, topdown=False, followlinks=False):
        current = Path(current_root)
        for name in file_names:
            member = current / name
            metadata = os.lstat(member)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise DeploymentAmbiguousError("private transaction file changed identity")
            os.unlink(member)
        for name in directory_names:
            member = current / name
            metadata = os.lstat(member)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise DeploymentAmbiguousError("private transaction directory changed identity")
            os.rmdir(member)
    if _identity(os.lstat(path)) != expected_identity:
        raise DeploymentAmbiguousError("private transaction root changed before cleanup")
    os.rmdir(path)
    _fsync_directory(path.parent)


def _unlink_exact(path: Path, expected_identity: tuple[int, int]) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode) or _identity(metadata) != expected_identity:
        raise DeploymentAmbiguousError("transaction file changed before cleanup")
    os.unlink(path)
    _fsync_directory(path.parent)


def _cleanup_created_file(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
    ):
        raise DeploymentAmbiguousError("private transaction file is unsafe to clean")
    os.unlink(path)
    _fsync_directory(path.parent)


def _publish_instruction(
    paths: DeploymentPaths,
    prior: _AgentsFile,
    desired: bytes,
    *,
    mode: int,
    operation_id: str,
    fault_injector: _FaultInjector | None = None,
) -> _PublishedInstruction:
    if prior.data == desired and prior.mode == mode:
        return _PublishedInstruction(False, prior, None, None, None)
    temporary = _new_temporary(paths.codex_home, label="rsi-agents", operation_id=operation_id)
    active_identity: tuple[int, int] | None = None
    old_identity: tuple[int, int] | None = None
    try:
        new_identity = _write_new_file(
            temporary,
            desired,
            mode=mode,
            fault_injector=fault_injector,
            write_boundary="instruction.temp.write",
            fsync_boundary="instruction.temp.fsync",
        )
        _cut(fault_injector, "instruction.replace")
        if prior.data is None:
            active_identity = _rename_noreplace(temporary, paths.agents_file)
        else:
            current = _read_agents(paths.agents_file)
            if (
                current.data != prior.data
                or current.mode != prior.mode
                or (current.device, current.inode) != (prior.device, prior.inode)
            ):
                raise DeploymentIntegrityError("global instruction file drifted before publication")
            active_identity, old_identity = _exchange(temporary, paths.agents_file)
            if active_identity != new_identity or old_identity != (prior.device, prior.inode):
                raise DeploymentAmbiguousError("global instruction exchange identity is ambiguous")
        _cut(fault_injector, "instruction.parent.fsync")
        _fsync_directory(paths.codex_home)
        _cut(fault_injector, "instruction.readback")
        readback = _read_agents(paths.agents_file)
        if readback.data != desired or readback.mode != mode or (
            readback.device,
            readback.inode,
        ) != active_identity:
            raise DeploymentAmbiguousError("global instruction publication readback differs")
        return _PublishedInstruction(True, prior, temporary, active_identity, old_identity)
    except DeploymentAmbiguousError:
        raise
    except Exception as original_error:
        try:
            if active_identity is not None:
                _restore_instruction(
                    paths,
                    _PublishedInstruction(
                        True,
                        prior,
                        temporary,
                        active_identity,
                        old_identity,
                    ),
                )
            else:
                _cleanup_created_file(temporary)
        except Exception:
            raise DeploymentAmbiguousError(
                "global instruction publication rollback failed; evidence was preserved"
            ) from original_error
        raise


def _restore_instruction(paths: DeploymentPaths, publication: _PublishedInstruction) -> None:
    if not publication.changed or publication.temporary is None:
        return
    current = _read_agents(paths.agents_file)
    if (current.device, current.inode) != publication.active_identity:
        raise DeploymentAmbiguousError("global instruction identity drifted before rollback")
    if publication.prior.data is None:
        restored_identity = _rename_noreplace(paths.agents_file, publication.temporary)
        if restored_identity != publication.active_identity:
            raise DeploymentAmbiguousError("global instruction absence rollback is ambiguous")
        _fsync_directory(paths.codex_home)
        _unlink_exact(publication.temporary, publication.active_identity)
        if _read_agents(paths.agents_file).data is not None:
            raise DeploymentAmbiguousError("global instruction absence was not restored")
        return
    if publication.old_identity is None:
        raise DeploymentAmbiguousError("global instruction rollback evidence is missing")
    active_identity, old_identity = _exchange(publication.temporary, paths.agents_file)
    if active_identity != publication.old_identity or old_identity != publication.active_identity:
        raise DeploymentAmbiguousError("global instruction reverse exchange differs")
    _fsync_directory(paths.codex_home)
    restored = _read_agents(paths.agents_file)
    if (
        restored.data != publication.prior.data
        or restored.mode != publication.prior.mode
        or (restored.device, restored.inode) != publication.old_identity
    ):
        raise DeploymentAmbiguousError("global instruction rollback readback differs")
    _unlink_exact(publication.temporary, publication.active_identity)


def _discard_prior_instruction(paths: DeploymentPaths, publication: _PublishedInstruction) -> None:
    if publication.changed and publication.temporary is not None and publication.old_identity is not None:
        _unlink_exact(publication.temporary, publication.old_identity)


def _publish_immutable_file(
    path: Path,
    payload: bytes,
    *,
    operation_id: str,
    kind: str,
    fault_injector: _FaultInjector | None = None,
) -> _PublishedFile:
    temporary = _new_temporary(path.parent, label=path.name, operation_id=operation_id)
    try:
        identity = _write_new_file(
            temporary,
            payload,
            mode=0o600,
            fault_injector=fault_injector,
            write_boundary=f"receipt.{kind}.write",
            fsync_boundary=f"receipt.{kind}.fsync",
        )
    except Exception:
        _cleanup_created_file(temporary)
        raise
    try:
        published_identity = _rename_noreplace(temporary, path)
    except DeploymentAmbiguousError:
        raise
    except Exception as original_error:
        try:
            _unlink_exact(temporary, identity)
        except Exception:
            raise DeploymentAmbiguousError(
                "immutable publication cleanup is ambiguous; evidence was preserved"
            ) from original_error
        raise
    if published_identity != identity:
        raise DeploymentAmbiguousError("immutable publication identity differs")
    try:
        _cut(fault_injector, f"receipt.{kind}.parent_fsync")
        _fsync_directory(path.parent)
        _cut(fault_injector, f"receipt.{kind}.readback")
        readback, stable = _read_regular_file(path, label=f"immutable {path.name}")
        if readback != payload or _identity(stable) != identity:
            raise DeploymentAmbiguousError("immutable publication readback differs")
        return _PublishedFile(path, identity)
    except Exception as original_error:
        if kind == "marker":
            raise DeploymentAmbiguousError(
                "receipt marker durability is ambiguous; evidence was preserved"
            ) from original_error
        try:
            _unlink_exact(path, identity)
        except Exception:
            raise DeploymentAmbiguousError(
                "receipt manifest cleanup is ambiguous; evidence was preserved"
            ) from original_error
        raise


def _validate_operation_id(operation_id: str) -> None:
    try:
        DeploymentReceipt(
            operation_id=operation_id,
            manifest_byte_length=1,
            manifest_digest="sha256:" + "0" * 64,
        )
    except DeploymentSchemaError:
        raise DeploymentError("deployment operation ID is invalid") from None


def _manifest_for_source(admitted: _AdmittedSource, operation_id: str) -> DeploymentManifest:
    installed_at = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    return DeploymentManifest(
        source_repository=os.fspath(admitted.repository),
        source_commit=admitted.commit,
        package_relative_path=PACKAGE_RELATIVE_PATH,
        production_allowlist_digest=admitted.allowlist_digest,
        file_entries=admitted.snapshot.entries,
        source_tree_digest=admitted.snapshot.tree_digest,
        installed_tree_digest=admitted.snapshot.tree_digest,
        managed_instruction_block_digest=MANAGED_BLOCK_DIGEST,
        installed_at=installed_at,
        operation_id=operation_id,
    )


def _active_receipt(paths: DeploymentPaths) -> tuple[DeploymentManifest, DeploymentReceipt] | None:
    status = _verified_status(paths)
    if status.state == "not-installed":
        return None
    if not status.verified or status.operation_id is None:
        raise DeploymentIntegrityError("current deployment is not verified")
    manifest_bytes, _ = _read_regular_file(
        paths.installed_root / MANIFEST_RELATIVE_PATH,
        label="installed deployment manifest",
    )
    receipt_bytes, _ = _read_regular_file(
        paths.receipts_root / f"{status.operation_id}.json",
        label="deployment receipt",
    )
    return DeploymentManifest.from_bytes(manifest_bytes), DeploymentReceipt.from_bytes(receipt_bytes)


def _operation_replay(
    paths: DeploymentPaths,
    admitted: _AdmittedSource,
    operation_id: str,
) -> DeploymentReceipt | None:
    marker = paths.receipts_root / f"{operation_id}.json"
    manifest_copy = paths.receipts_root / f"{operation_id}.manifest.json"
    marker_exists = marker.exists()
    manifest_exists = manifest_copy.exists()
    if not marker_exists and not manifest_exists:
        return None
    if not marker_exists or not manifest_exists:
        raise DeploymentAmbiguousError("operation has partial immutable authority")
    marker_bytes, _ = _read_regular_file(marker, label="existing deployment receipt")
    manifest_bytes, _ = _read_regular_file(manifest_copy, label="existing receipt manifest")
    receipt = DeploymentReceipt.from_bytes(marker_bytes)
    manifest = DeploymentManifest.from_bytes(manifest_bytes)
    request_matches = (
        receipt.operation_id == operation_id
        and manifest.operation_id == operation_id
        and receipt.manifest_byte_length == len(manifest_bytes)
        and receipt.manifest_digest == _sha256(manifest_bytes)
        and _active_matches_deploy_request(manifest, admitted)
    )
    if not request_matches:
        raise DeploymentOperationConflict("deployment operation ID conflicts with immutable authority")
    request_backup = _find_backup_for_successor(paths, operation_id)
    request_metadata = _canonical_mapping(
        request_backup.identity_payload,
        label="deployment replay backup metadata",
    )
    if (
        request_metadata.get("operationKind") != "deploy"
        or request_metadata.get("requestReceiptId") is not None
    ):
        raise DeploymentOperationConflict(
            "deployment replay operation kind conflicts with immutable authority"
        )
    active = _active_receipt(paths)
    if active is None or active[0].operation_id != operation_id or active[1] != receipt:
        raise DeploymentOperationConflict("replayed operation is not the active verified deployment")
    return receipt


def _active_matches_deploy_request(
    manifest: DeploymentManifest,
    admitted: _AdmittedSource,
) -> bool:
    return (
        manifest.source_repository == os.fspath(admitted.repository)
        and manifest.source_commit == admitted.commit
        and manifest.source_tree_digest == admitted.snapshot.tree_digest
        and manifest.installed_tree_digest == admitted.snapshot.tree_digest
        and manifest.file_entries == admitted.snapshot.entries
        and manifest.production_allowlist_digest == admitted.allowlist_digest
        and manifest.production_allowlist_entry_count == 0
        and manifest.managed_instruction_block_digest == MANAGED_BLOCK_DIGEST
        and manifest.mode == "observe"
        and manifest.hook_mode == "late-review"
    )


def _verify_active_before_receipt(
    paths: DeploymentPaths,
    manifest: DeploymentManifest,
    expected_agents: bytes,
) -> None:
    manifest_bytes, _ = _read_regular_file(
        paths.installed_root / MANIFEST_RELATIVE_PATH,
        label="installed deployment manifest",
    )
    if manifest_bytes != manifest.to_bytes():
        raise DeploymentIntegrityError("installed manifest differs before receipt publication")
    snapshot = scan_package(paths.installed_root, exclude_manifest=True)
    if snapshot.entries != manifest.file_entries or snapshot.tree_digest != manifest.installed_tree_digest:
        raise DeploymentIntegrityError("installed package differs before receipt publication")
    _verify_installed_modes(paths.installed_root, manifest)
    agents = _read_agents(paths.agents_file)
    if agents.data != expected_agents:
        raise DeploymentIntegrityError("global instructions differ before receipt publication")
    verify_agents_bytes(expected_agents, manifest.managed_instruction_block_digest)


def _canonical_mapping(payload: bytes, *, label: str) -> dict[str, object]:
    value = _strict_json(payload, label=label)
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise DeploymentIntegrityError(f"{label} is not canonical JSON")
    return value


def _backup_identity_payload(
    prior_manifest_bytes: bytes,
    prior_manifest: DeploymentManifest,
    agents: _AgentsFile,
    successor_manifest: DeploymentManifest,
    *,
    operation_kind: str = "deploy",
    request_receipt_id: str | None = None,
) -> bytes:
    if agents.data is None:
        agents_arm: dict[str, object] = {"state": "absent"}
    else:
        if agents.mode is None:
            raise DeploymentIntegrityError("present global instruction mode is missing")
        agents_arm = {
            "state": "present",
            "byteLength": len(agents.data),
            "digest": _sha256(agents.data),
            "mode": agents.mode,
        }
    return canonical_json_bytes(
        {
            "schemaVersion": 1,
            "domain": "rsi-global-deployment-backup-v1",
            "packageState": "present",
            "packageTreeDigest": prior_manifest.installed_tree_digest,
            "packageManifestByteLength": len(prior_manifest_bytes),
            "packageManifestDigest": _sha256(prior_manifest_bytes),
            "agents": agents_arm,
            "successorOperationId": successor_manifest.operation_id,
            "successorManifestDigest": _sha256(successor_manifest.to_bytes()),
            "operationKind": operation_kind,
            "requestReceiptId": request_receipt_id,
        }
    )


def _absent_backup_identity_payload(
    agents: _AgentsFile,
    successor_manifest: DeploymentManifest,
) -> bytes:
    agents_arm: dict[str, object]
    if agents.data is None:
        agents_arm = {"state": "absent"}
    else:
        if agents.mode is None:
            raise DeploymentIntegrityError("present global instruction mode is missing")
        agents_arm = {
            "state": "present",
            "byteLength": len(agents.data),
            "digest": _sha256(agents.data),
            "mode": agents.mode,
        }
    return canonical_json_bytes(
        {
            "schemaVersion": 1,
            "domain": "rsi-global-deployment-backup-v1",
            "packageState": "absent",
            "agents": agents_arm,
            "successorOperationId": successor_manifest.operation_id,
            "successorManifestDigest": _sha256(successor_manifest.to_bytes()),
            "operationKind": "deploy",
            "requestReceiptId": None,
        }
    )


def _validate_backup(
    path: Path,
    *,
    expected_payload: bytes | None = None,
) -> _BackupRecord:
    root = _safe_directory(path, exact_private=True)
    try:
        root_members = {entry.name for entry in os.scandir(path)}
    except OSError:
        raise DeploymentIntegrityError("cannot enumerate deployment backup") from None
    metadata_bytes, metadata_stat = _read_regular_file(
        path / "backup.json", label="deployment backup metadata"
    )
    if stat.S_IMODE(metadata_stat.st_mode) != 0o600:
        raise DeploymentIntegrityError("deployment backup metadata mode is invalid")
    metadata = _canonical_mapping(metadata_bytes, label="deployment backup metadata")
    if expected_payload is not None and metadata_bytes != expected_payload:
        raise DeploymentIntegrityError("deployment backup identity payload differs")
    common_keys = {
        "schemaVersion",
        "domain",
        "packageState",
        "agents",
        "successorOperationId",
        "successorManifestDigest",
        "operationKind",
        "requestReceiptId",
    }
    present_keys = common_keys | {
        "packageTreeDigest",
        "packageManifestByteLength",
        "packageManifestDigest",
    }
    package_state = metadata.get("packageState")
    if (
        set(metadata) != (present_keys if package_state == "present" else common_keys)
        or metadata.get("schemaVersion") != 1
        or metadata.get("domain") != "rsi-global-deployment-backup-v1"
        or package_state not in {"present", "absent"}
        or metadata.get("operationKind") not in {"deploy", "rollback"}
        or (
            metadata.get("requestReceiptId") is not None
            and type(metadata.get("requestReceiptId")) is not str
        )
    ):
        raise DeploymentIntegrityError("deployment backup metadata schema is invalid")
    if path.name != _sha256(metadata_bytes):
        raise DeploymentIntegrityError("deployment backup directory digest is invalid")
    expected_members = {"backup.json", "agents.bin"} if (path / "agents.bin").exists() else {"backup.json"}
    manifest: DeploymentManifest | None = None
    if package_state == "present":
        expected_members |= {"manifest.json", "package"}
        manifest_bytes, manifest_stat = _read_regular_file(
            path / "manifest.json", label="deployment backup manifest"
        )
        if stat.S_IMODE(manifest_stat.st_mode) != 0o600:
            raise DeploymentIntegrityError("deployment backup manifest mode is invalid")
        manifest = DeploymentManifest.from_bytes(manifest_bytes)
        if (
            metadata.get("packageTreeDigest") != manifest.installed_tree_digest
            or metadata.get("packageManifestByteLength") != len(manifest_bytes)
            or metadata.get("packageManifestDigest") != _sha256(manifest_bytes)
        ):
            raise DeploymentIntegrityError("deployment backup package binding is invalid")
        package = path / "package"
        snapshot = scan_package(package, exclude_manifest=True)
        if snapshot.entries != manifest.file_entries or snapshot.tree_digest != manifest.installed_tree_digest:
            raise DeploymentIntegrityError("deployment backup package differs from its manifest")
        package_manifest_bytes, _ = _read_regular_file(
            package / MANIFEST_RELATIVE_PATH,
            label="deployment backup package manifest",
        )
        if package_manifest_bytes != manifest_bytes:
            raise DeploymentIntegrityError("deployment backup manifest copies differ")
        _verify_installed_modes(package, manifest)
    if root_members != expected_members:
        raise DeploymentIntegrityError("deployment backup contains an unlisted member")
    agents_value = metadata.get("agents")
    if not isinstance(agents_value, dict):
        raise DeploymentIntegrityError("deployment backup AGENTS arm is invalid")
    state = agents_value.get("state")
    if state == "absent":
        if set(agents_value) != {"state"} or (path / "agents.bin").exists():
            raise DeploymentIntegrityError("absent deployment backup AGENTS arm is invalid")
        agents = _AgentsFile(None, None, None, None)
    elif state == "present":
        if set(agents_value) != {"state", "byteLength", "digest", "mode"}:
            raise DeploymentIntegrityError("present deployment backup AGENTS arm is invalid")
        agents_bytes, agents_stat = _read_regular_file(
            path / "agents.bin", label="deployment backup AGENTS bytes"
        )
        if stat.S_IMODE(agents_stat.st_mode) != 0o600:
            raise DeploymentIntegrityError("deployment backup AGENTS storage mode is invalid")
        mode = agents_value.get("mode")
        if (
            type(mode) is not int
            or mode < 0
            or mode > 0o777
            or agents_value.get("byteLength") != len(agents_bytes)
            or agents_value.get("digest") != _sha256(agents_bytes)
        ):
            raise DeploymentIntegrityError("deployment backup AGENTS binding is invalid")
        agents = _AgentsFile(agents_bytes, mode, agents_stat.st_dev, agents_stat.st_ino)
    else:
        raise DeploymentIntegrityError("deployment backup AGENTS state is invalid")
    return _BackupRecord(
        path=path,
        identity_payload=metadata_bytes,
        root_identity=_identity(root),
        created=False,
        prior_manifest=manifest,
        agents=agents,
        cleanup_ledger=_capture_cleanup_ledger(path),
    )


def _create_backup(
    paths: DeploymentPaths,
    prior_manifest: DeploymentManifest,
    prior_agents: _AgentsFile,
    successor_manifest: DeploymentManifest,
    *,
    operation_kind: str = "deploy",
    request_receipt_id: str | None = None,
    fault_injector: _FaultInjector | None = None,
) -> _BackupRecord:
    prior_manifest_bytes, _ = _read_regular_file(
        paths.installed_root / MANIFEST_RELATIVE_PATH,
        label="installed deployment manifest for backup",
    )
    if DeploymentManifest.from_bytes(prior_manifest_bytes) != prior_manifest:
        raise DeploymentIntegrityError("installed manifest drifted before backup")
    identity_payload = _backup_identity_payload(
        prior_manifest_bytes,
        prior_manifest,
        prior_agents,
        successor_manifest,
        operation_kind=operation_kind,
        request_receipt_id=request_receipt_id,
    )
    final = paths.backups_root / _sha256(identity_payload)
    try:
        os.lstat(final)
    except FileNotFoundError:
        pass
    else:
        existing = _validate_backup(final, expected_payload=identity_payload)
        return existing

    temporary = _new_temporary(
        paths.backups_root,
        label="rsi-backup-stage",
        operation_id=successor_manifest.operation_id,
    )
    _cut(fault_injector, "backup.staging.create")
    try:
        os.mkdir(temporary, 0o700)
        os.chmod(temporary, 0o700, follow_symlinks=False)
    except OSError:
        raise DeploymentError("cannot create private backup staging directory") from None
    temporary_identity = _identity(_safe_directory(temporary, exact_private=True))
    published = False
    try:
        active_snapshot = scan_package(paths.installed_root, exclude_manifest=True)
        if (
            active_snapshot.entries != prior_manifest.file_entries
            or active_snapshot.tree_digest != prior_manifest.installed_tree_digest
        ):
            raise DeploymentIntegrityError("active package drifted before backup")
        backup_source = _AdmittedSource(
            repository=Path(prior_manifest.source_repository),
            commit=prior_manifest.source_commit,
            package_root=paths.installed_root,
            snapshot=active_snapshot,
            allowlist_digest=prior_manifest.production_allowlist_digest,
        )
        _stage_package(
            backup_source,
            prior_manifest,
            temporary / "package",
            fault_injector=fault_injector,
            boundary_prefix="backup.package",
        )
        _write_new_file(
            temporary / "manifest.json",
            prior_manifest_bytes,
            mode=0o600,
            fault_injector=fault_injector,
            write_boundary="backup.manifest.write",
            fsync_boundary="backup.manifest.fsync",
        )
        if prior_agents.data is not None:
            _write_new_file(
                temporary / "agents.bin",
                prior_agents.data,
                mode=0o600,
                fault_injector=fault_injector,
                write_boundary="backup.agents.write",
                fsync_boundary="backup.agents.fsync",
            )
        _write_new_file(
            temporary / "backup.json",
            identity_payload,
            mode=0o600,
            fault_injector=fault_injector,
            write_boundary="backup.metadata.write",
            fsync_boundary="backup.metadata.fsync",
        )
        _cut(fault_injector, "backup.directory.fsync")
        _fsync_directory(temporary)
        _cut(fault_injector, "backup.rename")
        published_identity = _rename_noreplace(temporary, final)
        if published_identity != temporary_identity:
            raise DeploymentAmbiguousError("deployment backup publication identity differs")
        published = True
        _cut(fault_injector, "backup.parent.fsync")
        _fsync_directory(paths.backups_root)
        _cut(fault_injector, "backup.readback")
        record = _validate_backup(final, expected_payload=identity_payload)
    except DeploymentAmbiguousError:
        raise
    except Exception as original_error:
        try:
            _remove_tree_exact(
                final if published else temporary,
                temporary_identity,
            )
        except Exception:
            raise DeploymentAmbiguousError(
                "backup staging cleanup failed; evidence was preserved"
            ) from original_error
        raise
    return _BackupRecord(
        path=record.path,
        identity_payload=record.identity_payload,
        root_identity=record.root_identity,
        created=True,
        prior_manifest=record.prior_manifest,
        agents=record.agents,
        cleanup_ledger=record.cleanup_ledger,
    )


def _create_absent_backup(
    paths: DeploymentPaths,
    prior_agents: _AgentsFile,
    successor_manifest: DeploymentManifest,
    *,
    fault_injector: _FaultInjector | None = None,
) -> _BackupRecord:
    identity_payload = _absent_backup_identity_payload(prior_agents, successor_manifest)
    final = paths.backups_root / _sha256(identity_payload)
    try:
        os.lstat(final)
    except FileNotFoundError:
        pass
    else:
        return _validate_backup(final, expected_payload=identity_payload)
    temporary = _new_temporary(
        paths.backups_root,
        label="rsi-backup-stage",
        operation_id=successor_manifest.operation_id,
    )
    _cut(fault_injector, "backup.staging.create")
    try:
        os.mkdir(temporary, 0o700)
        os.chmod(temporary, 0o700, follow_symlinks=False)
    except OSError:
        raise DeploymentError("cannot create private backup staging directory") from None
    temporary_identity = _identity(_safe_directory(temporary, exact_private=True))
    published = False
    try:
        if prior_agents.data is not None:
            _write_new_file(
                temporary / "agents.bin",
                prior_agents.data,
                mode=0o600,
                fault_injector=fault_injector,
                write_boundary="backup.agents.write",
                fsync_boundary="backup.agents.fsync",
            )
        _write_new_file(
            temporary / "backup.json",
            identity_payload,
            mode=0o600,
            fault_injector=fault_injector,
            write_boundary="backup.metadata.write",
            fsync_boundary="backup.metadata.fsync",
        )
        _cut(fault_injector, "backup.directory.fsync")
        _fsync_directory(temporary)
        ledger = _capture_cleanup_ledger(temporary)
        _cut(fault_injector, "backup.rename")
        if _rename_noreplace(temporary, final) != temporary_identity:
            raise DeploymentAmbiguousError("deployment backup publication identity differs")
        published = True
        _cut(fault_injector, "backup.parent.fsync")
        _fsync_directory(paths.backups_root)
        _cut(fault_injector, "backup.readback")
        record = _validate_backup(final, expected_payload=identity_payload)
    except DeploymentAmbiguousError:
        raise
    except Exception as original_error:
        try:
            target = final if published else temporary
            _remove_tree_exact(target, temporary_identity, ledger if "ledger" in locals() else None)
        except Exception:
            raise DeploymentAmbiguousError(
                "absent backup cleanup failed; evidence was preserved"
            ) from original_error
        raise
    return _BackupRecord(
        path=record.path,
        identity_payload=record.identity_payload,
        root_identity=record.root_identity,
        created=True,
        prior_manifest=None,
        agents=record.agents,
        cleanup_ledger=record.cleanup_ledger,
    )


def _find_backup_for_successor(paths: DeploymentPaths, operation_id: str) -> _BackupRecord:
    candidates: list[_BackupRecord] = []
    try:
        entries = list(os.scandir(paths.backups_root))
    except OSError:
        raise DeploymentIntegrityError("cannot enumerate deployment backups") from None
    if len(entries) > 4096:
        raise DeploymentIntegrityError("deployment backup count exceeds its bound")
    for entry in entries:
        if not entry.name.startswith("sha256:"):
            raise DeploymentIntegrityError("deployment backup root contains an unknown member")
        record = _validate_backup(Path(entry.path))
        metadata = _canonical_mapping(
            record.identity_payload, label="deployment backup metadata"
        )
        if metadata.get("successorOperationId") == operation_id:
            candidates.append(record)
    if len(candidates) != 1:
        raise DeploymentIntegrityError("exact rollback backup is missing or ambiguous")
    return candidates[0]


def _remove_backup_if_created(record: _BackupRecord | None) -> None:
    if record is not None and record.created:
        _remove_tree_exact(record.path, record.root_identity, record.cleanup_ledger)


def _require_identity(path: Path, expected: tuple[int, int], *, label: str) -> None:
    try:
        actual = os.lstat(path)
    except OSError:
        raise DeploymentIntegrityError(f"{label} disappeared before exchange") from None
    if _identity(actual) != expected:
        raise DeploymentIntegrityError(f"{label} drifted before exchange")


def _exchange_transaction(
    paths: DeploymentPaths,
    source: _AdmittedSource,
    active_manifest: DeploymentManifest,
    current_agents: _AgentsFile,
    desired_agents: bytes,
    desired_agents_mode: int,
    successor_manifest: DeploymentManifest,
    *,
    recheck_source: bool,
    operation_kind: str = "deploy",
    request_receipt_id: str | None = None,
    fault_injector: _FaultInjector | None = None,
) -> DeploymentReceipt:
    operation_id = successor_manifest.operation_id
    manifest_bytes = successor_manifest.to_bytes()
    receipt = DeploymentReceipt(
        operation_id=operation_id,
        manifest_byte_length=len(manifest_bytes),
        manifest_digest=_sha256(manifest_bytes),
    )
    active_identity = _identity(os.lstat(paths.installed_root))
    active_cleanup_ledger = _capture_cleanup_ledger(paths.installed_root)
    stage = _new_temporary(
        paths.skills_root,
        label="rsi-package-stage",
        operation_id=operation_id,
    )
    stage_identity: tuple[int, int] | None = None
    stage_cleanup_ledger: _CleanupLedger | None = None
    exchanged = False
    instruction_publication: _PublishedInstruction | None = None
    receipt_manifest_publication: _PublishedFile | None = None
    backup: _BackupRecord | None = None
    marker_committed = False
    try:
        stage_identity = _stage_package(
            source,
            successor_manifest,
            stage,
            fault_injector=fault_injector,
        )
        stage_cleanup_ledger = _capture_cleanup_ledger(stage)
        if recheck_source:
            _recheck_admitted_source(source)
        current = _active_receipt(paths)
        if current is None or current[0] != active_manifest:
            raise DeploymentIntegrityError("active deployment drifted during staging")
        latest_agents = _read_agents(paths.agents_file)
        if latest_agents != current_agents:
            raise DeploymentIntegrityError("global instructions drifted during staging")
        _require_identity(paths.installed_root, active_identity, label="active package")
        backup = _create_backup(
            paths,
            active_manifest,
            current_agents,
            successor_manifest,
            operation_kind=operation_kind,
            request_receipt_id=request_receipt_id,
            fault_injector=fault_injector,
        )
        _cut(fault_injector, "package.exchange")
        if recheck_source:
            _recheck_admitted_source(source)
        _require_identity(paths.installed_root, active_identity, label="active package")

        new_identity, old_identity = _exchange(stage, paths.installed_root)
        if new_identity != stage_identity or old_identity != active_identity:
            raise DeploymentAmbiguousError("installed package exchange identity differs")
        exchanged = True
        _cut(fault_injector, "package.parent.fsync")
        _fsync_directory(paths.skills_root)

        instruction_publication = _publish_instruction(
            paths,
            current_agents,
            desired_agents,
            mode=desired_agents_mode,
            operation_id=operation_id,
            fault_injector=fault_injector,
        )
        _verify_active_before_receipt(
            paths,
            successor_manifest,
            desired_agents,
        )
        receipt_manifest_publication = _publish_immutable_file(
            paths.receipts_root / f"{operation_id}.manifest.json",
            manifest_bytes,
            operation_id=operation_id,
            kind="manifest",
            fault_injector=fault_injector,
        )
        _publish_immutable_file(
            paths.receipts_root / f"{operation_id}.json",
            receipt.to_bytes(),
            operation_id=operation_id,
            kind="marker",
            fault_injector=fault_injector,
        )
        marker_committed = True
        final = _verified_status(paths)
        if not final.verified or final.operation_id != operation_id:
            raise DeploymentAmbiguousError(
                "committed exchanged deployment does not verify"
            )
    except DeploymentAmbiguousError:
        raise
    except Exception as original_error:
        try:
            if marker_committed:
                raise DeploymentAmbiguousError(
                    "exchange transaction failed after marker publication"
                )
            if receipt_manifest_publication is not None:
                _unlink_exact(
                    receipt_manifest_publication.path,
                    receipt_manifest_publication.identity,
                )
            if instruction_publication is not None:
                _restore_instruction(paths, instruction_publication)
            if exchanged:
                _require_identity(paths.installed_root, stage_identity, label="new active package")  # type: ignore[arg-type]
                _require_identity(stage, active_identity, label="retained old package")
                restored_identity, displaced_identity = _exchange(stage, paths.installed_root)
                if restored_identity != active_identity or displaced_identity != stage_identity:
                    raise DeploymentAmbiguousError("reverse package exchange identity differs")
                _fsync_directory(paths.skills_root)
            if stage_identity is not None:
                _remove_tree_exact(stage, stage_identity, stage_cleanup_ledger)
            _remove_backup_if_created(backup)
        except DeploymentAmbiguousError:
            raise
        except Exception:
            raise DeploymentAmbiguousError(
                "exchange transaction rollback failed; evidence was preserved"
            ) from original_error
        raise
    else:
        if instruction_publication is not None:
            try:
                _discard_prior_instruction(paths, instruction_publication)
            except (DeploymentError, OSError):
                pass
        if stage_identity is not None:
            try:
                _remove_tree_exact(stage, active_identity, active_cleanup_ledger)
            except (DeploymentError, OSError):
                pass
        return receipt


def _read_regular_file(path: Path, *, label: str) -> tuple[bytes, os.stat_result]:
    try:
        named_before = os.lstat(path)
    except OSError:
        raise DeploymentIntegrityError(f"{label} is unavailable") from None
    if not stat.S_ISREG(named_before.st_mode):
        raise DeploymentIntegrityError(f"{label} is not a regular file")
    if named_before.st_uid != os.geteuid() or named_before.st_nlink != 1:
        raise DeploymentIntegrityError(f"{label} has unsafe ownership or link count")
    if named_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise DeploymentIntegrityError(f"{label} has unsafe writable permissions")
    if named_before.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise DeploymentIntegrityError(f"{label} has unsafe special mode bits")
    try:
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
    except OSError:
        raise DeploymentIntegrityError(f"cannot open {label} without following links") from None
    try:
        opened_before = os.fstat(descriptor)
        if (
            opened_before.st_dev,
            opened_before.st_ino,
            opened_before.st_mode,
            opened_before.st_nlink,
            opened_before.st_uid,
            opened_before.st_size,
            opened_before.st_mtime_ns,
            opened_before.st_ctime_ns,
        ) != (
            named_before.st_dev,
            named_before.st_ino,
            named_before.st_mode,
            named_before.st_nlink,
            named_before.st_uid,
            named_before.st_size,
            named_before.st_mtime_ns,
            named_before.st_ctime_ns,
        ):
            raise DeploymentIntegrityError(f"{label} changed before it was opened")
        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = os.read(descriptor, 1024 * 1024)
            except InterruptedError:
                continue
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 16 * 1024 * 1024:
                raise DeploymentIntegrityError(f"{label} exceeds its byte bound")
        opened_after = os.fstat(descriptor)
        try:
            named_after = os.lstat(path)
        except OSError:
            raise DeploymentIntegrityError(f"{label} changed while it was read") from None
        signatures = {
            (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_nlink,
                value.st_uid,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )
            for value in (named_before, opened_before, opened_after, named_after)
        }
        if len(signatures) != 1 or total != opened_after.st_size:
            raise DeploymentIntegrityError(f"{label} changed while it was read")
        return b"".join(chunks), opened_after
    finally:
        os.close(descriptor)


def _read_agents(path: Path) -> _AgentsFile:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return _AgentsFile(None, None, None, None)
    except OSError:
        raise DeploymentIntegrityError("global instruction path is unavailable") from None
    if not stat.S_ISREG(metadata.st_mode):
        raise DeploymentIntegrityError("global instruction path is not a regular file")
    data, stable = _read_regular_file(path, label="global instruction file")
    return _AgentsFile(
        data=data,
        mode=stat.S_IMODE(stable.st_mode),
        device=stable.st_dev,
        inode=stable.st_ino,
    )


def _run_git(repo: Path, *arguments: str) -> bytes:
    environment = {
        **{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
    }
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(repo), *arguments],
            check=False,
            capture_output=True,
            env=environment,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise DeploymentSourceError("Git source inspection failed") from None
    if completed.returncode != 0:
        raise DeploymentSourceError("Git source inspection failed")
    return completed.stdout


def _require_clean_git(repo: Path) -> str:
    top = _run_git(repo, "rev-parse", "--show-toplevel").decode("utf-8", "strict").strip()
    try:
        top_path = Path(top).resolve(strict=True)
    except OSError:
        raise DeploymentSourceError("Git top-level path is unavailable") from None
    if top_path != repo:
        raise DeploymentSourceError("source path is not the exact Git top level")
    commit = _run_git(repo, "rev-parse", "--verify", "HEAD").decode("ascii", "strict").strip()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise DeploymentSourceError("source HEAD is not an exact SHA-1 commit")
    dirty = _run_git(
        repo,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--no-renames",
    )
    if dirty:
        raise DeploymentSourceError("source Git worktree is not exactly clean")
    return commit


def _tracked_package(repo: Path, commit: str) -> dict[str, tuple[bool, str]]:
    raw = _run_git(
        repo,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        commit,
        "--",
        PACKAGE_RELATIVE_PATH,
    )
    result: dict[str, tuple[bool, str]] = {}
    prefix = PACKAGE_RELATIVE_PATH + "/"
    for record in raw.split(b"\x00"):
        if not record:
            continue
        try:
            header, encoded_path = record.split(b"\t", 1)
            mode, kind, object_id = header.split(b" ", 2)
            path = encoded_path.decode("utf-8", "strict")
        except (ValueError, UnicodeDecodeError):
            raise DeploymentSourceError("tracked package identity is malformed") from None
        if kind != b"blob" or mode not in {b"100644", b"100755"} or not path.startswith(prefix):
            raise DeploymentSourceError("tracked package contains an unsupported Git member")
        relative = path[len(prefix) :]
        if not relative or relative in result:
            raise DeploymentSourceError("tracked package membership is ambiguous")
        try:
            object_text = object_id.decode("ascii", "strict")
        except UnicodeDecodeError:
            raise DeploymentSourceError("tracked package object identity is malformed") from None
        if len(object_text) != 40 or any(value not in "0123456789abcdef" for value in object_text):
            raise DeploymentSourceError("tracked package object identity is malformed")
        result[relative] = (mode == b"100755", object_text)
    if not result:
        raise DeploymentSourceError("tracked package is empty")
    return result


def _verify_head_package_bytes(
    repository: Path,
    commit: str,
    package_root: Path,
    snapshot: PackageSnapshot,
) -> None:
    tracked = _tracked_package(repository, commit)
    if set(tracked) != set(snapshot.relative_paths):
        raise DeploymentSourceError("tracked package membership does not match the source tree")
    entries = {entry.relative_path: entry for entry in snapshot.entries}
    for relative, (executable, object_id) in tracked.items():
        entry = entries[relative]
        if executable is not entry.executable:
            raise DeploymentSourceError("tracked package executable identity does not match")
        head_bytes = _run_git(repository, "cat-file", "blob", object_id)
        working_bytes, _ = _read_regular_file(
            package_root / relative,
            label=f"source package member {relative}",
        )
        if head_bytes != working_bytes:
            raise DeploymentSourceError("source package differs from exact HEAD blob bytes")


def _recheck_admitted_source(admitted: _AdmittedSource) -> None:
    if _require_clean_git(admitted.repository) != admitted.commit:
        raise DeploymentSourceError("source HEAD changed during admission")
    verify_package_snapshot(admitted.package_root, admitted.snapshot)
    _verify_head_package_bytes(
        admitted.repository,
        admitted.commit,
        admitted.package_root,
        admitted.snapshot,
    )


def _strict_json(payload: bytes, *, label: str) -> object:
    if payload.startswith(b"\xef\xbb\xbf") or b"\x00" in payload or b"\r" in payload:
        raise DeploymentSourceError(f"{label} is not strict JSON")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise DeploymentSourceError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    def reject_float(_value: str) -> object:
        raise DeploymentSourceError(f"{label} contains a JSON float")

    try:
        return json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=unique,
            parse_float=reject_float,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                DeploymentSourceError(f"{label} contains a non-finite JSON number")
            ),
        )
    except DeploymentSourceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise DeploymentSourceError(f"{label} is not strict JSON") from None


def _strict_yaml(payload: bytes, *, label: str) -> object:
    """Parse the deliberately small, mapping-only package YAML profile.

    Deployment does not acquire a runtime YAML dependency.  The installed
    package's agent metadata uses a closed two-space-indented mapping subset;
    unsupported YAML features fail closed and the canonical skill validator
    independently parses ``SKILL.md`` with its maintained YAML implementation.
    """

    if payload.startswith(b"\xef\xbb\xbf") or b"\x00" in payload or b"\r" in payload:
        raise DeploymentSourceError(f"{label} is not strict YAML")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise DeploymentSourceError(f"{label} is not strict YAML") from None
    root: dict[str, object] = {}
    stack: list[tuple[int, dict[str, object]]] = [(-2, root)]
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if "\t" in raw_line:
            raise DeploymentSourceError(f"{label} is not strict YAML")
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent % 2 or indent > 32:
            raise DeploymentSourceError(f"{label} is not strict YAML")
        line = raw_line[indent:]
        if line.startswith(("---", "...", "%", "- ")) or ":" not in line:
            raise DeploymentSourceError(f"{label} uses unsupported YAML syntax")
        key, raw_value = line.split(":", 1)
        if (
            not key
            or not (key[0].isalpha() or key[0] == "_")
            or any(not (character.isalnum() or character in "_-") for character in key)
        ):
            raise DeploymentSourceError(f"{label} contains an invalid YAML key")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack or stack[-1][0] != indent - 2:
            raise DeploymentSourceError(f"{label} has invalid YAML indentation")
        parent = stack[-1][1]
        if key in parent:
            raise DeploymentSourceError(f"{label} contains a duplicate YAML key")
        value_text = raw_value.strip()
        if not value_text:
            value: object = {}
            parent[key] = value
            stack.append((indent, value))
            continue
        if any(token in value_text for token in ("&", "*", "!!", "${")):
            raise DeploymentSourceError(f"{label} uses unsupported YAML features")
        if value_text.startswith('"'):
            try:
                value = json.loads(value_text)
            except (json.JSONDecodeError, ValueError):
                raise DeploymentSourceError(f"{label} has an invalid YAML string") from None
            if type(value) is not str:
                raise DeploymentSourceError(f"{label} has an invalid YAML scalar")
        elif value_text.startswith("'"):
            if len(value_text) < 2 or not value_text.endswith("'"):
                raise DeploymentSourceError(f"{label} has an invalid YAML string")
            value = value_text[1:-1].replace("''", "'")
        elif value_text in {"true", "false"}:
            value = value_text == "true"
        elif value_text in {"null", "~"}:
            value = None
        elif value_text.lstrip("-").isdigit():
            value = int(value_text)
        elif any(token in value_text for token in ("{", "}", "[", "]", " #", ": ")):
            raise DeploymentSourceError(f"{label} uses unsupported YAML syntax")
        else:
            value = value_text
        parent[key] = value
    if not root:
        raise DeploymentSourceError(f"{label} is empty YAML")
    return root


def _validate_package_documents(package: Path, snapshot: PackageSnapshot) -> str:
    if "scripts/rsi.py" not in snapshot.relative_paths:
        raise DeploymentSourceError("RSI package entry point is missing")
    parsed_json: dict[str, object] = {}
    for entry in snapshot.entries:
        suffix = Path(entry.relative_path).suffix.lower()
        if suffix not in {".json", ".yaml", ".yml"}:
            continue
        payload, _metadata = _read_regular_file(
            package / entry.relative_path,
            label=f"package member {entry.relative_path}",
        )
        if suffix == ".json":
            parsed_json[entry.relative_path] = _strict_json(
                payload, label=entry.relative_path
            )
        else:
            _strict_yaml(payload, label=entry.relative_path)

    default = parsed_json.get("profiles/default.json")
    if not isinstance(default, dict) or default.get("mode") != "observe":
        raise DeploymentSourceError("default profile is not exactly observe mode")
    orchestration = default.get("orchestration")
    if not isinstance(orchestration, dict) or orchestration.get("hookMode") != "late-review":
        raise DeploymentSourceError("default profile is not exactly late-review")
    production = parsed_json.get("profiles/production.json")
    activation = production.get("activation") if isinstance(production, dict) else None
    allowlist = activation.get("allowedTargets") if isinstance(activation, dict) else None
    if type(allowlist) is not list or allowlist:
        raise DeploymentSourceError("production target allowlist is not exactly empty")

    validator = (
        _actual_user_home()
        / ".codex/skills/.system/skill-creator/scripts/quick_validate.py"
    )
    if not validator.is_file():
        raise DeploymentSourceError("skill package validator is unavailable")
    environment = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    try:
        checked = subprocess.run(
            [sys._base_executable, os.fspath(validator), os.fspath(package)],
            check=False,
            capture_output=True,
            env=environment,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise DeploymentSourceError("skill package validator failed") from None
    if checked.returncode != 0:
        raise DeploymentSourceError("skill package validator rejected the source")

    allowlist_bytes = canonical_json_bytes(
        {
            "schemaVersion": 1,
            "domain": _ALLOWLIST_DOMAIN,
            "entries": [],
        }
    )
    return _sha256(allowlist_bytes)


def _admit_source(source_repo: Path) -> _AdmittedSource:
    if not isinstance(source_repo, Path):
        raise DeploymentSourceError("source repository must be a Path")
    try:
        repository = source_repo.resolve(strict=True)
    except OSError:
        raise DeploymentSourceError("source repository is unavailable") from None
    if not repository.is_dir():
        raise DeploymentSourceError("source repository is not a directory")
    commit = _require_clean_git(repository)
    package_root = repository / PACKAGE_RELATIVE_PATH
    snapshot = scan_package(package_root, exclude_manifest=True)
    _verify_head_package_bytes(repository, commit, package_root, snapshot)
    allowlist_digest = _validate_package_documents(package_root, snapshot)
    admitted = _AdmittedSource(
        repository=repository,
        commit=commit,
        package_root=package_root,
        snapshot=snapshot,
        allowlist_digest=allowlist_digest,
    )
    _recheck_admitted_source(admitted)
    return admitted


def _verify_installed_modes(root: Path, manifest: DeploymentManifest) -> None:
    expected = {entry.relative_path: 0o700 if entry.executable else 0o600 for entry in manifest.file_entries}
    expected[MANIFEST_RELATIVE_PATH] = 0o600
    for path in [root, *root.rglob("*")]:
        metadata = os.lstat(path)
        if path.is_symlink():
            raise DeploymentIntegrityError("installed package contains a symlink")
        if metadata.st_uid != os.geteuid():
            raise DeploymentIntegrityError("installed package ownership is invalid")
        relative = "." if path == root else path.relative_to(root).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise DeploymentIntegrityError(f"installed directory mode is invalid: {relative}")
        elif stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1 or relative not in expected:
                raise DeploymentIntegrityError(f"installed file topology is invalid: {relative}")
            if stat.S_IMODE(metadata.st_mode) != expected[relative]:
                raise DeploymentIntegrityError(f"installed file mode is invalid: {relative}")
        else:
            raise DeploymentIntegrityError(f"installed member is invalid: {relative}")


def _verified_status(paths: DeploymentPaths) -> DeploymentStatus:
    if not paths.installed_root.exists():
        absent_marker = paths.state_root / "absent.json"
        try:
            absent_bytes, _ = _read_regular_file(
                absent_marker, label="absent deployment authority"
            )
        except FileNotFoundError:
            absent_bytes = None
        except (DeploymentIntegrityError, OSError):
            absent_bytes = b""
        if absent_bytes:
            try:
                absent = _canonical_mapping(
                    absent_bytes, label="absent deployment authority"
                )
                if set(absent) != {
                    "schemaVersion",
                    "domain",
                    "operationId",
                    "requestReceiptId",
                    "receiptDigest",
                } or absent.get("schemaVersion") != 1 or absent.get(
                    "domain"
                ) != "rsi-global-absent-authority-v1":
                    raise DeploymentIntegrityError("absent deployment authority is invalid")
                operation_id = absent.get("operationId")
                if type(operation_id) is not str:
                    raise DeploymentIntegrityError("absent operation identity is invalid")
                marker_bytes, _ = _read_regular_file(
                    paths.receipts_root / f"{operation_id}.json",
                    label="absent rollback receipt",
                )
                manifest_bytes, _ = _read_regular_file(
                    paths.receipts_root / f"{operation_id}.manifest.json",
                    label="absent rollback manifest",
                )
                receipt = DeploymentReceipt.from_bytes(marker_bytes)
                if (
                    receipt.operation_id != operation_id
                    or receipt.manifest_byte_length != len(manifest_bytes)
                    or receipt.manifest_digest != _sha256(manifest_bytes)
                    or absent.get("receiptDigest") != _sha256(marker_bytes)
                ):
                    raise DeploymentIntegrityError("absent receipt binding is invalid")
                return DeploymentStatus(
                    state="not-installed",
                    installed=False,
                    verified=False,
                    operation_id=operation_id,
                    receipt_digest=_sha256(marker_bytes),
                )
            except (DeploymentError, DeploymentSchemaError, OSError, ValueError) as error:
                return DeploymentStatus(
                    state="ambiguous",
                    installed=False,
                    verified=False,
                    detail=str(error)[:240],
                )
        try:
            orphaned = any(
                entry.name.endswith((".json", ".manifest.json"))
                for entry in os.scandir(paths.receipts_root)
            )
        except FileNotFoundError:
            orphaned = False
        except OSError:
            orphaned = True
        if orphaned:
            return DeploymentStatus(
                state="ambiguous",
                installed=False,
                verified=False,
                detail="receipt authority exists without an installed package",
            )
        return DeploymentStatus(state="not-installed", installed=False, verified=False)
    try:
        installed_manifest_path = paths.installed_root / MANIFEST_RELATIVE_PATH
        if not installed_manifest_path.exists():
            raise DeploymentAmbiguousError("installed deployment manifest is missing")
        manifest_bytes, _manifest_stat = _read_regular_file(
            installed_manifest_path,
            label="installed deployment manifest",
        )
        manifest = DeploymentManifest.from_bytes(manifest_bytes)
        snapshot = scan_package(paths.installed_root, exclude_manifest=True)
        if snapshot.entries != manifest.file_entries or snapshot.tree_digest != manifest.installed_tree_digest:
            raise DeploymentIntegrityError("installed package does not match its manifest")
        _verify_installed_modes(paths.installed_root, manifest)
        installed_allowlist_digest = _validate_package_documents(
            paths.installed_root,
            snapshot,
        )
        if installed_allowlist_digest != manifest.production_allowlist_digest:
            raise DeploymentIntegrityError(
                "installed production allowlist digest differs from its manifest"
            )
        receipt_manifest_path = (
            paths.receipts_root / f"{manifest.operation_id}.manifest.json"
        )
        receipt_path = paths.receipts_root / f"{manifest.operation_id}.json"
        if not receipt_manifest_path.exists() or not receipt_path.exists():
            raise DeploymentAmbiguousError(
                "deployment receipt authority is partial or missing"
            )
        receipt_manifest_bytes, _ = _read_regular_file(
            receipt_manifest_path,
            label="receipt deployment manifest",
        )
        if receipt_manifest_bytes != manifest_bytes:
            raise DeploymentAmbiguousError("deployment manifest copies differ")
        receipt_bytes, _ = _read_regular_file(
            receipt_path,
            label="deployment receipt",
        )
        receipt = DeploymentReceipt.from_bytes(receipt_bytes)
        if (
            receipt.operation_id != manifest.operation_id
            or receipt.manifest_byte_length != len(manifest_bytes)
            or receipt.manifest_digest != _sha256(manifest_bytes)
        ):
            raise DeploymentAmbiguousError("deployment receipt binding is invalid")
        agents = _read_agents(paths.agents_file)
        if agents.data is None:
            raise DeploymentIntegrityError("global instruction file is missing")
        verify_agents_bytes(agents.data, manifest.managed_instruction_block_digest)
        return DeploymentStatus(
            state="verified",
            installed=True,
            verified=True,
            operation_id=manifest.operation_id,
            source_commit=manifest.source_commit,
            tree_digest=manifest.installed_tree_digest,
            manifest_digest=receipt.manifest_digest,
            receipt_digest=_sha256(receipt_bytes),
        )
    except DeploymentAmbiguousError as error:
        return DeploymentStatus(
            state="ambiguous",
            installed=True,
            verified=False,
            detail=str(error)[:240],
        )
    except (
        DeploymentIntegrityError,
        DeploymentSourceError,
        DeploymentSchemaError,
        GlobalInstructionsError,
        OSError,
        ValueError,
    ) as error:
        return DeploymentStatus(
            state="invalid",
            installed=True,
            verified=False,
            detail=str(error)[:240],
        )


def _rollback_initial_to_absent(
    paths: DeploymentPaths,
    active_manifest: DeploymentManifest,
    backup: _BackupRecord,
    receipt_id: str,
    operation_id: str,
    *,
    fault_injector: _FaultInjector | None = None,
) -> DeploymentReceipt:
    successor = DeploymentManifest(
        source_repository=active_manifest.source_repository,
        source_commit=active_manifest.source_commit,
        package_relative_path=PACKAGE_RELATIVE_PATH,
        production_allowlist_digest=active_manifest.production_allowlist_digest,
        file_entries=active_manifest.file_entries,
        source_tree_digest=active_manifest.source_tree_digest,
        installed_tree_digest=active_manifest.installed_tree_digest,
        managed_instruction_block_digest=active_manifest.managed_instruction_block_digest,
        installed_at=datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        operation_id=operation_id,
    )
    manifest_bytes = successor.to_bytes()
    receipt = DeploymentReceipt(
        operation_id=operation_id,
        manifest_byte_length=len(manifest_bytes),
        manifest_digest=_sha256(manifest_bytes),
    )
    current_agents = _read_agents(paths.agents_file)
    active_identity = _identity(os.lstat(paths.installed_root))
    active_ledger = _capture_cleanup_ledger(paths.installed_root)
    retained = _new_temporary(
        paths.skills_root, label="rsi-uninstall", operation_id=operation_id
    )
    package_moved = False
    agents_publication: _PublishedInstruction | None = None
    absent_agents_temp: Path | None = None
    absent_agents_identity: tuple[int, int] | None = None
    manifest_publication: _PublishedFile | None = None
    marker_publication: _PublishedFile | None = None
    try:
        if _rename_noreplace(paths.installed_root, retained) != active_identity:
            raise DeploymentAmbiguousError("atomic uninstall package identity differs")
        package_moved = True
        _fsync_directory(paths.skills_root)
        if backup.agents.data is None:
            if current_agents.data is None or current_agents.device is None or current_agents.inode is None:
                raise DeploymentIntegrityError("current global instructions are unavailable")
            absent_agents_temp = _new_temporary(
                paths.codex_home, label="rsi-agents-uninstall", operation_id=operation_id
            )
            absent_agents_identity = _rename_noreplace(
                paths.agents_file, absent_agents_temp
            )
            if absent_agents_identity != (current_agents.device, current_agents.inode):
                raise DeploymentAmbiguousError("atomic instruction uninstall identity differs")
            _fsync_directory(paths.codex_home)
            if _read_agents(paths.agents_file).data is not None:
                raise DeploymentAmbiguousError("global instruction absence did not verify")
        else:
            if backup.agents.mode is None:
                raise DeploymentIntegrityError("backup global instruction mode is missing")
            agents_publication = _publish_instruction(
                paths,
                current_agents,
                backup.agents.data,
                mode=backup.agents.mode,
                operation_id=operation_id,
                fault_injector=fault_injector,
            )
        manifest_publication = _publish_immutable_file(
            paths.receipts_root / f"{operation_id}.manifest.json",
            manifest_bytes,
            operation_id=operation_id,
            kind="manifest",
            fault_injector=fault_injector,
        )
        marker_publication = _publish_immutable_file(
            paths.receipts_root / f"{operation_id}.json",
            receipt.to_bytes(),
            operation_id=operation_id,
            kind="marker",
            fault_injector=fault_injector,
        )
        absent_payload = canonical_json_bytes(
            {
                "schemaVersion": 1,
                "domain": "rsi-global-absent-authority-v1",
                "operationId": operation_id,
                "requestReceiptId": receipt_id,
                "receiptDigest": _sha256(receipt.to_bytes()),
            }
        )
        _publish_immutable_file(
            paths.state_root / "absent.json",
            absent_payload,
            operation_id=operation_id,
            kind="absent",
            fault_injector=fault_injector,
        )
    except Exception as original_error:
        try:
            if marker_publication is not None:
                _unlink_exact(marker_publication.path, marker_publication.identity)
            if manifest_publication is not None:
                _unlink_exact(manifest_publication.path, manifest_publication.identity)
            if agents_publication is not None:
                _restore_instruction(paths, agents_publication)
            if absent_agents_temp is not None and absent_agents_identity is not None:
                if _rename_noreplace(absent_agents_temp, paths.agents_file) != absent_agents_identity:
                    raise DeploymentAmbiguousError("instruction uninstall rollback differs")
                _fsync_directory(paths.codex_home)
            if package_moved:
                if _rename_noreplace(retained, paths.installed_root) != active_identity:
                    raise DeploymentAmbiguousError("package uninstall rollback differs")
                _fsync_directory(paths.skills_root)
        except Exception:
            raise DeploymentAmbiguousError(
                "initial rollback failed ambiguously; evidence was preserved"
            ) from original_error
        raise
    if agents_publication is not None:
        _discard_prior_instruction(paths, agents_publication)
    if absent_agents_temp is not None and absent_agents_identity is not None:
        _unlink_exact(absent_agents_temp, absent_agents_identity)
    _remove_tree_exact(retained, active_identity, active_ledger)
    return receipt


class GlobalRsiDeployer:
    """Plan and verify one fixed global RSI deployment."""

    def __init__(
        self,
        paths: DeploymentPaths | None = None,
        *,
        fault_injector: _FaultInjector | None = None,
        lock_timeout: float = 5.0,
    ) -> None:
        self.paths = DeploymentPaths.live() if paths is None else paths
        if type(self.paths) is not DeploymentPaths:
            raise DeploymentError("deployment paths are invalid")
        _validate_deployment_paths(self.paths)
        if fault_injector is not None and not self.paths.testing:
            raise DeploymentError("fault injection is available only with explicit test paths")
        if fault_injector is not None and not callable(fault_injector):
            raise DeploymentError("deployment fault injector is invalid")
        if (
            type(lock_timeout) not in {int, float}
            or isinstance(lock_timeout, bool)
            or lock_timeout <= 0
            or lock_timeout > 60
        ):
            raise DeploymentError("deployment lock timeout is invalid")
        if lock_timeout != 5.0 and not self.paths.testing:
            raise DeploymentError("custom lock timeout is available only with test paths")
        self._fault_injector = fault_injector
        self._lock_timeout = float(lock_timeout)

    def plan(self, source_repo: Path) -> DeploymentPlan:
        _validate_deployment_paths(self.paths)
        admitted = _admit_source(source_repo)
        with _shared_lock(self.paths, timeout=self._lock_timeout):
            agents = _read_agents(self.paths.agents_file)
            plan_agents_update(agents.data)
            current = _verified_status(self.paths)
            if current.state == "not-installed":
                action = "install"
            elif not current.verified:
                raise DeploymentIntegrityError("current deployment is not verified")
            else:
                active = _active_receipt(self.paths)
                action = (
                    "no-op"
                    if active is not None
                    and _active_matches_deploy_request(active[0], admitted)
                    else "update"
                )
        return DeploymentPlan(
            eligible=True,
            action=action,
            source_repository=os.fspath(admitted.repository),
            source_commit=admitted.commit,
            source_tree_digest=admitted.snapshot.tree_digest,
            managed_instruction_block_digest=MANAGED_BLOCK_DIGEST,
        )

    def deploy(self, source_repo: Path, operation_id: str) -> DeploymentReceipt:
        """Install one clean source commit and publish immutable authority last."""

        _validate_deployment_paths(self.paths)
        _validate_operation_id(operation_id)
        # A read-only preflight prevents invalid source/instruction input from
        # creating even the private lock layout.  Every identity is repeated
        # after exclusive serialization below.
        _admit_source(source_repo)
        with _shared_lock(self.paths, timeout=self._lock_timeout):
            preflight_agents = _read_agents(self.paths.agents_file)
            try:
                plan_agents_update(preflight_agents.data)
            except GlobalInstructionsError as error:
                raise DeploymentError(str(error)) from None
            preflight_status = _verified_status(self.paths)
            if preflight_status.state not in {"not-installed", "verified"}:
                raise DeploymentIntegrityError("current deployment is not verified")
        _require_atomic_backend()
        with _exclusive_lock(self.paths, timeout=self._lock_timeout):
            admitted = _admit_source(source_repo)
            replay = _operation_replay(self.paths, admitted, operation_id)
            if replay is not None:
                return replay

            active = _active_receipt(self.paths)
            if active is not None:
                if _active_matches_deploy_request(active[0], admitted):
                    return active[1]
                current_agents = _read_agents(self.paths.agents_file)
                try:
                    agents_update = plan_agents_update(current_agents.data)
                except GlobalInstructionsError as error:
                    raise DeploymentError(str(error)) from None
                desired_mode = current_agents.mode
                if current_agents.data is None or desired_mode is None:
                    raise DeploymentIntegrityError(
                        "verified deployment global instructions are unavailable"
                    )
                successor_manifest = _manifest_for_source(admitted, operation_id)
                return _exchange_transaction(
                    self.paths,
                    admitted,
                    active[0],
                    current_agents,
                    agents_update.after,
                    desired_mode,
                    successor_manifest,
                    recheck_source=True,
                    fault_injector=self._fault_injector,
                )

            prior_agents = _read_agents(self.paths.agents_file)
            try:
                agents_update = plan_agents_update(prior_agents.data)
            except GlobalInstructionsError as error:
                raise DeploymentError(str(error)) from None
            desired_mode = (
                agents_update.mode if prior_agents.data is None else prior_agents.mode
            )
            if desired_mode is None:
                raise DeploymentIntegrityError("global instruction mode is unavailable")
            manifest = _manifest_for_source(admitted, operation_id)
            manifest_bytes = manifest.to_bytes()
            receipt = DeploymentReceipt(
                operation_id=operation_id,
                manifest_byte_length=len(manifest_bytes),
                manifest_digest=_sha256(manifest_bytes),
            )
            initial_backup = _create_absent_backup(
                self.paths,
                prior_agents,
                manifest,
                fault_injector=self._fault_injector,
            )
            stage = _new_temporary(
                self.paths.skills_root,
                label="rsi-package-stage",
                operation_id=operation_id,
            )
            stage_identity: tuple[int, int] | None = None
            stage_cleanup_ledger: _CleanupLedger | None = None
            package_published = False
            instruction_publication: _PublishedInstruction | None = None
            receipt_manifest_publication: _PublishedFile | None = None
            marker_committed = False
            try:
                stage_identity = _stage_package(
                    admitted,
                    manifest,
                    stage,
                    fault_injector=self._fault_injector,
                )
                stage_cleanup_ledger = _capture_cleanup_ledger(stage)
                _recheck_admitted_source(admitted)

                _cut(self._fault_injector, "package.rename")
                _recheck_admitted_source(admitted)
                installed_identity = _rename_noreplace(stage, self.paths.installed_root)
                if installed_identity != stage_identity:
                    raise DeploymentAmbiguousError("installed package publication differs")
                package_published = True
                _cut(self._fault_injector, "package.parent.fsync")
                _fsync_directory(self.paths.skills_root)

                instruction_publication = _publish_instruction(
                    self.paths,
                    prior_agents,
                    agents_update.after,
                    mode=desired_mode,
                    operation_id=operation_id,
                    fault_injector=self._fault_injector,
                )
                _verify_active_before_receipt(
                    self.paths,
                    manifest,
                    agents_update.after,
                )

                receipt_manifest_publication = _publish_immutable_file(
                    self.paths.receipts_root / f"{operation_id}.manifest.json",
                    manifest_bytes,
                    operation_id=operation_id,
                    kind="manifest",
                    fault_injector=self._fault_injector,
                )
                _publish_immutable_file(
                    self.paths.receipts_root / f"{operation_id}.json",
                    receipt.to_bytes(),
                    operation_id=operation_id,
                    kind="marker",
                    fault_injector=self._fault_injector,
                )
                marker_committed = True
                final = _verified_status(self.paths)
                if not final.verified or final.operation_id != operation_id:
                    raise DeploymentAmbiguousError(
                        "committed deployment does not verify; evidence was preserved"
                    )
            except DeploymentAmbiguousError:
                raise
            except Exception as original_error:
                try:
                    if marker_committed:
                        raise DeploymentAmbiguousError(
                            "deployment failed after marker publication; evidence was preserved"
                        )
                    if receipt_manifest_publication is not None:
                        _unlink_exact(
                            receipt_manifest_publication.path,
                            receipt_manifest_publication.identity,
                        )
                    if instruction_publication is not None:
                        _restore_instruction(self.paths, instruction_publication)
                    if package_published:
                        restored = _rename_noreplace(self.paths.installed_root, stage)
                        if stage_identity is None or restored != stage_identity:
                            raise DeploymentAmbiguousError(
                                "package rollback identity differs; evidence was preserved"
                            )
                        _fsync_directory(self.paths.skills_root)
                        _remove_tree_exact(stage, stage_identity, stage_cleanup_ledger)
                    elif stage_identity is not None:
                        _remove_tree_exact(stage, stage_identity, stage_cleanup_ledger)
                    _remove_backup_if_created(initial_backup)
                except DeploymentAmbiguousError:
                    raise
                except Exception:
                    raise DeploymentAmbiguousError(
                        "deployment rollback failed; transaction evidence was preserved"
                    ) from original_error
                raise
            else:
                if instruction_publication is not None:
                    try:
                        _discard_prior_instruction(self.paths, instruction_publication)
                    except (DeploymentError, OSError):
                        pass
                return receipt

    def rollback(self, receipt_id: str, operation_id: str) -> DeploymentReceipt:
        """Restore the exact backup selected by the active deployment receipt."""

        _validate_deployment_paths(self.paths)
        _validate_operation_id(receipt_id)
        _validate_operation_id(operation_id)
        _require_atomic_backend()
        with _exclusive_lock(self.paths, timeout=self._lock_timeout):
            active = _active_receipt(self.paths)
            if active is None:
                absent_path = self.paths.state_root / "absent.json"
                try:
                    absent_bytes, _ = _read_regular_file(
                        absent_path, label="absent deployment authority"
                    )
                    absent = _canonical_mapping(
                        absent_bytes, label="absent deployment authority"
                    )
                except (DeploymentError, OSError):
                    raise DeploymentIntegrityError("cannot rollback a missing deployment") from None
                if (
                    absent.get("operationId") != operation_id
                    or absent.get("requestReceiptId") != receipt_id
                ):
                    raise DeploymentOperationConflict(
                        "absent rollback replay conflicts with immutable authority"
                    )
                replay_bytes, _ = _read_regular_file(
                    self.paths.receipts_root / f"{operation_id}.json",
                    label="absent rollback receipt",
                )
                replay = DeploymentReceipt.from_bytes(replay_bytes)
                if absent.get("receiptDigest") != _sha256(replay_bytes):
                    raise DeploymentIntegrityError("absent rollback receipt binding is invalid")
                return replay

            requested_marker = self.paths.receipts_root / f"{operation_id}.json"
            requested_manifest = (
                self.paths.receipts_root / f"{operation_id}.manifest.json"
            )
            if requested_marker.exists() or requested_manifest.exists():
                if not requested_marker.exists() or not requested_manifest.exists():
                    raise DeploymentAmbiguousError(
                        "rollback operation has partial immutable authority"
                    )
                receipt_bytes, _ = _read_regular_file(
                    requested_marker, label="existing rollback receipt"
                )
                manifest_bytes, _ = _read_regular_file(
                    requested_manifest, label="existing rollback manifest"
                )
                replay_receipt = DeploymentReceipt.from_bytes(receipt_bytes)
                replay_manifest = DeploymentManifest.from_bytes(manifest_bytes)
                replay_backup = _find_backup_for_successor(self.paths, operation_id)
                replay_metadata = _canonical_mapping(
                    replay_backup.identity_payload,
                    label="rollback replay backup metadata",
                )
                if (
                    active[0].operation_id == operation_id
                    and replay_manifest.operation_id == operation_id
                    and replay_receipt.operation_id == operation_id
                    and replay_receipt.manifest_byte_length == len(manifest_bytes)
                    and replay_receipt.manifest_digest == _sha256(manifest_bytes)
                    and replay_metadata.get("operationKind") == "rollback"
                    and replay_metadata.get("requestReceiptId") == receipt_id
                ):
                    return replay_receipt
                raise DeploymentOperationConflict(
                    "rollback operation ID conflicts with immutable authority"
                )

            backup = _find_backup_for_successor(
                self.paths, active[0].operation_id
            )
            if backup.prior_manifest is None:
                if receipt_id != active[0].operation_id:
                    raise DeploymentOperationConflict(
                        "initial rollback receipt does not select the active deployment"
                    )
                return _rollback_initial_to_absent(
                    self.paths,
                    active[0],
                    backup,
                    receipt_id,
                    operation_id,
                    fault_injector=self._fault_injector,
                )
            if receipt_id != active[0].operation_id:
                if receipt_id != backup.prior_manifest.operation_id:
                    raise DeploymentOperationConflict(
                        "rollback receipt is neither active nor immediately preceding"
                    )
                historical_manifest_bytes, _ = _read_regular_file(
                    self.paths.receipts_root / f"{receipt_id}.manifest.json",
                    label="immediately preceding deployment manifest",
                )
                historical_receipt_bytes, _ = _read_regular_file(
                    self.paths.receipts_root / f"{receipt_id}.json",
                    label="immediately preceding deployment receipt",
                )
                historical_receipt = DeploymentReceipt.from_bytes(
                    historical_receipt_bytes
                )
                if (
                    DeploymentManifest.from_bytes(historical_manifest_bytes)
                    != backup.prior_manifest
                    or historical_receipt.operation_id != receipt_id
                    or historical_receipt.manifest_byte_length
                    != len(historical_manifest_bytes)
                    or historical_receipt.manifest_digest
                    != _sha256(historical_manifest_bytes)
                ):
                    raise DeploymentIntegrityError(
                        "immediately preceding rollback receipt is invalid"
                    )
            backup_metadata = _canonical_mapping(
                backup.identity_payload,
                label="deployment backup metadata",
            )
            if backup_metadata.get("successorManifestDigest") != _sha256(
                active[0].to_bytes()
            ):
                raise DeploymentIntegrityError(
                    "rollback backup is not bound to the selected receipt"
                )
            if backup.agents.data is None or backup.agents.mode is None:
                raise DeploymentUnsupported(
                    "rollback to an absent global instruction file is not available"
                )
            verify_agents_bytes(
                backup.agents.data,
                backup.prior_manifest.managed_instruction_block_digest,
            )
            package_root = backup.path / "package"
            snapshot = scan_package(package_root, exclude_manifest=True)
            if (
                snapshot.entries != backup.prior_manifest.file_entries
                or snapshot.tree_digest
                != backup.prior_manifest.installed_tree_digest
            ):
                raise DeploymentIntegrityError("rollback backup package has drifted")
            backup_allowlist_digest = _validate_package_documents(
                package_root,
                snapshot,
            )
            if (
                backup_allowlist_digest
                != backup.prior_manifest.production_allowlist_digest
            ):
                raise DeploymentIntegrityError(
                    "rollback backup production allowlist binding is invalid"
                )
            source = _AdmittedSource(
                repository=Path(backup.prior_manifest.source_repository),
                commit=backup.prior_manifest.source_commit,
                package_root=package_root,
                snapshot=snapshot,
                allowlist_digest=backup.prior_manifest.production_allowlist_digest,
            )
            successor_manifest = DeploymentManifest(
                source_repository=backup.prior_manifest.source_repository,
                source_commit=backup.prior_manifest.source_commit,
                package_relative_path=PACKAGE_RELATIVE_PATH,
                production_allowlist_digest=backup.prior_manifest.production_allowlist_digest,
                file_entries=backup.prior_manifest.file_entries,
                source_tree_digest=backup.prior_manifest.source_tree_digest,
                installed_tree_digest=backup.prior_manifest.installed_tree_digest,
                managed_instruction_block_digest=backup.prior_manifest.managed_instruction_block_digest,
                installed_at=datetime.now(timezone.utc)
                .replace(microsecond=0)
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
                operation_id=operation_id,
            )
            current_agents = _read_agents(self.paths.agents_file)
            if current_agents.data is None or current_agents.mode is None:
                raise DeploymentIntegrityError(
                    "current global instructions are unavailable for rollback"
                )
            return _exchange_transaction(
                self.paths,
                source,
                active[0],
                current_agents,
                backup.agents.data,
                backup.agents.mode,
                successor_manifest,
                recheck_source=False,
                operation_kind="rollback",
                request_receipt_id=receipt_id,
                fault_injector=self._fault_injector,
            )

    def verify(self) -> DeploymentStatus:
        _validate_deployment_paths(self.paths)
        try:
            with _shared_lock(self.paths, timeout=self._lock_timeout):
                return _verified_status(self.paths)
        except DeploymentLockTimeout as error:
            return DeploymentStatus(
                state="busy",
                installed=self.paths.installed_root.exists(),
                verified=False,
                detail=str(error),
            )
        except DeploymentIntegrityError as error:
            return DeploymentStatus(
                state="invalid",
                installed=self.paths.installed_root.exists(),
                verified=False,
                detail=str(error)[:240],
            )

    def status(self) -> DeploymentStatus:
        return self.verify()


__all__ = [
    "DeploymentAmbiguousError",
    "DeploymentError",
    "DeploymentLockTimeout",
    "DeploymentOperationConflict",
    "DeploymentPaths",
    "DeploymentPlan",
    "DeploymentSourceError",
    "DeploymentStatus",
    "DeploymentUnsupported",
    "GlobalRsiDeployer",
]
