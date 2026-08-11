"""Durable append-only JSONL storage; SQLite is derived and disposable."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from .events import EventEnvelope, EventValidationError, fold_run


MAX_EVENT_LINE_BYTES = 64 * 1024
STATE_DIRECTORIES = (
    "locks",
    "objects",
    "objects/findings",
    "objects/evaluations",
    "objects/observations",
    "objects/proposals",
    "objects/post-images",
    "baselines",
    "experiments",
    "reports",
    "defragmentation",
    "rejected",
    "incidents",
)
CRITICAL_FILES = ("events.jsonl", "locks/events.lock", "index.sqlite")
SIDECAR_DIRECTORIES = frozenset(
    {
        "objects/findings",
        "objects/evaluations",
        "objects/observations",
        "objects/proposals",
        "reports",
        "defragmentation",
    }
)
TASK8_TOPOLOGY_DIRECTORIES = (
    "objects/transactions",
    "incidents/records",
    "incidents/quarantine",
    "locks/promotion",
    "locks/promotion/transactions",
    "locks/promotion/targets",
)
TASK8_GATE_LOCK = "locks/promotion/gate.lock"
TASK8_STORE_MARKER = ".rsi-promotion-store-v1"
TASK8_STORE_MARKER_BYTES = b'{"domain":"rsi-promotion-store-v1","schemaVersion":1}\n'
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class StoreIntegrityError(RuntimeError):
    """The durable ledger cannot safely support a lifecycle operation."""


def _authority_digest(value: str, *, label: str) -> str:
    if (
        type(value) is not str
        or not value.startswith("sha256:")
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise StoreIntegrityError(f"{label} is not an exact authority digest")
    return value


@dataclass(frozen=True, slots=True)
class HistoricalProviderAuthorityView:
    continuation_run_id: str
    origin_digest: str
    candidate_id: str
    candidate_state_binding_digest: str
    provider_prefix_digest: str

    def __post_init__(self) -> None:
        if type(self.continuation_run_id) is not str or not self.continuation_run_id.startswith("run_promote_"):
            raise StoreIntegrityError("historical authority continuation run is invalid")
        if type(self.candidate_id) is not str or not self.candidate_id:
            raise StoreIntegrityError("historical authority candidate is invalid")
        _authority_digest(self.origin_digest, label="historical origin digest")
        _authority_digest(
            self.candidate_state_binding_digest,
            label="historical candidate state binding digest",
        )
        _authority_digest(
            self.provider_prefix_digest, label="historical provider prefix digest"
        )


@dataclass(frozen=True, slots=True)
class OriginSourceWitness:
    object_class: str
    ref: str
    raw_digest: str
    device: int
    inode: int
    mode: int
    nlink: int
    byte_size: int
    mtime_ns: int
    ctime_ns: int

    def __post_init__(self) -> None:
        if type(self.object_class) is not str or not self.object_class:
            raise StoreIntegrityError("origin source object class is invalid")
        if type(self.ref) is not str or not self.ref:
            raise StoreIntegrityError("origin source reference is invalid")
        _authority_digest(self.raw_digest, label="origin source raw digest")
        for name in (
            "device", "inode", "mode", "nlink", "byte_size", "mtime_ns", "ctime_ns"
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise StoreIntegrityError(f"origin source {name} is invalid")
        if self.nlink != 1:
            raise StoreIntegrityError("origin source must be single-link")


@dataclass(frozen=True, slots=True)
class OriginLineageView:
    continuation_run_id: str
    origin_digest: str
    origin_receipt_digest: str
    semantic_binding_digest: str
    capture_event: EventEnvelope
    source_witnesses: tuple[OriginSourceWitness, ...]

    def __post_init__(self) -> None:
        if type(self.continuation_run_id) is not str or not self.continuation_run_id.startswith("run_promote_"):
            raise StoreIntegrityError("origin lineage continuation run is invalid")
        _authority_digest(self.origin_digest, label="origin lineage digest")
        _authority_digest(self.origin_receipt_digest, label="origin receipt digest")
        _authority_digest(self.semantic_binding_digest, label="origin semantic binding digest")
        if type(self.capture_event) is not EventEnvelope or self.capture_event.event_type != "candidate.captured":
            raise StoreIntegrityError("origin lineage capture event is invalid")
        if (
            type(self.source_witnesses) is not tuple
            or not self.source_witnesses
            or any(type(item) is not OriginSourceWitness for item in self.source_witnesses)
        ):
            raise StoreIntegrityError("origin source witness batch is invalid")
        ordered = tuple(
            sorted(
                self.source_witnesses,
                key=lambda item: (item.object_class.encode("utf-8"), item.ref.encode("utf-8")),
            )
        )
        if ordered != self.source_witnesses or len({(item.object_class, item.ref) for item in ordered}) != len(ordered):
            raise StoreIntegrityError("origin source witnesses are not sorted and unique")


@dataclass(frozen=True, slots=True)
class HistoricalProviderAuthorityBatch:
    views: tuple[HistoricalProviderAuthorityView, ...] = ()

    def __post_init__(self) -> None:
        if type(self.views) is not tuple or any(
            type(item) is not HistoricalProviderAuthorityView for item in self.views
        ):
            raise StoreIntegrityError("historical authority batch is not pre-admitted")
        keys = tuple((item.continuation_run_id, item.origin_digest) for item in self.views)
        if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise StoreIntegrityError("historical authority batch coverage is invalid")

    def by_key(self) -> dict[tuple[str, str], HistoricalProviderAuthorityView]:
        return {(item.continuation_run_id, item.origin_digest): item for item in self.views}


@dataclass(frozen=True, slots=True)
class OriginLineageBatch:
    views: tuple[OriginLineageView, ...] = ()

    def __post_init__(self) -> None:
        if type(self.views) is not tuple or any(
            type(item) is not OriginLineageView for item in self.views
        ):
            raise StoreIntegrityError("origin lineage batch is not pre-admitted")
        keys = tuple((item.continuation_run_id, item.origin_digest) for item in self.views)
        if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise StoreIntegrityError("origin lineage batch coverage is invalid")

    def by_key(self) -> dict[tuple[str, str], OriginLineageView]:
        return {(item.continuation_run_id, item.origin_digest): item for item in self.views}


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _strict_sidecar_json(data: bytes) -> object:
    if (
        not data
        or not data.endswith(b"\n")
        or b"\r" in data
        or data[:-1].endswith((b"\n", b" ", b"\t"))
    ):
        raise ValueError("invalid JSON framing")
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_json_constant,
    )


def _canonical_line(event: EventEnvelope) -> bytes:
    try:
        encoded = json.dumps(
            event.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError):
        raise StoreIntegrityError("event contains a non-canonical JSON value") from None
    if len(encoded) > MAX_EVENT_LINE_BYTES:
        raise StoreIntegrityError("event exceeds bounded JSONL line size")
    return encoded


def _fsync_directory(descriptor: int) -> None:
    """Durably order directory entries, tolerating only known platform limits."""
    try:
        os.fsync(descriptor)
    except OSError as error:
        tolerated = {errno.EINVAL}
        if hasattr(errno, "ENOTSUP"):
            tolerated.add(errno.ENOTSUP)
        if error.errno not in tolerated:
            raise


def _rename_noreplace_at(parent_fd: int, source: str, destination: str) -> None:
    """Atomically publish one name without the hard-link crash interval."""
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        # RENAME_EXCL is the Darwin no-replace primitive.
        result = libc.renameatx_np(
            parent_fd, ctypes.c_char_p(source_bytes),
            parent_fd, ctypes.c_char_p(destination_bytes), 0x4,
        )
    elif hasattr(libc, "renameat2"):
        # RENAME_NOREPLACE is Linux flag 1.
        result = libc.renameat2(
            parent_fd, ctypes.c_char_p(source_bytes),
            parent_fd, ctypes.c_char_p(destination_bytes), 0x1,
        )
    else:
        raise StoreIntegrityError("atomic no-replace publication is unavailable")
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(destination)
        raise OSError(error, os.strerror(error), destination)


def _open_unnamed_staging_at(staging_parent_fd: int) -> int:
    """Create a writeable regular staging inode with no authoritative name."""
    temporary_flag = getattr(os, "O_TMPFILE", 0)
    if sys.platform.startswith("linux") and temporary_flag:
        try:
            return os.open(
                ".", os.O_RDWR | temporary_flag | _NOFOLLOW, 0o600,
                dir_fd=staging_parent_fd,
            )
        except OSError as error:
            raise StoreIntegrityError(
                "unnamed Task 8 staging is unavailable"
            ) from error
    if sys.platform == "darwin":
        for _ in range(128):
            name = ".rsi-unbound-publish-" + secrets.token_hex(16)
            try:
                descriptor = os.open(
                    name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600,
                    dir_fd=staging_parent_fd,
                )
            except FileExistsError:
                continue
            try:
                os.unlink(name, dir_fd=staging_parent_fd)
            except Exception:
                os.close(descriptor)
                raise
            return descriptor
    raise StoreIntegrityError("unnamed Task 8 staging is unsupported")


def _publish_unnamed_noreplace_at(
    parent_fd: int, source_fd: int, destination: str
) -> None:
    """Publish an unnamed, fsynced inode without a second visible alias."""
    libc = ctypes.CDLL(None, use_errno=True)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(libc, "fclonefileat"):
        function = libc.fclonefileat
        function.argtypes = [
            ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32
        ]
        function.restype = ctypes.c_int
        result = function(
            source_fd, parent_fd, ctypes.c_char_p(destination_bytes), 0x3
        )
    elif sys.platform.startswith("linux") and hasattr(libc, "linkat"):
        function = libc.linkat
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        function.restype = ctypes.c_int
        result = function(
            source_fd,
            ctypes.c_char_p(b""),
            parent_fd,
            ctypes.c_char_p(destination_bytes),
            0x1000,
        )
    else:
        raise StoreIntegrityError("unnamed Task 8 publication is unsupported")
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(destination)
        raise OSError(error, os.strerror(error), destination)


class EventStore:
    """The event journal is source of truth; all lifecycle reads are strict."""

    def __init__(self, home: Path | str) -> None:
        self._read_only = False
        self._home_fd = -1
        self._promotion_init_lock = threading.RLock()
        self.home = Path(os.path.abspath(os.fspath(home)))
        if self.home == Path(self.home.anchor):
            raise StoreIntegrityError("unsafe state topology: home cannot be a filesystem root")
        self.events_path = self.home / "events.jsonl"
        self.lock_path = self.home / "locks" / "events.lock"
        self.index_path = self.home / "index.sqlite"
        self._validate_existing_topology()
        self.promotion_eligible = self._validate_promotion_topology()
        home_descriptor = self._open_absolute_directory(self.home, create=True, private_final=True)
        os.close(home_descriptor)
        for relative in STATE_DIRECTORIES:
            descriptor = self._open_relative_directory(relative, create=True)
            os.close(descriptor)
        for relative in CRITICAL_FILES:
            self._tighten_existing_file(relative)
        self._ensure_lock_file()
        self._home_fd = self._open_absolute_directory(
            self.home, create=False, private_final=False
        )

    @classmethod
    def open_existing(cls, home: Path | str) -> "EventStore":
        """Open a strict diagnostic handle without issuing a write-capable syscall."""
        instance = cls.__new__(cls)
        instance._read_only = True
        instance._home_fd = -1
        instance._promotion_init_lock = threading.RLock()
        instance.home = Path(os.path.abspath(os.fspath(home)))
        if instance.home == Path(instance.home.anchor):
            raise StoreIntegrityError("unsafe state topology: home cannot be a filesystem root")
        instance.events_path = instance.home / "events.jsonl"
        instance.lock_path = instance.home / "locks" / "events.lock"
        instance.index_path = instance.home / "index.sqlite"
        instance._validate_existing_topology()
        # A diagnostic open requires the complete legacy topology to preexist.
        home_fd = instance._open_absolute_directory(
            instance.home, create=False, private_final=False
        )
        instance._home_fd = home_fd
        for relative in STATE_DIRECTORIES:
            descriptor = instance._open_relative_directory(relative)
            os.close(descriptor)
        for relative in ("locks/events.lock",):
            instance._validate_named_regular(relative, expected_mode=0o600)
        instance.promotion_eligible = instance._validate_promotion_topology()
        return instance

    def _assert_writable(self) -> None:
        if getattr(self, "_read_only", False):
            raise StoreIntegrityError("existing-only read-only handle forbids mutation")

    @staticmethod
    def _parts(path: Path) -> tuple[str, ...]:
        return tuple(part for part in path.parts if part not in {path.anchor, ""})

    @classmethod
    def _open_absolute_directory(cls, path: Path, *, create: bool, private_final: bool = False) -> int:
        """Walk a directory path without following any component symlink."""
        absolute = Path(os.path.abspath(os.fspath(path)))
        descriptor = os.open(absolute.anchor, _DIRECTORY_FLAGS)
        parts = cls._parts(absolute)
        try:
            for position, part in enumerate(parts):
                try:
                    metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    if not create:
                        raise StoreIntegrityError("unsafe state topology: required directory is absent") from None
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    raise StoreIntegrityError("unsafe state topology: directory component is not a real directory")
                try:
                    child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                except OSError as error:
                    raise StoreIntegrityError("unsafe state topology: directory component cannot be opened safely") from error
                os.close(descriptor)
                descriptor = child
                if private_final and position == len(parts) - 1:
                    os.fchmod(descriptor, 0o700)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _open_home(self) -> int:
        retained = getattr(self, "_home_fd", -1)
        if retained == -1:
            return self._open_absolute_directory(
                self.home, create=False, private_final=False
            )
        try:
            named = self.home.lstat()
            opened = os.fstat(retained)
        except OSError as error:
            raise StoreIntegrityError(
                "unsafe state topology: retained home is unavailable"
            ) from error
        if (
            stat.S_ISLNK(named.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise StoreIntegrityError("unsafe state topology: state home identity changed")
        return os.dup(retained)

    def __del__(self) -> None:
        descriptor = getattr(self, "_home_fd", -1)
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError:
                pass
            self._home_fd = -1

    def _open_relative_directory(self, relative: str, *, create: bool = False) -> int:
        descriptor = self._open_home()
        try:
            for part in Path(relative).parts:
                try:
                    metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    if not create:
                        raise StoreIntegrityError("unsafe state topology: required directory is absent") from None
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    raise StoreIntegrityError("unsafe state topology: internal directory is not a real directory")
                try:
                    child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                except OSError as error:
                    raise StoreIntegrityError("unsafe state topology: internal directory cannot be opened safely") from error
                os.close(descriptor)
                descriptor = child
                if not getattr(self, "_read_only", False):
                    os.fchmod(descriptor, 0o700)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _validate_existing_topology(self) -> None:
        """Inspect the complete fixed topology before chmod, mkdir, or file creation."""
        try:
            home_metadata = self.home.lstat()
        except FileNotFoundError:
            # The descriptor-relative creator validates every existing ancestor.
            ancestor = self.home.parent
            while not ancestor.exists() and ancestor != Path(ancestor.anchor):
                ancestor = ancestor.parent
            descriptor = self._open_absolute_directory(ancestor, create=False)
            os.close(descriptor)
            return
        if not stat.S_ISDIR(home_metadata.st_mode) or stat.S_ISLNK(home_metadata.st_mode):
            raise StoreIntegrityError("unsafe state topology: home is not a real directory")
        descriptor = self._open_absolute_directory(self.home, create=False)
        os.close(descriptor)
        for relative in STATE_DIRECTORIES:
            candidate = self.home / relative
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise StoreIntegrityError("unsafe state topology: internal directory is not a real directory")
        for relative in CRITICAL_FILES:
            candidate = self.home / relative
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
                raise StoreIntegrityError("unsafe state topology: critical file is not a single-link regular file")

    def _read_named_bytes(self, relative: str, *, maximum: int = 256 * 1024 * 1024) -> bytes:
        parent, name = self._parent_descriptor(relative)
        descriptor = -1
        try:
            descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=parent)
            self._validate_open_regular(descriptor)
            metadata = os.fstat(descriptor)
            if metadata.st_size < 0 or metadata.st_size > maximum:
                raise StoreIntegrityError("bounded object size is invalid")
            chunks: list[bytes] = []
            remaining = metadata.st_size + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) != metadata.st_size:
                raise StoreIntegrityError("object changed during read")
            return data
        except OSError as error:
            raise StoreIntegrityError("unsafe state topology: object cannot be opened safely") from error
        finally:
            if descriptor != -1:
                os.close(descriptor)
            os.close(parent)

    def _validate_named_regular(self, relative: str, *, expected_mode: int = 0o600) -> os.stat_result:
        parent, name = self._parent_descriptor(relative)
        descriptor = -1
        try:
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
                raise StoreIntegrityError("unsafe topology: expected a single-link regular file")
            descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=parent)
            self._validate_open_regular(descriptor)
            opened = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
                raise StoreIntegrityError("unsafe topology: file identity changed")
            if stat.S_IMODE(opened.st_mode) != expected_mode or opened.st_uid != os.geteuid():
                raise StoreIntegrityError("unsafe topology: file mode or owner is invalid")
            return opened
        except FileNotFoundError:
            raise StoreIntegrityError("unsafe topology: required file is absent") from None
        finally:
            if descriptor != -1:
                os.close(descriptor)
            os.close(parent)

    def _validate_task8_object_directory(self, relative: str, *, incident: bool) -> None:
        descriptor = self._open_relative_directory(relative)
        try:
            metadata = os.fstat(descriptor)
            if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.geteuid():
                raise StoreIntegrityError("unsafe promotion topology directory mode or owner")
            for name in os.listdir(descriptor):
                if name.startswith(".rsi-tmp-") or not name.endswith(".json"):
                    raise StoreIntegrityError("unsafe transaction topology entry")
                try:
                    item = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except OSError as error:
                    raise StoreIntegrityError("unsafe transaction topology entry") from error
                if not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode) or item.st_nlink != 1:
                    raise StoreIntegrityError("unsafe transaction topology object")
                if stat.S_IMODE(item.st_mode) != 0o600 or item.st_uid != os.geteuid():
                    raise StoreIntegrityError("unsafe transaction topology object mode")
                fd = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=descriptor)
                try:
                    chunks: list[bytes] = []
                    while True:
                        chunk = os.read(fd, 64 * 1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    data = b"".join(chunks)
                finally:
                    os.close(fd)
                try:
                    parsed = _strict_sidecar_json(data)
                    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
                    raise StoreIntegrityError("corrupt canonical transaction sidecar object") from None
                if canonical != data or not isinstance(parsed, dict):
                    raise StoreIntegrityError("corrupt canonical transaction sidecar framing")
                if incident:
                    if parsed.get("kind") != "incident-record" or name != f"{parsed.get('incidentId')}.json":
                        raise StoreIntegrityError("corrupt incident transaction record")
                else:
                    digest = hashlib.sha256(data).hexdigest()
                    if parsed.get("kind") is None or not name.endswith(f"-{digest}.json"):
                        raise StoreIntegrityError("corrupt content-addressed transaction object")
        finally:
            os.close(descriptor)

    def _validate_promotion_topology(self) -> bool:
        marker = self.home / TASK8_STORE_MARKER
        participants = [self.home / item for item in TASK8_TOPOLOGY_DIRECTORIES]
        participants.append(self.home / TASK8_GATE_LOCK)
        exists = [path.exists() or path.is_symlink() for path in participants]
        marker_exists = marker.exists() or marker.is_symlink()
        if not marker_exists and not any(exists):
            return False
        if not marker_exists or not all(exists):
            raise StoreIntegrityError("partial promotion topology is not authoritative")
        for relative in TASK8_TOPOLOGY_DIRECTORIES:
            descriptor = self._open_relative_directory(relative)
            try:
                metadata = os.fstat(descriptor)
                if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.geteuid():
                    raise StoreIntegrityError("unsafe promotion topology directory mode")
            finally:
                os.close(descriptor)
        self._validate_named_regular(TASK8_GATE_LOCK)
        self._validate_named_regular(TASK8_STORE_MARKER)
        if self._read_named_bytes(TASK8_STORE_MARKER, maximum=len(TASK8_STORE_MARKER_BYTES)) != TASK8_STORE_MARKER_BYTES:
            raise StoreIntegrityError("promotion topology marker framing is invalid")
        self._validate_task8_object_directory("objects/transactions", incident=False)
        self._validate_task8_object_directory("incidents/records", incident=True)
        return True

    def initialize_promotion_topology(self) -> None:
        self._assert_writable()
        with self._promotion_init_lock:
            current = self._validate_promotion_topology()
            if current:
                self.promotion_eligible = True
                return
            try:
                for relative in TASK8_TOPOLOGY_DIRECTORIES:
                    descriptor = self._open_relative_directory(relative, create=True)
                    try:
                        os.fchmod(descriptor, 0o700)
                        _fsync_directory(descriptor)
                    finally:
                        os.close(descriptor)
                parent, name = self._parent_descriptor(TASK8_GATE_LOCK)
                try:
                    try:
                        gate = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, dir_fd=parent)
                    except FileExistsError:
                        gate = os.open(name, os.O_RDWR | _NOFOLLOW, dir_fd=parent)
                    try:
                        self._validate_open_regular(gate)
                        if os.fstat(gate).st_size != 0:
                            raise StoreIntegrityError("promotion gate lock is corrupt")
                        os.fchmod(gate, 0o600)
                        os.fsync(gate)
                    finally:
                        os.close(gate)
                    _fsync_directory(parent)
                finally:
                    os.close(parent)
                marker_parent = self._open_home()
                try:
                    marker = os.open(TASK8_STORE_MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, dir_fd=marker_parent)
                    try:
                        offset = 0
                        while offset < len(TASK8_STORE_MARKER_BYTES):
                            try:
                                written = os.write(marker, TASK8_STORE_MARKER_BYTES[offset:])
                            except InterruptedError:
                                continue
                            if written <= 0:
                                raise StoreIntegrityError("promotion marker write was incomplete")
                            offset += written
                        os.fsync(marker)
                    finally:
                        os.close(marker)
                    _fsync_directory(marker_parent)
                finally:
                    os.close(marker_parent)
            except (OSError, StoreIntegrityError) as error:
                # Marker-last: all pre-marker remnants remain a visible partial upgrade.
                if not isinstance(error, StoreIntegrityError):
                    raise StoreIntegrityError("promotion topology initialize or sync failed") from error
                raise
            self.promotion_eligible = self._validate_promotion_topology()

    def _parent_descriptor(self, relative: str) -> tuple[int, str]:
        path = Path(relative)
        parent = str(path.parent)
        descriptor = self._open_home() if parent == "." else self._open_relative_directory(parent)
        return descriptor, path.name

    @staticmethod
    def _validate_open_regular(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise StoreIntegrityError("unsafe state topology: file is not a single-link regular file")

    @staticmethod
    def _recover_owned_temp_links(parent: int, destination: int) -> None:
        """Remove only same-inode, same-owner RSI temp links left after publish."""
        destination_metadata = os.fstat(destination)
        if not stat.S_ISREG(destination_metadata.st_mode) or destination_metadata.st_nlink <= 1:
            return
        removed = False
        for name in os.listdir(parent):
            if not name.startswith(".rsi-tmp-"):
                continue
            try:
                metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if (
                stat.S_ISREG(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode)
                and metadata.st_uid == destination_metadata.st_uid == os.geteuid()
                and (metadata.st_dev, metadata.st_ino) == (destination_metadata.st_dev, destination_metadata.st_ino)
            ):
                os.unlink(name, dir_fd=parent)
                removed = True
        if removed:
            _fsync_directory(parent)

    def _tighten_existing_file(self, relative: str) -> None:
        parent, name = self._parent_descriptor(relative)
        try:
            try:
                metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
                raise StoreIntegrityError("unsafe state topology: critical file is not a single-link regular file")
            descriptor = None
            permission_error: PermissionError | None = None
            for access_mode in (os.O_RDWR, os.O_RDONLY, os.O_WRONLY):
                try:
                    descriptor = os.open(name, access_mode | _NOFOLLOW, dir_fd=parent)
                    break
                except PermissionError as error:
                    permission_error = error
                except OSError as error:
                    raise StoreIntegrityError("unsafe state topology: critical file cannot be opened safely") from error
            if descriptor is None:
                raise StoreIntegrityError("unsafe state topology: critical file cannot be opened safely") from permission_error
            try:
                self._validate_open_regular(descriptor)
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise StoreIntegrityError("unsafe state topology: critical file changed during validation")
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)

    def _ensure_lock_file(self) -> None:
        parent, name = self._parent_descriptor("locks/events.lock")
        try:
            try:
                descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, dir_fd=parent)
                created = True
            except FileExistsError:
                descriptor = os.open(name, os.O_RDWR | _NOFOLLOW, dir_fd=parent)
                created = False
            try:
                self._validate_open_regular(descriptor)
                os.fchmod(descriptor, 0o600)
                if created:
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if created:
                _fsync_directory(parent)
        except OSError as error:
            raise StoreIntegrityError("unsafe state topology: lock file cannot be created safely") from error
        finally:
            os.close(parent)

    def _assert_runtime_topology(self) -> None:
        self._validate_existing_topology()
        for relative in STATE_DIRECTORIES:
            descriptor = self._open_relative_directory(relative)
            os.close(descriptor)
        self._validate_promotion_topology()
        if getattr(self, "_read_only", False):
            self._validate_named_regular("locks/events.lock")
        else:
            self._tighten_existing_file("events.jsonl")
            self._tighten_existing_file("index.sqlite")
            self._tighten_existing_file("locks/events.lock")

    def _read_regular(self, relative: str, *, missing_ok: bool = False) -> bytes:
        parent, name = self._parent_descriptor(relative)
        try:
            try:
                descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                if missing_ok:
                    return b""
                raise
            except OSError as error:
                raise StoreIntegrityError("unsafe state topology: file cannot be opened safely") from error
            try:
                self._validate_open_regular(descriptor)
                if not getattr(self, "_read_only", False):
                    os.fchmod(descriptor, 0o600)
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(descriptor, 64 * 1024)
                    if not chunk:
                        return b"".join(chunks)
                    chunks.append(chunk)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)

    def _strict_events(
        self, *, historical_batch: object | None = None,
        origin_lineage_batch: object | None = None,
        pending_event: EventEnvelope | None = None,
    ) -> list[EventEnvelope]:
        self._assert_runtime_topology()
        data = self._read_regular("events.jsonl", missing_ok=True)
        if data and not data.endswith(b"\n"):
            raise StoreIntegrityError("malformed JSONL tail: missing newline")
        events: list[EventEnvelope] = []
        event_ids: set[str] = set()
        for line_number, line in enumerate(data.splitlines(), start=1):
            if not line:
                raise StoreIntegrityError(f"malformed JSONL line {line_number}: blank line")
            try:
                raw = json.loads(line, parse_constant=_reject_json_constant)
                event = EventEnvelope.from_mapping(raw)
            except (json.JSONDecodeError, EventValidationError, TypeError, UnicodeDecodeError) as error:
                raise StoreIntegrityError(f"malformed JSONL line {line_number}: {error}") from None
            if event.event_id in event_ids:
                raise StoreIntegrityError(f"duplicate eventId in JSONL line {line_number}")
            event_ids.add(event.event_id)
            events.append(event)
        self._validate_lifecycles(
            events,
            historical_batch=historical_batch,
            origin_lineage_batch=origin_lineage_batch,
            pending_event=pending_event,
        )
        return events

    @staticmethod
    def _validate_lifecycles(
        events: Iterable[EventEnvelope], *,
        historical_batch: object | None = None,
        origin_lineage_batch: object | None = None,
        pending_event: EventEnvelope | None = None,
    ) -> None:
        sequence = list(events)
        historical = EventStore._historical_views(historical_batch)
        lineage = EventStore._origin_views(origin_lineage_batch)
        has_task8 = any(event.run_id.startswith("run_promote_") for event in sequence) or (
            pending_event is not None and pending_event.run_id.startswith("run_promote_")
        )
        if not has_task8 and (historical or lineage):
            raise StoreIntegrityError("extraneous authority batch for legacy lifecycle")
        required: dict[tuple[str, str], EventEnvelope] = {}
        for event in sequence:
            if event.event_type != "promotion.gated" or not event.run_id.startswith("run_promote_"):
                continue
            origin_digest = event.payload.get("originDigest")
            if not isinstance(origin_digest, str):
                raise StoreIntegrityError("promotion gate origin digest is invalid")
            required[(event.run_id, origin_digest)] = event
        if (
            pending_event is not None
            and pending_event.event_type == "promotion.gated"
            and pending_event.run_id.startswith("run_promote_")
        ):
            pending_origin = pending_event.payload.get("originDigest")
            if not isinstance(pending_origin, str):
                raise StoreIntegrityError("pending promotion gate origin digest is invalid")
            required[(pending_event.run_id, pending_origin)] = pending_event
        if set(historical) != set(required) or set(lineage) != set(required):
            raise StoreIntegrityError("Task 8 authority batch coverage is incomplete or extraneous")
        by_run: dict[str, list[EventEnvelope]] = {}
        for event in sequence:
            by_run.setdefault(event.run_id, []).append(event)
        for run_events in by_run.values():
            try:
                external: dict[str, EventEnvelope] = {}
                gate = (
                    next((item for item in run_events if item.event_type == "promotion.gated"), None)
                    if run_events[0].run_id.startswith("run_promote_")
                    else None
                )
                if gate is not None:
                    key = (gate.run_id, str(gate.payload["originDigest"]))
                    lineage_view = lineage.get(key)
                    historical_view = historical.get(key)
                    if lineage_view is None or historical_view is None:
                        raise StoreIntegrityError("origin authority batch lacks the external capture")
                    candidate = lineage_view.capture_event
                    if (
                        candidate.event_id != gate.causation_id
                        or lineage_view.origin_digest != historical_view.origin_digest
                        or candidate.payload.get("providerCandidateId")
                        != historical_view.candidate_id
                    ):
                        raise StoreIntegrityError("origin/provider authority cross-binding conflicts")
                    external[candidate.event_id] = candidate
                fold_run(run_events, external_predecessors=external)
            except EventValidationError as error:
                raise StoreIntegrityError(f"invalid lifecycle: {error}") from None
        by_id = {event.event_id: event for event in sequence}
        run_started_at = {
            event.run_id: position
            for position, event in enumerate(sequence)
            if event.event_type == "run.started"
        }
        provider_operations: set[str] = set()
        for event in sequence:
            if event.event_type != "resolution.recorded":
                continue
            provider_operation_id = event.payload["providerOperationId"]
            if provider_operation_id in provider_operations:
                raise StoreIntegrityError("invalid lifecycle: duplicate provider operation terminal event")
            provider_operations.add(provider_operation_id)
        for position, event in enumerate(sequence):
            if event.event_type != "monitoring.recorded":
                continue
            if event.payload["evaluationId"] != f"event:{event.causation_id}":
                raise StoreIntegrityError("invalid lifecycle: monitoring evaluationId must match its causal evaluation")
            promotion_id = event.payload["promotionRef"].removeprefix("event:")
            promotion = by_id.get(promotion_id)
            if promotion is None or sequence.index(promotion) >= position:
                raise StoreIntegrityError("invalid lifecycle: monitoring promotionRef must name an earlier resolution")
            if sequence.index(promotion) >= run_started_at[event.run_id]:
                raise StoreIntegrityError("invalid lifecycle: promotion resolution must predate monitoring run.started")
            if promotion.run_id == event.run_id or promotion.event_type != "resolution.recorded":
                raise StoreIntegrityError("invalid lifecycle: monitoring promotionRef must name another run's promotion resolution")
            verification = by_id.get(promotion.causation_id or "")
            if verification is None or verification.event_type != "verification.completed":
                raise StoreIntegrityError("invalid lifecycle: monitoring promotionRef is not a promotion resolution")
            if not (verification.payload["liveReadback"] and verification.payload["tests"] == "passed" and verification.payload["attestationMatch"]):
                raise StoreIntegrityError("invalid lifecycle: monitoring promotionRef is not verified")
        for position, event in enumerate(sequence):
            if event.event_type != "global.report.generated":
                continue
            references = list(event.payload["sourceEvaluationRefs"])
            if not references or len(references) != len(set(references)):
                raise StoreIntegrityError(
                    "invalid lifecycle: global source evaluations must be nonempty and unique"
                )
            start_position = run_started_at[event.run_id]
            for reference in references:
                source_id = reference.removeprefix("event:")
                source = by_id.get(source_id)
                if (
                    not reference.startswith("event:")
                    or source is None
                    or source.event_type != "evaluation.completed"
                    or source.run_id == event.run_id
                    or sequence.index(source) >= start_position
                    or sequence.index(source) >= position
                ):
                    raise StoreIntegrityError(
                        "invalid lifecycle: global source evaluation reference is invalid"
                    )

    def read_events(
        self, *, historical_batch: object | None = None,
        origin_lineage_batch: object | None = None,
    ) -> list[EventEnvelope]:
        return self._strict_events(
            historical_batch=historical_batch,
            origin_lineage_batch=origin_lineage_batch,
        )

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        self._assert_runtime_topology()
        parent, name = self._parent_descriptor("locks/events.lock")
        try:
            descriptor = os.open(name, os.O_RDWR | os.O_APPEND | _NOFOLLOW, dir_fd=parent)
        except OSError as error:
            os.close(parent)
            raise StoreIntegrityError("unsafe state topology: lock file cannot be opened safely") from error
        os.close(parent)
        try:
            self._validate_open_regular(descriptor)
            os.fchmod(descriptor, 0o600)
        except Exception:
            os.close(descriptor)
            raise
        with os.fdopen(descriptor, "a+b", buffering=0) as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                # Recheck after acquiring the lock so an alias swap cannot enter a write.
                self._assert_runtime_topology()
                parent, name = self._parent_descriptor("locks/events.lock")
                try:
                    current = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=parent)
                    try:
                        self._validate_open_regular(current)
                        locked_metadata = os.fstat(lock.fileno())
                        current_metadata = os.fstat(current)
                        if (locked_metadata.st_dev, locked_metadata.st_ino) != (current_metadata.st_dev, current_metadata.st_ino):
                            raise StoreIntegrityError("unsafe state topology: lock file changed while locking")
                    finally:
                        os.close(current)
                finally:
                    os.close(parent)
                yield
                # No successful append authority survives a canonical-home
                # rebind while the retained store descriptor is locked.
                retained_check = self._open_home()
                os.close(retained_check)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def append(
        self, event: EventEnvelope, *, freshness_witness: object | None = None,
        historical_batch: object | None = None,
        origin_lineage_batch: object | None = None,
    ) -> EventEnvelope:
        self._assert_writable()
        self._validate_admitted_batches(event, historical_batch, origin_lineage_batch)
        line = _canonical_line(event)  # Serialize and bound before waiting for the lock.
        if freshness_witness is not None:
            raise StoreIntegrityError(
                "terminal root freshness requires a durable historical sidecar"
            )
        with self._exclusive_lock():
            recorded = self._strict_events(
                historical_batch=historical_batch,
                origin_lineage_batch=origin_lineage_batch,
                pending_event=event,
            )
            replay = self._preflight_append(
                recorded, event,
                historical_batch=historical_batch,
                origin_lineage_batch=origin_lineage_batch,
            )
            if replay is not None:
                return replay
            self._append_line_locked(line)
        return event

    @staticmethod
    def _validate_admitted_batches(
        event: EventEnvelope, historical_batch: object | None, origin_lineage_batch: object | None
    ) -> None:
        historical = EventStore._historical_views(historical_batch)
        lineage = EventStore._origin_views(origin_lineage_batch)
        if not event.run_id.startswith("run_promote_") and (historical or lineage):
            raise StoreIntegrityError("extraneous authority batch for legacy event")

    @staticmethod
    def _historical_views(
        batch: object | None,
    ) -> dict[tuple[str, str], HistoricalProviderAuthorityView]:
        if batch is None or (type(batch) is dict and not batch):
            return {}
        if type(batch) is not HistoricalProviderAuthorityBatch:
            raise StoreIntegrityError("historical authority batch is not pre-admitted")
        return batch.by_key()

    @staticmethod
    def _origin_views(
        batch: object | None,
    ) -> dict[tuple[str, str], OriginLineageView]:
        if batch is None or (type(batch) is dict and not batch):
            return {}
        if type(batch) is not OriginLineageBatch:
            raise StoreIntegrityError("origin lineage batch is not pre-admitted")
        return batch.by_key()

    def _preflight_append(
        self,
        recorded: list[EventEnvelope],
        event: EventEnvelope,
        freshness_context: tuple[
            str, tuple[str, ...], tuple[str, ...], str, str
        ] | None = None,
        historical_batch: object | None = None,
        origin_lineage_batch: object | None = None,
    ) -> EventEnvelope | None:
        for prior in recorded:
            if prior.idempotency_key == event.idempotency_key:
                if self._same_request(prior, event):
                    return prior
                raise StoreIntegrityError("idempotency key collision")
        if event.event_type == "finding.drafted":
            for prior in recorded:
                if (
                    prior.run_id != event.run_id
                    or prior.event_type != "finding.drafted"
                    or prior.payload["draftId"] != event.payload["draftId"]
                ):
                    continue
                if (
                    prior.payload_ref is None
                    and event.payload_ref is None
                    and prior.payload["targetSkill"] == event.payload["targetSkill"]
                    and prior.payload["proposedScope"] == event.payload["proposedScope"]
                ):
                    # Legacy findings intentionally merge later wording for the
                    # same scope/dedupe identity.  The draft id binds that
                    # identity; logical operation ids and summaries do not.
                    return prior
                if (
                    prior.payload_ref is not None
                    and event.payload_ref is not None
                    and prior.correlation_id == event.correlation_id
                    and prior.payload["targetSkill"] == event.payload["targetSkill"]
                    and prior.payload["proposedScope"] == event.payload["proposedScope"]
                    and prior.payload["summary"] == event.payload["summary"]
                ):
                    return prior
                raise StoreIntegrityError("finding draft dedupe conflict")
        self._task4_phase_guard(recorded, event, freshness_context)
        try:
            self._validate_lifecycles(
                [*recorded, event],
                historical_batch=historical_batch,
                origin_lineage_batch=origin_lineage_batch,
            )
        except EventValidationError as error:
            raise StoreIntegrityError(f"invalid lifecycle: {error}") from None
        return None

    def _append_line_locked(self, line: bytes) -> None:
        parent, name = self._parent_descriptor("events.jsonl")
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | _NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            self._validate_open_regular(descriptor)
            os.fchmod(descriptor, 0o600)
            written = os.write(descriptor, line)
            if written != len(line):
                raise StoreIntegrityError("incomplete O_APPEND write")
            os.fsync(descriptor)
        finally:
            if descriptor != -1:
                os.close(descriptor)
            _fsync_directory(parent)
            os.close(parent)

    def _sidecar_relative(self, path: Path) -> Path:
        absolute = Path(os.path.abspath(os.fspath(path)))
        try:
            relative = absolute.relative_to(self.home)
        except ValueError:
            raise StoreIntegrityError("unsafe sidecar destination") from None
        parent_relative = str(relative.parent)
        if (
            parent_relative not in SIDECAR_DIRECTORIES
            or not relative.name
            or relative.name in {".", ".."}
        ):
            raise StoreIntegrityError("unsafe sidecar destination")
        return relative

    def append_with_sidecar(
        self,
        event: EventEnvelope,
        path: Path,
        data: bytes,
        *,
        freshness_witness: object | None = None,
        historical_batch: object | None = None,
        origin_lineage_batch: object | None = None,
    ) -> EventEnvelope:
        """Atomically admit a sidecar/event pair under the journal phase guard.

        The immutable object is published before its referencing event while the
        same lock protects the max-draft decision. A rejected concurrent branch
        therefore cannot leak an unreferenced finding object.
        """
        self._assert_writable()
        self._validate_admitted_batches(
            event, historical_batch, origin_lineage_batch
        )
        line = _canonical_line(event)
        relative = self._sidecar_relative(path)
        expected_ref = str(relative).removeprefix("objects/")
        if event.payload_ref != expected_ref:
            raise StoreIntegrityError("sidecar event reference is inconsistent")
        freshness_context: tuple[
            str, tuple[str, ...], tuple[str, ...], str, str
        ] | None = None
        if freshness_witness is not None:
            if event.event_type != "run.closed":
                raise StoreIntegrityError(
                    "trusted root freshness is only valid for terminal append"
                )
            from .target_identity import (
                admit_freshness_witness_document,
                freshness_witness_digest,
                freshness_witness_roots,
            )

            historical, historical_digest, verification_digest = (
                admit_freshness_witness_document(
                    data, run_id=event.run_id, verification_binding_digest=None
                )
            )
            runtime_digest = freshness_witness_digest(freshness_witness)  # type: ignore[arg-type]
            if historical != freshness_witness or historical_digest != runtime_digest:
                raise StoreIntegrityError(
                    "historical freshness witness conflicts with terminal state"
                )
            raw_digest = "sha256:" + hashlib.sha256(data).hexdigest()
            expected_terminal_ref = (
                f"proposals/{event.run_id}-freshness-{raw_digest[7:]}.json"
            )
            if event.payload_ref != expected_terminal_ref:
                raise StoreIntegrityError(
                    "historical freshness sidecar reference is inconsistent"
                )
            freshness_context = (
                runtime_digest,
                *freshness_witness_roots(freshness_witness),  # type: ignore[arg-type]
                raw_digest,
                verification_digest,
            )
        with self._exclusive_lock():
            recorded = self._strict_events(
                historical_batch=historical_batch,
                origin_lineage_batch=origin_lineage_batch,
                pending_event=event,
            )
            replay = self._preflight_append(
                recorded, event, freshness_context,
                historical_batch=historical_batch,
                origin_lineage_batch=origin_lineage_batch,
            )
            if replay is not None:
                if replay.payload_ref is None:
                    raise StoreIntegrityError("sidecar replay lacks its durable payload reference")
                replay_relative = Path(replay.payload_ref)
                if replay_relative.parts[0] not in {"reports", "defragmentation"}:
                    replay_relative = Path("objects") / replay_relative
                try:
                    if self._read_regular(str(replay_relative)) != data:
                        raise StoreIntegrityError("sidecar replay conflicts with durable payload")
                except FileNotFoundError:
                    raise StoreIntegrityError("sidecar replay is missing its durable payload") from None
                return replay
            if freshness_witness is not None:
                from .target_identity import assert_freshness_witness

                try:
                    assert_freshness_witness(freshness_witness)  # type: ignore[arg-type]
                except Exception as error:
                    raise StoreIntegrityError(
                        "trusted root freshness changed before terminal append"
                    ) from error
            self._write_once_locked(relative, data)
            self._append_line_locked(line)
        return event

    def write_once(self, path: Path, data: bytes) -> None:
        """Publish complete immutable bytes with no overwrite and durable directory ordering."""
        self._assert_writable()
        relative = self._sidecar_relative(path)
        with self._exclusive_lock():
            self._write_once_locked(relative, data)

    def _write_once_locked(self, relative: Path, data: bytes) -> None:
        parent = self._open_relative_directory(str(relative.parent))
        temporary_name: str | None = None
        descriptor = -1
        try:
            try:
                existing = os.open(relative.name, os.O_RDONLY | _NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                existing = -1
            except OSError as error:
                raise StoreIntegrityError("unsafe existing sidecar") from error
            if existing != -1:
                try:
                    self._recover_owned_temp_links(parent, existing)
                    self._validate_open_regular(existing)
                    os.fchmod(existing, 0o600)
                    chunks: list[bytes] = []
                    while True:
                        chunk = os.read(existing, 64 * 1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    if b"".join(chunks) != data:
                        raise StoreIntegrityError("sidecar replay conflicts with durable payload")
                    return
                finally:
                    os.close(existing)

            for _ in range(128):
                candidate = ".rsi-tmp-" + str(os.getpid()) + "-" + secrets.token_hex(12)
                try:
                    descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, dir_fd=parent)
                    temporary_name = candidate
                    break
                except FileExistsError:
                    continue
            if descriptor == -1 or temporary_name is None:
                raise StoreIntegrityError("could not allocate a unique sidecar temporary file")
            self._validate_open_regular(descriptor)
            os.fchmod(descriptor, 0o600)
            view = memoryview(data)
            offset = 0
            while offset < len(view):
                try:
                    written = os.write(descriptor, view[offset:])
                except InterruptedError:
                    continue
                if written <= 0:
                    raise StoreIntegrityError("incomplete sidecar write")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            try:
                _rename_noreplace_at(parent, temporary_name, relative.name)
            except FileExistsError:
                existing = os.open(relative.name, os.O_RDONLY | _NOFOLLOW, dir_fd=parent)
                try:
                    self._recover_owned_temp_links(parent, existing)
                    self._validate_open_regular(existing)
                    os.fchmod(existing, 0o600)
                    chunks = []
                    while True:
                        chunk = os.read(existing, 64 * 1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    if b"".join(chunks) != data:
                        raise StoreIntegrityError("sidecar replay conflicts with durable payload")
                finally:
                    os.close(existing)
            _fsync_directory(parent)
        finally:
            if descriptor != -1:
                os.close(descriptor)
            try:
                if temporary_name is not None:
                    try:
                        os.unlink(temporary_name, dir_fd=parent)
                    except FileNotFoundError:
                        pass
                    _fsync_directory(parent)
            finally:
                os.close(parent)

    def read_sidecar(self, path: Path) -> bytes:
        absolute = Path(os.path.abspath(os.fspath(path)))
        try:
            relative = absolute.relative_to(self.home)
        except ValueError:
            raise StoreIntegrityError("unsafe sidecar destination") from None
        if str(relative.parent) not in SIDECAR_DIRECTORIES:
            raise StoreIntegrityError("unsafe sidecar destination")
        self._assert_runtime_topology()
        return self._read_regular(str(relative))

    @staticmethod
    def _same_request(prior: EventEnvelope, event: EventEnvelope) -> bool:
        """Transport timestamps and generated event ids are not request identity."""
        if prior.to_dict() == event.to_dict():
            return True
        return (
            isinstance(prior.correlation_id, str)
            and prior.correlation_id.startswith("sha256:")
            and
            prior.schema_version == event.schema_version
            and prior.event_type == event.event_type
            and prior.run_id == event.run_id
            and prior.correlation_id == event.correlation_id
            and prior.causation_id == event.causation_id
            and prior.idempotency_key == event.idempotency_key
            and prior.producer_version == event.producer_version
            and prior.to_dict()["payload"] == event.to_dict()["payload"]
            and prior.payload_ref == event.payload_ref
        )

    def _task4_phase_guard(
        self,
        recorded: list[EventEnvelope],
        event: EventEnvelope,
        freshness_context: tuple[
            str, tuple[str, ...], tuple[str, ...], str, str
        ] | None = None,
    ) -> None:
        """Enforce observe-only terminals while holding the journal lock."""
        run = [prior for prior in recorded if prior.run_id == event.run_id]
        started = next((prior for prior in run if prior.event_type == "run.started"), None)
        if started is None or not started.payload["activeSkills"] or not all("@sha256:" in str(value) for value in started.payload["activeSkills"]):
            return
        if started.payload.get("runKind", "local") != "local":
            return
        observed = [prior for prior in run if prior.event_type == "task.observed"]
        evaluations = [prior for prior in run if prior.event_type == "evaluation.completed"]
        if event.event_type == "finding.drafted" and sum(
            prior.event_type == "finding.drafted" for prior in run
        ) >= 3:
            raise StoreIntegrityError("finding draft cap reached")
        if event.event_type == "task.observed" and observed:
            raise StoreIntegrityError("duplicate task observation terminal")
        if event.event_type == "evaluation.completed":
            if len(observed) != 1:
                raise StoreIntegrityError("evaluation requires exactly one observation")
            logical_operation = event.payload["logicalOperationId"]
            operation_name = event.payload["targetSkill"]
            valid_name = __import__("re").fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}(?::[a-z0-9][a-z0-9._-]{0,62})?", operation_name)
            marker = ":" + operation_name + ":"
            prefix, separator, operation_version = logical_operation.rpartition(marker)
            if valid_name is None or not separator or not prefix or __import__("re").fullmatch(r"sha256:[0-9a-f]{64}", operation_version) is None:
                raise StoreIntegrityError("evaluation target name/version is not declared by run.started") from None
            identity = operation_name + "@" + operation_version
            if identity not in started.payload["activeSkills"]:
                raise StoreIntegrityError("evaluation target name/version is not declared by run.started")
            if any(prior.payload["targetSkill"] == event.payload["targetSkill"] for prior in evaluations):
                raise StoreIntegrityError("duplicate target evaluation")
        if event.event_type == "run.closed":
            declared = {str(value).split("@", 1)[0] for value in started.payload["activeSkills"]}
            evaluated = {prior.payload["targetSkill"] for prior in evaluations}
            if len(observed) != 1 or evaluated != declared or len(evaluations) != len(declared):
                raise StoreIntegrityError("close requires observation and all target evaluations")
            if started.payload["mode"] == "propose":
                from .candidates import CandidateBuilder
                from .hooks import LifecycleError, canonical_digest
                from .sanitize import sanitize_evidence

                reports = [prior for prior in run if prior.event_type == "report.generated"]
                admissions = [prior for prior in run if prior.event_type == "candidate.admission_decided"]
                captures = [prior for prior in run if prior.event_type == "candidate.captured"]
                drafts = []
                durable_evaluations: list[dict[str, object]] = []
                builder = CandidateBuilder(self)
                for evaluation_event in evaluations:
                    expected_ref = f"evaluations/{evaluation_event.event_id}.json"
                    if evaluation_event.payload_ref != expected_ref:
                        raise StoreIntegrityError("proposal close requires durable evaluations")
                    try:
                        raw = json.loads(self._read_regular("objects/" + expected_ref).decode("utf-8"))
                        if not isinstance(raw, dict):
                            raise ValueError
                        durable_evaluations.append(raw)
                        drafts.extend(
                            builder.build_from_snapshot(
                                raw,
                                run,
                                lambda relative: self._read_regular("objects/" + relative),
                            )
                        )
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, LifecycleError):
                        raise StoreIntegrityError("proposal close requires durable evaluations") from None
                expected: dict[str, tuple[str, str, object]] = {}
                evaluation_by_id = {
                    f"evaluation:{started.run_id}:{item.payload['targetSkill']}": item.event_id
                    for item in evaluations
                }
                for draft in drafts:
                    correlation = canonical_digest(draft.canonical_mapping())
                    binding = (evaluation_by_id.get(draft.evaluation_id, ""), draft.target_skill, draft)
                    if not binding[0] or correlation in expected:
                        raise StoreIntegrityError("proposal close has ambiguous candidate branches")
                    expected[correlation] = binding
                if len(admissions) != len(expected):
                    raise StoreIntegrityError("proposal close requires every candidate admission branch")
                seen: set[str] = set()
                for admission in admissions:
                    binding = expected.get(str(admission.correlation_id))
                    if (
                        binding is None
                        or admission.correlation_id in seen
                        or admission.causation_id != binding[0]
                        or admission.payload["targetSkill"] != binding[1]
                    ):
                        raise StoreIntegrityError("proposal close has invalid candidate admission correlation")
                    seen.add(str(admission.correlation_id))
                binding_ref = f"proposals/{event.run_id}.json"
                try:
                    provider_binding = (
                        _strict_sidecar_json(self._read_regular("objects/" + binding_ref))
                        if admissions
                        else {
                            "schemaVersion": 1,
                            "runId": event.run_id,
                            "providerRoot": "read-only-no-op",
                            "providerLearningHome": "read-only-no-op",
                            "providerDigest": "sha256:" + "0" * 64,
                            "contractRoots": [],
                            "targetRoots": [],
                        }
                    )
                except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    raise StoreIntegrityError("proposal close requires a durable provider binding") from None
                provider_fields = {
                    "schemaVersion", "runId", "providerRoot", "providerLearningHome",
                    "providerDigest", "contractRoots", "targetRoots",
                }
                if (
                    not isinstance(provider_binding, dict)
                    or set(provider_binding) != provider_fields
                    or provider_binding.get("schemaVersion") != 1
                    or provider_binding.get("runId") != event.run_id
                    or not isinstance(provider_binding.get("providerDigest"), str)
                    or __import__("re").fullmatch(r"sha256:[0-9a-f]{64}", str(provider_binding["providerDigest"])) is None
                    or not isinstance(provider_binding.get("targetRoots"), list)
                    or not isinstance(provider_binding.get("contractRoots"), list)
                ):
                    raise StoreIntegrityError("proposal close provider binding is invalid")
                trusted_root_witness: str | None = None
                if admissions:
                    target_bindings: list[dict[str, object]] = []
                    contract_bindings: list[dict[str, object]] | None = None
                    try:
                        for evaluation in durable_evaluations:
                            verification = evaluation.get("verificationBinding")
                            if not isinstance(verification, dict):
                                raise LifecycleError("missing verification binding")
                            target = verification.get("targetRoot")
                            contracts = verification.get("contractRoots")
                            if not isinstance(target, dict) or not isinstance(contracts, list):
                                raise LifecycleError("missing verification binding")
                            if contract_bindings is None:
                                contract_bindings = [dict(item) for item in contracts if isinstance(item, dict)]
                                if len(contract_bindings) != len(contracts):
                                    raise LifecycleError("invalid contract verification binding")
                            elif contracts != contract_bindings:
                                raise LifecycleError("conflicting contract verification binding")
                            target_bindings.append(dict(target))
                        if not target_bindings or not contract_bindings:
                            raise LifecycleError("missing verification binding")
                        if sorted(
                            str(item.get("canonicalRoot")) for item in target_bindings
                        ) != sorted(str(item) for item in provider_binding["targetRoots"]):
                            raise LifecycleError("target root mapping mismatch")
                        if sorted(
                            str(item.get("canonicalRoot")) for item in contract_bindings
                        ) != sorted(str(item) for item in provider_binding["contractRoots"]):
                            raise LifecycleError("contract root mapping mismatch")
                        evaluation_targets = {
                            (str(item.get("targetSkill")), str(item.get("targetSkillVersionHash")))
                            for item in durable_evaluations
                        }
                        proof_targets = {
                            (str(item.get("name")), str(item.get("versionHash")))
                            for item in target_bindings
                        }
                        if evaluation_targets != proof_targets:
                            raise LifecycleError("target identity mapping mismatch")
                        verification_bindings = {
                            "targetRoots": target_bindings,
                            "contractRoots": contract_bindings,
                        }
                        if freshness_context is None:
                            raise LifecycleError("missing terminal root freshness witness")
                        (
                            _runtime_witness_digest,
                            witness_targets,
                            witness_contracts,
                            historical_witness_digest,
                            witness_verification_digest,
                        ) = freshness_context
                        if (
                            sorted(witness_targets)
                            != sorted(str(item) for item in provider_binding["targetRoots"])
                            or sorted(witness_contracts)
                            != sorted(str(item) for item in provider_binding["contractRoots"])
                            or witness_verification_digest
                            != canonical_digest(verification_bindings)
                        ):
                            raise LifecycleError("terminal root freshness mapping mismatch")
                        trusted_root_witness = historical_witness_digest
                    except (LifecycleError, KeyError, TypeError):
                        raise StoreIntegrityError(
                            "proposal close trusted target binding is invalid"
                        ) from None
                provider_binding_digest = canonical_digest(provider_binding)
                captures_by_admission: dict[str | None, list[EventEnvelope]] = {}
                for capture in captures:
                    captures_by_admission.setdefault(capture.causation_id, []).append(capture)
                for admission in admissions:
                    draft = expected[str(admission.correlation_id)][2]
                    receipt_prefix = f"proposals/{getattr(draft, 'operation_id')}-"
                    receipt_ref = admission.payload_ref
                    if (
                        not isinstance(receipt_ref, str)
                        or not receipt_ref.startswith(receipt_prefix)
                        or not receipt_ref.endswith(".json")
                    ):
                        raise StoreIntegrityError("proposal close requires a durable route receipt")
                    receipt_digest = receipt_ref[len(receipt_prefix) : -len(".json")]
                    if __import__("re").fullmatch(r"[0-9a-f]{64}", receipt_digest) is None:
                        raise StoreIntegrityError("proposal close route receipt digest is invalid")
                    try:
                        receipt_bytes = self._read_regular("objects/" + receipt_ref)
                        if hashlib.sha256(receipt_bytes).hexdigest() != receipt_digest:
                            raise ValueError("route receipt digest mismatch")
                        receipt = _strict_sidecar_json(receipt_bytes)
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
                        raise StoreIntegrityError("proposal close requires a durable route receipt") from None
                    receipt_fields = {
                        "schemaVersion", "runId", "candidateCorrelation", "providerBindingRef",
                        "providerBindingDigest", "decision", "hardReasons", "routeDecision",
                    }
                    route_fields = {"status", "ownerSkill", "ownerPath", "matchedScope", "reason", "routeBinding"}
                    route_value = receipt.get("routeDecision") if isinstance(receipt, dict) else None
                    if (
                        not isinstance(receipt, dict)
                        or set(receipt) != receipt_fields
                        or receipt.get("schemaVersion") != 1
                        or receipt.get("runId") != event.run_id
                        or receipt.get("candidateCorrelation") != admission.correlation_id
                        or receipt.get("providerBindingRef") != binding_ref
                        or receipt.get("providerBindingDigest") != provider_binding_digest
                        or receipt.get("decision") != admission.payload["decision"]
                        or receipt.get("hardReasons") != list(admission.payload["hardReasons"])
                        or not isinstance(route_value, dict)
                        or set(route_value) != route_fields
                    ):
                        raise StoreIntegrityError("proposal close route receipt binding is invalid")
                    status = route_value["status"]
                    reason = route_value["reason"]
                    admitted_reason = (
                        sanitize_evidence([{"kind": "route", "summary": reason}])
                        if isinstance(reason, str)
                        else None
                    )
                    if (
                        admitted_reason is None
                        or not reason
                        or len(reason) > 1000
                        or admitted_reason.rejected_count
                        or admitted_reason.truncated_count
                        or len(admitted_reason.accepted) != 1
                        or admitted_reason.accepted[0]["summary"] != reason
                    ):
                        raise StoreIntegrityError("proposal close route reason is unsafe")
                    expected_reasons: list[str] = []
                    if status != "resolved":
                        if status not in {"needs-owner", "ownership-conflict"} or any(
                            route_value[key] is not None
                            for key in ("ownerSkill", "ownerPath", "matchedScope", "routeBinding")
                        ):
                            raise StoreIntegrityError("proposal close unresolved route receipt is invalid")
                        expected_reasons.append(str(status))
                    elif route_value["ownerSkill"] != getattr(draft, "target_skill"):
                        expected_reasons.append("owner-target-mismatch")
                    elif route_value["ownerPath"] not in provider_binding["targetRoots"]:
                        expected_reasons.append("owner-path-not-allowlisted")
                    elif not isinstance(route_value["matchedScope"], str) or not (
                        getattr(draft, "scope") == route_value["matchedScope"]
                        or getattr(draft, "scope").startswith(str(route_value["matchedScope"]) + ".")
                    ):
                        expected_reasons.append("route-scope-mismatch")
                    elif not isinstance(route_value["routeBinding"], str) or __import__("re").fullmatch(
                        r"[0-9a-f]{64}", str(route_value["routeBinding"])
                    ) is None:
                        expected_reasons.append("route-binding-missing")
                    if expected_reasons != list(admission.payload["hardReasons"]):
                        raise StoreIntegrityError("proposal close route decision is inconsistent")
                    expected_decision = "reject" if expected_reasons else "allow"
                    if admission.payload["decision"] != expected_decision:
                        raise StoreIntegrityError("proposal close route decision is inconsistent")
                    branch_captures = captures_by_admission.get(admission.event_id, [])
                    expected_count = 1 if expected_decision == "allow" else 0
                    if len(branch_captures) != expected_count:
                        raise StoreIntegrityError("proposal close requires every branch terminal")
                    if branch_captures:
                        capture = branch_captures[0]
                        candidate_id = str(capture.payload["providerCandidateId"])
                        expected_capture_payload = {
                            "logicalOperationId": f"proposal:capture-journal:{getattr(draft, 'operation_id')}",
                            "targetSkill": getattr(draft, "target_skill"),
                            "providerCandidateId": candidate_id,
                            "captureOperationId": getattr(draft, "operation_id"),
                            "owner": route_value["ownerSkill"],
                        }
                        expected_capture_correlation = canonical_digest(
                            {
                                "draft": getattr(draft, "canonical_mapping")(),
                                "providerCandidateId": candidate_id,
                            }
                        )
                        if (
                            capture.to_dict()["payload"] != expected_capture_payload
                            or capture.correlation_id != expected_capture_correlation
                            or capture.payload_ref is not None
                        ):
                            raise StoreIntegrityError("proposal close capture binding is invalid")
                if len(reports) != 1 or event.causation_id != reports[0].event_id:
                    raise StoreIntegrityError("proposal close requires exactly one final report")
                report_event = reports[0]
                try:
                    report_bytes = self._read_regular(f"reports/local-review-{event.run_id}.json")
                    report_value = _strict_sidecar_json(report_bytes)
                except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    raise StoreIntegrityError("proposal close requires a durable report") from None
                candidate_ids = sorted(str(item.payload["providerCandidateId"]) for item in captures)
                if len(set(candidate_ids)) != len(candidate_ids):
                    raise StoreIntegrityError("proposal close has duplicate provider candidate IDs")
                expected_status = "no-op" if not drafts else "completed" if candidate_ids else "rejected"
                expected_report = {
                    "schemaVersion": 1,
                    "runId": event.run_id,
                    "mode": "propose",
                    "status": expected_status,
                    "evaluationIds": sorted(item.event_id for item in evaluations),
                    "candidateIds": candidate_ids,
                    "rejectedCount": sum(item.payload["decision"] == "reject" for item in admissions),
                    "mutationPerformed": False,
                }
                report_digest = "sha256:" + hashlib.sha256(report_bytes).hexdigest()
                close_binding: dict[str, object] = {
                    "status": expected_status,
                    "observation": observed[0].event_id,
                    "evaluations": [item.event_id for item in evaluations],
                }
                if trusted_root_witness is not None:
                    close_binding["trustedRootWitness"] = trusted_root_witness
                if (
                    report_value != expected_report
                    or report_event.payload["pathDigest"] != report_digest
                    or report_event.correlation_id != canonical_digest(expected_report)
                    or list(report_event.payload["inputRefs"]) != expected_report["evaluationIds"]
                    or event.payload["status"] != expected_status
                    or event.correlation_id != canonical_digest(close_binding)
                ):
                    raise StoreIntegrityError("proposal close report binding is invalid")

    def rebuild_index(self) -> None:
        self._assert_writable()
        with self._exclusive_lock():
            events = self._strict_events()
            connection = sqlite3.connect(":memory:")
            try:
                connection.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, run_id TEXT NOT NULL, event_type TEXT NOT NULL, idempotency_key TEXT UNIQUE NOT NULL, event_json TEXT NOT NULL)")
                connection.executemany(
                    "INSERT INTO events(sequence, event_id, run_id, event_type, idempotency_key, event_json) VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        (number, event.event_id, event.run_id, event.event_type, event.idempotency_key,
                         json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False))
                        for number, event in enumerate(events, start=1)
                    ],
                )
                connection.commit()
                index_bytes = connection.serialize()
            finally:
                connection.close()

            directory = self._open_home()
            temporary_name: str | None = None
            descriptor = -1
            try:
                for _ in range(128):
                    candidate = ".index-" + secrets.token_hex(12) + ".sqlite"
                    try:
                        descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, dir_fd=directory)
                        temporary_name = candidate
                        break
                    except FileExistsError:
                        continue
                if descriptor == -1 or temporary_name is None:
                    raise StoreIntegrityError("could not allocate a unique index temporary file")
                self._validate_open_regular(descriptor)
                os.fchmod(descriptor, 0o600)
                view = memoryview(index_bytes)
                offset = 0
                while offset < len(view):
                    written = os.write(descriptor, view[offset:])
                    if written <= 0:
                        raise StoreIntegrityError("incomplete index write")
                    offset += written
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                self._tighten_existing_file("index.sqlite")
                os.replace(temporary_name, self.index_path.name, src_dir_fd=directory, dst_dir_fd=directory)
                temporary_name = None
                index_descriptor = os.open(self.index_path.name, os.O_RDONLY | _NOFOLLOW, dir_fd=directory)
                try:
                    self._validate_open_regular(index_descriptor)
                    os.fchmod(index_descriptor, 0o600)
                finally:
                    os.close(index_descriptor)
                _fsync_directory(directory)
            finally:
                if descriptor != -1:
                    os.close(descriptor)
                if temporary_name is not None:
                    try:
                        os.unlink(temporary_name, dir_fd=directory)
                    except FileNotFoundError:
                        pass
                os.close(directory)

    def doctor_salvage_report(self, report_path: Path | str) -> dict[str, object]:
        """Inspect individual lines without opening, rewriting, or trusting the ledger."""
        report = Path(os.path.abspath(os.fspath(report_path)))
        if report == self.events_path:
            raise StoreIntegrityError("salvage report cannot alias the source ledger")
        try:
            relative = report.relative_to(self.home / "reports")
        except ValueError:
            raise StoreIntegrityError("salvage report must be inside the reports directory")
        if len(relative.parts) != 1:
            raise StoreIntegrityError("salvage report must be inside the reports directory")
        try:
            report_metadata = report.lstat()
        except FileNotFoundError:
            report_metadata = None
        if report_metadata is not None:
            if stat.S_ISLNK(report_metadata.st_mode):
                raise StoreIntegrityError("salvage report cannot alias the source ledger")
            if self.events_path.exists():
                source_metadata = self.events_path.lstat()
                if (report_metadata.st_dev, report_metadata.st_ino) == (source_metadata.st_dev, source_metadata.st_ino):
                    raise StoreIntegrityError("salvage report cannot alias the source ledger")
            raise StoreIntegrityError("salvage report path must be a new regular file")
        source = self._read_regular("events.jsonl", missing_ok=True)
        corrupt_lines: list[int] = []
        valid_lines = 0
        for line_number, line in enumerate(source.splitlines(), start=1):
            try:
                if not line:
                    raise ValueError("blank")
                EventEnvelope.from_mapping(json.loads(line))
                valid_lines += 1
            except (ValueError, TypeError, json.JSONDecodeError, EventValidationError, UnicodeDecodeError):
                corrupt_lines.append(line_number)
        if source and not source.endswith(b"\n"):
            corrupt_lines.append(len(source.splitlines()) or 1)
        result: dict[str, object] = {"schemaVersion": 1, "source": str(self.events_path), "validLines": valid_lines, "corruptLines": sorted(set(corrupt_lines)), "sourceRewritten": False}
        payload = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        self.write_once(report, payload)
        return result


@dataclass(frozen=True, slots=True)
class PublishedSidecar:
    ref: str
    digest: str


class PromotionJournal:
    """Strict create-once Task 8 object publisher and replay reader."""

    _ROLE_BY_KIND = {
        "promotion-origin": "origin",
        "provider-snapshot": "snapshot",
        "apply-intent": "intent",
        "apply-readback": "readback",
        "live-verification": "verification",
        "rollback-readback": "readback",
        "resolution-readback": "resolution",
        "transaction-decision": "decision",
    }

    def __init__(self, store: EventStore) -> None:
        if not isinstance(store, EventStore) or getattr(store, "_read_only", False):
            raise StoreIntegrityError("promotion journal requires a writable EventStore")
        if not store.promotion_eligible:
            raise StoreIntegrityError("promotion topology is not initialized")
        self.store = store

    @staticmethod
    def _canonical_document(document: Mapping[str, Any]) -> bytes:
        if not isinstance(document, Mapping):
            raise StoreIntegrityError("promotion sidecar must be an object")
        try:
            return json.dumps(
                dict(document), sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8") + b"\n"
        except (TypeError, ValueError):
            raise StoreIntegrityError("promotion sidecar is not canonical JSON") from None

    @staticmethod
    def _admit_length(size_vector: Mapping[str, Any], exact: int, stage: str) -> None:
        from .promotion import PromotionError, validate_task8_document_length
        try:
            validate_task8_document_length(size_vector, exact_length=exact, pipeline_stage=stage)
        except PromotionError as error:
            raise StoreIntegrityError(f"promotion sidecar exact length bound failed: {error}") from None

    @staticmethod
    def _parse_canonical(data: bytes) -> dict[str, Any]:
        try:
            value = _strict_sidecar_json(data)
            canonical = json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode("utf-8") + b"\n"
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
            raise StoreIntegrityError("promotion sidecar is corrupt or non-canonical") from None
        if not isinstance(value, dict) or canonical != data:
            raise StoreIntegrityError("promotion sidecar is corrupt or non-canonical")
        return value

    @staticmethod
    def _strict_read_at(
        parent_fd: int,
        name: str,
        *,
        maximum: int,
        missing_ok: bool = False,
        sync: bool = False,
    ) -> bytes | None:
        descriptor = -1
        try:
            try:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=parent_fd)
            except FileNotFoundError:
                if missing_ok:
                    return None
                raise
            opened = os.fstat(descriptor)
            if (
                stat.S_ISLNK(named.st_mode)
                or not stat.S_ISREG(named.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or named.st_nlink != 1
                or opened.st_nlink != 1
                or named.st_uid != os.geteuid()
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(named.st_mode) != 0o600
                or stat.S_IMODE(opened.st_mode) != 0o600
                or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_size < 0
                or opened.st_size > maximum
            ):
                raise StoreIntegrityError("unsafe strict Task 8 sidecar topology")
            chunks: list[bytes] = []
            remaining = opened.st_size + 1
            while remaining:
                try:
                    chunk = os.read(descriptor, min(64 * 1024, remaining))
                except InterruptedError:
                    continue
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            after = os.fstat(descriptor)
            if (
                len(data) != opened.st_size
                or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
            ):
                raise StoreIntegrityError("Task 8 sidecar changed during strict read")
            if sync:
                os.fsync(descriptor)
            return data
        except OSError as error:
            raise StoreIntegrityError("strict Task 8 sidecar read failed") from error
        finally:
            if descriptor != -1:
                os.close(descriptor)

    def _publish_strict_locked(
        self,
        relative: Path,
        data: bytes,
        *,
        maximum: int,
        adopt_existing: bool = False,
    ) -> bytes:
        parent = self.store._open_relative_directory(str(relative.parent))
        staging = self.store._open_relative_directory("locks/promotion/transactions")
        source = -1
        try:
            for name in os.listdir(parent):
                if name.startswith(".rsi-tmp-") or name.startswith(".rsi-unbound-publish-"):
                    raise StoreIntegrityError("unexpected Task 8 publication alias")
            existing = self._strict_read_at(
                parent, relative.name, maximum=maximum, missing_ok=True
            )
            if existing is not None:
                if not adopt_existing and existing != data:
                    raise StoreIntegrityError("Task 8 sidecar replay conflicts")
                return existing
            source = _open_unnamed_staging_at(staging)
            metadata = os.fstat(source)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 0
            ):
                raise StoreIntegrityError("unnamed Task 8 staging inode is unsafe")
            os.fchmod(source, 0o600)
            view = memoryview(data)
            offset = 0
            while offset < len(view):
                try:
                    written = os.write(source, view[offset:])
                except InterruptedError:
                    continue
                if written <= 0:
                    raise StoreIntegrityError("incomplete strict Task 8 sidecar write")
                offset += written
            os.fsync(source)
            try:
                _publish_unnamed_noreplace_at(parent, source, relative.name)
            except FileExistsError:
                pass
            winner = self._strict_read_at(
                parent, relative.name, maximum=maximum, sync=True
            )
            assert winner is not None
            if not adopt_existing and winner != data:
                raise StoreIntegrityError("Task 8 sidecar no-replace winner conflicts")
            _fsync_directory(parent)
            return winner
        finally:
            if source != -1:
                os.close(source)
            os.close(staging)
            os.close(parent)

    def publish_transaction_sidecar(
        self, document: Mapping[str, Any], *, size_vector: Mapping[str, Any]
    ) -> PublishedSidecar:
        kind = document.get("kind")
        transaction_id = document.get("transactionId")
        role = self._ROLE_BY_KIND.get(kind)
        if role is None or not isinstance(transaction_id, str):
            raise StoreIntegrityError("promotion transaction sidecar kind is invalid")
        if size_vector.get("kind") != kind:
            raise StoreIntegrityError("promotion sidecar size vector kind conflicts")
        data = self._canonical_document(document)
        self._admit_length(size_vector, len(data), "allocation")
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        ref = f"transactions/{transaction_id}-{role}-{digest[7:]}.json"
        relative = Path("objects") / ref
        with self.store._exclusive_lock():
            self._admit_length(size_vector, len(data), "write")
            from .promotion import task8_sidecar_cap

            durable = self._publish_strict_locked(
                relative, data, maximum=task8_sidecar_cap(str(kind))
            )
            self._admit_length(size_vector, len(data), "readback")
            if durable != data:
                raise StoreIntegrityError("promotion sidecar readback conflict")
        return PublishedSidecar(ref, digest)

    def publish_incident_record(
        self, document: Mapping[str, Any], *, size_vector: Mapping[str, Any]
    ) -> PublishedSidecar:
        if document.get("kind") != "incident-record" or size_vector.get("kind") != "incident-record":
            raise StoreIntegrityError("incident record kind is invalid")
        incident_id = document.get("incidentId")
        if not isinstance(incident_id, str):
            raise StoreIntegrityError("incident record identifier is invalid")
        data = self._canonical_document(document)
        self._admit_length(size_vector, len(data), "allocation")
        ref = f"incidents/records/{incident_id}.json"
        relative = Path(ref)
        with self.store._exclusive_lock():
            from .promotion import task8_sidecar_cap

            winner = self._publish_strict_locked(
                relative,
                data,
                maximum=task8_sidecar_cap("incident-record"),
                adopt_existing=True,
            )
            parsed = self._parse_canonical(winner)
            if (
                parsed.get("kind") != "incident-record"
                or parsed.get("incidentId") != incident_id
                or parsed.get("transactionId") != document.get("transactionId")
                or parsed.get("runId") != document.get("runId")
                or parsed.get("planDigest") != document.get("planDigest")
                or parsed.get("eventBinding") != document.get("eventBinding")
            ):
                raise StoreIntegrityError("incident record fixed selector is corrupt or conflicting")
        digest = "sha256:" + hashlib.sha256(winner).hexdigest()
        return PublishedSidecar(ref, digest)

    def read_sidecar(
        self, ref: str, *, expected_kind: str, size_vector: Mapping[str, Any]
    ) -> dict[str, Any]:
        role = self._ROLE_BY_KIND.get(expected_kind)
        if role is None or size_vector.get("kind") != expected_kind:
            raise StoreIntegrityError("promotion sidecar expected kind is invalid")
        match = __import__("re").fullmatch(
            rf"transactions/(tx_[0-9a-f]{{64}})-{__import__('re').escape(role)}-([0-9a-f]{{64}})\.json",
            ref,
        )
        if match is None:
            raise StoreIntegrityError("promotion sidecar ref or kind is invalid")
        relative = Path("objects") / ref
        self.store._assert_runtime_topology()
        from .promotion import task8_sidecar_cap

        parent = self.store._open_relative_directory(str(relative.parent))
        try:
            data = self._strict_read_at(
                parent,
                relative.name,
                maximum=task8_sidecar_cap(expected_kind),
            )
            assert data is not None
        finally:
            os.close(parent)
        self._admit_length(size_vector, len(data), "read")
        digest = hashlib.sha256(data).hexdigest()
        if digest != match.group(2):
            raise StoreIntegrityError("promotion sidecar digest conflicts with its ref")
        parsed = self._parse_canonical(data)
        if parsed.get("kind") != expected_kind or parsed.get("transactionId") != match.group(1):
            raise StoreIntegrityError("promotion sidecar kind or transaction conflicts")
        self._admit_length(size_vector, len(data), "replay")
        return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m rsi_core.storage")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--home", required=True)
    doctor.add_argument("--salvage-report", required=True)
    arguments = parser.parse_args(argv)
    if arguments.command == "doctor":
        result = EventStore(arguments.home).doctor_salvage_report(arguments.salvage_report)
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
