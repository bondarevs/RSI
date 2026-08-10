"""Independent literal helpers for Task 8 authority tests.

This module deliberately does not import production builders.  Expected bytes,
digests, filesystem witnesses, and deterministic identifiers are recomputed by
the tests from the approved Task 8 schemas.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping


DIGEST_A = "sha256:" + "1" * 64
DIGEST_B = "sha256:" + "2" * 64
DIGEST_C = "sha256:" + "3" * 64
DIGEST_D = "sha256:" + "4" * 64
BARE_A = "1" * 64
NOW = datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc)


def canonical_no_lf(value: object) -> bytes:
    """Task 7/provider semantic canonical JSON (no trailing LF)."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_final_lf(value: object) -> bytes:
    """Task 8/EventStore canonical JSON (exactly one trailing LF)."""
    return canonical_no_lf(value) + b"\n"


def prefixed_digest(value: object, *, final_lf: bool = True) -> str:
    payload = canonical_final_lf(value) if final_lf else canonical_no_lf(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def raw_digest(payload: bytes, *, prefixed: bool = True) -> str:
    digest = hashlib.sha256(payload).hexdigest()
    return f"sha256:{digest}" if prefixed else digest


def task8_event_id(transaction_id: str, event_type: str) -> str:
    seed = {
        "domain": "rsi-promotion-event-v1",
        "eventType": event_type,
        "transactionId": transaction_id,
    }
    return "evt_" + prefixed_digest(seed, final_lf=False)[7:]


def task8_transaction_id(plan_digest: str) -> str:
    seed = {"domain": "rsi-promotion-transaction-v1", "planDigest": plan_digest}
    return "tx_" + prefixed_digest(seed, final_lf=False)[7:]


def task8_run_id(plan_digest: str) -> str:
    seed = {"domain": "rsi-promotion-continuation-v1", "planDigest": plan_digest}
    return "run_promote_" + prefixed_digest(seed, final_lf=False)[7:]


def task8_incident_id(transaction_id: str) -> str:
    seed = {"domain": "rsi-promotion-incident-v1", "transactionId": transaction_id}
    return "incident_" + prefixed_digest(seed, final_lf=False)[7:]


def lazy_module(name: str):
    """Let missing production seams fail a test without aborting collection."""
    return importlib.import_module(name)


def exact_keys(mapping: Mapping[str, Any], *keys: str) -> None:
    assert set(mapping) == set(keys)


def _entry_type(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular-file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode):
        return "block-device"
    if stat.S_ISCHR(mode):
        return "character-device"
    return "other-special"


def filesystem_witness(root: Path) -> tuple[dict[str, object], ...]:
    """Snapshot type/identity/mode/link/bytes without following symlinks."""
    root = Path(root)
    result: list[dict[str, object]] = []
    pending = [root]
    while pending:
        path = pending.pop()
        metadata = path.lstat()
        relative = "" if path == root else path.relative_to(root).as_posix()
        entry: dict[str, object] = {
            "relativePath": relative,
            "type": _entry_type(metadata.st_mode),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode),
            "uid": metadata.st_uid,
            "nlink": metadata.st_nlink,
            "size": metadata.st_size,
        }
        if stat.S_ISREG(metadata.st_mode):
            entry["bytes"] = path.read_bytes()
        elif stat.S_ISLNK(metadata.st_mode):
            entry["linkTarget"] = os.readlink(path)
        result.append(entry)
        if stat.S_ISDIR(metadata.st_mode):
            pending.extend(sorted(path.iterdir(), reverse=True))
    return tuple(sorted(result, key=lambda item: str(item["relativePath"]).encode("utf-8")))


@dataclass
class FixedClock:
    value: datetime = NOW

    def now(self) -> datetime:
        return self.value


@dataclass
class FixedNonceSource:
    values: list[str]

    def token_hex(self, byte_count: int) -> str:
        assert byte_count == 32
        if not self.values:
            raise AssertionError("nonce source exhausted")
        value = self.values.pop(0)
        assert len(value) == 64
        int(value, 16)
        return value
