from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from rsi_core.storage import EventStore, StoreIntegrityError

from test_events import make_event


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_runtime_directories_are_private_and_regular_files_are_owner_only(tmp_path: Path) -> None:
    """Ledger artifacts may not be readable or traversable by other local users."""
    store = EventStore(tmp_path)
    store.append(make_event("run.started", 1))
    store.rebuild_index()
    report = tmp_path / "reports" / "doctor.json"
    store.doctor_salvage_report(report)

    directories = [tmp_path, tmp_path / "locks", tmp_path / "objects", tmp_path / "objects" / "observations", tmp_path / "objects" / "post-images", tmp_path / "baselines", tmp_path / "experiments", tmp_path / "reports", tmp_path / "defragmentation", tmp_path / "rejected", tmp_path / "incidents"]
    files = [store.events_path, store.lock_path, store.index_path, report]

    assert all(mode(path) == 0o700 for path in directories)
    assert all(mode(path) & 0o077 == 0 for path in files)


def test_existing_permissive_artifacts_are_tightened(tmp_path: Path) -> None:
    """Umask or pre-existing files cannot widen the storage contract."""
    tmp_path.chmod(0o755)
    (tmp_path / "events.jsonl").write_text("", encoding="utf-8")
    (tmp_path / "events.jsonl").chmod(0o644)

    store = EventStore(tmp_path)

    assert mode(tmp_path) == 0o700
    assert mode(store.events_path) & 0o077 == 0


@pytest.mark.parametrize("unsafe_mode", [0o004, 0o040, 0o070])
def test_existing_regular_files_without_owner_access_fail_closed(tmp_path: Path, unsafe_mode: int) -> None:
    """Without a safely opened descriptor, tightening must not mutate by pathname."""
    events = tmp_path / "events.jsonl"
    events.write_bytes(b"state")
    descriptor = os.open(events, os.O_RDONLY)
    events.chmod(unsafe_mode)
    before = os.pread(descriptor, 5, 0), mode(events)

    try:
        with pytest.raises(StoreIntegrityError, match="cannot be opened safely"):
            EventStore(tmp_path)

        assert (os.pread(descriptor, 5, 0), mode(events)) == before
    finally:
        os.close(descriptor)
