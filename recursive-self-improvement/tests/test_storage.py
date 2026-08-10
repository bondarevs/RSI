from __future__ import annotations

import itertools
import hashlib
import json
import multiprocessing
import os
import random
import subprocess
import sys
import time
import fcntl
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from rsi_core.events import EventEnvelope, EventValidationError
from rsi_core import storage as storage_module
from rsi_core.storage import EventStore, StoreIntegrityError
from rsi_core.hooks import RunCoordinator
from rsi_core.observe import Observer

from task8_support import (
    canonical_final_lf,
    filesystem_witness,
    lazy_module,
    prefixed_digest,
)
from test_events import (
    EVENT_PAYLOADS,
    TASK8_MANIFEST_PRE_HASH,
    TASK8_PLAN_DIGEST,
    TASK8_POST_HASH,
    TASK8_PRE_HASH,
    _task8_event,
    _task8_event_id,
    _task8_event_raw,
    _task8_incident_id,
    _task8_run_id,
    _task8_transaction_id,
    make_event,
    promotion_prefix,
)


def _append_in_process(home: str, number: int) -> None:
    store = EventStore(Path(home))
    start = make_event("run.started", number, run_id=f"run-{number}")
    store.append(start)


def _rebuild_in_process(home: str, ready: multiprocessing.connection.Connection) -> None:
    ready.send("ready")
    EventStore(Path(home)).rebuild_index()


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
TASK8_STORE_MARKER_BYTES = canonical_final_lf(
    {"domain": "rsi-promotion-store-v1", "schemaVersion": 1}
)


def _trap_write_capable_syscalls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any accidental mutation during an existing-only operation observable."""
    real_open = os.open
    write_flags = (
        os.O_WRONLY
        | os.O_RDWR
        | os.O_CREAT
        | os.O_TRUNC
        | os.O_APPEND
        | os.O_EXCL
    )

    def checked_open(path, flags, *args, **kwargs):
        if flags & write_flags:
            raise AssertionError(f"write-capable os.open during read-only operation: {path}")
        return real_open(path, flags, *args, **kwargs)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("write-capable syscall during read-only operation")

    monkeypatch.setattr(os, "open", checked_open)
    for name in (
        "mkdir",
        "chmod",
        "fchmod",
        "unlink",
        "rename",
        "replace",
        "link",
        "write",
        "fsync",
    ):
        monkeypatch.setattr(os, name, forbidden)
    if hasattr(os, "fdatasync"):
        monkeypatch.setattr(os, "fdatasync", forbidden)
    monkeypatch.setattr(fcntl, "flock", forbidden)


def _task8_size_vector(
    kind: str,
    *,
    path_budget: int = 256,
    members: int = 1,
    protected_readbacks: int = 1,
    evidence_bytes: int = 8 * 1024,
    outer_bytes: int = 8 * 1024,
) -> dict[str, object]:
    return {
        "kind": kind,
        "pathBudgetBytes": path_budget,
        "memberCount": members,
        "protectedReadbackCount": protected_readbacks,
        "evidenceAndFramingBytes": evidence_bytes,
        "outerEnvelopeBytes": outer_bytes,
    }


def _target_witness() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "domain": "rsi-target-witness-v1",
        "rootIdentityDigest": "sha256:" + "1" * 64,
        "relativePath": "references/knowledge.md",
        "device": 1,
        "inode": 2,
        "type": "regular-file",
        "mode": 0o600,
        "uid": os.geteuid(),
        "nlink": 1,
        "size": 8,
        "artifactHash": TASK8_PRE_HASH,
        "manifestHash": TASK8_MANIFEST_PRE_HASH,
    }


def _incident_record(
    *,
    last_durable_event_type: str = "run.started",
) -> dict[str, object]:
    transaction_id = _task8_transaction_id()
    incident_id = _task8_incident_id()
    return {
        "schemaVersion": 1,
        "kind": "incident-record",
        "transactionId": transaction_id,
        "runId": _task8_run_id(),
        "planDigest": TASK8_PLAN_DIGEST,
        "eventBinding": _task8_event_id("incident.latched"),
        "incidentId": incident_id,
        "reasonCode": "preapply-provider-terminal",
        "rootIdentityDigest": "sha256:" + "1" * 64,
        "artifactPath": "references/knowledge.md",
        "expectedPreHash": TASK8_PRE_HASH,
        "expectedPostHash": TASK8_POST_HASH,
        "intentDigest": None,
        "lastDurableEventId": _task8_event_id(last_durable_event_type),
        "targetWitness": {
            "classification": "exact-pre",
            "target": _target_witness(),
        },
        "providerWitness": {
            "classification": "terminal",
            "candidateFullRecordDigest": "sha256:" + "2" * 64,
            "providerAuthorityBindingDigest": "sha256:" + "3" * 64,
            "resolutionRecordDigest": "sha256:" + "7" * 64,
            "errorCode": None,
        },
        "verifierWitness": {
            "classification": "not-reached",
            "receiptRef": None,
            "receiptDigest": None,
            "result": None,
            "errorCode": None,
        },
        "reservedNameWitness": {
            "name": ".rsi-promotion-swap-" + transaction_id[3:],
            "classification": "absent",
            "metadata": None,
            "authorityEventId": None,
            "authorityDigest": None,
        },
        "ancestryWitness": {
            "classification": "exact",
            "witnessDigest": "sha256:" + "4" * 64,
            "failureCode": None,
        },
        "exchangeWitness": None,
        "phaseWitness": {"kind": "ordinary"},
        "namespaceMutationLeaseEvidence": None,
        "quarantineTargets": [
            {
                "rootIdentityDigest": "sha256:" + "1" * 64,
                "artifactPath": "references/knowledge.md",
            }
        ],
        "requiresOperatorAction": True,
    }


def _promotion_origin_document() -> dict[str, object]:
    transaction_id = _task8_transaction_id()
    run_id = _task8_run_id()
    candidate_id = "20260809T120000Z-111111111111"
    gate = _task8_event_raw(
        "promotion.gated", causation_id="evt-origin-capture"
    )
    event_binding = {
        "eventId": gate["eventId"],
        "eventType": gate["eventType"],
        "idempotencyKey": gate["idempotencyKey"],
    }
    source_objects = [
        {
            "objectClass": object_class,
            "eventId": f"evt-origin-{index}",
            "eventType": event_type,
            "ref": ref,
            "digest": "sha256:" + f"{index:x}" * 64,
        }
        for index, (object_class, event_type, ref) in enumerate(
            (
                (
                    "close-freshness",
                    "run.closed",
                    "proposals/run-origin-freshness-" + "1" * 64 + ".json",
                ),
                ("evaluation", "evaluation.completed", "evaluations/evt-origin-evaluation.json"),
                ("finding", "finding.drafted", "findings/evt-origin-finding.json"),
                ("observation", "task.observed", "observations/evt-origin-observation.json"),
                ("proposal-report", "report.generated", "reports/local-review-run-origin.json"),
            ),
            start=1,
        )
    ]
    origin = {
        "originRunId": "run-origin",
        "originClosedEventId": "evt-origin-close",
        "proposalReportEventId": "evt-origin-report",
        "admissionEventId": "evt-origin-admission",
        "captureEventId": "evt-origin-capture",
        "evaluationEventId": "evt-origin-evaluation",
        "providerCandidateId": candidate_id,
        "captureOperationId": "op_capture_" + "1" * 32,
        "candidateDraftDigest": "sha256:" + "1" * 64,
        "providerCaptureRequestDigest": "2" * 64,
        "ownerSkill": "example",
        "ownerPath": "/trusted/skills/example",
        "matchedScope": "example.knowledge",
        "routeBinding": "3" * 64,
        "providerBindingRef": "proposals/run-origin.json",
        "providerBindingDigest": "sha256:" + "4" * 64,
        "routeReceiptRef": "proposals/op-capture-" + "5" * 64 + ".json",
        "routeReceiptDigest": "sha256:" + "5" * 64,
        "sourceObjects": source_objects,
    }
    experiment = {
        "artifactStoreIdentityDigest": "sha256:" + "1" * 64,
        "experimentOperationId": "experiment_" + "1" * 32,
        "reservationRef": "experiments/op-1/request.json",
        "reservationDigest": "sha256:" + "2" * 64,
        "experimentRequestDigest": "sha256:" + "3" * 64,
        "bundleRef": "experiments/op-1/bundle.json",
        "bundleDigest": "sha256:" + "4" * 64,
        "attestationRef": "experiments/op-1/attestation.json",
        "validationAttestationDigest": "sha256:" + "5" * 64,
        "planRef": "experiments/op-1/plan.json",
        "planId": "plan_" + TASK8_PLAN_DIGEST[7:],
        "planDigest": TASK8_PLAN_DIGEST,
        "postImageRef": "objects/post-images/" + "6" * 64,
        "postImageDigest": "sha256:" + "6" * 64,
        "stageAttestationRawRef": "stage-deployment-attestation.json",
        "stageAttestationRawDigest": "sha256:" + "7" * 64,
        "hookAttestationRawRef": "hook-deployment-attestation.json",
        "hookAttestationRawDigest": "sha256:" + "8" * 64,
        "task7CandidateBindingDigest": "sha256:" + "9" * 64,
        "candidateCaptureLineageBindingDigest": "sha256:" + "a" * 64,
        "candidateFullRecordDigest": "sha256:" + "b" * 64,
        "providerAuthorityBindingDigest": "sha256:" + "c" * 64,
        "candidateStateBindingDigest": "sha256:" + "d" * 64,
        "task8ControlPlaneVersion": "1.1.0",
        "task8AddendumDigest": "sha256:ef84059ca0df0d3804dc090616cef3e4abbe3ce7f11ec6f8535e74aa3afe02c0",
        "task8AddendumMarkdownDigest": "sha256:6fd2ab2a1d45e678f7eaf237c462c49e6dcf3ad133e30c41e28326b9d5f909b6",
        "controlPlaneDigest": "sha256:" + "e" * 64,
    }
    provider_historical_authority = {
        "ledgerIdentityDigest": "sha256:" + "1" * 64,
        "gateProviderContractDigest": "sha256:" + "2" * 64,
        "gateProviderVersionDigest": "sha256:" + "3" * 64,
        "gateProviderExecutionIdentityDigest": "sha256:" + "4" * 64,
        "ledgerProtocolVersion": "skill-learning-ledger-lock-v1",
        "ledgerProtocolDigest": "sha256:" + "5" * 64,
        "foldProfileId": "provider-fold-v1",
        "foldProfileDigest": "sha256:" + "6" * 64,
        "ledgerPrefix": {
            "byteLength": 1_024,
            "eventCount": 10,
            "lastEventId": "20260809T120200Z-222222222222",
            "prefixSha256": "sha256:" + "7" * 64,
        },
        "latestAuthorityEventId": "20260809T120100Z-333333333333",
        "candidateId": candidate_id,
        "candidateFullRecordDigest": "sha256:" + "b" * 64,
        "providerAuthorityBindingDigest": "sha256:" + "c" * 64,
        "task7CandidateBindingDigest": "sha256:" + "9" * 64,
        "candidateCaptureLineageBindingDigest": "sha256:" + "a" * 64,
        "candidateStateBindingDigest": "sha256:" + "d" * 64,
    }
    semantic = {
        "schemaVersion": 1,
        "domain": "rsi-promotion-origin-semantic-v1",
        "transactionId": transaction_id,
        "runId": run_id,
        "planDigest": TASK8_PLAN_DIGEST,
        "origin": origin,
        "experiment": experiment,
        "providerHistoricalAuthority": provider_historical_authority,
    }
    return {
        "schemaVersion": 1,
        "kind": "promotion-origin",
        "transactionId": transaction_id,
        "runId": run_id,
        "planDigest": TASK8_PLAN_DIGEST,
        "eventBinding": event_binding,
        "origin": origin,
        "experiment": experiment,
        "providerHistoricalAuthority": provider_historical_authority,
        "semanticBindingDigest": prefixed_digest(semantic),
    }


def test_append_and_idempotent_replay_return_recorded_event_without_new_line(tmp_path: Path) -> None:
    """A crash retry with the same request must reuse its durable record exactly."""
    store = EventStore(tmp_path)
    event = make_event("run.started", 1)

    first = store.append(event)
    second = store.append(event)

    assert first == second == event
    assert store.events_path.read_text(encoding="utf-8").count("\n") == 1


def test_idempotency_collision_fails_closed(tmp_path: Path) -> None:
    """The same key cannot silently stand for a different logical operation."""
    store = EventStore(tmp_path)
    store.append(make_event("run.started", 1))
    raw = make_event("run.started", 1).to_dict()
    raw["eventId"] = "evt-collision"
    collision = type(make_event("run.started", 1)).from_mapping(raw)

    with pytest.raises(StoreIntegrityError, match="idempotency"):
        store.append(collision)
    assert store.events_path.read_text(encoding="utf-8").count("\n") == 1


def test_malformed_tail_blocks_lifecycle_read_and_append_without_repairing_ledger(tmp_path: Path) -> None:
    """A corrupt source ledger cannot be trusted or silently repaired by a write."""
    store = EventStore(tmp_path)
    store.append(make_event("run.started", 1))
    with store.events_path.open("ab") as handle:
        handle.write(b'{"schemaVersion":')
    before = store.events_path.read_bytes()

    with pytest.raises(StoreIntegrityError, match="malformed"):
        store.read_events()
    with pytest.raises(StoreIntegrityError, match="malformed"):
        store.append(make_event("run.started", 2, run_id="run-2"))

    assert store.events_path.read_bytes() == before


def test_rebuild_sqlite_is_deterministic_and_refuses_corrupt_source(tmp_path: Path) -> None:
    """The index is disposable cache, never a way to bless malformed JSONL."""
    store = EventStore(tmp_path)
    first = make_event("run.started", 1)
    second = make_event("task.observed", 2, causation_id=first.event_id)
    store.append(first)
    store.append(second)

    store.rebuild_index()
    before = store.index_path.read_bytes()
    store.index_path.unlink()
    store.rebuild_index()
    assert store.index_path.read_bytes() == before

    with store.events_path.open("ab") as handle:
        handle.write(b"not-json\n")
    with pytest.raises(StoreIntegrityError, match="malformed"):
        store.rebuild_index()


def test_doctor_salvage_report_is_read_only_and_reports_corrupt_lines(tmp_path: Path) -> None:
    """The explicit salvage path can inspect damage but must not repair source bytes."""
    store = EventStore(tmp_path)
    store.append(make_event("run.started", 1))
    with store.events_path.open("ab") as handle:
        handle.write(b"broken\n")
    before = store.events_path.read_bytes()
    report = tmp_path / "reports" / "salvage.json"

    completed = subprocess.run(
        [sys.executable, "-m", "rsi_core.storage", "doctor", "--home", str(tmp_path), "--salvage-report", str(report)],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "scripts")},
    )

    assert completed.returncode == 0, completed.stderr
    assert store.events_path.read_bytes() == before
    assert json.loads(report.read_text(encoding="utf-8"))["corruptLines"] == [2]


@pytest.mark.parametrize("alias_kind", ["direct", "symlink", "hardlink"])
def test_doctor_rejects_report_path_that_aliases_source_ledger(tmp_path: Path, alias_kind: str) -> None:
    """A salvage report path must never designate the durable source inode."""
    store = EventStore(tmp_path)
    store.append(make_event("run.started", 1))
    if alias_kind == "direct":
        report = store.events_path
    elif alias_kind == "symlink":
        report = tmp_path / "reports" / "events-alias.json"
        report.symlink_to(store.events_path)
    else:
        report = tmp_path / "reports" / "events-hardlink.json"
        os.link(store.events_path, report)
    before = store.events_path.read_bytes()

    with pytest.raises(StoreIntegrityError, match="source ledger"):
        store.doctor_salvage_report(report)

    assert store.events_path.read_bytes() == before


def test_non_object_json_is_a_strict_store_error_and_a_salvage_corrupt_line(tmp_path: Path) -> None:
    """JSON arrays/scalars are malformed ledger entries, not uncaught parser errors."""
    store = EventStore(tmp_path)
    store.events_path.write_text("1\n", encoding="utf-8")
    with pytest.raises(StoreIntegrityError, match="malformed JSONL line 1"):
        store.read_events()

    report = tmp_path / "reports" / "salvage.json"
    result = store.doctor_salvage_report(report)
    assert result["corruptLines"] == [1]


def test_monitoring_must_link_to_an_earlier_promoted_resolution_in_another_run(tmp_path: Path) -> None:
    """Monitoring cannot self-attribute or point at an unproven/nonexistent promotion."""
    store = EventStore(tmp_path)
    promotion = promotion_prefix(mode="promote-safe", run_id="promotion-run")
    completed = make_event("apply.completed", 12, causation_id=promotion[-1].event_id, run_id="promotion-run")
    verified = make_event("verification.completed", 13, causation_id=completed.event_id, run_id="promotion-run")
    resolved = make_event("resolution.recorded", 14, causation_id=verified.event_id, run_id="promotion-run")
    for event in [*promotion, completed, verified, resolved]:
        store.append(event)
    started = make_event("run.started", 101, run_id="monitor-run")
    observed = make_event("task.observed", 102, causation_id=started.event_id, run_id="monitor-run")
    evaluation = make_event("evaluation.completed", 103, causation_id=observed.event_id, run_id="monitor-run")
    invalid = make_event("monitoring.recorded", 104, causation_id=evaluation.event_id, run_id="monitor-run", payload={**EVENT_PAYLOADS["monitoring.recorded"], "promotionRef": "event:missing", "evaluationId": f"event:{evaluation.event_id}"})

    for event in [started, observed, evaluation]:
        store.append(event)
    with pytest.raises(StoreIntegrityError, match="promotionRef"):
        store.append(invalid)

    valid = make_event("monitoring.recorded", 105, causation_id=evaluation.event_id, run_id="monitor-run", payload={**EVENT_PAYLOADS["monitoring.recorded"], "promotionRef": f"event:{resolved.event_id}", "evaluationId": f"event:{evaluation.event_id}"})
    assert store.append(valid) == valid


def test_resolution_provider_operation_id_is_unique_across_runs(tmp_path: Path) -> None:
    """Provider replay identifiers are ledger-global, not merely unique in one folded run."""
    store = EventStore(tmp_path)
    for run_id, offset in [("first", 0), ("second", 100)]:
        promotion = promotion_prefix(mode="promote-safe", run_id=run_id, offset=offset)
        completed = make_event("apply.completed", offset + 12, causation_id=promotion[-1].event_id, run_id=run_id)
        verified = make_event("verification.completed", offset + 13, causation_id=completed.event_id, run_id=run_id)
        resolved = make_event("resolution.recorded", offset + 14, causation_id=verified.event_id, run_id=run_id, payload={**EVENT_PAYLOADS["resolution.recorded"], "providerOperationId": "op-shared", "resolutionId": f"review-{run_id}"})
        for event in [*promotion, completed, verified]:
            store.append(event)
        if run_id == "first":
            store.append(resolved)
        else:
            with pytest.raises(StoreIntegrityError, match="provider operation"):
                store.append(resolved)


def test_monitoring_run_must_start_after_its_referenced_promotion_resolution(tmp_path: Path) -> None:
    """Appending monitoring late cannot make a previously started run independent/later."""
    store = EventStore(tmp_path)
    started = make_event("run.started", 101, run_id="monitor-run")
    observed = make_event("task.observed", 102, causation_id=started.event_id, run_id="monitor-run")
    evaluation = make_event("evaluation.completed", 103, causation_id=observed.event_id, run_id="monitor-run")
    for event in [started, observed, evaluation]:
        store.append(event)
    promotion = promotion_prefix(mode="promote-safe", run_id="promotion-run")
    completed = make_event("apply.completed", 12, causation_id=promotion[-1].event_id, run_id="promotion-run")
    verified = make_event("verification.completed", 13, causation_id=completed.event_id, run_id="promotion-run")
    resolved = make_event("resolution.recorded", 14, causation_id=verified.event_id, run_id="promotion-run")
    for event in [*promotion, completed, verified, resolved]:
        store.append(event)
    monitoring = make_event("monitoring.recorded", 104, causation_id=evaluation.event_id, run_id="monitor-run", payload={**EVENT_PAYLOADS["monitoring.recorded"], "promotionRef": f"event:{resolved.event_id}", "evaluationId": f"event:{evaluation.event_id}"})

    with pytest.raises(StoreIntegrityError, match="run.started"):
        store.append(monitoring)


def test_rebuild_index_holds_store_lock_and_atomically_replaces_existing_cache(tmp_path: Path) -> None:
    """Readers retain the old complete cache until a locked rebuild publishes the new one."""
    store = EventStore(tmp_path)
    store.append(make_event("run.started", 1))
    store.rebuild_index()
    old_index = store.index_path.read_bytes()
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    with store.lock_path.open("a+b", buffering=0) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        process = context.Process(target=_rebuild_in_process, args=(str(tmp_path), sender))
        process.start()
        assert receiver.recv() == "ready"
        time.sleep(0.1)
        assert process.is_alive()
        assert store.index_path.read_bytes() == old_index
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    process.join(timeout=30)
    assert process.exitcode == 0
    assert store.index_path.exists()


def test_concurrent_process_appends_are_complete_and_strictly_replayable(tmp_path: Path) -> None:
    """Independent processes must produce one complete, valid JSON line each."""
    context = multiprocessing.get_context("spawn")
    processes = [context.Process(target=_append_in_process, args=(str(tmp_path), number)) for number in range(1, 17)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
        assert process.exitcode == 0

    events = EventStore(tmp_path).read_events()
    assert {event.run_id for event in events} == {f"run-{number}" for number in range(1, 17)}
    assert len(events) == 16


def test_one_thousand_replay_permutations_are_idempotent(tmp_path: Path) -> None:
    """Retry order cannot create duplicate durable events or change their records."""
    store = EventStore(tmp_path)
    events = [make_event("run.started", number, run_id=f"run-{number}") for number in range(1, 5)]
    randomizer = random.Random(20260807)

    for _ in range(1_000):
        replay = list(events)
        randomizer.shuffle(replay)
        for event in replay:
            assert store.append(event) == event

    assert len(store.read_events()) == len(events)
    assert store.events_path.read_text(encoding="utf-8").count("\n") == len(events)


def test_observe_terminals_are_rejected_inside_the_store_lock(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    target = {"name": "mail", "versionHash": "sha256:" + "a" * 64}
    RunCoordinator(store).start(run_id="guarded", active_skills=[target], task_class="code.change", logical_operation_id="start", mode="observe", hook_mode="coordinated")
    request = dict(run_id="guarded", task_class="code.change", outcome="unverified", target_skills=[target], signals_by_target={"mail@" + target["versionHash"]: {}}, evidence=[], task_fingerprint="sha256:" + "1" * 64, artifact_digest="sha256:" + "2" * 64)
    Observer(store).observe(logical_operation_id="observe-one", **request)

    with pytest.raises(StoreIntegrityError, match="duplicate task observation"):
        Observer(store).observe(logical_operation_id="observe-two", **request)


def test_atomic_same_key_replay_reuses_record_despite_transport_timestamp(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    first = make_event("run.started", 1)
    raw_first = first.to_dict()
    raw_first["correlationId"] = "sha256:" + "b" * 64
    first = type(first).from_mapping(raw_first)
    changed = first.to_dict()
    changed["eventId"] = "evt-retry"
    changed["createdAt"] = "2026-08-08T00:00:01Z"
    retry = type(first).from_mapping(changed)

    assert store.append(first) == first
    assert store.append(retry) == first


def test_open_existing_legacy_home_reads_with_every_write_syscall_forbidden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read-only open must not create, chmod, lock, sync, or repair a legacy home."""
    creating = EventStore(tmp_path)
    started = make_event("run.started", 1)
    creating.append(started)
    sidecar_path = tmp_path / "objects" / "findings" / "legacy.json"
    sidecar_bytes = canonical_final_lf(
        {"kind": "legacy-read-only", "schemaVersion": 1}
    )
    creating.write_once(sidecar_path, sidecar_bytes)
    before = filesystem_witness(tmp_path)

    _trap_write_capable_syscalls(monkeypatch)
    existing = EventStore.open_existing(tmp_path)
    assert existing.promotion_eligible is False
    assert existing.read_events() == [started]
    assert existing.read_sidecar(sidecar_path) == sidecar_bytes
    assert filesystem_witness(tmp_path) == before


def test_open_existing_object_rejects_every_mutator_before_a_write_syscall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An existing-only handle cannot be upgraded into a writer by calling another method."""
    creating = EventStore(tmp_path)
    creating.append(make_event("run.started", 1))
    existing = EventStore.open_existing(tmp_path)
    before = filesystem_witness(tmp_path)
    draft_raw = make_event(
        "finding.drafted", 2, causation_id="evt-1"
    ).to_dict()
    draft_raw["payloadRef"] = "findings/evt-2.json"
    draft = EventEnvelope.from_mapping(draft_raw)
    sidecar = canonical_final_lf({"kind": "test-draft", "schemaVersion": 1})

    _trap_write_capable_syscalls(monkeypatch)
    mutators = (
        lambda: existing.append(make_event("run.started", 3, run_id="run-3")),
        lambda: existing.append_with_sidecar(
            draft,
            tmp_path / "objects" / "findings" / "evt-2.json",
            sidecar,
        ),
        lambda: existing.write_once(
            tmp_path / "objects" / "findings" / "orphan.json", sidecar
        ),
        existing.rebuild_index,
        existing.initialize_promotion_topology,
    )
    for mutate in mutators:
        with pytest.raises(StoreIntegrityError, match="read-only|existing|mutation"):
            mutate()
    assert filesystem_witness(tmp_path) == before


@pytest.mark.parametrize("partial", ["directory-only", "marker-only"])
def test_partial_promotion_topology_is_reported_without_repair(
    tmp_path: Path, partial: str
) -> None:
    """A crashed or reordered upgrade is neither legacy nor a valid Task 8 store."""
    EventStore(tmp_path)
    if partial == "directory-only":
        (tmp_path / "objects" / "transactions").mkdir(mode=0o700)
    else:
        (tmp_path / TASK8_STORE_MARKER).write_bytes(TASK8_STORE_MARKER_BYTES)
        (tmp_path / TASK8_STORE_MARKER).chmod(0o600)
    before = filesystem_witness(tmp_path)

    with pytest.raises(StoreIntegrityError, match="partial|topology|promotion"):
        EventStore.open_existing(tmp_path)
    assert filesystem_witness(tmp_path) == before

    with pytest.raises(StoreIntegrityError, match="partial|topology|promotion"):
        EventStore(tmp_path)

    assert filesystem_witness(tmp_path) == before


def test_explicit_promotion_initializer_publishes_exact_private_topology_marker_last(
    tmp_path: Path,
) -> None:
    """The sole upgrade path must publish all authority directories before its marker."""
    store = EventStore(tmp_path)

    store.initialize_promotion_topology()

    for relative in TASK8_TOPOLOGY_DIRECTORIES:
        metadata = (tmp_path / relative).lstat()
        assert stat.S_ISDIR(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o700
        assert metadata.st_uid == os.geteuid()
    gate = tmp_path / TASK8_GATE_LOCK
    marker = tmp_path / TASK8_STORE_MARKER
    assert gate.read_bytes() == b""
    assert stat.S_IMODE(gate.stat().st_mode) == 0o600
    assert gate.stat().st_nlink == 1
    assert marker.read_bytes() == TASK8_STORE_MARKER_BYTES
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    assert marker.stat().st_nlink == 1
    assert EventStore.open_existing(tmp_path).promotion_eligible is True


def test_initializer_fault_leaves_marker_absent_and_readers_never_finish_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A durability fault before the marker must remain a visible partial upgrade."""
    store = EventStore(tmp_path)
    real_sync = storage_module._fsync_directory

    def fail_sync(_descriptor: int) -> None:
        raise OSError("injected directory-sync fault")

    monkeypatch.setattr(storage_module, "_fsync_directory", fail_sync)
    with pytest.raises(StoreIntegrityError, match="sync|initialize|topology"):
        store.initialize_promotion_topology()
    assert not (tmp_path / TASK8_STORE_MARKER).exists()
    after_failure = filesystem_witness(tmp_path)

    monkeypatch.setattr(storage_module, "_fsync_directory", real_sync)
    with pytest.raises(StoreIntegrityError, match="partial|topology|promotion"):
        EventStore.open_existing(tmp_path)
    assert filesystem_witness(tmp_path) == after_failure


def test_open_existing_complete_promotion_home_is_zero_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid marker changes eligibility, never the read-only syscall contract."""
    store = EventStore(tmp_path)
    started = make_event("run.started", 1)
    store.append(started)
    store.initialize_promotion_topology()
    before = filesystem_witness(tmp_path)

    _trap_write_capable_syscalls(monkeypatch)
    existing = EventStore.open_existing(tmp_path)
    assert existing.promotion_eligible is True
    assert existing.read_events() == [started]
    assert filesystem_witness(tmp_path) == before


def test_exact_initializer_replay_and_concurrent_callers_converge(tmp_path: Path) -> None:
    """The explicit upgrade is idempotent only for the one complete exact topology."""
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    first = filesystem_witness(tmp_path)

    with ThreadPoolExecutor(max_workers=8) as executor:
        tuple(executor.map(lambda _index: store.initialize_promotion_topology(), range(32)))

    assert filesystem_witness(tmp_path) == first


def test_corrupt_promotion_marker_is_never_rewritten_or_normalized(tmp_path: Path) -> None:
    """Adding/removing the final LF is a binding failure, not a repair opportunity."""
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    marker = tmp_path / TASK8_STORE_MARKER
    marker.write_bytes(TASK8_STORE_MARKER_BYTES[:-1])
    marker.chmod(0o600)
    before = filesystem_witness(tmp_path)

    with pytest.raises(StoreIntegrityError, match="marker|framing|topology"):
        EventStore.open_existing(tmp_path)
    with pytest.raises(StoreIntegrityError, match="marker|framing|topology"):
        store.initialize_promotion_topology()

    assert filesystem_witness(tmp_path) == before


def test_existing_promotion_topology_is_never_permission_repaired(tmp_path: Path) -> None:
    """An unsafe transaction directory remains evidence of drift, not chmod input."""
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    transactions = tmp_path / "objects" / "transactions"
    transactions.chmod(0o755)
    before = filesystem_witness(tmp_path)

    with pytest.raises(StoreIntegrityError, match="mode|topology|unsafe"):
        EventStore.open_existing(tmp_path)

    assert stat.S_IMODE(transactions.stat().st_mode) == 0o755
    assert filesystem_witness(tmp_path) == before


@pytest.mark.parametrize(
    "entry_kind", ["symlink", "hardlink", "fifo", "malformed-object", "temp-alias"]
)
def test_transaction_object_topology_rejects_alias_special_corrupt_and_temp_entries(
    tmp_path: Path, entry_kind: str
) -> None:
    """Unexpected transaction entries cannot be adopted, repaired, or scanned as authority."""
    store = EventStore(tmp_path)
    store.append(make_event("run.started", 1))
    store.initialize_promotion_topology()
    directory = tmp_path / "objects" / "transactions"
    entry = directory / (
        ".rsi-tmp-attacker"
        if entry_kind == "temp-alias"
        else f"{_task8_transaction_id()}-origin-{'0' * 64}.json"
    )
    if entry_kind == "symlink":
        entry.symlink_to(store.events_path)
    elif entry_kind == "hardlink":
        os.link(store.events_path, entry)
    elif entry_kind == "fifo":
        os.mkfifo(entry, 0o600)
    else:
        entry.write_bytes(b"{}\n")
        entry.chmod(0o600)
    before = filesystem_witness(tmp_path)

    with pytest.raises(StoreIntegrityError, match="transaction|topology|unsafe|corrupt"):
        EventStore.open_existing(tmp_path)

    assert filesystem_witness(tmp_path) == before


def test_append_with_sidecar_is_marker_last_and_retry_converges_after_event_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash between immutable sidecar and event leaves an inert object, then exact replay converges."""
    store = EventStore(tmp_path)
    started = make_event("run.started", 1)
    store.append(started)
    draft_raw = make_event(
        "finding.drafted", 2, causation_id=started.event_id
    ).to_dict()
    draft_raw["payloadRef"] = "findings/evt-2.json"
    draft = EventEnvelope.from_mapping(draft_raw)
    sidecar = canonical_final_lf(
        {"draftId": "draft-1", "kind": "finding", "schemaVersion": 1}
    )
    path = tmp_path / "objects" / "findings" / "evt-2.json"
    original_append = store._append_line_locked

    def event_fault(_line: bytes) -> None:
        raise StoreIntegrityError("injected event append fault")

    monkeypatch.setattr(store, "_append_line_locked", event_fault)
    with pytest.raises(StoreIntegrityError, match="injected"):
        store.append_with_sidecar(draft, path, sidecar)
    assert path.read_bytes() == sidecar
    assert store.read_events() == [started]

    monkeypatch.setattr(store, "_append_line_locked", original_append)
    assert store.append_with_sidecar(draft, path, sidecar) == draft
    assert store.read_events() == [started, draft]
    assert path.read_bytes() == sidecar


def test_conflicting_sidecar_blocks_its_event_and_preserves_winner(tmp_path: Path) -> None:
    """A preexisting name with different bytes cannot gain a matching lifecycle marker."""
    store = EventStore(tmp_path)
    started = make_event("run.started", 1)
    store.append(started)
    raw = make_event("finding.drafted", 2, causation_id=started.event_id).to_dict()
    raw["payloadRef"] = "findings/evt-2.json"
    draft = EventEnvelope.from_mapping(raw)
    path = tmp_path / "objects" / "findings" / "evt-2.json"
    winner = canonical_final_lf({"kind": "winner", "schemaVersion": 1})
    contender = canonical_final_lf({"kind": "contender", "schemaVersion": 1})
    store.write_once(path, winner)

    with pytest.raises(StoreIntegrityError, match="conflict"):
        store.append_with_sidecar(draft, path, contender)

    assert path.read_bytes() == winner
    assert store.read_events() == [started]


def test_task8_size_vectors_lock_exact_200_144_and_64_kib_arithmetic() -> None:
    """Boundary admission must use counters, not allocate a 200 MiB fixture."""
    promotion_module = lazy_module("rsi_core.promotion")
    general = _task8_size_vector(
        "incident-record",
        path_budget=4 * 1024 * 1024,
        members=4_096,
        protected_readbacks=2,
        evidence_bytes=16 * 1024 * 1024,
        outer_bytes=16 * 1024 * 1024,
    )
    resolution = _task8_size_vector(
        "resolution-readback",
        path_budget=4 * 1024 * 1024,
        members=4_096,
        protected_readbacks=1,
        evidence_bytes=8 * 1024 * 1024,
        outer_bytes=8 * 1024 * 1024,
    )
    verifier = _task8_size_vector(
        "verifier-receipt",
        path_budget=0,
        members=0,
        protected_readbacks=0,
        evidence_bytes=32 * 1024,
        outer_bytes=32 * 1024,
    )

    assert promotion_module.compute_task8_preflight_bound(general) == 200 * 1024 * 1024
    assert promotion_module.compute_task8_preflight_bound(resolution) == 144 * 1024 * 1024
    assert promotion_module.compute_task8_preflight_bound(verifier) == 64 * 1024
    assert promotion_module.task8_sidecar_cap("promotion-origin") == 200 * 1024 * 1024
    assert promotion_module.task8_sidecar_cap("resolution-readback") == 144 * 1024 * 1024
    assert promotion_module.task8_sidecar_cap("verifier-receipt") == 64 * 1024


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: {**value, "pathBudgetBytes": 4 * 1024 * 1024 + 1},
        lambda value: {**value, "protectedReadbackCount": 3},
        lambda value: {**value, "memberCount": True},
        lambda value: {**value, "extra": 0},
    ],
)
def test_task8_size_vector_rejects_overflow_open_schema_and_boolean_integer(
    mutation,
) -> None:
    """No parser or downstream stage may silently widen the admitted allocation bound."""
    promotion_module = lazy_module("rsi_core.promotion")
    maximum = _task8_size_vector(
        "incident-record",
        path_budget=4 * 1024 * 1024,
        members=4_096,
        protected_readbacks=2,
        evidence_bytes=16 * 1024 * 1024,
        outer_bytes=16 * 1024 * 1024,
    )

    with pytest.raises(
        promotion_module.PromotionError, match="size|bound|vector|schema|integer"
    ):
        promotion_module.compute_task8_preflight_bound(mutation(maximum))


def test_exact_document_length_must_fit_its_preflight_bound_without_allocation() -> None:
    """A complete document cannot rely only on the larger per-kind cap."""
    promotion_module = lazy_module("rsi_core.promotion")
    vector = _task8_size_vector(
        "promotion-origin",
        path_budget=0,
        members=0,
        protected_readbacks=0,
        evidence_bytes=256,
        outer_bytes=256,
    )
    bound = promotion_module.compute_task8_preflight_bound(vector)
    assert bound == 512
    assert (
        promotion_module.validate_task8_document_length(
            vector, exact_length=bound, pipeline_stage="write"
        )
        == bound
    )
    with pytest.raises(
        promotion_module.PromotionError, match="exact|length|bound|cap"
    ):
        promotion_module.validate_task8_document_length(
            vector, exact_length=bound + 1, pipeline_stage="write"
        )


def test_resolution_event_stays_under_64_kib_while_sidecar_admission_is_144_mib() -> None:
    """The provider record belongs in the sidecar, never inline in the JSONL marker."""
    promotion_module = lazy_module("rsi_core.promotion")
    verified = _task8_event(
        "verification.completed",
        causation_id=_task8_event_id("apply.completed"),
        arm="affirmed",
    )
    resolution = _task8_event(
        "resolution.recorded", causation_id=verified.event_id
    )
    line = storage_module._canonical_line(resolution)
    vector = _task8_size_vector(
        "resolution-readback",
        path_budget=4 * 1024 * 1024,
        members=4_096,
        protected_readbacks=1,
        evidence_bytes=8 * 1024 * 1024,
        outer_bytes=8 * 1024 * 1024,
    )

    assert len(line) < 64 * 1024
    assert promotion_module.compute_task8_preflight_bound(vector) == 144 * 1024 * 1024
    assert "providerResolutionRecord" not in resolution.payload
    assert resolution.payload_ref == (
        f"transactions/{_task8_transaction_id()}-resolution-"
        f"{resolution.payload['resolutionDigest'][7:]}.json"
    )


def test_incident_record_is_one_fixed_transaction_cas_and_an_inert_orphan(
    tmp_path: Path,
) -> None:
    """The tx-only selector wins once; the record alone never adds lifecycle authority."""
    store = EventStore(tmp_path)
    started = make_event("run.started", 1)
    store.append(started)
    store.initialize_promotion_topology()
    journal = storage_module.PromotionJournal(store)
    record = _incident_record()
    expected_bytes = canonical_final_lf(record)
    expected_digest = "sha256:" + hashlib.sha256(expected_bytes).hexdigest()
    path = (
        tmp_path
        / "incidents"
        / "records"
        / f"{_task8_incident_id()}.json"
    )

    first = journal.publish_incident_record(
        record,
        size_vector=_task8_size_vector("incident-record", protected_readbacks=2),
    )
    second = journal.publish_incident_record(
        record,
        size_vector=_task8_size_vector("incident-record", protected_readbacks=2),
    )

    assert first == second
    assert path.read_bytes() == expected_bytes
    assert first.digest == expected_digest
    assert first.ref == f"incidents/records/{_task8_incident_id()}.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_nlink == 1
    assert store.read_events() == [started]


def test_incident_record_cas_loser_adopts_the_valid_fixed_winner_not_its_fresh_classification(
    tmp_path: Path,
) -> None:
    """A valid EEXIST winner selects the transaction record even when local evidence differs."""
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    journal = storage_module.PromotionJournal(store)
    vector = _task8_size_vector("incident-record", protected_readbacks=2)
    first_record = _incident_record(last_durable_event_type="run.started")
    contender = _incident_record(last_durable_event_type="promotion.gated")

    first = journal.publish_incident_record(first_record, size_vector=vector)
    adopted = journal.publish_incident_record(contender, size_vector=vector)

    assert adopted == first
    assert (
        tmp_path / "incidents" / "records" / f"{_task8_incident_id()}.json"
    ).read_bytes() == canonical_final_lf(first_record)


def test_transaction_sidecar_is_content_addressed_create_once_and_inert_until_event(
    tmp_path: Path,
) -> None:
    """A valid origin object is durable evidence only after its exact gate marker exists."""
    store = EventStore(tmp_path)
    started = make_event("run.started", 1)
    store.append(started)
    store.initialize_promotion_topology()
    journal = storage_module.PromotionJournal(store)
    document = _promotion_origin_document()
    data = canonical_final_lf(document)
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    ref = (
        f"transactions/{_task8_transaction_id()}-origin-{digest[7:]}.json"
    )
    path = tmp_path / "objects" / ref
    vector = _task8_size_vector("promotion-origin", protected_readbacks=0)

    first = journal.publish_transaction_sidecar(document, size_vector=vector)
    second = journal.publish_transaction_sidecar(document, size_vector=vector)

    assert first == second
    assert first.ref == ref
    assert first.digest == digest
    assert path.read_bytes() == data
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_nlink == 1
    assert journal.read_sidecar(
        ref, expected_kind="promotion-origin", size_vector=vector
    ) == document
    assert store.read_events() == [started]
    assert EventStore.open_existing(tmp_path).read_events() == [started]


def test_transaction_sidecar_uses_dedicated_strict_publisher_not_legacy_helpers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    journal = storage_module.PromotionJournal(store)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Task 8 transaction publication used a legacy helper")

    monkeypatch.setattr(store, "_write_once_locked", forbidden)
    monkeypatch.setattr(store, "_read_regular", forbidden)
    published = journal.publish_transaction_sidecar(
        _promotion_origin_document(),
        size_vector=_task8_size_vector("promotion-origin", protected_readbacks=0),
    )

    assert published.ref.startswith(f"transactions/{_task8_transaction_id()}-origin-")


def test_transaction_sidecar_prepublication_failure_leaves_no_named_temp_and_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    journal = storage_module.PromotionJournal(store)
    document = _promotion_origin_document()
    vector = _task8_size_vector("promotion-origin", protected_readbacks=0)
    real_publish = getattr(storage_module, "_publish_unnamed_noreplace_at", None)
    calls = 0

    def crash_once(parent_fd: int, source_fd: int, destination: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected prepublication crash")
        assert real_publish is not None
        real_publish(parent_fd, source_fd, destination)

    monkeypatch.setattr(
        storage_module, "_publish_unnamed_noreplace_at", crash_once, raising=False
    )
    with pytest.raises(OSError, match="injected prepublication crash"):
        journal.publish_transaction_sidecar(document, size_vector=vector)

    transactions = tmp_path / "objects" / "transactions"
    assert list(transactions.iterdir()) == []
    assert EventStore.open_existing(tmp_path).promotion_eligible is True

    published = journal.publish_transaction_sidecar(document, size_vector=vector)
    assert (tmp_path / "objects" / published.ref).is_file()
    assert all(not item.name.startswith(".rsi-tmp-") for item in transactions.iterdir())


def test_transaction_sidecar_publish_and_replay_apply_the_shared_exact_length_bound(
    tmp_path: Path,
) -> None:
    """Journal write/read paths must enforce the one promotion-module bound implementation."""
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    journal = storage_module.PromotionJournal(store)
    document = _promotion_origin_document()
    exact_length = len(canonical_final_lf(document))
    underbound = _task8_size_vector(
        "promotion-origin",
        path_budget=0,
        members=0,
        protected_readbacks=0,
        evidence_bytes=0,
        outer_bytes=exact_length - 1,
    )
    before = filesystem_witness(tmp_path)

    with pytest.raises(StoreIntegrityError, match="exact|length|bound|size"):
        journal.publish_transaction_sidecar(document, size_vector=underbound)
    assert filesystem_witness(tmp_path) == before

    valid = _task8_size_vector("promotion-origin", protected_readbacks=0)
    result = journal.publish_transaction_sidecar(document, size_vector=valid)
    durable = (tmp_path / "objects" / result.ref).read_bytes()
    with pytest.raises(StoreIntegrityError, match="exact|length|bound|size"):
        journal.read_sidecar(
            result.ref,
            expected_kind="promotion-origin",
            size_vector=underbound,
        )
    assert (tmp_path / "objects" / result.ref).read_bytes() == durable


def test_transaction_sidecar_replay_rejects_changed_bytes_hardlink_and_orphan_ref(
    tmp_path: Path,
) -> None:
    """Name/digest/kind/identity must all agree before a transaction object can be consumed."""
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    journal = storage_module.PromotionJournal(store)
    document = _promotion_origin_document()
    vector = _task8_size_vector("promotion-origin", protected_readbacks=0)
    result = journal.publish_transaction_sidecar(document, size_vector=vector)
    path = tmp_path / "objects" / result.ref
    alias = path.with_name("attacker-alias.json")
    os.link(path, alias)

    with pytest.raises(StoreIntegrityError, match="link|topology|sidecar"):
        journal.read_sidecar(
            result.ref, expected_kind="promotion-origin", size_vector=vector
        )
    assert path.stat().st_nlink == 2

    alias.unlink()
    wrong_ref = result.ref.replace("-origin-", "-intent-")
    with pytest.raises(StoreIntegrityError, match="kind|ref|sidecar|missing|absent"):
        journal.read_sidecar(
            wrong_ref, expected_kind="promotion-origin", size_vector=vector
        )

    changed = path.read_bytes()[:-1] + b" \n"
    path.write_bytes(changed)
    path.chmod(0o600)
    with pytest.raises(StoreIntegrityError, match="digest|canonical|sidecar|conflict"):
        journal.read_sidecar(
            result.ref, expected_kind="promotion-origin", size_vector=vector
        )
    assert path.read_bytes() == changed


@pytest.mark.parametrize("write_behavior", ["short", "eintr-once"])
def test_transaction_sidecar_complete_write_loop_handles_short_write_and_eintr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    write_behavior: str,
) -> None:
    """A successful marker may follow only the complete intended canonical bytes."""
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    journal = storage_module.PromotionJournal(store)
    document = _promotion_origin_document()
    expected = canonical_final_lf(document)
    vector = _task8_size_vector("promotion-origin", protected_readbacks=0)
    real_write = os.write
    calls = 0

    def injected_write(descriptor: int, data) -> int:
        nonlocal calls
        calls += 1
        if write_behavior == "eintr-once" and calls == 1:
            raise InterruptedError("injected EINTR")
        limited = data[: max(1, len(data) // 3)]
        return real_write(descriptor, limited)

    monkeypatch.setattr(os, "write", injected_write)
    result = journal.publish_transaction_sidecar(document, size_vector=vector)

    assert calls > 1
    assert (tmp_path / "objects" / result.ref).read_bytes() == expected


def test_concurrent_incident_record_publishers_adopt_one_byte_identical_winner(
    tmp_path: Path,
) -> None:
    """Racing classifiers for one transaction cannot create reason-derived alternatives."""
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    journal = storage_module.PromotionJournal(store)
    record = _incident_record()
    vector = _task8_size_vector("incident-record", protected_readbacks=2)

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = tuple(
            executor.map(
                lambda _index: journal.publish_incident_record(
                    record, size_vector=vector
                ),
                range(64),
            )
        )

    assert len({result.digest for result in results}) == 1
    names = [path.name for path in (tmp_path / "incidents" / "records").iterdir()]
    assert names == [f"{_task8_incident_id()}.json"]


def test_poisoned_fixed_incident_selector_blocks_without_alternate_record(
    tmp_path: Path,
) -> None:
    """Malformed EEXIST is corruption, not permission to choose another incident name."""
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    path = (
        tmp_path
        / "incidents"
        / "records"
        / f"{_task8_incident_id()}.json"
    )
    path.write_bytes(b"{}\n")
    path.chmod(0o600)
    before = path.read_bytes()

    with pytest.raises(StoreIntegrityError, match="incident|corrupt|conflict"):
        storage_module.PromotionJournal(store).publish_incident_record(
            _incident_record(),
            size_vector=_task8_size_vector(
                "incident-record", protected_readbacks=2
            ),
        )

    assert path.read_bytes() == before
    assert [item.name for item in path.parent.iterdir()] == [path.name]


def test_lifecycle_validation_accepts_only_exact_empty_batches_for_legacy_store(
    tmp_path: Path,
) -> None:
    """Legacy validation has an explicit empty authority context, not an implicit provider lookup."""
    store = EventStore(tmp_path)
    started = make_event("run.started", 1)

    assert (
        EventStore._validate_lifecycles(
            [started], historical_batch={}, origin_lineage_batch={}
        )
        is None
    )
    assert store.append(
        started, historical_batch={}, origin_lineage_batch={}
    ) == started

    before = store.events_path.read_bytes()
    with pytest.raises(StoreIntegrityError, match="extraneous|batch|legacy"):
        EventStore._validate_lifecycles(
            [started],
            historical_batch={"unexpected": object()},
            origin_lineage_batch={},
        )
    assert store.events_path.read_bytes() == before


def test_task8_deterministic_start_replay_converges_despite_audit_timestamp(
    tmp_path: Path,
) -> None:
    """Two coordinators importing one plan produce one durable start marker."""
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    first = _task8_event(
        "run.started", created_at="2026-08-09T00:00:00Z"
    )
    retry = _task8_event(
        "run.started", created_at="2026-08-10T23:59:59Z"
    )

    recorded = store.append(
        first, historical_batch={}, origin_lineage_batch={}
    )
    replayed = store.append(
        retry, historical_batch={}, origin_lineage_batch={}
    )

    assert recorded == replayed
    assert recorded.event_id == _task8_event_id("run.started")
    assert store.events_path.read_text(encoding="utf-8").count("\n") == 1


def test_invalid_historical_batch_is_rejected_before_eventstore_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EventStore never invokes a provider/batch builder or reverses provider-to-store order."""
    store = EventStore(tmp_path)

    class CallerBatchBuilder:
        def __call__(self):
            raise AssertionError("EventStore attempted to construct provider authority")

    def lock_must_not_be_entered():
        raise AssertionError("invalid batch reached the EventStore lock")

    monkeypatch.setattr(store, "_exclusive_lock", lock_must_not_be_entered)
    with pytest.raises(StoreIntegrityError, match="batch|pre-admitted|authority"):
        store.append(
            make_event("run.started", 1),
            historical_batch=CallerBatchBuilder(),
            origin_lineage_batch={},
        )
    assert not store.events_path.exists()


def test_task8_external_gate_without_complete_pre_admitted_batches_is_zero_write(
    tmp_path: Path,
) -> None:
    """The JSONL fold cannot open provider/lineage state to manufacture a missing bridge."""
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    started = _task8_event("run.started")
    gated = _task8_event(
        "promotion.gated", causation_id="evt-missing-origin-capture"
    )
    store.append(
        started,
        historical_batch={},
        origin_lineage_batch={},
    )
    before = filesystem_witness(tmp_path)

    with pytest.raises(StoreIntegrityError, match="origin|historical|external|batch"):
        store.append(
            gated,
            historical_batch={},
            origin_lineage_batch={},
        )

    assert filesystem_witness(tmp_path) == before


def test_task8_external_gate_consumes_exact_pre_admitted_batches_during_append(
    tmp_path: Path,
) -> None:
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    started = _task8_event("run.started")
    origin = make_event(
        "candidate.captured", 77, run_id="run-task6-origin"
    )
    gated = _task8_event("promotion.gated", causation_id=origin.event_id)
    origin_digest = gated.payload["originDigest"]
    source = storage_module.OriginSourceWitness(
        object_class="task6-capture",
        ref=f"event:{origin.event_id}",
        raw_digest="sha256:" + "8" * 64,
        device=1,
        inode=2,
        mode=0o600,
        nlink=1,
        byte_size=128,
        mtime_ns=1,
        ctime_ns=1,
    )
    historical = storage_module.HistoricalProviderAuthorityBatch(
        (
            storage_module.HistoricalProviderAuthorityView(
                continuation_run_id=gated.run_id,
                origin_digest=origin_digest,
                candidate_id=origin.payload["providerCandidateId"],
                candidate_state_binding_digest="sha256:" + "9" * 64,
                provider_prefix_digest="sha256:" + "a" * 64,
            ),
        )
    )
    lineage = storage_module.OriginLineageBatch(
        (
            storage_module.OriginLineageView(
                continuation_run_id=gated.run_id,
                origin_digest=origin_digest,
                origin_receipt_digest="sha256:" + "b" * 64,
                semantic_binding_digest="sha256:" + "c" * 64,
                capture_event=origin,
                source_witnesses=(source,),
            ),
        )
    )

    store.append(started, historical_batch={}, origin_lineage_batch={})
    assert store.append(
        gated,
        historical_batch=historical,
        origin_lineage_batch=lineage,
    ) == gated

    assert store.read_events(
        historical_batch=historical,
        origin_lineage_batch=lineage,
    )[-1] == gated


def test_task8_external_gate_rejects_mutable_caller_dict_as_authority(
    tmp_path: Path,
) -> None:
    store = EventStore(tmp_path)
    store.initialize_promotion_topology()
    started = _task8_event("run.started")
    origin = make_event("candidate.captured", 78, run_id="run-task6-origin")
    gated = _task8_event("promotion.gated", causation_id=origin.event_id)
    store.append(started, historical_batch={}, origin_lineage_batch={})

    with pytest.raises(StoreIntegrityError, match="pre-admitted|authority|batch"):
        store.append(
            gated,
            historical_batch={"provider-prefix": {"admitted": True}},
            origin_lineage_batch={origin.event_id: origin},
        )


def test_eventstore_retained_home_identity_rejects_path_rebind_before_append(
    tmp_path: Path,
) -> None:
    home = tmp_path / "state"
    store = EventStore(home)
    detached = tmp_path / "detached-state"
    os.rename(home, detached)
    replacement = EventStore(home)
    replacement_before = filesystem_witness(home)

    with pytest.raises(StoreIntegrityError, match="home|identity|topology"):
        store.append(make_event("run.started", 901))

    assert filesystem_witness(home) == replacement_before
    assert replacement.read_events() == []
