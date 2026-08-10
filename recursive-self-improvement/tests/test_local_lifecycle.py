from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import threading
from typing import Callable

import pytest

from rsi_core.candidates import CandidateBuilder
from rsi_core.evolver_adapter import CandidateRef, EvolverAdapter, ProviderCompatibilityError, ProviderValidationResult, RouteDecision
from rsi_core.hooks import LifecycleError, RunCoordinator, VerificationResult, append_event, canonical_digest
from rsi_core.proposal import ProposalService
from rsi_core.storage import EventStore, StoreIntegrityError
import rsi_core.target_identity as target_identity


PROVIDER_ROOT = Path.home() / ".codex" / "skills" / "skill-evolver"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
ROUTE_BINDING = "d" * 64
RSI_CLI = Path(__file__).resolve().parents[1] / "scripts" / "rsi.py"
TASK8_CLI_PLAN_DIGEST = "sha256:" + "b" * 64
TASK8_CLI_ATTESTATION_DIGEST = "sha256:" + "c" * 64
TASK8_CLI_TARGET_PRE_HASH = "sha256:" + "d" * 64


def _task8_cli_canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _task8_cli_prefixed_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_task8_cli_canonical(value)).hexdigest()


def _task8_cli_run_id(plan_digest: str) -> str:
    return "run_promote_" + _task8_cli_prefixed_digest(
        {"domain": "rsi-promotion-continuation-v1", "planDigest": plan_digest}
    )[7:]


def _task8_cli_operation_id(plan_digest: str) -> str:
    return "promote_" + _task8_cli_prefixed_digest(
        {"domain": "rsi-promote-cli-v1", "planDigest": plan_digest}
    )[7:]


def _load_rsi_cli_module():
    spec = importlib.util.spec_from_file_location("task8_rsi_cli", RSI_CLI)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _task8_cli_arguments(
    *,
    home: Path | None = None,
    candidate_id: str = "20260808T120000Z-a1b2c3d4e5f6",
    plan_digest: str = TASK8_CLI_PLAN_DIGEST,
    attestation_digest: str = TASK8_CLI_ATTESTATION_DIGEST,
    target_pre_hash: str = TASK8_CLI_TARGET_PRE_HASH,
    run_id: str | None = None,
    operation_id: str | None = None,
) -> list[str]:
    command = [
        "promote-candidate",
        "--candidate-id",
        candidate_id,
        "--promotion-plan",
        plan_digest,
        "--validation-attestation",
        attestation_digest,
        "--expected-target-hash",
        target_pre_hash,
        "--run-id",
        run_id or _task8_cli_run_id(plan_digest),
        "--idempotency-key",
        operation_id or _task8_cli_operation_id(plan_digest),
        "--json",
    ]
    if home is not None:
        command[1:1] = ["--home", str(home)]
    return command


def _tree_manifest(root: Path) -> list[tuple[str, str, int, bytes]]:
    result: list[tuple[str, str, int, bytes]] = []
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if path.is_symlink():
            result.append((str(path.relative_to(root)), "symlink", metadata.st_mode & 0o7777, os.readlink(path).encode()))
        elif path.is_dir():
            result.append((str(path.relative_to(root)), "directory", metadata.st_mode & 0o7777, b""))
        else:
            result.append((str(path.relative_to(root)), "file", metadata.st_mode & 0o7777, path.read_bytes()))
    return result


def _identity_tree_manifest(
    root: Path,
) -> tuple[bool, list[tuple[str, str, int, int, int, int, int, bytes]]]:
    if not root.exists():
        return False, []
    result: list[tuple[str, str, int, int, int, int, int, bytes]] = []
    for path in [root, *sorted(root.rglob("*"))]:
        metadata = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        if path.is_symlink():
            kind, content = "symlink", os.readlink(path).encode("utf-8")
        elif path.is_dir():
            kind, content = "directory", b""
        else:
            kind, content = "file", path.read_bytes()
        result.append(
            (
                relative,
                kind,
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode & 0o7777,
                metadata.st_nlink,
                metadata.st_size,
                content,
            )
        )
    return True, result


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "targets" / "mail"
    (target / "references").mkdir(parents=True, exist_ok=True)
    (target / "SKILL.md").write_text("---\nname: mail\ndescription: Test target\n---\n", encoding="utf-8")
    (target / "references" / "transport.md").write_text("# Transport\n", encoding="utf-8")
    (target / "skill-contract.json").write_text(json.dumps({"schemaVersion": 1, "name": "mail", "kind": "role", "owns": ["mail.transport"], "provides": []}), encoding="utf-8")
    return target


def _seed(**updates: object) -> dict[str, object]:
    seed: dict[str, object] = {
        "sourceSkill": "mail", "targetSkill": "mail", "targetSkillVersionHash": DIGEST_A,
        "kind": "gotcha", "changeClass": "knowledge", "scope": "mail.transport.smtp",
        "destinationClass": "reference", "dedupeKey": "mail.transport.smtp.readback",
        "relatedSkills": ["mail"], "targetHint": "references/transport.md",
        "title": "Verify transport readback",
        "finding": "Treat transport acceptance as provisional until bounded readback confirms delivery.",
        "evidence": ["A deterministic fixture separated acceptance from confirmed delivery."],
        "confidence": 0.9, "risk": "low", "novel": True, "causallyRelated": True,
    }
    seed.update(updates)
    return seed


def _verified(tmp_path: Path, seeds: list[dict[str, object]], *, mode: str = "propose") -> tuple[EventStore, list[dict[str, object]]]:
    target = {"name": "mail", "versionHash": DIGEST_A}
    target_root = _target(tmp_path)
    store = EventStore(tmp_path / "rsi")

    def authority(**_: object) -> VerificationResult:
        return VerificationResult.success(
            "run-proposal",
            DIGEST_B,
            [target],
            DIGEST_C,
            target_roots=[target_root],
            contract_roots=[target_root],
        )

    coordinator = RunCoordinator(store, verification_authority=authority)
    coordinator.start(run_id="run-proposal", active_skills=[target], task_class="code.change", logical_operation_id="start", mode=mode, hook_mode="coordinated")
    for number, seed in enumerate(seeds):
        coordinator.note_candidate_finding(run_id="run-proposal", seed=seed, logical_operation_id=f"seed-{number}")
    result = coordinator.verify_primary_task(run_id="run-proposal", logical_operation_id="verify", task_class="code.change", target_skills=[target], task_fingerprint=DIGEST_B, artifact_digest=DIGEST_C, signals_by_target={"mail@" + DIGEST_A: {}}, evidence=[{"kind": "test", "summary": "A deterministic verification fixture passed."}], baseline_lookup=lambda *_: {"ref": "baseline:known", "signals": {}, "hardInvariantsPassed": True})
    return store, result["evaluations"]


def _verified_with_trusted_roots(
    tmp_path: Path,
    target: Path,
    *,
    contract_roots: list[Path] | None = None,
) -> tuple[EventStore, list[dict[str, object]]]:
    identity = {"name": "mail", "versionHash": DIGEST_A}
    store = EventStore(tmp_path / "rsi")

    def authority(**_: object) -> VerificationResult:
        return VerificationResult.success(
            "run-root-bound",
            DIGEST_B,
            [identity],
            DIGEST_C,
            target_roots=[target],
            contract_roots=contract_roots or [target],
        )

    coordinator = RunCoordinator(store, verification_authority=authority)
    coordinator.start(
        run_id="run-root-bound",
        active_skills=[identity],
        task_class="code.change",
        logical_operation_id="start",
        mode="propose",
        hook_mode="coordinated",
    )
    coordinator.note_candidate_finding(
        run_id="run-root-bound", seed=_seed(), logical_operation_id="seed"
    )
    result = coordinator.verify_primary_task(
        run_id="run-root-bound",
        logical_operation_id="verify",
        task_class="code.change",
        target_skills=[identity],
        task_fingerprint=DIGEST_B,
        artifact_digest=DIGEST_C,
        signals_by_target={"mail@" + DIGEST_A: {}},
        evidence=[{"kind": "test", "summary": "A deterministic root-bound fixture passed."}],
        baseline_lookup=lambda *_: {
            "ref": "baseline:known",
            "signals": {},
            "hardInvariantsPassed": True,
        },
    )
    return store, result["evaluations"]


class ProviderSpy:
    def __init__(self, learning_home: Path, decision: RouteDecision) -> None:
        self.learning_home = learning_home
        self.provider_root = PROVIDER_ROOT
        self.decision = decision
        self.captured: list[object] = []
        self.calls: list[str] = []

    def route(self, _scope: str, _roots: object) -> RouteDecision:
        self.calls.append("route")
        return self.decision

    def validate(self) -> ProviderValidationResult:
        self.calls.append("validate")
        return ProviderValidationResult(0, 0, "f" * 64)

    def route_capture(self, candidate: object, _roots: object, route_binding: str) -> CandidateRef:
        self.calls.append("capture")
        assert route_binding == self.decision.route_binding
        self.captured.append(candidate)
        return CandidateRef("20260808T120000Z-a1b2c3d4e5f6", None)


@pytest.mark.parametrize("status", ["needs-owner", "ownership-conflict"])
def test_unresolved_route_records_only_reject_terminal_and_never_captures(tmp_path: Path, status: str) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    decision = RouteDecision(status, None, None, None, "Routing is unresolved.")
    provider = ProviderSpy(tmp_path / "learning", decision)

    result = ProposalService(store, provider, contract_roots=[target], target_roots=[target]).resume("run-proposal", "proposal")

    assert result["status"] == "rejected"
    assert provider.captured == []
    assert provider.calls == ["validate", "route"]
    events = store.read_events()
    assert [event.event_type for event in events][-3:] == ["candidate.admission_decided", "report.generated", "run.closed"]
    assert not any(event.event_type == "candidate.captured" for event in events)


def test_owner_target_mismatch_rejects_without_capture(tmp_path: Path) -> None:
    target = _target(tmp_path)
    other = tmp_path / "targets" / "other"
    other.mkdir()
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(tmp_path / "learning", RouteDecision("resolved", "other", str(other), "mail.transport", "Longest owned scope", ROUTE_BINDING))

    result = ProposalService(store, provider, contract_roots=[target], target_roots=[target]).resume("run-proposal", "proposal")

    assert result["status"] == "rejected" and provider.captured == []


def test_route_reason_is_sanitized_before_durable_receipt_or_admission(tmp_path: Path) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved",
            "mail",
            str(target),
            "mail.transport",
            "Contact maintainer@example.com before capture.",
            ROUTE_BINDING,
        ),
    )

    with pytest.raises(LifecycleError, match="route|reason|unsafe|receipt"):
        ProposalService(
            store, provider, contract_roots=[target], target_roots=[target]
        ).resume("run-proposal", "proposal")

    events = store.read_events()
    assert not any(
        event.event_type in {"candidate.admission_decided", "candidate.captured", "report.generated", "run.closed"}
        for event in events
    )
    assert not list((store.home / "objects" / "proposals").glob("rsi-capture-*.json"))


def test_missing_trusted_verification_is_typed_and_never_calls_provider(tmp_path: Path) -> None:
    target = _target(tmp_path)
    store = EventStore(tmp_path / "rsi")
    RunCoordinator(store).start(run_id="run-proposal", active_skills=[{"name": "mail", "versionHash": DIGEST_A}], task_class="code.change", logical_operation_id="start", mode="propose", hook_mode="coordinated")
    provider = ProviderSpy(tmp_path / "learning", RouteDecision("resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING))

    with pytest.raises(LifecycleError, match="trusted verification"):
        ProposalService(store, provider, contract_roots=[target], target_roots=[target]).resume("run-proposal", "proposal")

    assert provider.captured == []


def test_complete_proposal_replays_exactly_and_closes_missing_journal_transition(tmp_path: Path) -> None:
    target = _target(tmp_path)
    store, evaluations = _verified(tmp_path, [_seed()])
    draft = CandidateBuilder(store).build(evaluations[0])[0]
    learning = tmp_path / "learning"
    provider = EvolverAdapter(PROVIDER_ROOT, learning)
    service = ProposalService(store, provider, contract_roots=[target], target_roots=[target])

    # Commit the provider operation first, reproducing caller journal loss.
    route = provider.route(draft.scope, [target])
    assert route.route_binding is not None
    committed = provider.route_capture(draft, [target], route.route_binding)
    first = service.resume("run-proposal", "proposal")
    ledger_before = (store.home / "events.jsonl").read_bytes()
    provider_before = (learning / "events.jsonl").read_bytes()
    second = service.resume("run-proposal", "proposal")

    assert first == second
    assert first["status"] == "completed" and first["candidateIds"] == [committed.candidate_id]
    assert (store.home / "events.jsonl").read_bytes() == ledger_before
    assert (learning / "events.jsonl").read_bytes() == provider_before
    assert [event.event_type for event in store.read_events()][-4:] == ["candidate.admission_decided", "candidate.captured", "report.generated", "run.closed"]
    assert not any(event.event_type == "promotion.gated" for event in store.read_events())


@pytest.mark.parametrize("churn", ["chmod-restore", "atomic-replace", "rewrite-same-bytes"])
def test_closed_proposal_replay_uses_historical_freshness_after_benign_metadata_churn(
    tmp_path: Path, churn: str
) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )
    service = ProposalService(
        store, provider, contract_roots=[target], target_roots=[target]
    )
    first = service.resume("run-proposal", "proposal")
    ledger_before = (store.home / "events.jsonl").read_bytes()
    provider_calls = list(provider.calls)
    victim = target / "references" / "transport.md"
    original = victim.read_bytes()
    mode = victim.stat().st_mode & 0o7777
    if churn == "chmod-restore":
        victim.chmod(mode ^ 0o100)
        victim.chmod(mode)
    elif churn == "atomic-replace":
        replacement = victim.with_name("replacement.md")
        replacement.write_bytes(original)
        replacement.chmod(mode)
        os.replace(replacement, victim)
    else:
        victim.write_bytes(original)
        victim.chmod(mode)

    second = service.resume("run-proposal", "replay")

    assert second == first
    assert (store.home / "events.jsonl").read_bytes() == ledger_before
    assert provider.calls == provider_calls


def test_terminal_close_persists_content_addressed_historical_freshness(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )
    ProposalService(
        store, provider, contract_roots=[target], target_roots=[target]
    ).resume("run-proposal", "proposal")
    closed = next(event for event in store.read_events() if event.event_type == "run.closed")

    assert isinstance(closed.payload_ref, str)
    assert closed.payload_ref.startswith("proposals/run-proposal-freshness-")
    suffix = closed.payload_ref.removeprefix("proposals/run-proposal-freshness-").removesuffix(".json")
    assert len(suffix) == 64 and all(character in "0123456789abcdef" for character in suffix)
    payload = (store.home / "objects" / closed.payload_ref).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == suffix
    value = json.loads(payload)
    assert set(value) == {
        "schemaVersion", "runId", "verificationBindingDigest", "witnessDigest", "witness"
    }
    assert value["schemaVersion"] == 1 and value["runId"] == "run-proposal"
    assert set(value["witness"]) == {"targetRoots", "contractRoots"}


@pytest.mark.parametrize(
    "sidecar_kind", ["report", "observation", "evaluation", "finding", "freshness"]
)
def test_closed_proposal_replay_revalidates_every_durable_sidecar(tmp_path: Path, sidecar_kind: str) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(tmp_path / "learning", RouteDecision("resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING))
    service = ProposalService(store, provider, contract_roots=[target], target_roots=[target])
    service.resume("run-proposal", "proposal")
    events = store.read_events()
    if sidecar_kind == "report":
        path = store.home / "reports" / "local-review-run-proposal.json"
    elif sidecar_kind == "freshness":
        event = next(item for item in events if item.event_type == "run.closed")
        assert event.payload_ref is not None
        path = store.home / "objects" / event.payload_ref
    else:
        event_type = {
            "observation": "task.observed",
            "evaluation": "evaluation.completed",
            "finding": "finding.drafted",
        }[sidecar_kind]
        event = next(item for item in events if item.event_type == event_type)
        assert event.payload_ref is not None
        path = store.home / "objects" / event.payload_ref
    path.unlink()

    with pytest.raises((LifecycleError, StoreIntegrityError), match="durable|unavailable|report|sidecar"):
        service.resume("run-proposal", "replay")


@pytest.mark.parametrize(
    "sidecar_kind", ["provider-binding", "route-receipt", "historical-freshness"]
)
def test_closed_proposal_replay_rejects_noncanonical_proposal_sidecar_framing(
    tmp_path: Path, sidecar_kind: str
) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )
    service = ProposalService(store, provider, contract_roots=[target], target_roots=[target])
    service.resume("run-proposal", "proposal")
    if sidecar_kind == "provider-binding":
        path = store.home / "objects" / "proposals" / "run-proposal.json"
    elif sidecar_kind == "route-receipt":
        admission = next(
            event for event in store.read_events() if event.event_type == "candidate.admission_decided"
        )
        assert admission.payload_ref is not None
        path = store.home / "objects" / admission.payload_ref
    else:
        closed = next(event for event in store.read_events() if event.event_type == "run.closed")
        assert closed.payload_ref is not None
        path = store.home / "objects" / closed.payload_ref
    path.write_bytes(path.read_bytes() + b"\n")

    with pytest.raises((LifecycleError, StoreIntegrityError), match="durable|unavailable|binding|receipt"):
        service.resume("run-proposal", "replay")


def _rewrite_ledger_events(
    store: EventStore,
    mutate: Callable[[list[dict[str, object]]], list[dict[str, object]]],
) -> None:
    values = [json.loads(line) for line in (store.home / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    rewritten = mutate(values)
    (store.home / "events.jsonl").write_text(
        "\n".join(json.dumps(value, sort_keys=True, separators=(",", ":")) for value in rewritten) + "\n",
        encoding="utf-8",
    )


def test_closed_proposal_replay_revalidates_capture_semantic_binding(tmp_path: Path) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )
    service = ProposalService(store, provider, contract_roots=[target], target_roots=[target])
    service.resume("run-proposal", "proposal")

    def forge(values: list[dict[str, object]]) -> list[dict[str, object]]:
        capture = next(value for value in values if value["eventType"] == "candidate.captured")
        capture["payload"]["owner"] = "other"  # type: ignore[index]
        return values

    _rewrite_ledger_events(store, forge)

    with pytest.raises((LifecycleError, StoreIntegrityError), match="capture|branch|binding"):
        service.resume("run-proposal", "replay")


@pytest.mark.parametrize("boundary", ["closed-replay", "under-lock-close"])
def test_route_receipt_raw_digest_binding_rejects_post_close_reason_edit(
    tmp_path: Path, boundary: str
) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )
    service = ProposalService(store, provider, contract_roots=[target], target_roots=[target])
    service.resume("run-proposal", "proposal")
    admission = next(
        event for event in store.read_events() if event.event_type == "candidate.admission_decided"
    )
    assert admission.payload_ref is not None
    receipt_path = store.home / "objects" / admission.payload_ref
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["routeDecision"]["reason"] = "A different safe route explanation."
    receipt_path.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    if boundary == "under-lock-close":
        _rewrite_ledger_events(
            store,
            lambda values: [value for value in values if value["eventType"] != "run.closed"],
        )

    with pytest.raises((LifecycleError, StoreIntegrityError), match="receipt|digest|binding|route"):
        if boundary == "closed-replay":
            service.resume("run-proposal", "replay")
        else:
            RunCoordinator(store).close(
                run_id="run-proposal",
                logical_operation_id="proposal:run-proposal:close",
                status="completed",
            )


def test_store_close_revalidates_capture_semantic_binding_under_lock(tmp_path: Path) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )
    service = ProposalService(store, provider, contract_roots=[target], target_roots=[target])
    service.resume("run-proposal", "proposal")

    def reopen_with_forged_capture(values: list[dict[str, object]]) -> list[dict[str, object]]:
        result = [value for value in values if value["eventType"] != "run.closed"]
        capture = next(value for value in result if value["eventType"] == "candidate.captured")
        capture["payload"]["captureOperationId"] = "rsi-capture-forged"  # type: ignore[index]
        return result

    _rewrite_ledger_events(store, reopen_with_forged_capture)

    with pytest.raises(StoreIntegrityError, match="capture|branch|binding"):
        RunCoordinator(store).close(
            run_id="run-proposal",
            logical_operation_id="proposal:run-proposal:close",
            status="completed",
        )


def test_terminal_reject_is_replayed_without_rerouting_if_ownership_later_changes(tmp_path: Path) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(tmp_path / "learning", RouteDecision("needs-owner", None, None, None, "No owner"))
    service = ProposalService(store, provider, contract_roots=[target], target_roots=[target])

    def lose_after_admission(*_args: object, **_kwargs: object):
        raise OSError("injected report-boundary crash")

    original_write_report = service._write_report
    service._write_report = lose_after_admission  # type: ignore[method-assign]
    with pytest.raises(OSError, match="report-boundary"):
        service.resume("run-proposal", "first")
    service._write_report = original_write_report  # type: ignore[method-assign]
    assert len([event for event in store.read_events() if event.event_type == "candidate.admission_decided"]) == 1
    provider.decision = RouteDecision("resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING)

    result = service.resume("run-proposal", "replay")

    assert result["status"] == "rejected"
    assert provider.calls.count("route") == 1 and provider.calls.count("capture") == 0
    assert provider.captured == []


def test_no_eligible_candidate_is_deterministic_noop(tmp_path: Path) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [])
    provider = ProviderSpy(tmp_path / "learning", RouteDecision("resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING))
    service = ProposalService(store, provider, contract_roots=[target], target_roots=[target])

    first = service.resume("run-proposal", "proposal")
    before = (store.home / "events.jsonl").read_bytes()
    second = service.resume("run-proposal", "proposal")

    assert first == second and first["status"] == "no-op"
    assert provider.captured == [] and (store.home / "events.jsonl").read_bytes() == before


def test_no_eligible_candidate_closes_noop_without_provider_or_capture_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [])

    class IncompatibleProvider(ProviderSpy):
        def validate(self) -> ProviderValidationResult:
            self.calls.append("validate")
            raise ProviderCompatibilityError("provider unavailable")

    provider = IncompatibleProvider(tmp_path / "learning", RouteDecision("resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING))
    monkeypatch.setenv("CODEX_RSI_MODE", "observe")

    result = ProposalService(store, provider, contract_roots=[target], target_roots=[target]).resume("run-proposal", "no-op")

    assert result["status"] == "no-op"
    assert provider.calls == [] and provider.captured == []


def test_resume_rejects_provider_learning_home_drift_after_commit_before_rsi_journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    learning_a = tmp_path / "learning-a"
    learning_b = tmp_path / "learning-b"
    first = ProposalService(
        store,
        EvolverAdapter(PROVIDER_ROOT, learning_a),
        contract_roots=[target],
        target_roots=[target],
    )
    original_append = store.append
    faulted = False

    def fail_capture_journal(event: object):
        nonlocal faulted
        if getattr(event, "event_type", None) == "candidate.captured" and not faulted:
            faulted = True
            raise OSError("injected caller journal loss")
        return original_append(event)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "append", fail_capture_journal)
    with pytest.raises(OSError, match="journal loss"):
        first.resume("run-proposal", "first")
    monkeypatch.setattr(store, "append", original_append)
    assert (learning_a / "events.jsonl").exists()

    second = ProposalService(
        store,
        EvolverAdapter(PROVIDER_ROOT, learning_b),
        contract_roots=[target],
        target_roots=[target],
    )
    with pytest.raises(LifecycleError, match="provider|learning|binding|configuration"):
        second.resume("run-proposal", "second")

    assert not (learning_b / "events.jsonl").exists()


def test_verified_legacy_draft_is_incomplete_for_capture_and_provider_spy_sees_no_route(tmp_path: Path) -> None:
    target = _target(tmp_path)
    target_identity = {"name": "mail", "versionHash": DIGEST_A}
    store = EventStore(tmp_path / "rsi")
    authority = lambda **_: VerificationResult.success("run-proposal", DIGEST_B, [target_identity], DIGEST_C)
    coordinator = RunCoordinator(store, verification_authority=authority)
    coordinator.start(run_id="run-proposal", active_skills=[target_identity], task_class="code.change", logical_operation_id="start", mode="propose", hook_mode="coordinated")
    coordinator.note_finding("run-proposal", {"proposedScope": "mail.transport", "proposedDedupeKey": "mail.transport.legacy", "summary": "A bounded legacy observation."}, "legacy")
    coordinator.verify_primary_task(run_id="run-proposal", logical_operation_id="verify", task_class="code.change", target_skills=[target_identity], task_fingerprint=DIGEST_B, artifact_digest=DIGEST_C, signals_by_target={"mail@" + DIGEST_A: {}}, baseline_lookup=lambda *_: {"ref": "baseline:known", "signals": {}, "hardInvariantsPassed": True})
    provider = ProviderSpy(tmp_path / "learning", RouteDecision("resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING))

    result = ProposalService(store, provider, contract_roots=[target], target_roots=[target]).resume("run-proposal", "proposal")

    assert result["status"] == "no-op"
    assert provider.calls == [] and provider.captured == []


def test_existing_admission_is_reused_across_changed_caller_key_without_duplicate_branch(tmp_path: Path) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])

    class FailOnceProvider(ProviderSpy):
        fail_capture = True

        def route_capture(self, candidate: object, roots: object, route_binding: str) -> CandidateRef:
            self.calls.append("capture")
            if self.fail_capture:
                self.fail_capture = False
                raise OSError("injected capture boundary crash")
            return super().route_capture(candidate, roots, route_binding)

    provider = FailOnceProvider(tmp_path / "learning", RouteDecision("resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING))
    service = ProposalService(store, provider, contract_roots=[target], target_roots=[target])
    with pytest.raises(OSError, match="capture boundary"):
        service.resume("run-proposal", "first-caller")
    admission = next(event for event in store.read_events() if event.event_type == "candidate.admission_decided")

    result = service.resume("run-proposal", "second-caller")

    events = store.read_events()
    assert result["status"] == "completed"
    assert len([event for event in events if event.event_type == "candidate.admission_decided"]) == 1
    assert next(event for event in events if event.event_type == "candidate.captured").causation_id == admission.event_id


def test_store_rejects_duplicate_capture_terminal_for_one_admission(tmp_path: Path) -> None:
    store, evaluations = _verified(tmp_path, [_seed()])
    draft = CandidateBuilder(store).build(evaluations[0])[0]
    admission = append_event(store, event_type="candidate.admission_decided", run_id="run-proposal", logical_operation_id="admit", target_skill="mail", causation_id=evaluations[0]["eventId"], payload={"decision": "allow", "hardReasons": []}, correlation_id=canonical_digest(draft.canonical_mapping()))
    append_event(store, event_type="candidate.captured", run_id="run-proposal", logical_operation_id="capture-one", target_skill="mail", causation_id=admission.event_id, payload={"providerCandidateId": "candidate-one", "captureOperationId": draft.operation_id, "owner": "mail"}, correlation_id=DIGEST_B)

    with pytest.raises(Exception, match="duplicate|terminal"):
        append_event(store, event_type="candidate.captured", run_id="run-proposal", logical_operation_id="capture-two", target_skill="mail", causation_id=admission.event_id, payload={"providerCandidateId": "candidate-one", "captureOperationId": draft.operation_id, "owner": "mail"}, correlation_id=DIGEST_B)


def test_candidate_worthy_run_cannot_report_and_close_without_admission_branches(tmp_path: Path) -> None:
    store, evaluations = _verified(tmp_path, [_seed()])
    evaluation = evaluations[0]
    report = append_event(store, event_type="report.generated", run_id="run-proposal", logical_operation_id="bypass-report", target_skill="rsi", causation_id=evaluation["eventId"], payload={"reportKind": "local", "pathDigest": DIGEST_B, "inputRefs": [evaluation["eventId"]], "mutationPerformed": False}, correlation_id=DIGEST_C)

    with pytest.raises(Exception, match="admission|branch|candidate"):
        RunCoordinator(store).close(run_id="run-proposal", logical_operation_id="bypass-close", status="no-op")

    assert not any(event.event_type == "run.closed" for event in store.read_events())


def test_store_rejects_forged_admission_correlation_at_direct_close_boundary(tmp_path: Path) -> None:
    store, evaluations = _verified(tmp_path, [_seed()])
    evaluation = evaluations[0]
    forged = append_event(
        store,
        event_type="candidate.admission_decided",
        run_id="run-proposal",
        logical_operation_id="forged-admission",
        target_skill="mail",
        causation_id=evaluation["eventId"],
        payload={"decision": "reject", "hardReasons": ["forged"]},
        correlation_id=DIGEST_B,
    )
    report_body = {
        "schemaVersion": 1,
        "runId": "run-proposal",
        "mode": "propose",
        "status": "rejected",
        "evaluationIds": [evaluation["eventId"]],
        "candidateIds": [],
        "rejectedCount": 1,
        "mutationPerformed": False,
    }
    report_bytes = json.dumps(report_body, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    report_digest = "sha256:" + hashlib.sha256(report_bytes).hexdigest()
    store.write_once(store.home / "reports" / "local-review-run-proposal.json", report_bytes)
    report = append_event(
        store,
        event_type="report.generated",
        run_id="run-proposal",
        logical_operation_id="forged-report",
        target_skill="rsi",
        causation_id=forged.event_id,
        payload={"reportKind": "local", "pathDigest": report_digest, "inputRefs": [evaluation["eventId"]], "mutationPerformed": False},
        correlation_id=canonical_digest(report_body),
    )

    with pytest.raises(Exception, match="admission|correlation|candidate|branch"):
        append_event(
            store,
            event_type="run.closed",
            run_id="run-proposal",
            logical_operation_id="direct-close",
            target_skill="rsi",
            causation_id=report.event_id,
            payload={"status": "rejected", "linkedIds": []},
            correlation_id=DIGEST_C,
        )


def test_store_rejects_exact_candidate_reject_without_durable_route_receipt(tmp_path: Path) -> None:
    store, evaluations = _verified(tmp_path, [_seed()])
    evaluation = evaluations[0]
    draft = CandidateBuilder(store).build(evaluation)[0]
    admission = append_event(
        store,
        event_type="candidate.admission_decided",
        run_id="run-proposal",
        logical_operation_id="forged-exact-admission",
        target_skill="mail",
        causation_id=evaluation["eventId"],
        payload={"decision": "reject", "hardReasons": ["needs-owner"]},
        correlation_id=canonical_digest(draft.canonical_mapping()),
    )
    report_body = {
        "schemaVersion": 1,
        "runId": "run-proposal",
        "mode": "propose",
        "status": "rejected",
        "evaluationIds": [evaluation["eventId"]],
        "candidateIds": [],
        "rejectedCount": 1,
        "mutationPerformed": False,
    }
    report_bytes = json.dumps(report_body, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    store.write_once(store.home / "reports" / "local-review-run-proposal.json", report_bytes)
    report = append_event(
        store,
        event_type="report.generated",
        run_id="run-proposal",
        logical_operation_id="forged-exact-report",
        target_skill="rsi",
        causation_id=admission.event_id,
        payload={
            "reportKind": "local",
            "pathDigest": "sha256:" + hashlib.sha256(report_bytes).hexdigest(),
            "inputRefs": [evaluation["eventId"]],
            "mutationPerformed": False,
        },
        correlation_id=canonical_digest(report_body),
    )

    with pytest.raises(Exception, match="receipt|binding|route|admission|proposal"):
        append_event(
            store,
            event_type="run.closed",
            run_id="run-proposal",
            logical_operation_id="forged-exact-close",
            target_skill="rsi",
            causation_id=report.event_id,
            payload={"status": "rejected", "linkedIds": []},
            correlation_id=DIGEST_C,
        )


def test_kill_switch_blocks_provider_validation_and_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(tmp_path / "learning", RouteDecision("resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING))
    monkeypatch.setenv("CODEX_RSI_ENABLED", "0")

    with pytest.raises(LifecycleError, match="kill switch|mode"):
        ProposalService(store, provider, contract_roots=[target], target_roots=[target]).resume("run-proposal", "proposal")

    assert provider.calls == [] and provider.captured == []


def test_kill_switch_is_rechecked_after_route_immediately_before_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])

    class FlipProvider(ProviderSpy):
        def route(self, scope: str, roots: object) -> RouteDecision:
            result = super().route(scope, roots)
            monkeypatch.setenv("CODEX_RSI_MODE", "observe")
            return result

    provider = FlipProvider(tmp_path / "learning", RouteDecision("resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING))

    with pytest.raises(LifecycleError, match="kill switch|mode"):
        ProposalService(store, provider, contract_roots=[target], target_roots=[target]).resume("run-proposal", "proposal")

    assert provider.calls == ["validate", "route"] and provider.captured == []


def test_public_cli_cannot_self_assert_verification(tmp_path: Path) -> None:
    target = _target(tmp_path)
    payload = tmp_path / "input.json"
    payload.write_text(json.dumps({
        "mode": "propose", "hookMode": "coordinated", "taskClass": "code.change",
        "activeSkills": [{"name": "mail", "versionHash": DIGEST_A}],
        "taskFingerprint": DIGEST_B, "artifactDigest": DIGEST_C,
        "signalsByTarget": {"mail@" + DIGEST_A: {}}, "evidence": [], "findings": [],
        "verified": True,
    }), encoding="utf-8")
    command = [sys.executable, str(Path(__file__).resolve().parents[1] / "scripts" / "rsi.py"), "local-review", "--home", str(tmp_path / "rsi"), "--target-root", str(target), "--provider-root", str(PROVIDER_ROOT), "--provider-learning-home", str(tmp_path / "learning"), "--contract-root", str(target), "--run-id", "run-public", "--idempotency-key", "review", "--input-file", str(payload), "--json"]

    completed = subprocess.run(command, capture_output=True, text=True, check=False)

    assert completed.returncode == 2
    assert json.loads(completed.stdout)["error"]["code"] == "invalid-arguments"
    assert not (tmp_path / "rsi").exists() and not (tmp_path / "learning").exists()


def test_public_valid_propose_request_blocks_before_any_durable_mutation(tmp_path: Path) -> None:
    target = _target(tmp_path)
    payload = tmp_path / "input.json"
    payload.write_text(
        json.dumps(
            {
                "mode": "propose",
                "hookMode": "coordinated",
                "taskClass": "code.change",
                "activeSkills": [{"name": "mail", "versionHash": DIGEST_A}],
                "taskFingerprint": DIGEST_B,
                "artifactDigest": DIGEST_C,
                "signalsByTarget": {"mail@" + DIGEST_A: {}},
                "evidence": [],
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    home = tmp_path / "rsi"
    learning = tmp_path / "learning"
    command = [
        sys.executable,
        str(Path(__file__).resolve().parents[1] / "scripts" / "rsi.py"),
        "local-review",
        "--home",
        str(home),
        "--target-root",
        str(target),
        "--provider-root",
        str(PROVIDER_ROOT),
        "--provider-learning-home",
        str(learning),
        "--contract-root",
        str(target),
        "--run-id",
        "run-public-valid",
        "--idempotency-key",
        "review",
        "--input-file",
        str(payload),
        "--json",
    ]

    completed = subprocess.run(command, capture_output=True, text=True, check=False)

    assert completed.returncode == 6
    envelope = json.loads(completed.stdout)
    assert envelope["status"] == "blocked"
    assert envelope["errors"] == [
        {
            "code": "trusted-verification-required",
            "message": "public proposal input cannot establish trusted verification",
            "retryable": False,
            "details": {},
        }
    ]
    assert envelope["eventIds"] == [] and envelope["mutationPerformed"] is False
    assert not home.exists() and not learning.exists()


def test_trusted_two_target_cli_allowlists_and_captures_both_owner_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mail = _target(tmp_path)
    calendar = tmp_path / "targets" / "calendar"
    (calendar / "references").mkdir(parents=True)
    (calendar / "SKILL.md").write_text("---\nname: calendar\n---\n", encoding="utf-8")
    (calendar / "references" / "transport.md").write_text("# Transport\n", encoding="utf-8")
    (calendar / "skill-contract.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "name": "calendar",
                "kind": "role",
                "owns": ["calendar.transport"],
                "provides": [],
            }
        ),
        encoding="utf-8",
    )
    targets = [
        {"name": "mail", "versionHash": DIGEST_A},
        {"name": "calendar", "versionHash": DIGEST_B},
    ]
    home = tmp_path / "rsi"
    store = EventStore(home)

    def authority(**_: object) -> VerificationResult:
        return VerificationResult.success(
            "run-two-targets",
            DIGEST_C,
            targets,
            DIGEST_A,
            target_roots=[mail, calendar],
            contract_roots=[mail, calendar],
        )

    coordinator = RunCoordinator(store, verification_authority=authority)
    coordinator.start(
        run_id="run-two-targets",
        active_skills=targets,
        task_class="code.change",
        logical_operation_id="start",
        mode="propose",
        hook_mode="coordinated",
    )
    coordinator.note_candidate_finding(
        run_id="run-two-targets", seed=_seed(), logical_operation_id="mail-seed"
    )
    coordinator.note_candidate_finding(
        run_id="run-two-targets",
        seed=_seed(
            sourceSkill="calendar",
            targetSkill="calendar",
            targetSkillVersionHash=DIGEST_B,
            scope="calendar.transport.sync",
            dedupeKey="calendar.transport.sync.readback",
            relatedSkills=["calendar"],
            title="Verify calendar transport readback",
        ),
        logical_operation_id="calendar-seed",
    )
    coordinator.verify_primary_task(
        run_id="run-two-targets",
        logical_operation_id="verify",
        task_class="code.change",
        target_skills=targets,
        task_fingerprint=DIGEST_C,
        artifact_digest=DIGEST_A,
        signals_by_target={"mail@" + DIGEST_A: {}, "calendar@" + DIGEST_B: {}},
        evidence=[{"kind": "test", "summary": "A deterministic two-target fixture passed."}],
        baseline_lookup=lambda *_: {
            "ref": "baseline:known",
            "signals": {},
            "hardInvariantsPassed": True,
        },
    )
    provider_root = tmp_path / "provider"
    provider_root.mkdir()
    learning = tmp_path / "learning"

    class MultiTargetProvider:
        def __init__(self) -> None:
            self.provider_root = provider_root
            self.learning_home = learning

        def validate(self) -> ProviderValidationResult:
            return ProviderValidationResult(0, 0, "f" * 64)

        def route(self, scope: str, roots: object) -> RouteDecision:
            owner = scope.split(".", 1)[0]
            owner_path = mail if owner == "mail" else calendar
            return RouteDecision(
                "resolved",
                owner,
                str(owner_path),
                owner + ".transport",
                "Longest owned scope",
                ROUTE_BINDING,
            )

        def route_capture(self, candidate: object, roots: object, route_binding: str) -> CandidateRef:
            assert route_binding == ROUTE_BINDING
            return CandidateRef("provider-" + str(candidate.target_skill), None)  # type: ignore[attr-defined]

    script = Path(__file__).resolve().parents[1] / "scripts" / "rsi.py"
    spec = importlib.util.spec_from_file_location("rsi_task6_two_target_cli", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "EvolverAdapter", lambda *_: MultiTargetProvider())
    payload = tmp_path / "resume.json"
    payload.write_text(
        json.dumps(
            {
                "mode": "propose",
                "hookMode": "coordinated",
                "taskClass": "code.change",
                "activeSkills": targets,
                "taskFingerprint": DIGEST_C,
                "artifactDigest": DIGEST_A,
                "signalsByTarget": {"mail@" + DIGEST_A: {}, "calendar@" + DIGEST_B: {}},
                "evidence": [],
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    before = {_root.name: _tree_manifest(_root) for _root in (mail, calendar)}

    exit_code = module.main(
        [
            "local-review",
            "--home",
            str(home),
            "--target-root",
            str(mail),
            "--target-root",
            str(calendar),
            "--provider-root",
            str(provider_root),
            "--provider-learning-home",
            str(learning),
            "--contract-root",
            str(mail),
            "--contract-root",
            str(calendar),
            "--run-id",
            "run-two-targets",
            "--idempotency-key",
            "proposal",
            "--input-file",
            str(payload),
            "--json",
        ]
    )
    envelope = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert envelope["status"] == "completed"
    assert envelope["candidateIds"] == ["provider-calendar", "provider-mail"]
    assert {_root.name: _tree_manifest(_root) for _root in (mail, calendar)} == before


def test_distinct_drafts_cannot_share_one_provider_candidate_id(tmp_path: Path) -> None:
    target = _target(tmp_path)
    store, _ = _verified(
        tmp_path,
        [
            _seed(dedupeKey="mail.transport.smtp.readback", title="Verify transport readback"),
            _seed(dedupeKey="mail.transport.smtp.retry", title="Verify transport retry"),
        ],
    )
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )

    with pytest.raises((LifecycleError, StoreIntegrityError), match="candidate|duplicate|collision|reused"):
        ProposalService(
            store, provider, contract_roots=[target], target_roots=[target]
        ).resume("run-proposal", "proposal")

    events = store.read_events()
    assert len([event for event in events if event.event_type == "candidate.captured"]) == 1
    assert not any(event.event_type in {"report.generated", "run.closed"} for event in events)


def test_verified_target_root_cannot_be_first_pinned_to_same_name_different_bytes(
    tmp_path: Path,
) -> None:
    trusted = _target(tmp_path / "trusted")
    substituted = _target(tmp_path / "substituted")
    (substituted / "SKILL.md").write_text(
        "---\nname: mail\ndescription: Byte-different substitute\n---\n",
        encoding="utf-8",
    )
    store, evaluations = _verified_with_trusted_roots(tmp_path / "state", trusted)
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(substituted), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )

    with pytest.raises(LifecycleError, match="verified target|root|manifest|binding"):
        ProposalService(
            store,
            provider,
            contract_roots=[substituted],
            target_roots=[substituted],
        ).resume("run-root-bound", "proposal")

    assert provider.calls == [] and provider.captured == []
    assert not (store.home / "objects" / "proposals" / "run-root-bound.json").exists()
    assert not any(
        event.event_type == "candidate.admission_decided" for event in store.read_events()
    )
    observation = next(
        event for event in store.read_events() if event.event_type == "task.observed"
    )
    observation_value = json.loads(
        (store.home / "objects" / str(observation.payload_ref)).read_text(encoding="utf-8")
    )
    assert observation_value["verificationBindings"]["targetRoots"][0]["canonicalRoot"] == str(trusted)
    assert evaluations[0]["verificationBinding"]["targetRoot"]["canonicalRoot"] == str(trusted)


def test_verified_target_bytes_and_contract_root_graph_are_rechecked_before_provider(
    tmp_path: Path,
) -> None:
    trusted = _target(tmp_path / "trusted")
    contract_root = tmp_path / "contracts"
    contract_root.mkdir()
    contract_copy = contract_root / "mail"
    contract_copy.mkdir()
    (contract_copy / "skill-contract.json").write_bytes(
        (trusted / "skill-contract.json").read_bytes()
    )
    store, _ = _verified_with_trusted_roots(
        tmp_path / "state", trusted, contract_roots=[contract_root]
    )
    (trusted / "references" / "transport.md").write_text("# Changed after verification\n", encoding="utf-8")
    (contract_copy / "skill-contract.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "name": "mail",
                "kind": "role",
                "owns": ["mail.transport", "mail.synthetic"],
                "provides": [],
            }
        ),
        encoding="utf-8",
    )
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(trusted), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )

    with pytest.raises(LifecycleError, match="verified target|contract root|manifest|binding"):
        ProposalService(
            store,
            provider,
            contract_roots=[contract_root],
            target_roots=[trusted],
        ).resume("run-root-bound", "proposal")

    assert provider.calls == [] and provider.captured == []
    assert not (store.home / "objects" / "proposals" / "run-root-bound.json").exists()


def test_verified_root_symlink_alias_is_rejected_before_provider(tmp_path: Path) -> None:
    trusted = _target(tmp_path / "trusted")
    store, _ = _verified_with_trusted_roots(tmp_path / "state", trusted)
    alias = tmp_path / "mail-alias"
    alias.symlink_to(trusted, target_is_directory=True)
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(trusted), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )

    with pytest.raises(LifecycleError, match="symlink|root|binding"):
        ProposalService(
            store, provider, contract_roots=[alias], target_roots=[alias]
        ).resume("run-root-bound", "proposal")

    assert provider.calls == [] and provider.captured == []


def test_target_manifest_scan_never_holds_journal_lock_against_unrelated_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )
    ProposalService(
        store, provider, contract_roots=[target], target_roots=[target]
    ).resume("run-proposal", "proposal")
    _rewrite_ledger_events(
        store,
        lambda values: [value for value in values if value["eventType"] != "run.closed"],
    )
    entered = threading.Event()
    release = threading.Event()
    original_entries = target_identity._tree_entries

    def blocked_entries(root: Path) -> list[dict[str, object]]:
        if threading.current_thread().name == "proposal-close" and not entered.is_set():
            entered.set()
            assert release.wait(timeout=5)
        return original_entries(root)

    monkeypatch.setattr(target_identity, "_tree_entries", blocked_entries)
    close_errors: list[BaseException] = []

    def close_proposal() -> None:
        try:
            RunCoordinator(store).close(
                run_id="run-proposal",
                logical_operation_id="proposal:run-proposal:close",
                status="completed",
            )
        except BaseException as error:  # pragma: no cover - asserted below
            close_errors.append(error)

    closer = threading.Thread(target=close_proposal, name="proposal-close")
    closer.start()
    assert entered.wait(timeout=5)
    unrelated_done = threading.Event()
    unrelated_errors: list[BaseException] = []

    def append_unrelated() -> None:
        try:
            RunCoordinator(store).start(
                run_id="run-unrelated",
                active_skills=[{"name": "mail", "versionHash": DIGEST_A}],
                task_class="code.change",
                logical_operation_id="start",
                mode="observe",
                hook_mode="coordinated",
            )
            unrelated_done.set()
        except BaseException as error:  # pragma: no cover - asserted below
            unrelated_errors.append(error)

    unrelated = threading.Thread(target=append_unrelated)
    unrelated.start()
    progressed_without_scan = unrelated_done.wait(timeout=0.5)
    release.set()
    closer.join(timeout=10)
    unrelated.join(timeout=10)

    assert progressed_without_scan is True
    assert not closer.is_alive() and not unrelated.is_alive()
    assert close_errors == [] and unrelated_errors == []


def test_stale_verified_target_still_fails_close_before_terminal_append(tmp_path: Path) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )
    ProposalService(
        store, provider, contract_roots=[target], target_roots=[target]
    ).resume("run-proposal", "proposal")
    _rewrite_ledger_events(
        store,
        lambda values: [value for value in values if value["eventType"] != "run.closed"],
    )
    (target / "references" / "transport.md").write_text("# Stale after verification\n", encoding="utf-8")

    with pytest.raises((LifecycleError, StoreIntegrityError), match="target|manifest|binding"):
        RunCoordinator(store).close(
            run_id="run-proposal",
            logical_operation_id="proposal:run-proposal:close",
            status="completed",
        )

    assert not any(event.event_type == "run.closed" for event in store.read_events())


@pytest.mark.parametrize(
    "mutation_kind",
    ["in-place-same-size", "atomic-replace", "directory-member", "symlink-alias"],
)
def test_target_mutation_after_full_scan_fails_at_terminal_append_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation_kind: str,
) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )
    ProposalService(
        store, provider, contract_roots=[target], target_roots=[target]
    ).resume("run-proposal", "proposal")
    _rewrite_ledger_events(
        store,
        lambda values: [value for value in values if value["eventType"] != "run.closed"],
    )
    freshness_before = set(
        (store.home / "objects" / "proposals").glob("run-proposal-freshness-*.json")
    )
    victim = target / "references" / "transport.md"
    original_bytes = victim.read_bytes()
    original_append = store.append_with_sidecar
    mutation_count = 0

    def mutate_before_terminal_append(
        event: object, path: Path, data: bytes, **kwargs: object
    ) -> object:
        nonlocal mutation_count
        if getattr(event, "event_type", None) != "run.closed":
            return original_append(event, path, data, **kwargs)  # type: ignore[arg-type]
        mutation_count += 1
        if mutation_count == 1:
            if mutation_kind == "in-place-same-size":
                changed = bytes(byte ^ 1 if index == 0 else byte for index, byte in enumerate(original_bytes))
                assert len(changed) == len(original_bytes)
                victim.write_bytes(changed)
            elif mutation_kind == "atomic-replace":
                replacement = victim.with_name("replacement.md")
                replacement.write_bytes(original_bytes)
                os.replace(replacement, victim)
            elif mutation_kind == "directory-member":
                (target / "references" / "added.md").write_text("# Added after scan\n", encoding="utf-8")
            else:
                outside = tmp_path / "outside.md"
                outside.write_bytes(original_bytes)
                victim.unlink()
                victim.symlink_to(outside)
        return original_append(event, path, data, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "append_with_sidecar", mutate_before_terminal_append)

    with pytest.raises((LifecycleError, StoreIntegrityError), match="target|manifest|binding|fresh"):
        RunCoordinator(store).close(
            run_id="run-proposal",
            logical_operation_id="proposal:run-proposal:close",
            status="completed",
        )

    assert mutation_count >= 1
    assert not any(event.event_type == "run.closed" for event in store.read_events())
    assert set(
        (store.home / "objects" / "proposals").glob("run-proposal-freshness-*.json")
    ) == freshness_before


def test_target_mutation_returned_from_full_scan_is_not_rebased_as_fresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )
    ProposalService(
        store, provider, contract_roots=[target], target_roots=[target]
    ).resume("run-proposal", "proposal")
    _rewrite_ledger_events(
        store,
        lambda values: [value for value in values if value["eventType"] != "run.closed"],
    )
    victim = target / "references" / "transport.md"
    original_revalidate = target_identity.revalidate_verification_bindings
    calls = 0

    def mutate_after_scan(*args: object, **kwargs: object) -> object:
        nonlocal calls
        result = original_revalidate(*args, **kwargs)
        calls += 1
        if calls == 1:
            replacement = victim.with_name("replacement.md")
            replacement.write_bytes(victim.read_bytes())
            os.replace(replacement, victim)
        return result

    monkeypatch.setattr(
        target_identity, "revalidate_verification_bindings", mutate_after_scan
    )

    with pytest.raises((LifecycleError, StoreIntegrityError), match="target|manifest|binding|fresh"):
        RunCoordinator(store).close(
            run_id="run-proposal",
            logical_operation_id="proposal:run-proposal:close",
            status="completed",
        )

    assert calls >= 1
    assert not any(event.event_type == "run.closed" for event in store.read_events())


@pytest.mark.parametrize(
    "swap_kind",
    ["target-internal", "contract-internal", "target-ancestor", "contract-ancestor"],
)
def test_terminal_freshness_rebinds_every_open_directory_on_unwind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_kind: str
) -> None:
    target = _target(tmp_path / "trusted")
    contract_container = tmp_path / "contract-container"
    contract_root = contract_container / "contracts"
    contract_owner = contract_root / "mail"
    contract_owner.mkdir(parents=True)
    (contract_owner / "skill-contract.json").write_bytes(
        (target / "skill-contract.json").read_bytes()
    )
    store, _ = _verified_with_trusted_roots(
        tmp_path / "state", target, contract_roots=[contract_root]
    )
    provider = ProviderSpy(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )
    ProposalService(
        store, provider, contract_roots=[contract_root], target_roots=[target]
    ).resume("run-root-bound", "proposal")
    _rewrite_ledger_events(
        store,
        lambda values: [value for value in values if value["eventType"] != "run.closed"],
    )
    freshness_before = set(
        (store.home / "objects" / "proposals").glob("run-root-bound-freshness-*.json")
    )
    armed = False
    swaps = 0
    original_append = store.append_with_sidecar
    original_open_relative = target_identity._open_relative_checked
    original_open_ancestry = target_identity._open_directory_ancestry

    def swap_directory(source: Path) -> None:
        nonlocal swaps
        moved = source.with_name(source.name + "-opened")
        source.rename(moved)
        source.symlink_to(moved, target_is_directory=True)
        swaps += 1

    def open_relative_with_swap(
        parent: int, name: str, expected: os.stat_result
    ) -> tuple[int, os.stat_result]:
        opened = original_open_relative(parent, name, expected)
        if armed and swaps == 0:
            if swap_kind == "target-internal" and name == "references":
                swap_directory(target / "references")
            elif swap_kind == "contract-internal" and name == "mail":
                swap_directory(contract_owner)
        return opened

    def open_ancestry_with_swap(root: Path) -> object:
        opened = original_open_ancestry(root)
        if armed and swaps == 0:
            if swap_kind == "target-ancestor" and root == target:
                swap_directory(target.parent)
            elif swap_kind == "contract-ancestor" and root == contract_root:
                swap_directory(contract_container)
        return opened

    def terminal_append(
        event: object, path: Path, data: bytes, **kwargs: object
    ) -> object:
        nonlocal armed
        if getattr(event, "event_type", None) != "run.closed":
            return original_append(event, path, data, **kwargs)  # type: ignore[arg-type]
        armed = True
        try:
            return original_append(event, path, data, **kwargs)  # type: ignore[arg-type]
        finally:
            armed = False

    monkeypatch.setattr(target_identity, "_open_relative_checked", open_relative_with_swap)
    monkeypatch.setattr(target_identity, "_open_directory_ancestry", open_ancestry_with_swap)
    monkeypatch.setattr(store, "append_with_sidecar", terminal_append)

    with pytest.raises((LifecycleError, StoreIntegrityError), match="target|root|fresh|unsafe"):
        RunCoordinator(store).close(
            run_id="run-root-bound",
            logical_operation_id="proposal:run-root-bound:close",
            status="completed",
        )

    assert swaps == 1
    assert not any(event.event_type == "run.closed" for event in store.read_events())
    assert set(
        (store.home / "objects" / "proposals").glob("run-root-bound-freshness-*.json")
    ) == freshness_before


@pytest.mark.parametrize("limit_kind", ["entries", "bytes"])
def test_trusted_target_manifest_has_finite_entry_and_byte_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit_kind: str
) -> None:
    target = _target(tmp_path)
    if limit_kind == "entries":
        monkeypatch.setattr(target_identity, "MAX_TARGET_ENTRIES", 2)
    else:
        monkeypatch.setattr(target_identity, "MAX_TARGET_BYTES", 8)

    with pytest.raises(LifecycleError, match="bound|limit|large|entries"):
        target_identity.build_target_root_binding(target, "mail", DIGEST_A)


def test_trusted_target_manifest_stabilization_attempts_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _target(tmp_path)
    calls = 0

    def always_changes(_root: Path) -> list[dict[str, object]]:
        nonlocal calls
        calls += 1
        return [{"path": "SKILL.md", "sequence": calls}]

    monkeypatch.setattr(target_identity, "MAX_MANIFEST_ATTEMPTS", 3)
    monkeypatch.setattr(target_identity, "_tree_entries", always_changes)

    with pytest.raises(LifecycleError, match="stabilize"):
        target_identity._stable_tree_digest(target)

    assert calls == 3


@pytest.mark.parametrize("boundary", ["closed-replay", "under-lock-close"])
def test_durable_closure_rejects_forged_cross_draft_provider_candidate_collision(
    tmp_path: Path, boundary: str
) -> None:
    target = _target(tmp_path)
    store, evaluations = _verified(
        tmp_path,
        [
            _seed(dedupeKey="mail.transport.smtp.readback", title="Verify transport readback"),
            _seed(dedupeKey="mail.transport.smtp.retry", title="Verify transport retry"),
        ],
    )

    class DistinctProvider(ProviderSpy):
        def route_capture(self, candidate: object, roots: object, route_binding: str) -> CandidateRef:
            super().route_capture(candidate, roots, route_binding)
            return CandidateRef(f"provider-candidate-{len(self.captured)}", None)

    provider = DistinctProvider(
        tmp_path / "learning",
        RouteDecision(
            "resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING
        ),
    )
    service = ProposalService(store, provider, contract_roots=[target], target_roots=[target])
    service.resume("run-proposal", "proposal")
    drafts = CandidateBuilder(store).build(evaluations[0])
    report_path = store.home / "reports" / "local-review-run-proposal.json"
    report_value = json.loads(report_path.read_text(encoding="utf-8"))
    duplicate_id = str(report_value["candidateIds"][0])
    report_value["candidateIds"] = [duplicate_id, duplicate_id]
    report_bytes = json.dumps(
        report_value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8") + b"\n"
    report_path.write_bytes(report_bytes)

    def forge(values: list[dict[str, object]]) -> list[dict[str, object]]:
        captures = [value for value in values if value["eventType"] == "candidate.captured"]
        second = captures[1]
        operation = str(second["payload"]["captureOperationId"])  # type: ignore[index]
        draft = next(item for item in drafts if item.operation_id == operation)
        second["payload"]["providerCandidateId"] = duplicate_id  # type: ignore[index]
        second["correlationId"] = canonical_digest(
            {"draft": draft.canonical_mapping(), "providerCandidateId": duplicate_id}
        )
        report_event = next(value for value in values if value["eventType"] == "report.generated")
        report_event["payload"]["pathDigest"] = "sha256:" + hashlib.sha256(report_bytes).hexdigest()  # type: ignore[index]
        report_event["correlationId"] = canonical_digest(report_value)
        if boundary == "under-lock-close":
            return [value for value in values if value["eventType"] != "run.closed"]
        return values

    _rewrite_ledger_events(store, forge)

    with pytest.raises((LifecycleError, StoreIntegrityError), match="candidate|duplicate|collision|capture"):
        if boundary == "closed-replay":
            service.resume("run-proposal", "replay")
        else:
            RunCoordinator(store).close(
                run_id="run-proposal",
                logical_operation_id="proposal:run-proposal:close",
                status="completed",
            )


def test_trusted_stage2_local_review_e2e_captures_reports_closes_and_preserves_target(tmp_path: Path) -> None:
    target = _target(tmp_path)
    before = _tree_manifest(target)
    store, _ = _verified(tmp_path, [_seed()])
    payload = tmp_path / "resume.json"
    payload.write_text(json.dumps({
        "mode": "propose", "hookMode": "coordinated", "taskClass": "code.change",
        "activeSkills": [{"name": "mail", "versionHash": DIGEST_A}],
        "taskFingerprint": DIGEST_B, "artifactDigest": DIGEST_C,
        "signalsByTarget": {"mail@" + DIGEST_A: {}}, "evidence": [], "findings": [],
    }), encoding="utf-8")
    command = [sys.executable, str(Path(__file__).resolve().parents[1] / "scripts" / "rsi.py"), "local-review", "--home", str(store.home), "--target-root", str(target), "--provider-root", str(PROVIDER_ROOT), "--provider-learning-home", str(tmp_path / "learning"), "--contract-root", str(target), "--run-id", "run-proposal", "--idempotency-key", "proposal", "--input-file", str(payload), "--json"]

    first = subprocess.run(command, capture_output=True, text=True, check=False)
    ledger = (store.home / "events.jsonl").read_bytes()
    provider_ledger = (tmp_path / "learning" / "events.jsonl").read_bytes()
    second = subprocess.run(command, capture_output=True, text=True, check=False)

    assert first.returncode == second.returncode == 0, first.stdout + first.stderr
    assert json.loads(first.stdout) == json.loads(second.stdout)
    assert json.loads(first.stdout)["candidateIds"]
    assert (store.home / "events.jsonl").read_bytes() == ledger
    assert (tmp_path / "learning" / "events.jsonl").read_bytes() == provider_ledger
    assert _tree_manifest(target) == before


def test_cli_maps_real_provider_operation_conflict_to_exit_eight(tmp_path: Path) -> None:
    target = _target(tmp_path)
    store, evaluations = _verified(tmp_path, [_seed()])
    draft = CandidateBuilder(store).build(evaluations[0])[0]
    learning = tmp_path / "learning"
    provider_environment = os.environ.copy()
    provider_environment["CODEX_SKILL_LEARNING_HOME"] = str(learning)
    conflicting = subprocess.run(
        [
            sys.executable,
            "-B",
            str(PROVIDER_ROOT / "scripts" / "learning_log.py"),
            "capture",
            "--operation-id",
            draft.operation_id,
            "--skill-name",
            draft.target_skill,
            "--skill-path",
            str(target),
            "--kind",
            draft.kind,
            "--change-class",
            draft.change_class,
            "--title",
            draft.title,
            "--finding",
            draft.finding,
            "--evidence",
            draft.evidence[0],
            "--confidence",
            repr(draft.confidence),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=provider_environment,
    )
    assert conflicting.returncode == 0, conflicting.stdout + conflicting.stderr
    payload = tmp_path / "resume-conflict.json"
    payload.write_text(json.dumps({
        "mode": "propose", "hookMode": "coordinated", "taskClass": "code.change",
        "activeSkills": [{"name": "mail", "versionHash": DIGEST_A}],
        "taskFingerprint": DIGEST_B, "artifactDigest": DIGEST_C,
        "signalsByTarget": {"mail@" + DIGEST_A: {}}, "evidence": [], "findings": [],
    }), encoding="utf-8")
    command = [sys.executable, str(Path(__file__).resolve().parents[1] / "scripts" / "rsi.py"), "local-review", "--home", str(store.home), "--target-root", str(target), "--provider-root", str(PROVIDER_ROOT), "--provider-learning-home", str(learning), "--contract-root", str(target), "--run-id", "run-proposal", "--idempotency-key", "proposal", "--input-file", str(payload), "--json"]

    completed = subprocess.run(command, capture_output=True, text=True, check=False)

    assert completed.returncode == 8
    assert json.loads(completed.stdout)["error"]["code"] == "operation-id-conflict"


@pytest.mark.parametrize("alias", ["state", "learning"])
def test_overlapping_or_symlink_aliased_control_roots_fail_before_provider_call(tmp_path: Path, alias: str) -> None:
    target = _target(tmp_path)
    store, _ = _verified(tmp_path, [_seed()])
    learning = target / "learning" if alias == "learning" else tmp_path / "learning"
    if alias == "state":
        link = tmp_path / "target-alias"
        link.symlink_to(target, target_is_directory=True)
        roots = [link]
    else:
        roots = [target]
    provider = ProviderSpy(learning, RouteDecision("resolved", "mail", str(target), "mail.transport", "Longest owned scope", ROUTE_BINDING))

    with pytest.raises(LifecycleError, match="disjoint|symlink"):
        ProposalService(store, provider, contract_roots=[target], target_roots=roots).resume("run-proposal", "proposal")

    assert provider.captured == []


def _closed_task6_origin(
    tmp_path: Path,
) -> tuple[EventStore, Path, str]:
    store, _ = _verified(tmp_path, [_seed()])
    target = tmp_path / "targets" / "mail"
    provider = ProviderSpy(
        tmp_path / "task6-provider-learning",
        RouteDecision(
            "resolved",
            "mail",
            str(target),
            "mail.transport",
            "Longest owned scope",
            ROUTE_BINDING,
        ),
    )

    result = ProposalService(
        store,
        provider,
        contract_roots=[target],
        target_roots=[target],
    ).resume("run-proposal", "proposal")

    assert result["status"] == "completed"
    assert result["candidateIds"] == ["20260808T120000Z-a1b2c3d4e5f6"]
    origin_events = [event for event in store.read_events() if event.run_id == "run-proposal"]
    assert sum(event.event_type == "candidate.captured" for event in origin_events) == 1
    assert sum(event.event_type == "run.closed" for event in origin_events) == 1
    assert origin_events[-1].event_type == "run.closed"
    return store, target, str(result["candidateIds"][0])


def test_task8_promote_candidate_cli_is_closed_to_the_six_literal_selectors_and_ids() -> None:
    module = _load_rsi_cli_module()
    command = _task8_cli_arguments()

    arguments = module._parser().parse_args(command)

    assert set(vars(arguments)) == {
        "command",
        "home",
        "json",
        "candidate_id",
        "promotion_plan",
        "validation_attestation",
        "expected_target_hash",
        "run_id",
        "idempotency_key",
    }
    assert arguments.command == "promote-candidate"
    assert arguments.candidate_id == "20260808T120000Z-a1b2c3d4e5f6"
    assert arguments.promotion_plan == TASK8_CLI_PLAN_DIGEST
    assert arguments.validation_attestation == TASK8_CLI_ATTESTATION_DIGEST
    assert arguments.expected_target_hash == TASK8_CLI_TARGET_PRE_HASH
    assert arguments.run_id == _task8_cli_run_id(TASK8_CLI_PLAN_DIGEST)
    assert arguments.idempotency_key == _task8_cli_operation_id(
        TASK8_CLI_PLAN_DIGEST
    )
    assert arguments.json is True

    for forbidden in (
        ("--origin-run-id", "run-proposal"),
        ("--capture-event-id", "evt-capture"),
        ("--input-file", "plan.json"),
        ("--provider-learning-home", "/tmp/provider"),
        ("--artifact-store", "/tmp/artifacts"),
    ):
        with pytest.raises(SystemExit):
            module._parser().parse_args([*command, *forbidden])


def test_task8_cli_missing_v2_plan_never_reopens_or_counterfeits_the_closed_task6_origin(
    tmp_path: Path,
) -> None:
    store, target, candidate_id = _closed_task6_origin(tmp_path)
    unused_provider_home = tmp_path / "provider-must-not-be-invoked"
    before = {
        "store": _identity_tree_manifest(store.home),
        "target": _identity_tree_manifest(target),
        "provider": _identity_tree_manifest(unused_provider_home),
    }
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["CODEX_SKILL_LEARNING_HOME"] = str(unused_provider_home)
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(RSI_CLI),
            *_task8_cli_arguments(home=store.home, candidate_id=candidate_id),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 6, completed.stdout + completed.stderr
    response = json.loads(completed.stdout)
    assert response["command"] == "promote-candidate"
    assert response["runId"] == _task8_cli_run_id(TASK8_CLI_PLAN_DIGEST)
    assert response["status"] in {"blocked", "failed"}
    assert response["error"]["code"] != "invalid-arguments"
    assert {
        "store": _identity_tree_manifest(store.home),
        "target": _identity_tree_manifest(target),
        "provider": _identity_tree_manifest(unused_provider_home),
    } == before

    after_events = store.read_events()
    assert {event.run_id for event in after_events} == {"run-proposal"}
    assert sum(event.event_type == "candidate.captured" for event in after_events) == 1
    assert sum(event.event_type == "run.closed" for event in after_events) == 1


def test_task8_cli_malformed_pathlike_or_nondeterministic_selectors_are_zero_write(
    tmp_path: Path,
) -> None:
    store, target, candidate_id = _closed_task6_origin(tmp_path)
    unused_provider_home = tmp_path / "provider-must-not-be-invoked"
    before = {
        "store": _identity_tree_manifest(store.home),
        "target": _identity_tree_manifest(target),
        "provider": _identity_tree_manifest(unused_provider_home),
    }
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["CODEX_SKILL_LEARNING_HOME"] = str(unused_provider_home)
    mutations = (
        {"candidate_id": "../candidate"},
        {"plan_digest": "file:///tmp/plan.json"},
        {"attestation_digest": "sha256:" + "A" * 64},
        {"target_pre_hash": "d" * 64},
        {"run_id": "run_promote_" + "0" * 64},
        {"operation_id": "promote_" + "0" * 64},
    )

    for mutation in mutations:
        selectors: dict[str, object] = {
            "home": store.home,
            "candidate_id": candidate_id,
        }
        selectors.update(mutation)
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(RSI_CLI),
                *_task8_cli_arguments(**selectors),
            ],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 2, completed.stdout + completed.stderr
        response = json.loads(completed.stdout)
        assert response["command"] == "promote-candidate"
        assert isinstance(response["error"]["code"], str)
        assert response["error"]["code"]
        assert {
            "store": _identity_tree_manifest(store.home),
            "target": _identity_tree_manifest(target),
            "provider": _identity_tree_manifest(unused_provider_home),
        } == before

    events = store.read_events()
    assert {event.run_id for event in events} == {"run-proposal"}
    assert sum(event.event_type == "candidate.captured" for event in events) == 1
    assert sum(event.event_type == "run.closed" for event in events) == 1
