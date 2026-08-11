#!/usr/bin/env python3
"""Small, strict CLI for the pre-provider-v2 observe-only RSI lifecycle."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from rsi_core.defragment import DefragmentationService
from rsi_core.evaluate import Evaluator
from rsi_core.evolver_adapter import (
    EvolverAdapter,
    OperationIdConflict,
    ProviderProtocolError,
)
from rsi_core.hooks import (
    LifecycleError,
    RunCoordinator,
    append_event,
    canonical_digest,
)
from rsi_core.observe import Observer
from rsi_core.proposal import ProposalService
from rsi_core.report import GlobalReportService, MonitoringService, read_report
from rsi_core.storage import EventStore, StoreIntegrityError
from rsi_core.validation import (
    validate_cli_identifiers,
    validate_evaluate,
    validate_finding,
    validate_local_review,
    validate_observe,
)

MAX_INPUT_BYTES = 64 * 1024
TASK8_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
TASK8_CANDIDATE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")


def _envelope(command: str, run_id: str | None, *, status: str, mode: str = "observe", event_ids: list[str] | None = None, candidate_ids: list[str] | None = None, mutation: bool = False, warnings: list[str] | None = None, errors: list[object] | None = None, **extra: object) -> dict[str, object]:
    return {"schemaVersion": 1, "command": command, "status": status, "mode": mode, "runId": run_id, "eventIds": event_ids or [], "candidateIds": candidate_ids or [], "mutationPerformed": mutation, "warnings": warnings or [], "errors": errors or [], **extra}


def _error(command: str, run_id: str | None, code: str, message: str, *, retryable: bool = False, details: Mapping[str, object] | None = None) -> dict[str, object]:
    return {"schemaVersion": 1, "command": command, "runId": run_id, "status": "failed", "error": {"code": code, "message": message, "retryable": retryable, "details": dict(details or {})}}


def _read_json_input(path: str | None) -> dict[str, object]:
    if not path:
        raise LifecycleError("--run-id, --idempotency-key, and --input-file are required")
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1) if path == "-" else Path(path).read_bytes()
        if len(raw) > MAX_INPUT_BYTES:
            raise LifecycleError("input exceeds byte limit")
        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise LifecycleError("input must be a JSON object") from error
    if not isinstance(value, dict):
        raise LifecycleError("input must be a JSON object")
    return value


def _require_write_arguments(arguments: argparse.Namespace) -> dict[str, object]:
    if not arguments.run_id or not arguments.idempotency_key or not arguments.input_file:
        raise LifecycleError("--run-id, --idempotency-key, and --input-file are required")
    return _read_json_input(arguments.input_file)


def _write_report(store: EventStore, *, run_id: str, logical_operation_id: str, causation_id: str, report: Mapping[str, object]) -> str:
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    path = store.home / "reports" / ("local-review-" + run_id + ".json")
    try:
        store.write_once(path, encoded)
    except Exception as error:
        raise LifecycleError("report replay conflicts with durable payload") from error
    event = append_event(store, event_type="report.generated", run_id=run_id, logical_operation_id=logical_operation_id, target_skill="rsi", causation_id=causation_id, payload={"reportKind": "local", "pathDigest": digest, "inputRefs": [causation_id], "mutationPerformed": False}, correlation_id=canonical_digest(report))
    return event.event_id


def _run_local_review(arguments: argparse.Namespace, body: Mapping[str, object]) -> dict[str, object]:
    mode = str(body["mode"])
    hook_mode = str(body["hookMode"])
    task_class = str(body["taskClass"])
    active_skills = body["activeSkills"]
    assert isinstance(active_skills, list)
    blocked = _envelope(
        "local-review",
        arguments.run_id,
        status="blocked",
        mode=mode,
        errors=[
            {
                "code": "trusted-verification-required",
                "message": "public proposal input cannot establish trusted verification",
                "retryable": False,
                "details": {},
            }
        ],
    )
    events_path = Path(os.path.abspath(arguments.home)) / "events.jsonl"
    if mode == "propose" and not events_path.exists():
        return blocked
    store = EventStore(arguments.home)
    existing = [event for event in store.read_events() if event.run_id == arguments.run_id]
    if mode == "propose" and not existing:
        return blocked
    if existing and mode == "propose":
        if not arguments.provider_root or not arguments.provider_learning_home or not arguments.contract_root:
            raise ProviderProtocolError("provider root, learning home, and contract roots are required")
        adapter = EvolverAdapter(arguments.provider_root, arguments.provider_learning_home)
        return ProposalService(
            store,
            adapter,
            contract_roots=arguments.contract_root,
            target_roots=arguments.target_root,
        ).resume(arguments.run_id, arguments.idempotency_key)
    coordinator = RunCoordinator(store)
    started = coordinator.start(run_id=arguments.run_id, active_skills=active_skills, task_class=task_class, logical_operation_id=arguments.idempotency_key + ":start", mode=mode, hook_mode=hook_mode, final_artifacts=body.get("finalArtifacts"))
    noted: list[str] = []
    findings = body.get("findings", [])
    assert isinstance(findings, list)
    for number, finding in enumerate(findings):
        assert isinstance(finding, Mapping)
        result = coordinator.note_finding(arguments.run_id, finding, arguments.idempotency_key + ":note:" + str(number))
        noted.extend(result["eventIds"])
    observed = Observer(store).observe(run_id=arguments.run_id, logical_operation_id=arguments.idempotency_key + ":observe", task_class=task_class, outcome="unverified", target_skills=active_skills, signals_by_target=body.get("signalsByTarget") if hook_mode == "coordinated" else {item["name"] + "@" + item["versionHash"]: {} for item in active_skills}, evidence=body.get("finalArtifacts") if hook_mode == "late-review" else body["evidence"], task_fingerprint=str(body["taskFingerprint"]), artifact_digest=str(body["artifactDigest"]))
    evaluations = Evaluator(store).evaluate_per_target(run_id=arguments.run_id, observation=observed["observation"], observation_event_id=observed["eventIds"][0], logical_operation_id=arguments.idempotency_key + ":evaluate")
    report = {"schemaVersion": 1, "runId": arguments.run_id, "mode": mode, "observationEventId": observed["eventIds"][0], "evaluationIds": [item["eventId"] for item in evaluations], "candidateIds": [], "mutationPerformed": False}
    report_event = _write_report(store, run_id=arguments.run_id, logical_operation_id=arguments.idempotency_key + ":report", causation_id=evaluations[-1]["eventId"], report=report)
    blocked = mode in {"propose", "promote-safe"}
    closed = coordinator.close(run_id=arguments.run_id, logical_operation_id=arguments.idempotency_key + ":close", status="blocked" if blocked else "completed")
    warnings = list(started["warnings"])
    errors: list[object] = []
    if blocked:
        errors.append({"code": "provider-v2-required", "message": "canonical candidate capture and promotion require provider v2", "retryable": False, "details": {}})
    return _envelope("local-review", arguments.run_id, status="blocked" if blocked else "completed", mode=mode, event_ids=[*started["eventIds"], *noted, *observed["eventIds"], *[item["eventId"] for item in evaluations], report_event, *closed["eventIds"]], warnings=warnings, errors=errors)


def _require_disjoint_home(home: str, target_roots: Sequence[str] | None, provider_learning_home: str | None = None) -> None:
    if not target_roots:
        raise LifecycleError("--target-root is required")
    raw_targets = [Path(os.path.abspath(value)) for value in target_roots]
    raw_state = Path(os.path.abspath(home))
    for raw_target in raw_targets:
        try:
            target_metadata = raw_target.lstat()
        except FileNotFoundError:
            raise LifecycleError("target root must be an existing real directory") from None
        if not stat.S_ISDIR(target_metadata.st_mode) or stat.S_ISLNK(target_metadata.st_mode):
            raise LifecycleError("target root must be an existing real directory")
    for raw in (*raw_targets, raw_state):
        current = Path(raw.anchor)
        for part in raw.parts[1:]:
            current /= part
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                break
            if stat.S_ISLNK(metadata.st_mode):
                raise LifecycleError("RSI home and target roots cannot use symlink aliases")
            if current != raw and not stat.S_ISDIR(metadata.st_mode):
                raise LifecycleError("RSI home has unsafe filesystem topology")
    targets = [raw.resolve(strict=True) for raw in raw_targets]
    state = raw_state.resolve(strict=False)
    for number, target in enumerate(targets):
        if target == state or target in state.parents or state in target.parents:
            raise LifecycleError("RSI home must be disjoint from target root")
        for other in targets[number + 1 :]:
            if target == other or target in other.parents or other in target.parents:
                raise LifecycleError("target roots must be distinct and non-overlapping")
    if provider_learning_home:
        learning = Path(os.path.abspath(provider_learning_home)).resolve(strict=False)
        for raw in (Path(os.path.abspath(provider_learning_home)),):
            current = Path(raw.anchor)
            for part in raw.parts[1:]:
                current /= part
                try:
                    metadata = current.lstat()
                except FileNotFoundError:
                    break
                if stat.S_ISLNK(metadata.st_mode):
                    raise LifecycleError("provider learning home cannot use symlink aliases")
        pairs = [(learning, target) for target in targets] + [(learning, state)]
        if any(first == second or first in second.parents or second in first.parents for first, second in pairs):
            raise LifecycleError("RSI home, provider learning home, and target root must be disjoint")
    if raw_state.exists():
        pending = [raw_state]
        while pending:
            directory = pending.pop()
            try:
                entries = list(os.scandir(directory))
            except OSError as error:
                raise LifecycleError("RSI home has unsafe filesystem topology") from error
            for entry in entries:
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise LifecycleError("RSI home has unsafe filesystem topology")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(Path(entry.path))
                elif not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise LifecycleError("RSI home has unsafe filesystem topology")


def _dispatch(arguments: argparse.Namespace) -> dict[str, object]:
    if arguments.command == "preflight":
        return _envelope("preflight", None, status="completed", mode="observe", providerCompatible=False, canonicalCaptureAvailable=False)
    if arguments.command == "doctor":
        store = EventStore(arguments.home)
        result = store.doctor_salvage_report(arguments.salvage_report)
        return _envelope("doctor", None, status="completed", doctor=result)
    if arguments.command == "promote-candidate":
        for label in (
            "promotion_plan", "validation_attestation", "expected_target_hash"
        ):
            value = getattr(arguments, label)
            if not isinstance(value, str) or TASK8_DIGEST_PATTERN.fullmatch(value) is None:
                raise LifecycleError("promotion selectors must be canonical sha256 digests")
        if not TASK8_CANDIDATE_PATTERN.fullmatch(arguments.candidate_id):
            raise LifecycleError("candidate selector is invalid")
        expected_run = "run_promote_" + hashlib.sha256(
            json.dumps(
                {
                    "domain": "rsi-promotion-continuation-v1",
                    "planDigest": arguments.promotion_plan,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        expected_operation = "promote_" + hashlib.sha256(
            json.dumps(
                {
                    "domain": "rsi-promote-cli-v1",
                    "planDigest": arguments.promotion_plan,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if arguments.run_id != expected_run or arguments.idempotency_key != expected_operation:
            raise LifecycleError("promotion continuation identifiers are not deterministic")
        # This admission is intentionally zero-write.  The selectors name
        # constructor-attested V2 objects; a missing object is a semantic
        # blocked result and must never synthesize or reopen the Task 6 run.
        EventStore.open_existing(arguments.home).read_events()
        return {
            "schemaVersion": 1,
            "command": "promote-candidate",
            "runId": arguments.run_id,
            "status": "blocked",
            "error": {
                "code": "promotion-plan-unavailable",
                "message": "the selected immutable Task 7 V2 promotion plan is unavailable",
                "retryable": False,
                "details": {},
            },
        }
    body = _require_write_arguments(arguments)
    run_id, operation = validate_cli_identifiers(arguments.run_id, arguments.idempotency_key)
    arguments.run_id, arguments.idempotency_key = run_id, operation
    if arguments.command == "monitor":
        expected = {
            "promotionRef",
            "evaluationRef",
            "baseline",
            "variant",
            "causalAttribution",
            "expectedControlPlaneVersion",
        }
        if set(body) != expected:
            raise LifecycleError("monitor input has invalid fields")
        if not isinstance(body["baseline"], Mapping) or not isinstance(body["variant"], Mapping):
            raise LifecycleError("monitor records must be JSON objects")
        _require_disjoint_home(arguments.home, arguments.target_root)
        result = MonitoringService(EventStore(arguments.home)).record(
            run_id=run_id,
            logical_operation_id=operation,
            promotion_ref=str(body["promotionRef"]),
            evaluation_ref=str(body["evaluationRef"]),
            baseline=body["baseline"],
            variant=body["variant"],
            causal_attribution=str(body["causalAttribution"]),
            expected_control_plane_version=str(body["expectedControlPlaneVersion"]),
        )
        return _envelope(
            "monitor",
            run_id,
            status="completed" if result["outcome"] != "quarantined" else "quarantined",
            event_ids=list(result["eventIds"]),
            mutation=False,
            **{key: value for key, value in result.items() if key not in {"schemaVersion", "runId", "eventIds", "mutationPerformed"}},
        )
    if arguments.command == "global-review":
        expected = {
            "sourceEvaluationRefs",
            "records",
            "minimumFingerprints",
            "minimumSkills",
        }
        if set(body) != expected or not isinstance(body["sourceEvaluationRefs"], list) or not isinstance(body["records"], list):
            raise LifecycleError("global-review input has invalid fields")
        if any(type(value) is not str for value in body["sourceEvaluationRefs"]) or any(
            not isinstance(value, Mapping) for value in body["records"]
        ):
            raise LifecycleError("global-review sources are invalid")
        _require_disjoint_home(arguments.home, arguments.target_root)
        result = GlobalReportService(EventStore(arguments.home)).generate(
            run_id=run_id,
            logical_operation_id=operation,
            source_evaluation_refs=body["sourceEvaluationRefs"],
            records=body["records"],
            minimum_fingerprints=body["minimumFingerprints"],  # type: ignore[arg-type]
            minimum_skills=body["minimumSkills"],  # type: ignore[arg-type]
        )
        return _envelope(
            "global-review",
            run_id,
            status="completed" if result["conclusion"] == "supported" else str(result["conclusion"]),
            event_ids=list(result["eventIds"]),
            mutation=False,
            **{key: value for key, value in result.items() if key not in {"schemaVersion", "runId", "eventIds", "mutationPerformed"}},
        )
    if arguments.command == "report":
        if set(body) != {"reportRef"}:
            raise LifecycleError("report input has invalid fields")
        report = read_report(EventStore.open_existing(arguments.home), body["reportRef"])
        return _envelope("report", run_id, status="completed", mutation=False, report=report)
    if arguments.command == "defrag-audit":
        if set(body) != {"registrationManifest", "ruleDeclarations"}:
            raise LifecycleError("defrag-audit input has invalid fields")
        if not isinstance(body["registrationManifest"], Mapping) or not isinstance(body["ruleDeclarations"], list):
            raise LifecycleError("defrag-audit input is invalid")
        _require_disjoint_home(arguments.home, arguments.target_root)
        result = DefragmentationService(EventStore(arguments.home), arguments.target_root).audit(
            run_id=run_id,
            logical_operation_id=operation,
            registration_manifest=body["registrationManifest"],
            rule_declarations=body["ruleDeclarations"],
        )
        return _envelope(
            "defrag-audit",
            run_id,
            status="completed-with-findings" if result["findings"] else "completed",
            event_ids=list(result["eventIds"]),
            mutation=False,
            **{key: value for key, value in result.items() if key not in {"schemaVersion", "runId", "eventIds", "mutationPerformed"}},
        )
    if arguments.command == "defrag-plan":
        expected = {"auditRef", "ledgerEntries", "ownerTargetHashes", "goldenTests"}
        if set(body) != expected or not isinstance(body["ledgerEntries"], list) or not isinstance(body["ownerTargetHashes"], Mapping) or not isinstance(body["goldenTests"], list):
            raise LifecycleError("defrag-plan input has invalid fields")
        _require_disjoint_home(arguments.home, arguments.target_root)
        result = DefragmentationService(EventStore(arguments.home), arguments.target_root).plan(
            run_id=run_id,
            logical_operation_id=operation,
            audit_ref=str(body["auditRef"]),
            ledger_entries=body["ledgerEntries"],
            owner_target_hashes=body["ownerTargetHashes"],
            golden_tests=body["goldenTests"],
        )
        return _envelope(
            "defrag-plan",
            run_id,
            status="validated-proposal",
            event_ids=list(result["eventIds"]),
            mutation=False,
            **{key: value for key, value in result.items() if key not in {"schemaVersion", "runId", "eventIds", "mutationPerformed"}},
        )
    if arguments.command == "defrag-validate":
        if set(body) != {"planRef"}:
            raise LifecycleError("defrag-validate input has invalid fields")
        _require_disjoint_home(arguments.home, arguments.target_root)
        result = DefragmentationService(EventStore(arguments.home), arguments.target_root).validate(
            run_id=run_id,
            logical_operation_id=operation,
            plan_ref=str(body["planRef"]),
        )
        return _envelope(
            "defrag-validate",
            run_id,
            status=str(result["status"]),
            event_ids=list(result["eventIds"]),
            mutation=False,
            **{key: value for key, value in result.items() if key not in {"schemaVersion", "runId", "eventIds", "mutationPerformed", "status"}},
        )
    if arguments.command == "local-review":
        admitted = validate_local_review(body)
        _require_disjoint_home(arguments.home, arguments.target_root, arguments.provider_learning_home)
        return _run_local_review(arguments, admitted)
    if arguments.command == "note-finding":
        admitted = validate_finding(body)
        store = EventStore(arguments.home)
        result = RunCoordinator(store).note_finding(arguments.run_id, admitted, arguments.idempotency_key)
        return _envelope("note-finding", arguments.run_id, status=result["status"], event_ids=result["eventIds"], candidate_ids=[])
    if arguments.command == "observe":
        admitted = validate_observe(body)
        store = EventStore(arguments.home)
        result = Observer(store).observe(run_id=arguments.run_id, logical_operation_id=arguments.idempotency_key, task_class=admitted["taskClass"], outcome="unverified", target_skills=admitted["targetSkills"], signals_by_target=admitted["signalsByTarget"], evidence=admitted["evidence"], task_fingerprint=admitted["taskFingerprint"], artifact_digest=admitted["artifactDigest"])
        return _envelope("observe", arguments.run_id, status="completed", event_ids=result["eventIds"], candidate_ids=[], observation=result["observation"])
    if arguments.command == "evaluate":
        admitted = validate_evaluate(body)
        observation, event_id = admitted["observation"], admitted["observationEventId"]
        assert isinstance(observation, Mapping) and isinstance(event_id, str)
        store = EventStore(arguments.home)
        results = Evaluator(store).evaluate_per_target(run_id=arguments.run_id, observation=observation, observation_event_id=event_id, logical_operation_id=arguments.idempotency_key)
        return _envelope("evaluate", arguments.run_id, status="completed", event_ids=[item["eventId"] for item in results], candidate_ids=[], evaluations=results)
    raise LifecycleError("unsupported command")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    commands = parser.add_subparsers(dest="command")
    for name in (
        "preflight",
        "note-finding",
        "observe",
        "evaluate",
        "local-review",
        "monitor",
        "global-review",
        "report",
        "defrag-audit",
        "defrag-plan",
        "defrag-validate",
    ):
        command = commands.add_parser(name, add_help=False)
        command.add_argument("--home", default=str(Path.home() / ".codex" / "rsi"))
        command.add_argument("--json", action="store_true")
        if name != "preflight":
            command.add_argument("--run-id")
            command.add_argument("--idempotency-key")
            command.add_argument("--input-file")
        if name in {"local-review", "monitor", "global-review", "defrag-audit", "defrag-plan", "defrag-validate"}:
            command.add_argument("--target-root", action="append", required=True)
        if name == "local-review":
            command.add_argument("--provider-root")
            command.add_argument("--provider-learning-home")
            command.add_argument("--contract-root", action="append")
    doctor = commands.add_parser("doctor", add_help=False)
    doctor.add_argument("--home", required=True)
    doctor.add_argument("--salvage-report", required=True)
    doctor.add_argument("--json", action="store_true")
    promote = commands.add_parser("promote-candidate", add_help=False)
    promote.add_argument("--home", default=str(Path.home() / ".codex" / "rsi"))
    promote.add_argument("--json", action="store_true")
    promote.add_argument("--candidate-id", required=True)
    promote.add_argument("--promotion-plan", required=True)
    promote.add_argument("--validation-attestation", required=True)
    promote.add_argument("--expected-target-hash", required=True)
    promote.add_argument("--run-id", required=True)
    promote.add_argument("--idempotency-key", required=True)
    return parser


def _result_exit_code(result: Mapping[str, object]) -> int:
    status = result.get("status")
    if status in {"ambiguous", "quarantined"}:
        return 9
    codes: list[str] = []
    error = result.get("error")
    if isinstance(error, Mapping) and isinstance(error.get("code"), str):
        codes.append(str(error["code"]))
    errors = result.get("errors")
    if isinstance(errors, Sequence) and not isinstance(errors, (str, bytes)):
        for item in errors:
            if isinstance(item, Mapping) and isinstance(item.get("code"), str):
                codes.append(str(item["code"]))
    normalized = " ".join(codes).lower()
    if any(token in normalized for token in ("operation-id-conflict", "concurrency", "hash-conflict")):
        return 8
    if "approval" in normalized:
        return 7
    if any(token in normalized for token in ("provider", "dependency", "promotion-plan-unavailable")):
        return 6
    if any(token in normalized for token in ("validation", "attestation")):
        return 5
    if any(token in normalized for token in ("store", "ledger", "integrity")):
        return 4
    if any(token in normalized for token in ("policy", "allowlist")):
        return 3
    if status == "blocked":
        return 6
    if status == "failed":
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    command = argv if argv is not None else sys.argv[1:]
    try:
        arguments = parser.parse_args(command)
    except SystemExit:
        print(json.dumps(_error(command[0] if command else "", None, "invalid-arguments", "invalid command arguments"), sort_keys=True, separators=(",", ":")))
        return 2
    if not getattr(arguments, "command", None):
        print(json.dumps(_error("", None, "invalid-arguments", "a command is required"), sort_keys=True, separators=(",", ":")))
        return 2
    try:
        result = _dispatch(arguments)
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return _result_exit_code(result)
    except LifecycleError as error:
        print(json.dumps(_error(arguments.command, getattr(arguments, "run_id", None), "invalid-arguments", str(error)), sort_keys=True, separators=(",", ":")))
        return 2
    except StoreIntegrityError as error:
        print(json.dumps(_error(arguments.command, getattr(arguments, "run_id", None), "store-integrity", str(error), retryable=False), sort_keys=True, separators=(",", ":")))
        return 4
    except OperationIdConflict as error:
        print(json.dumps(_error(arguments.command, getattr(arguments, "run_id", None), error.code, str(error), retryable=False), sort_keys=True, separators=(",", ":")))
        return 8
    except ProviderProtocolError as error:
        print(json.dumps(_error(arguments.command, getattr(arguments, "run_id", None), error.code, str(error), retryable=False), sort_keys=True, separators=(",", ":")))
        return 6
    except (OSError, TypeError, ValueError):
        print(json.dumps(_error(arguments.command, getattr(arguments, "run_id", None), "invalid-schema", "request could not be processed safely"), sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
