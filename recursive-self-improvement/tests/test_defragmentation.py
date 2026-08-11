from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from rsi_core.events import EventValidationError, fold_run
from rsi_core.hashing import build_skill_manifest
from rsi_core.storage import EventStore, StoreIntegrityError


def _contract(name: str, kind: str = "role") -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "name": name,
        "version": "1",
        "kind": kind,
        "owns": [f"{kind}.{name}"],
        "provides": [],
        "requires": [],
        "conflicts": [],
        "loadPolicy": "on-demand",
        "entrypoints": {"skill": "SKILL.md"},
        "profiles": [],
        "safety": {"destructive": False, "network": False, "writesExternalState": False},
    }


def _skill(root: Path, name: str = "role-skill") -> Path:
    root.mkdir(parents=True)
    (root / "references").mkdir()
    (root / "profiles").mkdir()
    (root / "SKILL.md").write_text(
        "# Role\n\nRule: own the business decision.\nRule: coordinate the workflow.\n",
        encoding="utf-8",
    )
    (root / "references" / "transport.md").write_text(
        "Rule: retry transport with bounded backoff.\n",
        encoding="utf-8",
    )
    (root / "profiles" / "default.json").write_text(
        '{"mode":"observe","region":"local"}\n', encoding="utf-8"
    )
    (root / "skill-contract.json").write_text(
        json.dumps(_contract(name), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return root


def _snapshot(root: Path) -> tuple[tuple[str, str, int, bytes], ...]:
    items: list[tuple[str, str, int, bytes]] = []
    for path in sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root)).encode()):
        metadata = path.lstat()
        relative = str(path.relative_to(root))
        if stat.S_ISLNK(metadata.st_mode):
            items.append((relative, "symlink", stat.S_IMODE(metadata.st_mode), os.readlink(path).encode()))
        elif stat.S_ISDIR(metadata.st_mode):
            items.append((relative, "directory", stat.S_IMODE(metadata.st_mode), b""))
        else:
            items.append((relative, "file", stat.S_IMODE(metadata.st_mode), path.read_bytes()))
    return tuple(items)


def _registration(canonical: Path, runtime: Path, name: str = "role-skill") -> dict[str, object]:
    digest = build_skill_manifest(canonical).digest
    return {
        "schemaVersion": 1,
        "skillName": name,
        "canonical": {"path": str(canonical), "digest": digest},
        "runtimeRegistrations": [
            {
                "path": str(runtime),
                "type": "symlink",
                "expectedRealpath": str(canonical.resolve()),
                "expectedDigest": digest,
            }
        ],
    }


def _declarations() -> list[dict[str, object]]:
    return [
        {
            "artifact": "SKILL.md",
            "rule": "Rule: own the business decision.",
            "classification": "role",
            "owner": {"skill": "role-skill", "scope": "role.role-skill", "capability": None},
            "duplicateOf": None,
        },
        {
            "artifact": "references/transport.md",
            "rule": "Rule: retry transport with bounded backoff.",
            "classification": "capability",
            "owner": {"skill": "transport-capability", "scope": "capability.transport", "capability": "transport"},
            "duplicateOf": None,
        },
        {
            "artifact": "profiles/default.json",
            "rule": '"mode":"observe"',
            "classification": "profile",
            "owner": {"skill": "role-skill", "scope": "profile.runtime", "capability": None},
            "duplicateOf": None,
        },
        {
            "artifact": "SKILL.md",
            "rule": "Rule: coordinate the workflow.",
            "classification": "workflow",
            "owner": {"skill": "role-skill", "scope": "workflow.coordination", "capability": None},
            "duplicateOf": None,
        },
    ]


def _audit_fixture(tmp_path: Path):
    from rsi_core.defragment import RuleInventory, audit_registration

    source_parent = tmp_path / "source"
    runtime_parent = tmp_path / "runtime"
    canonical = _skill(source_parent / "role-skill")
    runtime_parent.mkdir()
    runtime = runtime_parent / "role-skill"
    runtime.symlink_to(canonical, target_is_directory=True)
    registration = _registration(canonical, runtime)
    report = audit_registration(registration, allowed_roots=(source_parent, runtime_parent))
    inventory = RuleInventory.build(
        skill_name="role-skill",
        canonical_root=canonical,
        registration_digest=report.digest,
        declarations=_declarations(),
    )
    return source_parent, runtime_parent, canonical, runtime, registration, report, inventory


def test_registration_audit_accepts_canonical_symlink_and_detects_runtime_copy_drift(tmp_path: Path) -> None:
    from rsi_core.defragment import audit_registration

    source_parent, runtime_parent, _canonical, runtime, registration, report, _ = _audit_fixture(tmp_path)
    assert report.drift is False
    assert report.findings == ()
    runtime.unlink()
    copied = _skill(runtime, "role-skill")
    (copied / "SKILL.md").write_text("diverged\n", encoding="utf-8")
    drift = audit_registration(registration, allowed_roots=(source_parent, runtime_parent))
    assert drift.drift is True
    assert "runtime-registration-copy" in drift.findings
    assert "runtime-registration-digest-drift" in drift.findings


def test_rule_inventory_has_stable_ids_and_all_normative_classifications(tmp_path: Path) -> None:
    from rsi_core.defragment import RuleInventory

    *_, canonical, _runtime, _registration, report, inventory = _audit_fixture(tmp_path)
    reversed_inventory = RuleInventory.build(
        skill_name="role-skill",
        canonical_root=canonical,
        registration_digest=report.digest,
        declarations=reversed(_declarations()),
    )
    assert inventory.digest == reversed_inventory.digest
    assert [entry.rule_id for entry in inventory.entries] == [
        entry.rule_id for entry in reversed_inventory.entries
    ]
    assert {entry.classification for entry in inventory.entries} == {
        "role",
        "capability",
        "profile",
        "workflow",
    }
    assert len({entry.rule_id for entry in inventory.entries}) == len(inventory.entries)


def test_inventory_rejects_unbound_rule_and_profile_misclassification(tmp_path: Path) -> None:
    from rsi_core.defragment import DefragmentationError, RuleInventory

    *_, canonical, _runtime, _registration, report, _inventory = _audit_fixture(tmp_path)
    missing = [*_declarations(), {**_declarations()[0], "rule": "Rule: invented."}]
    with pytest.raises(DefragmentationError):
        RuleInventory.build("role-skill", canonical, report.digest, missing)
    wrong = [{**item} for item in _declarations()]
    wrong[2] = {**wrong[2], "classification": "role"}
    with pytest.raises(DefragmentationError):
        RuleInventory.build("role-skill", canonical, report.digest, wrong)
    missing_capability = [{**item} for item in _declarations()]
    missing_capability[1] = {
        **missing_capability[1],
        "owner": {
            "skill": "transport-capability",
            "scope": "capability.transport",
            "capability": None,
        },
    }
    with pytest.raises(DefragmentationError, match="capability owner"):
        RuleInventory.build(
            "role-skill", canonical, report.digest, missing_capability
        )


def _ledger_entries(inventory) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for number, rule in enumerate(inventory.entries):
        action = ("keep", "move", "split", "replace-with-reference")[number]
        entries.append(
            {
                "sourceRuleId": rule.rule_id,
                "action": action,
                "owner": rule.owner,
                "newRuleIds": ["rule_new_a", "rule_new_b"] if action == "split" else [],
                "duplicateEvidence": None,
                "reason": "owner-scoped migration proposal",
                "approval": "required",
                "verification": ["golden-tests", "byte-identity"],
            }
        )
    return entries


def test_migration_ledger_requires_exactly_one_disposition_per_rule(tmp_path: Path) -> None:
    from rsi_core.defragment import DefragmentationError, MigrationLedger

    *_, inventory = _audit_fixture(tmp_path)
    entries = _ledger_entries(inventory)
    ledger = MigrationLedger.build(inventory, entries)
    assert {item.source_rule_id for item in ledger.entries} == {
        item.rule_id for item in inventory.entries
    }
    with pytest.raises(DefragmentationError):
        MigrationLedger.build(inventory, entries[:-1])
    with pytest.raises(DefragmentationError):
        MigrationLedger.build(inventory, [*entries, entries[0]])


def test_split_requires_new_descendants_and_duplicate_requires_survivor(tmp_path: Path) -> None:
    from rsi_core.defragment import DefragmentationError, MigrationLedger

    *_, inventory = _audit_fixture(tmp_path)
    entries = _ledger_entries(inventory)
    split_index = next(i for i, item in enumerate(entries) if item["action"] == "split")
    bad_split = [{**item} for item in entries]
    bad_split[split_index] = {**bad_split[split_index], "newRuleIds": []}
    with pytest.raises(DefragmentationError):
        MigrationLedger.build(inventory, bad_split)

    duplicate = [{**item} for item in entries]
    duplicate[0] = {
        **duplicate[0],
        "action": "delete-duplicate",
        "duplicateEvidence": None,
    }
    with pytest.raises(DefragmentationError):
        MigrationLedger.build(inventory, duplicate)


def test_confirmed_duplicate_binds_equivalent_survivor_and_can_be_proposed_for_deletion(tmp_path: Path) -> None:
    from rsi_core.defragment import MigrationLedger, RuleInventory

    *_, canonical, _runtime, _registration, report, _inventory = _audit_fixture(tmp_path)
    (canonical / "references" / "duplicate.md").write_text(
        "Rule: retry transport with bounded backoff.\n", encoding="utf-8"
    )
    declarations = [*_declarations()]
    declarations.append(
        {
            "artifact": "references/duplicate.md",
            "rule": "Rule: retry transport with bounded backoff.",
            "classification": "capability",
            "owner": {"skill": "transport-capability", "scope": "capability.transport", "capability": "transport"},
            "duplicateOf": None,
        }
    )
    initial = RuleInventory.build("role-skill", canonical, report.digest, declarations)
    survivor = next(item for item in initial.entries if item.artifact == "references/transport.md")
    duplicate = next(item for item in initial.entries if item.artifact == "references/duplicate.md")
    declarations[-1] = {
        **declarations[-1],
        "classification": "duplicate",
        "duplicateOf": survivor.rule_id,
    }
    inventory = RuleInventory.build("role-skill", canonical, report.digest, declarations)
    entries = []
    for item in inventory.entries:
        deleting = item.rule_id == duplicate.rule_id
        entries.append(
            {
                "sourceRuleId": item.rule_id,
                "action": "delete-duplicate" if deleting else "keep",
                "owner": item.owner,
                "newRuleIds": [],
                "duplicateEvidence": (
                    {"survivingRuleId": survivor.rule_id, "semanticDigest": survivor.semantic_digest}
                    if deleting
                    else None
                ),
                "reason": "confirmed equivalent duplicate" if deleting else "retain survivor",
                "approval": "required",
                "verification": ["semantic-equivalence", "byte-identity"],
            }
        )
    ledger = MigrationLedger.build(inventory, entries)
    removed = next(item for item in ledger.entries if item.action == "delete-duplicate")
    assert removed.duplicate_evidence == {
        "survivingRuleId": survivor.rule_id,
        "semanticDigest": survivor.semantic_digest,
    }


def test_umbrella_plan_groups_owner_changes_and_binds_tests_and_rollback(tmp_path: Path) -> None:
    from rsi_core.defragment import MigrationLedger, MigrationPlan

    *_, inventory = _audit_fixture(tmp_path)
    ledger = MigrationLedger.build(inventory, _ledger_entries(inventory))
    owners = {entry.owner["skill"] for entry in ledger.entries}
    hashes = {owner: "sha256:" + hashlib.sha256(owner.encode()).hexdigest() for owner in owners}
    tests = [
        {"testId": "golden-owner-" + owner, "ownerSkill": owner, "decisionFacts": ["same-outcome"], "safetyGates": ["no-target-write"]}
        for owner in sorted(owners)
    ]
    plan = MigrationPlan.build(inventory, ledger, hashes, tests)
    assert {item["ownerSkill"] for item in plan.change_sets} == owners
    assert all(item["entryIds"] for item in plan.change_sets)
    assert plan.status == "validated-proposal"
    assert plan.golden_test_plan["tests"] == tests
    assert plan.rollback_plan["restoreOrder"] == sorted(owners, reverse=True)
    assert plan.mutation_performed is False
    assert set(plan.to_mapping()) == {
        "schemaVersion",
        "migrationId",
        "ruleInventoryDigest",
        "ledgerDigest",
        "changeSets",
        "goldenTestManifestDigest",
        "rollbackPlanDigest",
        "status",
    }
    persisted = ledger.to_mapping()["entries"][0]
    assert set(persisted) == {
        "schemaVersion",
        "migrationId",
        "source",
        "classification",
        "action",
        "owner",
        "newRuleIds",
        "duplicateEvidence",
        "reason",
        "approval",
        "verification",
    }
    assert set(persisted["source"]) == {"skill", "artifact", "sourceHash", "ruleId"}


def test_defrag_service_publishes_exact_sequence_without_target_mutation(tmp_path: Path) -> None:
    from rsi_core.defragment import DefragmentationService

    source, runtime, _canonical, _runtime_path, registration, _report, _inventory = _audit_fixture(tmp_path)
    before = (_snapshot(source), _snapshot(runtime))
    service = DefragmentationService(EventStore(tmp_path / "state"), (source, runtime))
    audit = service.audit(
        run_id="run_defrag_001",
        logical_operation_id="defrag_001",
        registration_manifest=registration,
        rule_declarations=_declarations(),
    )
    inventory_entries = audit["inventory"]["entries"]
    entries = []
    for item in inventory_entries:
        entries.append(
            {
                "sourceRuleId": item["ruleId"],
                "action": "keep",
                "owner": item["owner"],
                "newRuleIds": [],
                "duplicateEvidence": None,
                "reason": "retain authoritative owner",
                "approval": "required",
                "verification": ["golden-tests", "byte-identity"],
            }
        )
    owners = sorted({item["owner"]["skill"] for item in inventory_entries})
    plan = service.plan(
        run_id="run_defrag_001",
        logical_operation_id="defrag_001",
        audit_ref=audit["auditRef"],
        ledger_entries=entries,
        owner_target_hashes={owner: "sha256:" + hashlib.sha256(owner.encode()).hexdigest() for owner in owners},
        golden_tests=[
            {"testId": "golden-" + owner, "ownerSkill": owner, "decisionFacts": ["same-outcome"], "safetyGates": ["no-target-write"]}
            for owner in owners
        ],
    )
    validated = service.validate(
        run_id="run_defrag_001",
        logical_operation_id="defrag_001",
        plan_ref=plan["planRef"],
    )
    assert validated["status"] == "validated-proposal"
    assert validated["mutationPerformed"] is False
    assert before == (_snapshot(source), _snapshot(runtime))
    events = EventStore.open_existing(tmp_path / "state").read_events()
    assert [event.event_type for event in events] == [
        "run.started",
        "defrag.audit.completed",
        "defrag.plan.built",
        "defrag.plan.validated",
        "run.closed",
    ]
    assert fold_run(events).status == "completed"
    for reference in (audit["auditRef"], plan["planRef"], validated["validationRef"]):
        path = tmp_path / "state" / reference
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.read_bytes().endswith(b"\n")


def test_defrag_events_are_rejected_in_local_runs_and_close_requires_validation(tmp_path: Path) -> None:
    from rsi_core.defragment import DefragmentationService

    source, runtime, _canonical, _runtime_path, registration, _report, _inventory = _audit_fixture(tmp_path)
    service = DefragmentationService(EventStore(tmp_path / "state"), (source, runtime))
    audit = service.audit("run_defrag_002", "defrag_002", registration, _declarations())
    events = EventStore.open_existing(tmp_path / "state").read_events()
    start, audited = events
    local_start = type(start).from_mapping({
        **start.to_dict(),
        "payload": {**start.to_dict()["payload"], "runKind": "local"},
    })
    with pytest.raises(EventValidationError):
        fold_run((local_start, audited))
    from rsi_core.hooks import append_event

    with pytest.raises(StoreIntegrityError, match="validated plan"):
        append_event(
            service.store,
            event_type="run.closed",
            run_id="run_defrag_002",
            logical_operation_id="defrag_002:early-close",
            target_skill="rsi",
            causation_id=audited.event_id,
            payload={"status": "completed", "linkedIds": [audited.event_id]},
        )
    assert audit["mutationPerformed"] is False


def test_plan_rechecks_registration_and_validate_rechecks_audit(tmp_path: Path) -> None:
    from rsi_core.defragment import DefragmentationError, DefragmentationService

    source, runtime_parent, canonical, runtime, registration, _report, _inventory = _audit_fixture(tmp_path)
    service = DefragmentationService(EventStore(tmp_path / "state"), (source, runtime_parent))
    audit = service.audit("run_defrag_drift", "defrag_drift", registration, _declarations())
    runtime.unlink()
    _skill(runtime, "role-skill")
    with pytest.raises(DefragmentationError, match="changed after audit"):
        service.plan(
            "run_defrag_drift",
            "defrag_drift",
            audit["auditRef"],
            [],
            {},
            [],
        )
    assert canonical.exists()


def test_content_addressed_plan_tamper_fails_closed_and_exact_retry_converges(tmp_path: Path) -> None:
    from rsi_core.defragment import DefragmentationError, DefragmentationService

    source, runtime, canonical, _runtime_path, registration, _report, _inventory = _audit_fixture(tmp_path)
    service = DefragmentationService(EventStore(tmp_path / "state"), (source, runtime))
    audit = service.audit("run_defrag_retry", "defrag_retry", registration, _declarations())
    entries = [
        {
            "sourceRuleId": item["ruleId"],
            "action": "keep",
            "owner": item["owner"],
            "newRuleIds": [],
            "duplicateEvidence": None,
            "reason": "retain",
            "approval": "required",
            "verification": ["golden-tests", "byte-identity"],
        }
        for item in audit["inventory"]["entries"]
    ]
    owners = sorted({item["owner"]["skill"] for item in audit["inventory"]["entries"]})
    hashes = {owner: "sha256:" + hashlib.sha256(owner.encode()).hexdigest() for owner in owners}
    tests = [
        {"testId": "golden-" + owner, "ownerSkill": owner, "decisionFacts": ["same-outcome"], "safetyGates": ["no-target-write"]}
        for owner in owners
    ]
    plan = service.plan("run_defrag_retry", "defrag_retry", audit["auditRef"], entries, hashes, tests)
    assert service.plan("run_defrag_retry", "defrag_retry", audit["auditRef"], entries, hashes, tests) == plan
    skill_path = canonical / "SKILL.md"
    skill_bytes = skill_path.read_bytes()
    skill_path.write_bytes(skill_bytes + b"external drift\n")
    with pytest.raises(DefragmentationError, match="changed after audit"):
        service.validate("run_defrag_retry", "defrag_retry", plan["planRef"])
    skill_path.write_bytes(skill_bytes)
    plan_path = service.store.home / plan["planRef"]
    original = plan_path.read_bytes()
    plan_path.write_bytes(original[:-2] + b" \n")
    with pytest.raises(DefragmentationError, match="content address"):
        service.validate("run_defrag_retry", "defrag_retry", plan["planRef"])


@settings(max_examples=12, deadline=None)
@given(st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), min_size=1, max_size=80))
def test_registration_audit_is_read_only_for_generated_skill_bytes(suffix: str) -> None:
    from rsi_core.defragment import DefragmentationService, audit_registration

    with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
        tmp_path = Path(directory)
        source = tmp_path / "source"
        runtime_parent = tmp_path / "runtime"
        canonical = _skill(source / "generated")
        with (canonical / "references" / "generated.txt").open("w", encoding="utf-8") as stream:
            stream.write(suffix)
        runtime_parent.mkdir()
        runtime = runtime_parent / "generated"
        runtime.symlink_to(canonical, target_is_directory=True)
        registration = _registration(canonical, runtime, "generated")
        before = (_snapshot(source), _snapshot(runtime_parent))
        audit_registration(registration, allowed_roots=(source, runtime_parent))
        assert before == (_snapshot(source), _snapshot(runtime_parent))
        service = DefragmentationService(
            EventStore(tmp_path / "state"), (source, runtime_parent)
        )
        audited = service.audit(
            "run_defrag_property", "defrag_property", registration, _declarations()
        )
        assert before == (_snapshot(source), _snapshot(runtime_parent))
        entries = [
            {
                "sourceRuleId": item["ruleId"],
                "action": "keep",
                "owner": item["owner"],
                "newRuleIds": [],
                "duplicateEvidence": None,
                "reason": "property retain",
                "approval": "required",
                "verification": ["golden-tests", "byte-identity"],
            }
            for item in audited["inventory"]["entries"]
        ]
        owners = sorted(
            {item["owner"]["skill"] for item in audited["inventory"]["entries"]}
        )
        planned = service.plan(
            "run_defrag_property",
            "defrag_property",
            audited["auditRef"],
            entries,
            {
                owner: "sha256:" + hashlib.sha256(owner.encode()).hexdigest()
                for owner in owners
            },
            [
                {
                    "testId": "golden-" + owner,
                    "ownerSkill": owner,
                    "decisionFacts": ["same-outcome"],
                    "safetyGates": ["no-target-write"],
                }
                for owner in owners
            ],
        )
        assert before == (_snapshot(source), _snapshot(runtime_parent))
        service.validate(
            "run_defrag_property", "defrag_property", planned["planRef"]
        )
        assert before == (_snapshot(source), _snapshot(runtime_parent))


def test_module_has_no_apply_entrypoint() -> None:
    import rsi_core.defragment as module

    forbidden = {"apply", "apply_plan", "execute", "execute_plan", "delete_duplicate"}
    assert forbidden.isdisjoint(vars(module))


def test_cli_defrag_commands_leave_targets_byte_identical(tmp_path: Path) -> None:
    source, runtime, _canonical, _runtime_path, registration, _report, inventory = _audit_fixture(tmp_path)
    before = (_snapshot(source), _snapshot(runtime))
    state = tmp_path / "state"
    script = Path(__file__).parents[1] / "scripts" / "rsi.py"
    audit_input = tmp_path / "audit.json"
    audit_input.write_text(json.dumps({"registrationManifest": registration, "ruleDeclarations": _declarations()}), encoding="utf-8")

    def run(command: str, body: Path, operation: str) -> dict[str, object]:
        completed = subprocess.run(
            [
                sys.executable,
                str(script),
                command,
                "--home",
                str(state),
                "--run-id",
                "run_defrag_cli",
                "--idempotency-key",
                operation,
                "--input-file",
                str(body),
                "--target-root",
                str(source),
                "--target-root",
                str(runtime),
                "--json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads(completed.stdout)
        assert result["mutationPerformed"] is False
        assert before == (_snapshot(source), _snapshot(runtime))
        return result

    audited = run("defrag-audit", audit_input, "defrag_cli")
    entries = [
        {
            "sourceRuleId": entry.rule_id,
            "action": "keep",
            "owner": entry.owner,
            "newRuleIds": [],
            "duplicateEvidence": None,
            "reason": "retain",
            "approval": "required",
            "verification": ["golden-tests", "byte-identity"],
        }
        for entry in inventory.entries
    ]
    owners = sorted({entry.owner["skill"] for entry in inventory.entries})
    plan_input = tmp_path / "plan.json"
    plan_input.write_text(
        json.dumps(
            {
                "auditRef": audited["auditRef"],
                "ledgerEntries": entries,
                "ownerTargetHashes": {owner: "sha256:" + hashlib.sha256(owner.encode()).hexdigest() for owner in owners},
                "goldenTests": [
                    {"testId": "golden-" + owner, "ownerSkill": owner, "decisionFacts": ["same-outcome"], "safetyGates": ["no-target-write"]}
                    for owner in owners
                ],
            }
        ),
        encoding="utf-8",
    )
    planned = run("defrag-plan", plan_input, "defrag_cli")
    validate_input = tmp_path / "validate.json"
    validate_input.write_text(json.dumps({"planRef": planned["planRef"]}), encoding="utf-8")
    validated = run("defrag-validate", validate_input, "defrag_cli")
    assert validated["status"] == "validated-proposal"
    assert before == (_snapshot(source), _snapshot(runtime))
