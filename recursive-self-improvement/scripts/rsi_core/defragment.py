"""Read-only, proposal-first skill defragmentation.

This module inventories migration candidates and publishes immutable RSI-side
plans.  It intentionally exposes no filesystem-apply operation.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import unicodedata
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .events import EventEnvelope
from .hashing import (
    ManifestError,
    build_skill_manifest,
    canonical_json_digest,
    raw_sha256,
)
from .hooks import LifecycleError, append_event
from .storage import EventStore, StoreIntegrityError

MAX_DEFRAG_OBJECT_BYTES = 4 * 1024 * 1024
MAX_RULES = 4096
MAX_RULE_BYTES = 64 * 1024
_DIGEST_PREFIX = "sha256:"
_CLASSIFICATIONS = frozenset({"role", "capability", "profile", "workflow", "duplicate"})
_ACTIONS = frozenset({"keep", "move", "split", "replace-with-reference", "delete-duplicate"})


class DefragmentationError(LifecycleError):
    """A defragmentation input cannot form a closed read-only proposal."""


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise DefragmentationError("defragmentation object is not canonical JSON") from error
    if len(encoded) > MAX_DEFRAG_OBJECT_BYTES:
        raise DefragmentationError("defragmentation object exceeds its byte limit")
    return encoded


def _digest_bytes(value: bytes) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(value).hexdigest()


def _digest_mapping(value: Mapping[str, object]) -> str:
    return canonical_json_digest(value)


def _exact_mapping(value: object, keys: set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise DefragmentationError(f"{label} has invalid fields")
    return value


def _text(value: object, label: str, *, maximum: int = 4096) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise DefragmentationError(f"{label} is invalid")
    if value != unicodedata.normalize("NFC", value) or "\x00" in value:
        raise DefragmentationError(f"{label} is not canonical text")
    return value


def _digest(value: object, label: str) -> str:
    text = _text(value, label, maximum=71)
    if len(text) != 71 or not text.startswith(_DIGEST_PREFIX):
        raise DefragmentationError(f"{label} is invalid")
    if any(character not in "0123456789abcdef" for character in text[7:]):
        raise DefragmentationError(f"{label} is invalid")
    return text


def _locator(value: object, label: str) -> str:
    text = _text(value, label, maximum=8191)
    path = PurePosixPath(text)
    if path.is_absolute() or text in {".", ".."} or any(part in {"", ".", ".."} for part in path.parts):
        raise DefragmentationError(f"{label} is not a canonical relative locator")
    return text


def _safe_absolute(value: object, label: str) -> Path:
    text = _text(value, label, maximum=4096)
    path = Path(text)
    if not path.is_absolute() or Path(os.path.abspath(path)) != path:
        raise DefragmentationError(f"{label} is not a canonical absolute path")
    return path


def _inside_allowed(path: Path, roots: Sequence[Path]) -> bool:
    absolute = Path(os.path.abspath(path))
    return any(absolute == root or root in absolute.parents for root in roots)


def _assert_safe_parent_walk(path: Path, roots: Sequence[Path], label: str) -> None:
    candidates = [root for root in roots if path == root or root in path.parents]
    if len(candidates) != 1:
        raise DefragmentationError(f"{label} is not under one unique admitted root")
    root = candidates[0]
    current = root
    for component in path.relative_to(root).parts[:-1]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            raise DefragmentationError(f"{label} parent is missing") from None
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise DefragmentationError(f"{label} uses an unsafe parent topology")


@dataclass(frozen=True, slots=True)
class RegistrationAudit:
    skill_name: str
    canonical_path: str
    canonical_digest: str
    registrations: tuple[dict[str, object], ...]
    findings: tuple[str, ...]

    @property
    def drift(self) -> bool:
        return bool(self.findings)

    def to_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "kind": "registration-audit",
            "skillName": self.skill_name,
            "canonicalPath": self.canonical_path,
            "canonicalDigest": self.canonical_digest,
            "runtimeRegistrations": list(self.registrations),
            "findings": list(self.findings),
            "drift": self.drift,
            "mutationPerformed": False,
        }

    @property
    def digest(self) -> str:
        return _digest_mapping(self.to_mapping())


def audit_registration(
    registration_manifest: Mapping[str, object],
    *,
    allowed_roots: Iterable[Path | str],
) -> RegistrationAudit:
    manifest = _exact_mapping(
        registration_manifest,
        {"schemaVersion", "skillName", "canonical", "runtimeRegistrations"},
        "skill registration manifest",
    )
    if manifest["schemaVersion"] != 1:
        raise DefragmentationError("skill registration manifest version is unsupported")
    skill_name = _text(manifest["skillName"], "skill name")
    roots = tuple(Path(os.path.abspath(os.fspath(root))) for root in allowed_roots)
    if not roots:
        raise DefragmentationError("at least one allowed target root is required")
    for root in roots:
        try:
            metadata = root.lstat()
        except FileNotFoundError:
            raise DefragmentationError("allowed target root is missing") from None
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise DefragmentationError("allowed target root must be a real directory")
    for number, root in enumerate(roots):
        for other in roots[number + 1 :]:
            if root == other or root in other.parents or other in root.parents:
                raise DefragmentationError("allowed target roots must be unique and disjoint")

    canonical_map = _exact_mapping(manifest["canonical"], {"path", "digest"}, "canonical registration")
    canonical_path = _safe_absolute(canonical_map["path"], "canonical path")
    expected_digest = _digest(canonical_map["digest"], "canonical digest")
    if not _inside_allowed(canonical_path, roots):
        raise DefragmentationError("canonical path is outside admitted roots")
    try:
        canonical_metadata = canonical_path.lstat()
    except FileNotFoundError:
        raise DefragmentationError("canonical skill is missing") from None
    if not stat.S_ISDIR(canonical_metadata.st_mode) or stat.S_ISLNK(canonical_metadata.st_mode):
        raise DefragmentationError("canonical skill must be a real directory")
    try:
        actual_digest = build_skill_manifest(canonical_path).digest
    except ManifestError as error:
        raise DefragmentationError("canonical skill manifest is invalid") from error
    findings: set[str] = set()
    if actual_digest != expected_digest:
        findings.add("canonical-source-digest-drift")

    runtime_values = manifest["runtimeRegistrations"]
    if not isinstance(runtime_values, list) or len(runtime_values) > 64:
        raise DefragmentationError("runtime registrations are invalid")
    registrations: list[dict[str, object]] = []
    seen_paths: set[str] = set()
    for raw in runtime_values:
        item = _exact_mapping(
            raw,
            {"path", "type", "expectedRealpath", "expectedDigest"},
            "runtime registration",
        )
        path = _safe_absolute(item["path"], "runtime path")
        expected_type = _text(item["type"], "runtime type")
        if expected_type not in {"symlink", "directory"}:
            raise DefragmentationError("runtime type is unsupported")
        expected_realpath = _safe_absolute(item["expectedRealpath"], "runtime real path")
        runtime_digest = _digest(item["expectedDigest"], "runtime expected digest")
        if not _inside_allowed(path, roots):
            raise DefragmentationError("runtime path is outside admitted roots")
        _assert_safe_parent_walk(path, roots, "runtime path")
        if expected_realpath != canonical_path.resolve(strict=True):
            raise DefragmentationError("runtime registration does not name canonical source")
        if runtime_digest != expected_digest:
            raise DefragmentationError("runtime registration digest differs from canonical authority")
        if str(path) in seen_paths:
            raise DefragmentationError("runtime registration path is duplicated")
        seen_paths.add(str(path))
        status = "ok"
        observed_type = "missing"
        observed_digest: str | None = None
        observed_realpath: str | None = None
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            status = "missing"
            findings.add("runtime-registration-missing")
        else:
            if stat.S_ISLNK(metadata.st_mode):
                observed_type = "symlink"
                try:
                    observed_realpath = str(path.resolve(strict=True))
                except FileNotFoundError:
                    observed_realpath = None
                    status = "missing"
                    findings.add("runtime-registration-missing")
                    registrations.append(
                        {
                            "path": str(path),
                            "expectedType": expected_type,
                            "expectedRealpath": str(expected_realpath),
                            "expectedDigest": runtime_digest,
                            "observedType": observed_type,
                            "observedRealpath": observed_realpath,
                            "observedDigest": observed_digest,
                            "status": status,
                        }
                    )
                    continue
                if expected_type != "symlink":
                    status = "unexpected-type"
                    findings.add("runtime-registration-type-drift")
                elif observed_realpath != str(expected_realpath):
                    status = "divergent"
                    findings.add("runtime-registration-target-drift")
                else:
                    try:
                        observed_digest = build_skill_manifest(path.resolve(strict=True)).digest
                    except ManifestError as error:
                        raise DefragmentationError("runtime target manifest is invalid") from error
            elif stat.S_ISDIR(metadata.st_mode):
                observed_type = "directory"
                observed_realpath = str(path.resolve(strict=True))
                status = "copy"
                findings.add("runtime-registration-copy")
                try:
                    observed_digest = build_skill_manifest(path).digest
                except ManifestError as error:
                    raise DefragmentationError("runtime copy manifest is invalid") from error
            else:
                observed_type = "other"
                status = "unexpected-type"
                findings.add("runtime-registration-type-drift")
            if observed_digest is not None and observed_digest != runtime_digest:
                status = "divergent"
                findings.add("runtime-registration-digest-drift")
        registrations.append(
            {
                "path": str(path),
                "expectedType": expected_type,
                "expectedRealpath": str(expected_realpath),
                "expectedDigest": runtime_digest,
                "observedType": observed_type,
                "observedRealpath": observed_realpath,
                "observedDigest": observed_digest,
                "status": status,
            }
        )
    return RegistrationAudit(
        skill_name,
        str(canonical_path),
        actual_digest,
        tuple(sorted(registrations, key=lambda entry: str(entry["path"]).encode("utf-8"))),
        tuple(sorted(findings)),
    )


def _owner(value: object) -> dict[str, object]:
    item = _exact_mapping(value, {"skill", "scope", "capability"}, "rule owner")
    skill = _text(item["skill"], "owner skill")
    scope = _text(item["scope"], "owner scope")
    capability = item["capability"]
    if capability is not None:
        capability = _text(capability, "owner capability")
    return {"skill": skill, "scope": scope, "capability": capability}


@dataclass(frozen=True, slots=True)
class RuleInventoryEntry:
    rule_id: str
    artifact: str
    source_hash: str
    semantic_digest: str
    classification: str
    owner: dict[str, object]
    duplicate_of: str | None

    def to_mapping(self) -> dict[str, object]:
        return {
            "ruleId": self.rule_id,
            "artifact": self.artifact,
            "sourceHash": self.source_hash,
            "semanticDigest": self.semantic_digest,
            "classification": self.classification,
            "owner": dict(self.owner),
            "duplicateOf": self.duplicate_of,
        }


def _validate_inventory_ownership(entries: Sequence[RuleInventoryEntry]) -> None:
    owners_by_scope: dict[str, tuple[object, object]] = {}
    by_id = {entry.rule_id: entry for entry in entries}
    for entry in entries:
        capability = entry.owner["capability"]
        if entry.classification == "capability" and capability is None:
            raise DefragmentationError("capability rule requires a capability owner")
        if entry.classification in {"role", "profile", "workflow"} and capability is not None:
            raise DefragmentationError("non-capability rule cannot claim a capability owner")
        scope = str(entry.owner["scope"])
        identity = (entry.owner["skill"], capability)
        prior = owners_by_scope.setdefault(scope, identity)
        if prior != identity:
            raise DefragmentationError("one scope cannot have multiple future owners")
        if entry.classification == "duplicate":
            survivor = by_id.get(entry.duplicate_of or "")
            if (
                survivor is None
                or survivor.rule_id == entry.rule_id
                or survivor.classification == "duplicate"
                or survivor.semantic_digest != entry.semantic_digest
                or survivor.owner != entry.owner
            ):
                raise DefragmentationError(
                    "duplicate classification requires an equivalent surviving rule"
                )
        elif entry.duplicate_of is not None:
            raise DefragmentationError(
                "only duplicate classification may name a surviving rule"
            )


@dataclass(frozen=True, slots=True)
class RuleInventory:
    skill_name: str
    canonical_root_digest: str
    registration_digest: str
    entries: tuple[RuleInventoryEntry, ...]

    @classmethod
    def build(
        cls,
        skill_name: str,
        canonical_root: Path | str,
        registration_digest: str,
        declarations: Iterable[Mapping[str, object]],
    ) -> RuleInventory:
        skill = _text(skill_name, "inventory skill")
        registration = _digest(registration_digest, "registration digest")
        root = Path(canonical_root)
        try:
            root_digest = build_skill_manifest(root).digest
        except ManifestError as error:
            raise DefragmentationError("inventory skill manifest is invalid") from error
        values = list(declarations)
        if not values or len(values) > MAX_RULES:
            raise DefragmentationError("rule declarations are empty or exceed their bound")
        entries: list[RuleInventoryEntry] = []
        seen_semantic_locator: set[tuple[str, str]] = set()
        for raw in values:
            item = _exact_mapping(
                raw,
                {"artifact", "rule", "classification", "owner", "duplicateOf"},
                "rule declaration",
            )
            artifact = _locator(item["artifact"], "rule artifact")
            rule = _text(item["rule"], "rule text", maximum=MAX_RULE_BYTES)
            classification = _text(item["classification"], "rule classification")
            if classification not in _CLASSIFICATIONS:
                raise DefragmentationError("rule classification is unsupported")
            if artifact.startswith("profiles/") and classification != "profile":
                raise DefragmentationError("profile artifacts require profile classification")
            if classification == "profile" and not artifact.startswith("profiles/"):
                raise DefragmentationError("profile classification requires a profile artifact")
            path = root / artifact
            try:
                metadata = path.lstat()
                data = path.read_bytes()
            except (FileNotFoundError, OSError) as error:
                raise DefragmentationError("rule artifact is missing or unreadable") from error
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise DefragmentationError("rule artifact must be a regular file")
            try:
                decoded = data.decode("utf-8", "strict")
            except UnicodeDecodeError as error:
                raise DefragmentationError("rule artifact is not UTF-8") from error
            if decoded.count(rule) != 1:
                raise DefragmentationError("declared rule must occur exactly once in its artifact")
            semantic = _digest_mapping(
                {
                    "schemaVersion": 1,
                    "domain": "rsi-rule-semantics-v1",
                    "text": " ".join(rule.split()),
                }
            )
            key = (artifact, semantic)
            if key in seen_semantic_locator:
                raise DefragmentationError("duplicate rule declaration")
            seen_semantic_locator.add(key)
            rule_id = "rule_" + _digest_mapping(
                {
                    "schemaVersion": 1,
                    "domain": "rsi-rule-id-v1",
                    "skill": skill,
                    "artifact": artifact,
                    "semanticDigest": semantic,
                }
            )[7:39]
            duplicate_of = item["duplicateOf"]
            if duplicate_of is not None:
                duplicate_of = _text(duplicate_of, "duplicate rule id")
            entries.append(
                RuleInventoryEntry(
                    rule_id,
                    artifact,
                    raw_sha256(data),
                    semantic,
                    classification,
                    _owner(item["owner"]),
                    duplicate_of,
                )
            )
        entries.sort(key=lambda entry: entry.rule_id.encode("utf-8"))
        _validate_inventory_ownership(entries)
        return cls(skill, root_digest, registration, tuple(entries))

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> RuleInventory:
        item = _exact_mapping(
            value,
            {"schemaVersion", "kind", "skillName", "canonicalRootDigest", "registrationDigest", "entries"},
            "rule inventory",
        )
        if item["schemaVersion"] != 1 or item["kind"] != "rule-inventory":
            raise DefragmentationError("rule inventory discriminator is invalid")
        raw_entries = item["entries"]
        if not isinstance(raw_entries, list) or not raw_entries:
            raise DefragmentationError("rule inventory entries are invalid")
        entries: list[RuleInventoryEntry] = []
        for raw in raw_entries:
            entry = _exact_mapping(
                raw,
                {"ruleId", "artifact", "sourceHash", "semanticDigest", "classification", "owner", "duplicateOf"},
                "rule inventory entry",
            )
            duplicate = entry["duplicateOf"]
            if duplicate is not None:
                duplicate = _text(duplicate, "duplicate rule id")
            classification = _text(entry["classification"], "rule classification")
            if classification not in _CLASSIFICATIONS:
                raise DefragmentationError("rule classification is unsupported")
            entries.append(
                RuleInventoryEntry(
                    _text(entry["ruleId"], "rule id"),
                    _locator(entry["artifact"], "rule artifact"),
                    _digest(entry["sourceHash"], "source hash"),
                    _digest(entry["semanticDigest"], "semantic digest"),
                    classification,
                    _owner(entry["owner"]),
                    duplicate,
                )
            )
        ordered = tuple(sorted(entries, key=lambda entry: entry.rule_id.encode("utf-8")))
        if list(entries) != list(ordered) or len({entry.rule_id for entry in entries}) != len(entries):
            raise DefragmentationError("rule inventory ordering or uniqueness is invalid")
        _validate_inventory_ownership(entries)
        return cls(
            _text(item["skillName"], "inventory skill"),
            _digest(item["canonicalRootDigest"], "canonical root digest"),
            _digest(item["registrationDigest"], "registration digest"),
            ordered,
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "kind": "rule-inventory",
            "skillName": self.skill_name,
            "canonicalRootDigest": self.canonical_root_digest,
            "registrationDigest": self.registration_digest,
            "entries": [entry.to_mapping() for entry in self.entries],
        }

    @property
    def digest(self) -> str:
        return _digest_mapping(self.to_mapping())


@dataclass(frozen=True, slots=True)
class MigrationLedgerEntry:
    migration_id: str
    source_rule_id: str
    source_skill: str
    source_artifact: str
    source_hash: str
    classification: str
    action: str
    owner: dict[str, object]
    new_rule_ids: tuple[str, ...]
    duplicate_evidence: dict[str, str] | None
    reason: str
    verification: tuple[str, ...]

    @property
    def entry_id(self) -> str:
        return "migration_" + _digest_mapping(self.to_mapping())[7:39]

    def to_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "migrationId": self.migration_id,
            "source": {
                "skill": self.source_skill,
                "artifact": self.source_artifact,
                "sourceHash": self.source_hash,
                "ruleId": self.source_rule_id,
            },
            "classification": self.classification,
            "action": self.action,
            "owner": dict(self.owner),
            "newRuleIds": list(self.new_rule_ids),
            "duplicateEvidence": None if self.duplicate_evidence is None else dict(self.duplicate_evidence),
            "reason": self.reason,
            "approval": "required",
            "verification": list(self.verification),
        }


@dataclass(frozen=True, slots=True)
class MigrationLedger:
    migration_id: str
    inventory_digest: str
    entries: tuple[MigrationLedgerEntry, ...]

    @classmethod
    def build(cls, inventory: RuleInventory, entries: Iterable[Mapping[str, object]]) -> MigrationLedger:
        if not isinstance(inventory, RuleInventory):
            raise DefragmentationError("migration ledger inventory is invalid")
        raw_entries = list(entries)
        if len(raw_entries) != len(inventory.entries):
            raise DefragmentationError("migration ledger must cover every rule exactly once")
        by_rule = {entry.rule_id: entry for entry in inventory.entries}
        migration_id = (
            "defrag:" + inventory.skill_name + ":" + inventory.digest[7:19]
        )
        parsed: list[MigrationLedgerEntry] = []
        for raw in raw_entries:
            item = _exact_mapping(
                raw,
                {"sourceRuleId", "action", "owner", "newRuleIds", "duplicateEvidence", "reason", "approval", "verification"},
                "migration ledger entry",
            )
            source = _text(item["sourceRuleId"], "source rule id")
            action = _text(item["action"], "migration action")
            if source not in by_rule or action not in _ACTIONS or item["approval"] != "required":
                raise DefragmentationError("migration disposition is invalid")
            owner = _owner(item["owner"])
            new_values = item["newRuleIds"]
            if not isinstance(new_values, list) or any(type(value) is not str or not value for value in new_values):
                raise DefragmentationError("new rule ids are invalid")
            new_ids = tuple(new_values)
            if len(set(new_ids)) != len(new_ids) or any(value in by_rule for value in new_ids):
                raise DefragmentationError("split descendants are not new and unique")
            if any(not value.startswith("rule_") for value in new_ids):
                raise DefragmentationError("split descendant rule id is invalid")
            evidence_value = item["duplicateEvidence"]
            evidence: dict[str, str] | None = None
            if evidence_value is not None:
                evidence_map = _exact_mapping(
                    evidence_value,
                    {"survivingRuleId", "semanticDigest"},
                    "duplicate evidence",
                )
                evidence = {
                    "survivingRuleId": _text(evidence_map["survivingRuleId"], "surviving rule id"),
                    "semanticDigest": _digest(evidence_map["semanticDigest"], "duplicate semantic digest"),
                }
            verification = item["verification"]
            if not isinstance(verification, list) or not verification or any(type(value) is not str or not value for value in verification):
                raise DefragmentationError("migration verification is invalid")
            if action == "split":
                if not new_ids or evidence is not None:
                    raise DefragmentationError("split requires new descendants only")
            elif new_ids:
                raise DefragmentationError("only split may declare new rule ids")
            if action == "delete-duplicate":
                if evidence is None:
                    raise DefragmentationError("duplicate deletion requires surviving evidence")
                survivor = by_rule.get(evidence["survivingRuleId"])
                if (
                    by_rule[source].classification != "duplicate"
                    or by_rule[source].duplicate_of != evidence["survivingRuleId"]
                    or survivor is None
                    or survivor.rule_id == source
                ):
                    raise DefragmentationError("duplicate survivor is invalid")
                if survivor.semantic_digest != by_rule[source].semantic_digest or evidence["semanticDigest"] != survivor.semantic_digest:
                    raise DefragmentationError("duplicate rules are not semantically equivalent")
            elif evidence is not None:
                raise DefragmentationError("duplicate evidence is only valid for duplicate deletion")
            parsed.append(
                MigrationLedgerEntry(
                    migration_id,
                    source,
                    inventory.skill_name,
                    by_rule[source].artifact,
                    by_rule[source].source_hash,
                    by_rule[source].classification,
                    action,
                    owner,
                    new_ids,
                    evidence,
                    _text(item["reason"], "migration reason"),
                    tuple(verification),
                )
            )
        sources = [entry.source_rule_id for entry in parsed]
        if Counter(sources) != Counter(by_rule.keys()):
            raise DefragmentationError("migration ledger must cover every rule exactly once")
        all_new_ids = [rule_id for entry in parsed for rule_id in entry.new_rule_ids]
        if len(all_new_ids) != len(set(all_new_ids)):
            raise DefragmentationError("split descendant ids conflict across ledger entries")
        actions = {entry.source_rule_id: entry.action for entry in parsed}
        for entry in parsed:
            if entry.duplicate_evidence is not None and actions[entry.duplicate_evidence["survivingRuleId"]] == "delete-duplicate":
                raise DefragmentationError("duplicate survivor cannot also be deleted")
        parsed.sort(key=lambda entry: entry.source_rule_id.encode("utf-8"))
        return cls(migration_id, inventory.digest, tuple(parsed))

    @classmethod
    def from_mapping(cls, inventory: RuleInventory, value: Mapping[str, object]) -> MigrationLedger:
        item = _exact_mapping(value, {"schemaVersion", "kind", "migrationId", "inventoryDigest", "entries"}, "migration ledger")
        if item["schemaVersion"] != 1 or item["kind"] != "migration-ledger" or item["inventoryDigest"] != inventory.digest:
            raise DefragmentationError("migration ledger binding is invalid")
        entries = item["entries"]
        if not isinstance(entries, list):
            raise DefragmentationError("migration ledger entries are invalid")
        inputs: list[dict[str, object]] = []
        inventory_by_id = {entry.rule_id: entry for entry in inventory.entries}
        for raw in entries:
            entry = _exact_mapping(
                raw,
                {
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
                },
                "persisted migration ledger entry",
            )
            source = _exact_mapping(
                entry["source"],
                {"skill", "artifact", "sourceHash", "ruleId"},
                "migration source",
            )
            rule_id = _text(source["ruleId"], "source rule id")
            rule = inventory_by_id.get(rule_id)
            if (
                entry["schemaVersion"] != 1
                or entry["migrationId"] != item["migrationId"]
                or rule is None
                or source["skill"] != inventory.skill_name
                or source["artifact"] != rule.artifact
                or source["sourceHash"] != rule.source_hash
                or entry["classification"] != rule.classification
            ):
                raise DefragmentationError("persisted migration source is invalid")
            inputs.append(
                {
                    "sourceRuleId": rule_id,
                    "action": entry["action"],
                    "owner": entry["owner"],
                    "newRuleIds": entry["newRuleIds"],
                    "duplicateEvidence": entry["duplicateEvidence"],
                    "reason": entry["reason"],
                    "approval": entry["approval"],
                    "verification": entry["verification"],
                }
            )
        rebuilt = cls.build(inventory, inputs)
        if rebuilt.migration_id != item["migrationId"]:
            raise DefragmentationError("migration ledger id is invalid")
        return rebuilt

    def to_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "kind": "migration-ledger",
            "migrationId": self.migration_id,
            "inventoryDigest": self.inventory_digest,
            "entries": [entry.to_mapping() for entry in self.entries],
        }

    @property
    def digest(self) -> str:
        return _digest_mapping(self.to_mapping())


@dataclass(frozen=True, slots=True)
class MigrationPlan:
    migration_id: str
    rule_inventory_digest: str
    ledger_digest: str
    change_sets: tuple[dict[str, object], ...]
    golden_test_plan: dict[str, object]
    golden_test_manifest_digest: str
    rollback_plan: dict[str, object]
    rollback_plan_digest: str
    status: str = "validated-proposal"
    mutation_performed: bool = False

    @classmethod
    def build(
        cls,
        inventory: RuleInventory,
        ledger: MigrationLedger,
        owner_target_hashes: Mapping[str, object],
        golden_tests: Iterable[Mapping[str, object]],
    ) -> MigrationPlan:
        if ledger.inventory_digest != inventory.digest:
            raise DefragmentationError("migration plan inventory binding is invalid")
        owners = sorted({str(entry.owner["skill"]) for entry in ledger.entries}, key=lambda value: value.encode("utf-8"))
        if set(owner_target_hashes) != set(owners):
            raise DefragmentationError("owner target hashes do not cover exact migration owners")
        change_sets: list[dict[str, object]] = []
        for owner in owners:
            change_sets.append(
                {
                    "ownerSkill": owner,
                    "targetPreHash": _digest(owner_target_hashes[owner], "owner target hash"),
                    "entryIds": sorted(
                        (entry.entry_id for entry in ledger.entries if entry.owner["skill"] == owner),
                        key=lambda value: value.encode("utf-8"),
                    ),
                }
            )
        tests: list[dict[str, object]] = []
        for raw in golden_tests:
            item = _exact_mapping(raw, {"testId", "ownerSkill", "decisionFacts", "safetyGates"}, "golden test")
            owner = _text(item["ownerSkill"], "golden test owner")
            if owner not in owners:
                raise DefragmentationError("golden test owner is not a migration owner")
            facts = item["decisionFacts"]
            gates = item["safetyGates"]
            if not isinstance(facts, list) or not facts or any(type(value) is not str or not value for value in facts):
                raise DefragmentationError("golden decision facts are invalid")
            if not isinstance(gates, list) or not gates or any(type(value) is not str or not value for value in gates):
                raise DefragmentationError("golden safety gates are invalid")
            tests.append(
                {
                    "testId": _text(item["testId"], "golden test id"),
                    "ownerSkill": owner,
                    "decisionFacts": list(facts),
                    "safetyGates": list(gates),
                }
            )
        tests.sort(key=lambda item: str(item["testId"]).encode("utf-8"))
        if len({item["testId"] for item in tests}) != len(tests) or {item["ownerSkill"] for item in tests} != set(owners):
            raise DefragmentationError("golden tests must uniquely cover every owner")
        golden = {"schemaVersion": 1, "kind": "golden-test-plan", "tests": tests}
        rollback = {
            "schemaVersion": 1,
            "kind": "coordinated-rollback-plan",
            "changeSetOrder": owners,
            "restoreOrder": list(reversed(owners)),
            "verification": ["restore-owner-pre-hashes", "rerun-golden-tests", "confirm-byte-identity"],
            "mutationPerformed": False,
        }
        return cls(
            ledger.migration_id,
            inventory.digest,
            ledger.digest,
            tuple(change_sets),
            golden,
            _digest_mapping(golden),
            rollback,
            _digest_mapping(rollback),
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "migrationId": self.migration_id,
            "ruleInventoryDigest": self.rule_inventory_digest,
            "ledgerDigest": self.ledger_digest,
            "changeSets": list(self.change_sets),
            "goldenTestManifestDigest": self.golden_test_manifest_digest,
            "rollbackPlanDigest": self.rollback_plan_digest,
            "status": self.status,
        }

    @property
    def digest(self) -> str:
        return _digest_mapping(self.to_mapping())


def _strict_json(raw: bytes, label: str) -> dict[str, object]:
    if not raw or len(raw) > MAX_DEFRAG_OBJECT_BYTES or not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise DefragmentationError(f"{label} framing is invalid")
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result
    try:
        value = json.loads(raw[:-1].decode("utf-8", "strict"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise DefragmentationError(f"{label} JSON is invalid") from error
    if not isinstance(value, dict) or _canonical_bytes(value) != raw:
        raise DefragmentationError(f"{label} is not canonical")
    return value


def _content_ref(prefix: str, body: Mapping[str, object]) -> tuple[str, bytes, str]:
    encoded = _canonical_bytes(body)
    digest = _digest_bytes(encoded)
    return f"defragmentation/{prefix}-{digest[7:]}.json", encoded, digest


class DefragmentationService:
    """Publish a three-step read-only defragmentation proposal lifecycle."""

    def __init__(self, store: EventStore, allowed_roots: Iterable[Path | str]) -> None:
        self.store = store
        self.allowed_roots = tuple(Path(os.path.abspath(os.fspath(root))) for root in allowed_roots)
        if not self.allowed_roots:
            raise DefragmentationError("defragmentation target roots are required")

    def _events(self, run_id: str) -> list[EventEnvelope]:
        return [event for event in self.store.read_events() if event.run_id == run_id]

    def _read_ref(self, reference: object, label: str) -> dict[str, object]:
        ref = _text(reference, label)
        if not ref.startswith("defragmentation/") or PurePosixPath(ref).name != Path(ref).name:
            raise DefragmentationError(f"{label} is outside defragmentation storage")
        try:
            raw = self.store.read_sidecar(self.store.home / ref)
        except (StoreIntegrityError, FileNotFoundError) as error:
            raise DefragmentationError(f"{label} is unavailable") from error
        name = PurePosixPath(ref).name
        if not name.endswith(".json") or "-" not in name:
            raise DefragmentationError(f"{label} is not content addressed")
        expected_hex = name[:-5].rsplit("-", 1)[-1]
        if len(expected_hex) != 64 or _digest_bytes(raw)[7:] != expected_hex:
            raise DefragmentationError(f"{label} content address is invalid")
        return _strict_json(raw, label)

    def _admit_audit(self, value: Mapping[str, object]) -> RuleInventory:
        audit = _exact_mapping(
            value,
            {
                "schemaVersion",
                "kind",
                "registrationManifest",
                "registration",
                "registrationDigest",
                "inventory",
                "inventoryDigest",
                "findings",
                "mutationPerformed",
            },
            "defragmentation audit",
        )
        if (
            audit["schemaVersion"] != 1
            or audit["kind"] != "defragmentation-audit"
            or audit["mutationPerformed"] is not False
            or not isinstance(audit["registrationManifest"], Mapping)
            or not isinstance(audit["registration"], Mapping)
            or not isinstance(audit["inventory"], Mapping)
        ):
            raise DefragmentationError("defragmentation audit discriminator is invalid")
        current = audit_registration(
            audit["registrationManifest"], allowed_roots=self.allowed_roots
        )
        if (
            current.to_mapping() != dict(audit["registration"])
            or current.digest != audit["registrationDigest"]
        ):
            raise DefragmentationError(
                "canonical or runtime registration changed after audit"
            )
        inventory = RuleInventory.from_mapping(audit["inventory"])
        if (
            inventory.digest != audit["inventoryDigest"]
            or inventory.registration_digest != current.digest
            or inventory.canonical_root_digest
            != build_skill_manifest(current.canonical_path).digest
        ):
            raise DefragmentationError("audit inventory binding is invalid")
        return inventory

    def audit(
        self,
        run_id: str,
        logical_operation_id: str,
        registration_manifest: Mapping[str, object],
        rule_declarations: Iterable[Mapping[str, object]],
    ) -> dict[str, object]:
        report = audit_registration(registration_manifest, allowed_roots=self.allowed_roots)
        inventory = RuleInventory.build(
            report.skill_name,
            report.canonical_path,
            report.digest,
            rule_declarations,
        )
        body = {
            "schemaVersion": 1,
            "kind": "defragmentation-audit",
            "registrationManifest": dict(registration_manifest),
            "registration": report.to_mapping(),
            "registrationDigest": report.digest,
            "inventory": inventory.to_mapping(),
            "inventoryDigest": inventory.digest,
            "findings": list(report.findings),
            "mutationPerformed": False,
        }
        audit_ref, encoded, audit_digest = _content_ref("audit", body)
        events = self._events(run_id)
        if not events:
            started = append_event(
                self.store,
                event_type="run.started",
                run_id=run_id,
                logical_operation_id=logical_operation_id + ":start",
                target_skill="rsi",
                causation_id=None,
                payload={
                    "mode": "observe",
                    "hookMode": "late-review",
                    "activeSkills": [f"{report.skill_name}@{report.canonical_digest}"],
                    "policyVersion": "1",
                    "controlPlaneVersion": "defragmentation-v1",
                    "runKind": "defrag",
                },
                correlation_id=audit_digest,
            )
        else:
            started = events[0]
            if started.event_type != "run.started" or started.payload.get("runKind") != "defrag":
                raise DefragmentationError("run id belongs to a different lifecycle")
        audited = append_event(
            self.store,
            event_type="defrag.audit.completed",
            run_id=run_id,
            logical_operation_id=logical_operation_id + ":audit",
            target_skill="rsi",
            causation_id=started.event_id,
            payload={
                "registrationDigest": report.digest,
                "inventoryDigest": inventory.digest,
                "findings": list(report.findings),
                "mutationPerformed": False,
            },
            correlation_id=audit_digest,
            payload_ref=audit_ref,
            sidecar_path=self.store.home / audit_ref,
            sidecar_bytes=encoded,
        )
        return {
            "schemaVersion": 1,
            "runId": run_id,
            "auditRef": audit_ref,
            "auditDigest": audit_digest,
            "registrationDigest": report.digest,
            "inventoryDigest": inventory.digest,
            "inventory": inventory.to_mapping(),
            "findings": list(report.findings),
            "eventIds": [started.event_id, audited.event_id],
            "mutationPerformed": False,
        }

    def plan(
        self,
        run_id: str,
        logical_operation_id: str,
        audit_ref: str,
        ledger_entries: Iterable[Mapping[str, object]],
        owner_target_hashes: Mapping[str, object],
        golden_tests: Iterable[Mapping[str, object]],
    ) -> dict[str, object]:
        audit = self._read_ref(audit_ref, "auditRef")
        inventory = self._admit_audit(audit)
        ledger = MigrationLedger.build(inventory, ledger_entries)
        plan = MigrationPlan.build(inventory, ledger, owner_target_hashes, golden_tests)
        body = {
            "schemaVersion": 1,
            "kind": "defragmentation-plan",
            "auditRef": audit_ref,
            "auditDigest": _digest_bytes(_canonical_bytes(audit)),
            "inventory": inventory.to_mapping(),
            "inventoryDigest": inventory.digest,
            "ledger": ledger.to_mapping(),
            "ledgerDigest": ledger.digest,
            "plan": plan.to_mapping(),
            "planDigest": plan.digest,
            "goldenTestPlan": plan.golden_test_plan,
            "rollbackPlan": plan.rollback_plan,
            "mutationPerformed": False,
        }
        plan_ref, encoded, raw_digest = _content_ref("plan", body)
        events = self._events(run_id)
        audited = next((event for event in events if event.event_type == "defrag.audit.completed" and event.payload_ref == audit_ref), None)
        if audited is None:
            raise DefragmentationError("auditRef is not bound to this run")
        if (
            audited.payload["registrationDigest"] != inventory.registration_digest
            or audited.payload["inventoryDigest"] != inventory.digest
            or audited.correlation_id != body["auditDigest"]
        ):
            raise DefragmentationError("audit event conflicts with its durable object")
        planned = append_event(
            self.store,
            event_type="defrag.plan.built",
            run_id=run_id,
            logical_operation_id=logical_operation_id + ":plan",
            target_skill="rsi",
            causation_id=audited.event_id,
            payload={
                "ruleInventoryDigest": inventory.digest,
                "ledgerDigest": ledger.digest,
                "umbrellaPlanDigest": plan.digest,
            },
            correlation_id=raw_digest,
            payload_ref=plan_ref,
            sidecar_path=self.store.home / plan_ref,
            sidecar_bytes=encoded,
        )
        return {
            "schemaVersion": 1,
            "runId": run_id,
            "planRef": plan_ref,
            "planDigest": plan.digest,
            "ledgerDigest": ledger.digest,
            "eventIds": [planned.event_id],
            "mutationPerformed": False,
        }

    def validate(self, run_id: str, logical_operation_id: str, plan_ref: str) -> dict[str, object]:
        body = self._read_ref(plan_ref, "planRef")
        plan_map = _exact_mapping(
            body,
            {"schemaVersion", "kind", "auditRef", "auditDigest", "inventory", "inventoryDigest", "ledger", "ledgerDigest", "plan", "planDigest", "goldenTestPlan", "rollbackPlan", "mutationPerformed"},
            "defragmentation plan object",
        )
        if plan_map["schemaVersion"] != 1 or plan_map["kind"] != "defragmentation-plan" or plan_map["mutationPerformed"] is not False:
            raise DefragmentationError("defragmentation plan discriminator is invalid")
        inventory_value = plan_map["inventory"]
        ledger_value = plan_map["ledger"]
        migration_value = plan_map["plan"]
        if not isinstance(inventory_value, Mapping) or not isinstance(ledger_value, Mapping) or not isinstance(migration_value, Mapping):
            raise DefragmentationError("defragmentation plan graph is invalid")
        inventory = RuleInventory.from_mapping(inventory_value)
        ledger = MigrationLedger.from_mapping(inventory, ledger_value)
        if inventory.digest != plan_map["inventoryDigest"] or ledger.digest != plan_map["ledgerDigest"]:
            raise DefragmentationError("defragmentation plan graph digest is invalid")
        audit_value = self._read_ref(plan_map["auditRef"], "auditRef")
        if _digest_bytes(_canonical_bytes(audit_value)) != plan_map["auditDigest"]:
            raise DefragmentationError("plan audit digest is invalid")
        admitted_inventory = self._admit_audit(audit_value)
        if admitted_inventory.to_mapping() != inventory.to_mapping():
            raise DefragmentationError("plan inventory differs from its fresh audit")
        if _digest_mapping(migration_value) != plan_map["planDigest"]:
            raise DefragmentationError("umbrella migration plan digest is invalid")
        required = {
            "schemaVersion", "migrationId", "ruleInventoryDigest", "ledgerDigest", "changeSets",
            "goldenTestManifestDigest", "rollbackPlanDigest", "status",
        }
        _exact_mapping(migration_value, required, "umbrella migration plan")
        if (
            migration_value["status"] != "validated-proposal"
            or migration_value["ruleInventoryDigest"] != inventory.digest
            or migration_value["ledgerDigest"] != ledger.digest
        ):
            raise DefragmentationError("umbrella migration plan authority is invalid")
        golden = plan_map["goldenTestPlan"]
        rollback = plan_map["rollbackPlan"]
        if not isinstance(golden, Mapping) or not isinstance(rollback, Mapping):
            raise DefragmentationError("validation plans are invalid")
        if _digest_mapping(golden) != migration_value["goldenTestManifestDigest"] or _digest_mapping(rollback) != migration_value["rollbackPlanDigest"]:
            raise DefragmentationError("validation plan digest is invalid")
        change_sets = migration_value["changeSets"]
        tests = golden.get("tests")
        if not isinstance(change_sets, list) or not isinstance(tests, list):
            raise DefragmentationError("migration change sets or golden tests are invalid")
        owner_hashes: dict[str, object] = {}
        for raw in change_sets:
            item = _exact_mapping(
                raw,
                {"ownerSkill", "targetPreHash", "entryIds"},
                "owner change set",
            )
            owner = _text(item["ownerSkill"], "change-set owner")
            if owner in owner_hashes:
                raise DefragmentationError("owner change set is duplicated")
            owner_hashes[owner] = item["targetPreHash"]
        rebuilt_plan = MigrationPlan.build(inventory, ledger, owner_hashes, tests)
        if (
            rebuilt_plan.to_mapping() != dict(migration_value)
            or rebuilt_plan.golden_test_plan != dict(golden)
            or rebuilt_plan.rollback_plan != dict(rollback)
        ):
            raise DefragmentationError("umbrella migration plan does not replay exactly")
        validation = {
            "schemaVersion": 1,
            "kind": "defragmentation-validation",
            "planRef": plan_ref,
            "planDigest": plan_map["planDigest"],
            "coverage": "passed",
            "goldenValidation": "passed",
            "rollbackValidation": "passed",
            "status": "validated-proposal",
            "mutationPerformed": False,
        }
        validation_ref, encoded, validation_digest = _content_ref("validation", validation)
        events = self._events(run_id)
        planned = next((event for event in events if event.event_type == "defrag.plan.built" and event.payload_ref == plan_ref), None)
        if planned is None:
            raise DefragmentationError("planRef is not bound to this run")
        if (
            planned.payload["ruleInventoryDigest"] != inventory.digest
            or planned.payload["ledgerDigest"] != ledger.digest
            or planned.payload["umbrellaPlanDigest"] != plan_map["planDigest"]
            or planned.correlation_id != _digest_bytes(_canonical_bytes(body))
        ):
            raise DefragmentationError("plan event conflicts with its durable object")
        validated = append_event(
            self.store,
            event_type="defrag.plan.validated",
            run_id=run_id,
            logical_operation_id=logical_operation_id + ":validate",
            target_skill="rsi",
            causation_id=planned.event_id,
            payload={
                "coverage": "passed",
                "goldenValidation": "passed",
                "rollbackValidation": "passed",
                "mutationPerformed": False,
            },
            correlation_id=validation_digest,
            payload_ref=validation_ref,
            sidecar_path=self.store.home / validation_ref,
            sidecar_bytes=encoded,
        )
        closed = append_event(
            self.store,
            event_type="run.closed",
            run_id=run_id,
            logical_operation_id=logical_operation_id + ":close",
            target_skill="rsi",
            causation_id=validated.event_id,
            payload={"status": "completed", "linkedIds": [validated.event_id]},
            correlation_id=validation_digest,
        )
        return {
            **validation,
            "runId": run_id,
            "validationRef": validation_ref,
            "validationDigest": validation_digest,
            "eventIds": [validated.event_id, closed.event_id],
        }
