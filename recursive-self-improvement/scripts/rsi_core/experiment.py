"""Pure isolated candidate validation and immutable Task 7 promotion plans.

This module intentionally has no lifecycle journal or provider mutation seam.
Task 8 owns the cross-run FSM and the only production-mutating transaction.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import argparse
import base64
import binascii
from dataclasses import dataclass, field, replace as dataclass_replace
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import hashlib
from itertools import islice
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unicodedata
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import unquote

from .attestations import (
    AllowlistEntry,
    AttestationChainLink,
    AttestationError,
    DeploymentAttestation,
    DeploymentExpectation,
    OrchestrationHookScope,
    OrchestrationHookSubject,
    RolloutStageScope,
    RolloutStageSubject,
    TrustedAttestationChain,
    TrustedReplayBinding,
    TrustedSignatureVerifier,
    ValidationControlPlane,
    ValidationAttestation,
    ValidationExpectation,
    VerifiedDeploymentPair,
    VerifiedValidationAttestation,
    allowlist_entry_digest,
    attestation_body_digest,
    canonical_root_identity_digest,
    parse_timestamp,
    parse_deployment_attestation,
    parse_validation_attestation,
    registration_manifest_digest,
    registration_manifest_digest_bytes,
    verify_deployment_attestation,
    verify_deployment_pair,
    verify_validation_attestation,
)
from .hashing import (
    ArtifactReplacement,
    ManifestEntry,
    ManifestError,
    SkillManifest,
    build_skill_manifest,
    canonical_json_bytes,
    canonical_json_digest,
    manifest_with_replacement,
    post_image_ref,
    raw_sha256,
    verify_post_image,
)
from .sanitize import sanitize_evidence


class ExperimentError(RuntimeError):
    """Validation cannot produce a trusted immutable artifact."""


class ExperimentConflict(ExperimentError):
    """An operation, target, or immutable artifact was rebound."""


class ExperimentStoreError(ExperimentError):
    """The isolated artifact store is unsafe or incomplete."""


class SandboxExecutionError(ExperimentError):
    """A trusted sandbox executor failed without a valid bounded result."""


class SandboxUnavailable(SandboxExecutionError):
    """The requested containment boundary could not be proven."""


class SandboxTimeout(SandboxExecutionError):
    pass


class SandboxOutputLimit(SandboxExecutionError):
    pass


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REF_RE = re.compile(r"object:sha256:[0-9a-f]{64}\Z")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CASE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CREDENTIAL_KEY_PATTERN = (
    r"(?:api[_ -]+token|access[_ -]+token|auth[_ -]+token|"
    r"client[_ -]+secret|secret[_ -]+key)"
)
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:(?P<credential_quote>[\"'])"
    + _CREDENTIAL_KEY_PATTERN
    + r"(?P=credential_quote)\]?|"
    + _CREDENTIAL_KEY_PATTERN
    + r")"
    r"\s*(?::|(?<![=])=(?!=))\s*"
    r'(?:"[^"\r\n]+"|\'[^\'\r\n]+\'|[^\s"\'#;,\]\}:=]+)',
    re.IGNORECASE,
)
_BASE64_ARTIFACT_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])"
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_MAX_POST_IMAGE_BYTES = 4 * 1024 * 1024
_MAX_REQUEST_BYTES = 512 * 1024
_MAX_BUNDLE_BYTES = 1024 * 1024
_STORE_MARKER = ".rsi-experiment-store-v1"
_STORE_MARKER_BYTES = b'{"domain":"rsi-experiment-store-v1","schemaVersion":1}'
_STORE_MARKER_TEMP_RE = re.compile(r"\.tmp-[0-9a-f]{32}\Z")
_STORE_INITIALIZER_ATTEMPTS = 100
_STORE_INITIALIZER_RETRY_SECONDS = 0.005
_STORE_REQUIRED_DIRECTORIES = (
    "locks",
    "locks/experiments",
    "locks/objects",
    "objects",
    "objects/post-images",
    "experiments",
)


def _require_digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ExperimentError(f"{label} must be a sha256 digest")
    return value


def _require_id(value: object, label: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise ExperimentError(f"{label} is invalid")
    return value


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    if isinstance(value, list):
        return [_plain(item) for item in value]
    return value


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ExperimentError("immutable mapping contains a non-string key")
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if value is None or type(value) in {str, bool, int, float}:
        return value
    raise ExperimentError("immutable mapping contains an unsupported value")


def _canonical_relative_path(value: str) -> str:
    if type(value) is not str or not value:
        raise ExperimentError("artifact relative path is invalid")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise ExperimentError("artifact relative path is invalid") from None
    if len(encoded) > 1024 or unicodedata.normalize("NFC", value) != value:
        raise ExperimentError("artifact relative path is invalid")
    path = PurePosixPath(value)
    if (
        value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or str(path) != value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ExperimentError("artifact relative path is unsafe")
    return value


def _canonical_existing_directory(value: object, label: str) -> Path:
    if type(value) is not str:
        raise ExperimentError(f"{label} must be a canonical directory")
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise ExperimentError(f"{label} must be a canonical directory")
    if path in {Path(path.anchor), Path.home(), Path.cwd()}:
        raise ExperimentError(f"{label} is a broad root")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ExperimentError(f"{label} must be an existing canonical directory") from None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or resolved != path
    ):
        raise ExperimentError(f"{label} is a symlink or noncanonical directory")
    return path


def _paths_overlap(first: Path, second: Path) -> bool:
    try:
        common = Path(os.path.commonpath((str(first), str(second))))
    except ValueError:
        return False
    return common == first or common == second


@dataclass(frozen=True, slots=True)
class ArtifactProposal:
    relative_path: str
    post_image: bytes
    post_hash: str

    def __post_init__(self) -> None:
        _canonical_relative_path(self.relative_path)
        if (
            type(self.post_image) is not bytes
            or not self.post_image
            or len(self.post_image) > _MAX_POST_IMAGE_BYTES
            or raw_sha256(self.post_image) != _require_digest(self.post_hash, "post-image")
        ):
            raise ExperimentError("post-image bytes do not match the declared post-image hash")

    @classmethod
    def build(
        cls, *, relative_path: str, post_image: bytes, post_hash: str
    ) -> "ArtifactProposal":
        return cls(relative_path, post_image, post_hash)

    def replace(self, **changes: object) -> "ArtifactProposal":
        return dataclass_replace(self, **changes)

    def to_mapping(self) -> dict[str, object]:
        return {
            "relativePath": self.relative_path,
            "postHash": self.post_hash,
            "postImageRef": post_image_ref(self.post_image),
            "byteSize": len(self.post_image),
        }


@dataclass(frozen=True, slots=True)
class CandidateBinding:
    candidate_id: str
    provider_request_digest: str
    capture_operation_id: str
    capture_binding_digest: str
    evaluation_id: str
    target_skill: str
    target_skill_version_hash: str
    task_class: str
    owner_skill: str
    change_class: str
    destination_class: str
    evidence_refs: tuple[str, ...]
    _binding_bytes: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _require_id(self.candidate_id, "candidate ID")
        _require_digest(self.provider_request_digest, "provider request")
        _require_id(self.capture_operation_id, "candidate capture operation")
        _require_digest(self.capture_binding_digest, "candidate capture binding")
        _require_id(self.evaluation_id, "candidate evaluation")
        _require_id(self.target_skill, "candidate target skill")
        _require_digest(self.target_skill_version_hash, "candidate target skill version")
        _require_id(self.task_class, "candidate task class")
        _require_id(self.owner_skill, "candidate owner skill")
        if type(self.change_class) is not str or self.change_class not in {"knowledge", "behavior", "material", "global", "defrag"}:
            raise ExperimentError("candidate change class is invalid")
        if type(self.destination_class) is not str or self.destination_class not in {
            "reference", "skill", "script", "profile", "agents", "contract", "tests", "evaluator", "metrics"
        }:
            raise ExperimentError("candidate destination is invalid")
        if (
            type(self.evidence_refs) is not tuple
            or not self.evidence_refs
            or len(self.evidence_refs) > 5
            or len(set(self.evidence_refs)) != len(self.evidence_refs)
            or self.evidence_refs != tuple(sorted(self.evidence_refs, key=lambda item: item.encode("utf-8")))
            or any(
                type(item) is not str
                or re.fullmatch(r"event:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", item)
                is None
                for item in self.evidence_refs
            )
        ):
            raise ExperimentError("candidate evidence refs are invalid")
        admitted_refs = tuple(str(item) for item in self.evidence_refs)
        object.__setattr__(self, "evidence_refs", admitted_refs)
        object.__setattr__(
            self,
            "_binding_bytes",
            canonical_json_bytes(self._live_binding_mapping()),
        )

    def replace(self, **changes: object) -> "CandidateBinding":
        return dataclass_replace(self, **changes)

    def _live_lineage_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "domain": "rsi-captured-candidate-lineage-v1",
            "candidateId": self.candidate_id,
            "providerRequestDigest": self.provider_request_digest,
            "captureOperationId": self.capture_operation_id,
            "captureBindingDigest": self.capture_binding_digest,
            "evaluationId": self.evaluation_id,
            "targetSkill": self.target_skill,
            "targetSkillVersionHash": self.target_skill_version_hash,
            "taskClass": self.task_class,
            "ownerSkill": self.owner_skill,
        }

    def _live_binding_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "domain": "rsi-captured-candidate-binding-v1",
            "lineage": self._live_lineage_mapping(),
            "changeClass": self.change_class,
            "destinationClass": self.destination_class,
            "evidenceRefs": list(self.evidence_refs),
        }

    def binding_mapping(self) -> dict[str, object]:
        return json.loads(self._binding_bytes.decode("utf-8"))

    def assert_admitted(self) -> None:
        if canonical_json_bytes(self._live_binding_mapping()) != self._binding_bytes:
            raise ExperimentError("candidate binding changed after admission")

    def lineage_mapping(self) -> dict[str, object]:
        return dict(self.binding_mapping()["lineage"])

    @property
    def digest(self) -> str:
        return raw_sha256(self._binding_bytes)

    def to_mapping(self) -> dict[str, object]:
        binding = self.binding_mapping()
        return {**binding, "candidateDigest": self.digest}


@dataclass(frozen=True, slots=True)
class TargetBinding:
    skill_name: str
    canonical_root: str
    owner_contract_hash: str
    registration_manifest: Mapping[str, object]
    allowlist_entry: AllowlistEntry
    manifest_pre_hash: str

    def __post_init__(self) -> None:
        _require_id(self.skill_name, "target skill name")
        root = _canonical_existing_directory(self.canonical_root, "target canonical root")
        _require_digest(self.owner_contract_hash, "owner contract")
        _require_digest(self.manifest_pre_hash, "target pre-manifest")
        if type(self.registration_manifest) is not dict:
            raise ExperimentError("target registration manifest must be an exact mapping")
        if type(self.allowlist_entry) is not AllowlistEntry:
            raise ExperimentError("target allowlist entry is invalid")
        registration = dict(self.registration_manifest)
        required_registration = {
            "schemaVersion",
            "entryId",
            "skillName",
            "canonicalRoot",
            "files",
        }
        if (
            not required_registration.issubset(registration)
            or type(registration["schemaVersion"]) is not int
            or registration["schemaVersion"] != 1
            or registration["entryId"] != self.allowlist_entry.entry_id
            or registration["skillName"] != self.skill_name
            or registration["canonicalRoot"] != str(root)
            or type(registration["files"]) is not list
            or "SKILL.md" not in registration["files"]
            or "skill-contract.json" not in registration["files"]
            or any(type(item) is not str for item in registration["files"])
        ):
            raise ExperimentError("target registration/skill/root binding is invalid")
        admitted_allowlist = AllowlistEntry(
            self.allowlist_entry.entry_id,
            self.allowlist_entry.skill_name,
            self.allowlist_entry.canonical_root_identity_digest,
            self.allowlist_entry.contract_hash,
        )
        if (
            admitted_allowlist.skill_name != self.skill_name
            or admitted_allowlist.contract_hash != self.owner_contract_hash
        ):
            raise ExperimentError("target allowlist contract/skill binding is invalid")
        try:
            registration_digest = registration_manifest_digest(registration)
            expected_root_identity = canonical_root_identity_digest(
                root, registration_digest
            )
        except AttestationError as error:
            raise ExperimentError("target registration identity is invalid") from error
        if admitted_allowlist.canonical_root_identity_digest != expected_root_identity:
            raise ExperimentError("target allowlist root identity binding is invalid")
        object.__setattr__(self, "allowlist_entry", admitted_allowlist)
        object.__setattr__(self, "registration_manifest", _freeze(registration))

    def replace(self, **changes: object) -> "TargetBinding":
        values: dict[str, object] = {
            "skill_name": self.skill_name,
            "canonical_root": self.canonical_root,
            "owner_contract_hash": self.owner_contract_hash,
            "registration_manifest": _plain(self.registration_manifest),
            "allowlist_entry": self.allowlist_entry,
            "manifest_pre_hash": self.manifest_pre_hash,
        }
        values.update(changes)
        return TargetBinding(**values)

    def to_mapping(self) -> dict[str, object]:
        return {
            "skillName": self.skill_name,
            "canonicalRoot": self.canonical_root,
            "ownerContractHash": self.owner_contract_hash,
            "registrationManifest": _plain(self.registration_manifest),
            "allowlistEntry": self.allowlist_entry.to_mapping(),
            "manifestPreHash": self.manifest_pre_hash,
        }


def _expectation_mapping(value: DeploymentExpectation) -> dict[str, object]:
    if not isinstance(value, DeploymentExpectation):
        raise ExperimentError("deployment expectation is invalid")
    return {
        "attestationType": value.attestation_type,
        "issuer": value.issuer,
        "subject": value.subject.to_mapping(),
        "scope": value.scope.to_mapping(),
        "predecessorAttestationDigest": value.predecessor_attestation_digest,
    }


@dataclass(frozen=True, slots=True)
class HarnessBinding:
    path: str
    bytes_digest: str
    version: str
    holdout_digest: str
    expected_case_ids: tuple[str, ...]
    expected_invariant_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.path) is not str or not os.path.isabs(self.path):
            raise ExperimentError("harness path must be absolute and canonical")
        path = Path(self.path)
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise ExperimentError("harness path must be an existing regular artifact") from None
        if (
            resolved != path
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size < 0
            or metadata.st_size > _MAX_BUNDLE_BYTES
        ):
            raise ExperimentError("harness path is not a safe canonical regular artifact")
        _require_digest(self.bytes_digest, "harness bytes")
        _require_digest(self.holdout_digest, "harness holdout")
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise ExperimentError("harness artifact cannot be read") from error
        if raw_sha256(payload) != self.bytes_digest:
            raise ExperimentError("harness bytes do not match the pinned digest")
        if type(self.version) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", self.version):
            raise ExperimentError("harness version is invalid")
        for label, values in (
            ("case", self.expected_case_ids),
            ("invariant", self.expected_invariant_ids),
        ):
            if (
                type(values) is not tuple
                or not values
                or len(values) > 256
                or len(set(values)) != len(values)
                or values
                != tuple(sorted(values, key=lambda item: item.encode("utf-8")))
                or any(
                    type(item) is not str or _CASE_RE.fullmatch(item) is None
                    for item in values
                )
            ):
                raise ExperimentError(
                    f"harness expected {label} identities are not canonical"
                )
            object.__setattr__(
                self,
                "expected_case_ids" if label == "case" else "expected_invariant_ids",
                tuple(str(item) for item in values),
            )

    def to_mapping(self) -> dict[str, object]:
        return {
            "path": self.path,
            "bytesDigest": self.bytes_digest,
            "version": self.version,
            "holdoutDigest": self.holdout_digest,
            "expectedCaseIds": list(self.expected_case_ids),
            "expectedInvariantIds": list(self.expected_invariant_ids),
        }

    @property
    def digest(self) -> str:
        return canonical_json_digest(self.to_mapping())


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    backend: str
    timeout_seconds: int
    cpu_seconds: int
    memory_bytes: int
    process_limit: int
    file_descriptor_limit: int
    file_size_bytes: int
    output_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.backend, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,63}", self.backend):
            raise ExperimentError("sandbox backend is invalid")
        values = (
            self.timeout_seconds,
            self.cpu_seconds,
            self.memory_bytes,
            self.process_limit,
            self.file_descriptor_limit,
            self.file_size_bytes,
            self.output_bytes,
        )
        if any(type(item) is not int or item < 1 for item in values):
            raise ExperimentError("sandbox resource policy is invalid")
        if (
            self.timeout_seconds > 3600
            or self.cpu_seconds > self.timeout_seconds
            or self.memory_bytes > 8 * 1024 * 1024 * 1024
            or self.process_limit > 64
            or self.file_descriptor_limit > 1024
            or self.file_size_bytes > 64 * 1024 * 1024
            or self.output_bytes > 16 * 1024 * 1024
        ):
            raise ExperimentError("sandbox resource policy exceeds its bound")

    @classmethod
    def local_default(
        cls, *, timeout_seconds: int = 30, output_bytes: int = 64 * 1024
    ) -> "SandboxPolicy":
        return cls(
            "macos-seatbelt-v1",
            timeout_seconds,
            min(timeout_seconds, 10),
            256 * 1024 * 1024,
            1,
            32,
            2 * 1024 * 1024,
            output_bytes,
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "backend": self.backend,
            "timeoutSeconds": self.timeout_seconds,
            "cpuSeconds": self.cpu_seconds,
            "memoryBytes": self.memory_bytes,
            "processLimit": self.process_limit,
            "fileDescriptorLimit": self.file_descriptor_limit,
            "fileSizeBytes": self.file_size_bytes,
            "outputBytes": self.output_bytes,
            "network": "deny",
            "dns": "deny",
            "subprocess": "deny",
            "environment": "minimal-allowlist",
        }

    @property
    def digest(self) -> str:
        return canonical_json_digest(self.to_mapping())


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    case_id: str
    passed: bool

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str) or _CASE_RE.fullmatch(self.case_id) is None:
            raise ExperimentError("sandbox case identity is invalid")
        if type(self.passed) is not bool:
            raise ExperimentError("sandbox case result is invalid")

    def to_mapping(self) -> dict[str, object]:
        return {"id": self.case_id, "passed": self.passed}


@dataclass(frozen=True, slots=True)
class SuiteOutcome:
    cases: tuple[CaseOutcome, ...]
    hard_invariants: tuple[CaseOutcome, ...]

    def __post_init__(self) -> None:
        for label, values in (("case", self.cases), ("hard invariant", self.hard_invariants)):
            if type(values) is not tuple or not values or any(type(item) is not CaseOutcome for item in values):
                raise ExperimentError(f"sandbox {label} results are invalid")
            copied = tuple(CaseOutcome(item.case_id, item.passed) for item in values)
            if len({item.case_id for item in copied}) != len(copied):
                raise ExperimentError(f"sandbox {label} identities contain duplicates")
            object.__setattr__(
                self,
                "cases" if label == "case" else "hard_invariants",
                tuple(sorted(copied, key=lambda item: item.case_id.encode("utf-8"))),
            )

    def to_mapping(self) -> dict[str, object]:
        return {
            "cases": [item.to_mapping() for item in self.cases],
            "hardInvariants": [item.to_mapping() for item in self.hard_invariants],
        }


@dataclass(frozen=True, slots=True)
class SandboxExecution:
    baseline: SuiteOutcome
    variant: SuiteOutcome
    artifact_digests: tuple[str, ...]
    sandbox_policy_digest: str
    external_mutation_performed: bool
    invocation_digest: str
    executor_identity_digest: str
    capability_report_digest: str

    def __post_init__(self) -> None:
        if type(self.baseline) is not SuiteOutcome or type(self.variant) is not SuiteOutcome:
            raise ExperimentError("sandbox suite results are invalid")
        self.baseline.__post_init__()
        self.variant.__post_init__()
        if (
            type(self.artifact_digests) is not tuple
            or not self.artifact_digests
            or self.artifact_digests != tuple(sorted(self.artifact_digests))
            or len(set(self.artifact_digests)) != len(self.artifact_digests)
        ):
            raise ExperimentError("sandbox artifact digests are not canonical")
        for item in self.artifact_digests:
            _require_digest(item, "sandbox artifact")
        _require_digest(self.sandbox_policy_digest, "sandbox policy")
        _require_digest(self.invocation_digest, "sandbox invocation")
        _require_digest(self.executor_identity_digest, "sandbox executor identity")
        _require_digest(self.capability_report_digest, "sandbox capability report")
        if type(self.external_mutation_performed) is not bool:
            raise ExperimentError("sandbox mutation result is invalid")

    def to_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "domain": "rsi-sandbox-execution-receipt-v1",
            "invocationDigest": self.invocation_digest,
            "executorIdentityDigest": self.executor_identity_digest,
            "capabilityReportDigest": self.capability_report_digest,
            "baseline": self.baseline.to_mapping(),
            "variant": self.variant.to_mapping(),
            "artifactDigests": list(self.artifact_digests),
            "sandboxPolicyDigest": self.sandbox_policy_digest,
            "externalMutationPerformed": self.external_mutation_performed,
        }

    @property
    def digest(self) -> str:
        return canonical_json_digest(self.to_mapping())


@dataclass(frozen=True, slots=True)
class SandboxInvocation:
    baseline_root: Path
    variant_root: Path
    harness: HarnessBinding
    sandbox_policy: SandboxPolicy
    scratch_parent: Path
    artifact_relative_path: str = ""
    post_image: bytes = b""
    host_home_probe: str = ""
    mcp_probe: str = ""
    outside_write_probe: str = ""
    operation_id: str = ""
    request_digest: str = ""
    baseline_manifest_digest: str = ""
    variant_manifest_digest: str = ""
    replacement_digest: str = ""
    post_image_digest: str = ""
    trusted_state_fingerprint: str = ""
    control_plane_digest: str = ""
    harness_binding_digest: str = ""
    executor_identity_digest: str = ""
    capability_report_digest: str = ""
    invocation_nonce: str = ""

    def __post_init__(self) -> None:
        _require_id(self.operation_id, "sandbox operation")
        for label, digest in (
            ("request", self.request_digest),
            ("baseline manifest", self.baseline_manifest_digest),
            ("variant manifest", self.variant_manifest_digest),
            ("replacement", self.replacement_digest),
            ("post-image", self.post_image_digest),
            ("trusted state", self.trusted_state_fingerprint),
            ("control plane", self.control_plane_digest),
            ("harness binding", self.harness_binding_digest),
            ("executor identity", self.executor_identity_digest),
            ("capability report", self.capability_report_digest),
        ):
            _require_digest(digest, f"sandbox invocation {label}")
        if type(self.invocation_nonce) is not str or re.fullmatch(
            r"[0-9a-f]{32}", self.invocation_nonce
        ) is None:
            raise ExperimentError("sandbox invocation nonce is invalid")
        if type(self.harness) is not HarnessBinding or type(
            self.sandbox_policy
        ) is not SandboxPolicy:
            raise ExperimentError("sandbox invocation nested binding is invalid")
        _canonical_relative_path(self.artifact_relative_path)
        if (
            type(self.post_image) is not bytes
            or not self.post_image
            or raw_sha256(self.post_image) != self.post_image_digest
            or self.harness.digest != self.harness_binding_digest
            or self.sandbox_policy.digest == ""
        ):
            raise ExperimentError("sandbox invocation artifact/binding is invalid")

    def identity_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "domain": "rsi-sandbox-invocation-v1",
            "operationId": self.operation_id,
            "requestDigest": self.request_digest,
            "baselineManifestDigest": self.baseline_manifest_digest,
            "variantManifestDigest": self.variant_manifest_digest,
            "replacementDigest": self.replacement_digest,
            "postImageDigest": self.post_image_digest,
            "trustedStateFingerprint": self.trusted_state_fingerprint,
            "controlPlaneDigest": self.control_plane_digest,
            "harnessBindingDigest": self.harness_binding_digest,
            "sandboxPolicyDigest": self.sandbox_policy.digest,
            "executorIdentityDigest": self.executor_identity_digest,
            "capabilityReportDigest": self.capability_report_digest,
            "invocationNonce": self.invocation_nonce,
        }

    @property
    def digest(self) -> str:
        return canonical_json_digest(self.identity_mapping())


class TrustedSandboxExecutor(ABC):
    """Injected trusted executor; sandbox/candidate data cannot implement this as a bool."""

    @property
    @abstractmethod
    def identity_digest(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def capability_report_digest(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def execute(self, invocation: SandboxInvocation) -> SandboxExecution:
        raise NotImplementedError


_MACOS_PROBE_INTERPRETERS = (
    Path(
        "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/"
        "Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python"
    ),
)
_MACOS_PROFILE_TEMPLATE = """(version 1)
(deny default)
(import "system.sb")
(deny network*)
(deny process-fork)
(allow process-exec (literal {interpreter}))
(allow file-read-metadata (subpath "/Applications"))
(allow file-read-metadata (subpath {probe_root}))
(allow file-read*
  (subpath {framework_root})
  (subpath "/System")
  (subpath "/usr/lib")
  (subpath "/private/var/db/timezone")
  (literal "/dev/null")
  (literal {baseline})
  (literal {variant})
  (literal {harness})
  (subpath {scratch}))
(allow file-write*
  (literal "/dev/null")
  (subpath {scratch}))
"""
_MACOS_PROBE_WORKER = r'''import errno
import json
import os
import resource
import shlex
import socket
import subprocess
import sys

config = json.loads(sys.argv[1])
denied_errnos = {errno.EACCES, errno.EPERM}

def denied(call):
    try:
        call()
    except OSError as error:
        return error.errno in denied_errnos or isinstance(error, PermissionError)
    except Exception:
        return False
    return False

def read(path):
    with open(path, "rb") as stream:
        stream.read(1)

def write(path):
    with open(path, "wb") as stream:
        stream.write(b"x")

def connect(family, address):
    client = socket.socket(family, socket.SOCK_STREAM)
    try:
        client.settimeout(0.5)
        client.connect(address)
    finally:
        client.close()

def bind_loopback():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
    finally:
        server.close()

def dns_denied():
    try:
        socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return True
    except OSError as error:
        return error.errno in denied_errnos
    return False

def fork_denied():
    try:
        child = os.fork()
    except OSError as error:
        return error.errno in denied_errnos
    if child == 0:
        os._exit(0)
    os.waitpid(child, 0)
    return False

def posix_spawn_denied():
    try:
        child = os.posix_spawn(
            config["interpreter"],
            [config["interpreter"], "-I", "-S", "-c", "pass"],
            {},
        )
    except OSError as error:
        return error.errno in denied_errnos
    os.waitpid(child, 0)
    return False

def system_denied():
    command = "/usr/bin/touch " + shlex.quote(config["system_marker"])
    command += " >/dev/null 2>&1"
    return os.system(command) != 0 and not os.path.exists(config["system_marker"])

def subprocess_denied():
    try:
        completed = subprocess.run(
            [config["interpreter"], "-I", "-S", "-c", "pass"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return True
    return completed.returncode != 0

def only_standard_fds():
    for descriptor in range(3, 64):
        try:
            os.fstat(descriptor)
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            return False
        return False
    return True

def scratch_allowed():
    path = os.path.join(config["scratch"], "worker-write")
    try:
        write(path)
        read(path)
        os.unlink(path)
    except OSError:
        return False
    return True

def hard_memory_enforced():
    limit = int(config["memory_limit"])
    results = []
    for name in ("RLIMIT_AS", "RLIMIT_DATA", "RLIMIT_RSS"):
        if not hasattr(resource, name):
            results.append(False)
            continue
        try:
            resource.setrlimit(getattr(resource, name), (limit, limit))
            results.append(resource.getrlimit(getattr(resource, name)) == (limit, limit))
        except (OSError, ValueError):
            results.append(False)
    return all(results)

for readable in (config["baseline"], config["variant"], config["harness"]):
    read(readable)

result = {
    "filesystem_read_denied": denied(lambda: read(config["secret_read"])),
    "filesystem_write_denied": denied(lambda: write(config["outside_write"])),
    "baseline_write_denied": denied(lambda: write(config["baseline"])),
    "variant_write_denied": denied(lambda: write(config["variant"])),
    "harness_write_denied": denied(lambda: write(config["harness"])),
    "host_home_denied": denied(lambda: os.listdir(config["host_home"])),
    "network_external_denied": denied(
        lambda: connect(socket.AF_INET, ("192.0.2.1", 9))
    ),
    "network_loopback_denied": denied(
        lambda: connect(socket.AF_INET, ("127.0.0.1", int(config["loopback_port"])))
    ),
    "network_bind_denied": denied(bind_loopback),
    "dns_denied": dns_denied(),
    "unix_socket_denied": denied(
        lambda: connect(socket.AF_UNIX, config["unix_socket"])
    ),
    "fork_denied": fork_denied(),
    "posix_spawn_denied": posix_spawn_denied(),
    "system_denied": system_denied(),
    "subprocess_denied": subprocess_denied(),
    "secret_environment_absent": "RSI_SANDBOX_PROBE_SECRET" not in os.environ,
    "mcp_tool_denied": denied(lambda: read(config["mcp_probe"])),
    "stdin_eof": os.read(0, 1) == b"",
    "only_standard_fds": only_standard_fds(),
    "scratch_write_allowed": scratch_allowed(),
    "hard_memory_enforced": hard_memory_enforced(),
}
sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
'''
_MACOS_SAME_IMAGE_EXEC_WORKER = r'''import errno
import json
import os
import sys

interpreter = sys.argv[1]
success_marker = "RSI_SAME_IMAGE_EXEC_SUCCEEDED"
try:
    os.execv(
        interpreter,
        [interpreter, "-I", "-S", "-c", "print(" + repr(success_marker) + ")"],
    )
except OSError as error:
    denied = error.errno in {errno.EACCES, errno.EPERM}
    sys.stdout.write(json.dumps({"denied": denied}, sort_keys=True, separators=(",", ":")))
'''
_MACOS_EXECUTOR_AUTHORITY = object()


@dataclass(frozen=True, slots=True)
class CapabilityReport:
    filesystem_read_denied: bool
    filesystem_write_denied: bool
    baseline_write_denied: bool
    variant_write_denied: bool
    harness_write_denied: bool
    host_home_denied: bool
    network_external_denied: bool
    network_loopback_denied: bool
    network_bind_denied: bool
    dns_denied: bool
    unix_socket_denied: bool
    fork_denied: bool
    posix_spawn_denied: bool
    system_denied: bool
    subprocess_denied: bool
    secret_environment_absent: bool
    mcp_tool_denied: bool
    stdin_eof: bool
    only_standard_fds: bool
    scratch_write_allowed: bool
    hard_memory_enforced: bool
    same_image_exec_denied: bool
    complete: bool
    worker_digest: str
    same_image_worker_digest: str
    backend_digest: str
    interpreter_digest: str
    profile_digest: str
    os_build_digest: str

    _GATES = (
        "filesystem_read_denied",
        "filesystem_write_denied",
        "baseline_write_denied",
        "variant_write_denied",
        "harness_write_denied",
        "host_home_denied",
        "network_external_denied",
        "network_loopback_denied",
        "network_bind_denied",
        "dns_denied",
        "unix_socket_denied",
        "fork_denied",
        "posix_spawn_denied",
        "system_denied",
        "subprocess_denied",
        "secret_environment_absent",
        "mcp_tool_denied",
        "stdin_eof",
        "only_standard_fds",
        "scratch_write_allowed",
        "hard_memory_enforced",
        "same_image_exec_denied",
    )

    def __post_init__(self) -> None:
        if any(type(getattr(self, field_name)) is not bool for field_name in self._GATES):
            raise ExperimentError("sandbox capability gates must be exact booleans")
        if type(self.complete) is not bool or (
            self.complete
            and not all(getattr(self, field_name) for field_name in self._GATES)
        ):
            raise ExperimentError("sandbox capability completeness is invalid")
        _require_digest(self.worker_digest, "sandbox worker")
        _require_digest(self.same_image_worker_digest, "sandbox same-image worker")
        _require_digest(self.backend_digest, "sandbox backend executable")
        _require_digest(self.interpreter_digest, "sandbox interpreter")
        _require_digest(self.profile_digest, "sandbox profile")
        _require_digest(self.os_build_digest, "sandbox OS build")

    def to_mapping(self) -> dict[str, object]:
        mapping = {
            "schemaVersion": 1,
            "domain": "rsi-macos-sandbox-capability-report-v1",
            "complete": self.complete,
            "workerDigest": self.worker_digest,
            "sameImageWorkerDigest": self.same_image_worker_digest,
            "backendDigest": self.backend_digest,
            "interpreterDigest": self.interpreter_digest,
            "profileDigest": self.profile_digest,
            "osBuildDigest": self.os_build_digest,
        }
        mapping.update(
            {
                "".join(
                    part if index == 0 else part.title()
                    for index, part in enumerate(field_name.split("_"))
                ): getattr(self, field_name)
                for field_name in self._GATES
            }
        )
        return mapping

    @property
    def digest(self) -> str:
        return canonical_json_digest(self.to_mapping())


def _macos_os_build_digest() -> str:
    identity = os.uname()
    return canonical_json_digest(
        {
            "sysname": identity.sysname,
            "nodenameExcluded": True,
            "release": identity.release,
            "version": identity.version,
            "machine": identity.machine,
        }
    )


def _unavailable_capability_report(
    *,
    backend_digest: str | None = None,
    interpreter_digest: str | None = None,
) -> CapabilityReport:
    values: dict[str, object] = {
        field_name: False for field_name in CapabilityReport._GATES
    }
    values.update(
        {
            "complete": False,
            "worker_digest": raw_sha256(_MACOS_PROBE_WORKER.encode("utf-8")),
            "same_image_worker_digest": raw_sha256(
                _MACOS_SAME_IMAGE_EXEC_WORKER.encode("utf-8")
            ),
            "backend_digest": backend_digest or raw_sha256(b"unavailable"),
            "interpreter_digest": interpreter_digest or raw_sha256(b"unavailable"),
            "profile_digest": raw_sha256(_MACOS_PROFILE_TEMPLATE.encode("utf-8")),
            "os_build_digest": _macos_os_build_digest(),
        }
    )
    return CapabilityReport(**values)


@dataclass(frozen=True, slots=True)
class _PinnedExecutable:
    path: Path
    digest: str
    device: int
    inode: int
    size: int
    modified_ns: int
    mode: int
    owner: int
    group: int


def _pin_root_owned_executable(candidate: Path) -> _PinnedExecutable | None:
    if type(candidate) is not Path:
        candidate = Path(candidate)
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        descriptor = os.open(candidate, os.O_RDONLY | _NOFOLLOW)
    except (OSError, RuntimeError):
        return None
    try:
        opened = os.fstat(descriptor)
        if (
            not candidate.is_absolute()
            or resolved != candidate
            or not stat.S_ISREG(metadata.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino)
            or metadata.st_nlink != 1
            or opened.st_nlink != 1
            or opened.st_uid != 0
            or stat.S_IMODE(opened.st_mode) & 0o022
            or not stat.S_IMODE(opened.st_mode) & 0o111
            or opened.st_size < 1
            or opened.st_size > 128 * 1024 * 1024
        ):
            return None
        payload = bytearray()
        while len(payload) <= 128 * 1024 * 1024:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, 128 * 1024 * 1024 + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        final = os.fstat(descriptor)
        if (
            len(payload) != opened.st_size
            or (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_mode,
                opened.st_uid,
                opened.st_gid,
                opened.st_nlink,
            )
            != (
                final.st_dev,
                final.st_ino,
                final.st_size,
                final.st_mtime_ns,
                final.st_mode,
                final.st_uid,
                final.st_gid,
                final.st_nlink,
            )
        ):
            return None
        return _PinnedExecutable(
            candidate,
            raw_sha256(bytes(payload)),
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_mode,
            opened.st_uid,
            opened.st_gid,
        )
    finally:
        os.close(descriptor)


def _pinned_executable_is_current(binding: _PinnedExecutable) -> bool:
    if type(binding) is not _PinnedExecutable:
        return False
    current = _pin_root_owned_executable(binding.path)
    return current == binding


def _pinned_macos_backend() -> _PinnedExecutable | None:
    # Never execute the result of an ambient PATH search. Seatbelt is a fixed
    # platform component whose canonical identity is admitted directly.
    return _pin_root_owned_executable(Path("/usr/bin/sandbox-exec"))


def _pinned_macos_interpreter() -> _PinnedExecutable | None:
    for candidate in _MACOS_PROBE_INTERPRETERS:
        binding = _pin_root_owned_executable(candidate)
        if binding is not None:
            return binding
    return None


def _macos_probe_profile(
    *,
    interpreter: Path,
    baseline: Path,
    variant: Path,
    harness: Path,
    scratch: Path,
) -> str:
    framework_root = Path(
        "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/"
        "Python3.framework"
    )
    return _MACOS_PROFILE_TEMPLATE.format(
        interpreter=json.dumps(str(interpreter)),
        framework_root=json.dumps(str(framework_root)),
        probe_root=json.dumps(str(baseline.parent)),
        baseline=json.dumps(str(baseline)),
        variant=json.dumps(str(variant)),
        harness=json.dumps(str(harness)),
        scratch=json.dumps(str(scratch)),
    )


def _terminate_probe_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def _run_bounded_probe_command(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    timeout_seconds: float,
    output_limit_bytes: int,
) -> subprocess.CompletedProcess[bytes] | None:
    if (
        type(command) not in {list, tuple}
        or not command
        or any(type(item) is not str or not item for item in command)
        or type(environment) is not dict
        or any(type(key) is not str or type(value) is not str for key, value in environment.items())
        or type(timeout_seconds) not in {int, float}
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
        or type(output_limit_bytes) is not int
        or output_limit_bytes < 1
        or output_limit_bytes > 1024 * 1024
    ):
        return None
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(environment),
            close_fds=True,
            start_new_session=True,
            bufsize=0,
        )
    except OSError:
        return None
    if process.stdout is None or process.stderr is None:
        _terminate_probe_process(process)
        return None

    output = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    failed = False
    try:
        for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream.fileno(), selectors.EVENT_READ, label)
        deadline = time.monotonic() + float(timeout_seconds)
        while selector.get_map():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                failed = True
                break
            events = selector.select(min(remaining_time, 0.1))
            if not events:
                continue
            for key, _ in events:
                total = len(output["stdout"]) + len(output["stderr"])
                read_bound = min(64 * 1024, output_limit_bytes - total + 1)
                try:
                    chunk = os.read(key.fd, max(1, read_bound))
                except BlockingIOError:
                    continue
                except OSError:
                    failed = True
                    break
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                output[key.data].extend(chunk)
                if len(output["stdout"]) + len(output["stderr"]) > output_limit_bytes:
                    failed = True
                    break
            if failed:
                break
        if failed:
            _terminate_probe_process(process)
            return None
        try:
            return_code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _terminate_probe_process(process)
            return None
        return subprocess.CompletedProcess(
            list(command),
            return_code,
            bytes(output["stdout"]),
            bytes(output["stderr"]),
        )
    except (OSError, ValueError):
        _terminate_probe_process(process)
        return None
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass


def _run_sandbox_probe_process(
    *,
    sandbox_exec: _PinnedExecutable,
    profile: str,
    interpreter: _PinnedExecutable,
    worker: str,
    arguments: Sequence[str],
) -> subprocess.CompletedProcess[bytes] | None:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }
    if not _pinned_executable_is_current(
        sandbox_exec
    ) or not _pinned_executable_is_current(interpreter):
        return None
    completed = _run_bounded_probe_command(
        [
            str(sandbox_exec.path),
            "-p",
            profile,
            str(interpreter.path),
            "-I",
            "-S",
            "-c",
            worker,
            *arguments,
        ],
        environment=environment,
        timeout_seconds=15,
        output_limit_bytes=64 * 1024,
    )
    if completed is None:
        return None
    if not _pinned_executable_is_current(
        sandbox_exec
    ) or not _pinned_executable_is_current(interpreter):
        return None
    return completed


class MacOSSandboxExecutor(TrustedSandboxExecutor):
    """Diagnostic real Seatbelt probe with a fail-closed local execution boundary."""

    def __init__(self, *, capability_report: CapabilityReport | None = None) -> None:
        fresh = self.probe_capabilities()
        if capability_report is not None:
            if type(capability_report) is not CapabilityReport:
                raise SandboxUnavailable(
                    "sandbox-unavailable: capability report type is not trusted"
                )
            try:
                admitted = CapabilityReport(
                    **{
                        field_name: getattr(capability_report, field_name)
                        for field_name in (
                            *CapabilityReport._GATES,
                            "complete",
                            "worker_digest",
                            "same_image_worker_digest",
                            "backend_digest",
                            "interpreter_digest",
                            "profile_digest",
                            "os_build_digest",
                        )
                    }
                )
            except (ExperimentError, AttributeError, TypeError) as error:
                raise SandboxUnavailable(
                    "sandbox-unavailable: capability report admission failed"
                ) from error
            if admitted != fresh:
                raise SandboxUnavailable(
                    "sandbox-unavailable: capability report does not match a fresh host probe"
                )
        if not fresh.complete:
            raise SandboxUnavailable(
                "sandbox-unavailable: the local containment boundary is incomplete"
            )
        # Task 7 deliberately ships no local success backend. A future backend must
        # bind these exact probe identities to its worker and profile before this
        # authority token can ever be minted.
        raise SandboxUnavailable(
            "sandbox-unavailable: validated local target execution is not installed"
        )

    @staticmethod
    def probe_capabilities(
        *, target_execution_marker: Path | None = None
    ) -> CapabilityReport:
        # The marker is intentionally never passed to either trusted probe worker.
        # It is a test witness that capability discovery cannot run target code.
        if target_execution_marker is not None and not isinstance(
            target_execution_marker, Path
        ):
            raise SandboxUnavailable("sandbox-unavailable: target marker is invalid")
        if os.uname().sysname != "Darwin":
            return _unavailable_capability_report()
        sandbox_exec = _pinned_macos_backend()
        if sandbox_exec is None:
            return _unavailable_capability_report()
        interpreter_binding = _pinned_macos_interpreter()
        if interpreter_binding is None:
            return _unavailable_capability_report(
                backend_digest=sandbox_exec.digest
            )
        interpreter = interpreter_binding
        values: dict[str, bool] = {
            field_name: False for field_name in CapabilityReport._GATES
        }
        with tempfile.TemporaryDirectory(prefix="rsi-sandbox-probe-") as directory:
            # Seatbelt compares canonical vnode paths; /var is a symlink to
            # /private/var on macOS, so the policy and worker must bind the same
            # canonical spelling.
            root = Path(directory).resolve(strict=True)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            baseline = root / "baseline.json"
            variant = root / "variant.json"
            harness = root / "harness.py"
            secret_read = root / "secret.txt"
            mcp_probe = root / "mcp-secret.json"
            for path, payload in (
                (baseline, b"baseline"),
                (variant, b"variant"),
                (harness, b"harness"),
                (secret_read, b"secret"),
                (mcp_probe, b"mcp"),
            ):
                path.write_bytes(payload)
                path.chmod(0o600)
            outside_write = root / "outside-write"
            system_marker = root / "system-marker"
            unix_socket_path = root / "probe.sock"
            loopback_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            unix_server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                loopback_server.bind(("127.0.0.1", 0))
                loopback_server.listen(1)
                unix_server.bind(str(unix_socket_path))
                unix_server.listen(1)
                profile = _macos_probe_profile(
                    interpreter=interpreter.path,
                    baseline=baseline,
                    variant=variant,
                    harness=harness,
                    scratch=scratch,
                )
                configuration = {
                    "baseline": str(baseline),
                    "variant": str(variant),
                    "harness": str(harness),
                    "secret_read": str(secret_read),
                    "mcp_probe": str(mcp_probe),
                    "outside_write": str(outside_write),
                    "system_marker": str(system_marker),
                    "host_home": str(Path.home()),
                    "scratch": str(scratch),
                    "loopback_port": loopback_server.getsockname()[1],
                    "unix_socket": str(unix_socket_path),
                    "interpreter": str(interpreter.path),
                    "memory_limit": 256 * 1024 * 1024,
                }
                completed = _run_sandbox_probe_process(
                    sandbox_exec=sandbox_exec,
                    profile=profile,
                    interpreter=interpreter,
                    worker=_MACOS_PROBE_WORKER,
                    arguments=(
                        json.dumps(configuration, sort_keys=True, separators=(",", ":")),
                    ),
                )
                if completed is not None and completed.returncode == 0:
                    try:
                        payload = json.loads(completed.stdout.decode("utf-8", "strict"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        payload = None
                    expected = set(CapabilityReport._GATES) - {"same_image_exec_denied"}
                    if (
                        type(payload) is dict
                        and set(payload) == expected
                        and all(type(payload[key]) is bool for key in expected)
                    ):
                        values.update(payload)

                exec_probe = _run_sandbox_probe_process(
                    sandbox_exec=sandbox_exec,
                    profile=profile,
                    interpreter=interpreter,
                    worker=_MACOS_SAME_IMAGE_EXEC_WORKER,
                    arguments=(str(interpreter.path),),
                )
                if exec_probe is not None:
                    output = exec_probe.stdout.decode("utf-8", "replace").strip()
                    if output == "RSI_SAME_IMAGE_EXEC_SUCCEEDED":
                        values["same_image_exec_denied"] = False
                    elif exec_probe.returncode == 0:
                        try:
                            parsed = json.loads(output)
                        except json.JSONDecodeError:
                            parsed = None
                        values["same_image_exec_denied"] = bool(
                            type(parsed) is dict
                            and set(parsed) == {"denied"}
                            and parsed["denied"] is True
                        )
            except OSError:
                pass
            finally:
                loopback_server.close()
                unix_server.close()

        report_values: dict[str, object] = dict(values)
        report_values.update(
            {
                # Task 7 intentionally has no local success backend. These
                # booleans are diagnostic evidence only, never an authority
                # grant, even on a future host where every current canary passes.
                "complete": False,
                "worker_digest": raw_sha256(_MACOS_PROBE_WORKER.encode("utf-8")),
                "same_image_worker_digest": raw_sha256(
                    _MACOS_SAME_IMAGE_EXEC_WORKER.encode("utf-8")
                ),
                "backend_digest": sandbox_exec.digest,
                "interpreter_digest": interpreter.digest,
                "profile_digest": raw_sha256(_MACOS_PROFILE_TEMPLATE.encode("utf-8")),
                "os_build_digest": _macos_os_build_digest(),
            }
        )
        return CapabilityReport(**report_values)

    @property
    def identity_digest(self) -> str:
        if getattr(self, "_authority", None) is not _MACOS_EXECUTOR_AUTHORITY:
            raise SandboxUnavailable(
                "sandbox-unavailable: local executor authority is absent"
            )
        return self._identity_digest

    @property
    def capability_report_digest(self) -> str:
        if getattr(self, "_authority", None) is not _MACOS_EXECUTOR_AUTHORITY:
            raise SandboxUnavailable(
                "sandbox-unavailable: local executor authority is absent"
            )
        return self._capability_report.digest

    def execute(self, invocation: SandboxInvocation) -> SandboxExecution:
        del invocation
        raise SandboxUnavailable(
            "sandbox-unavailable: validated local target execution is not installed"
        )


class TrustedValidationIssuer(ABC):
    """Injected host issuer; no signing secret enters staging or persisted request data."""

    @abstractmethod
    def issue(self, signed_body: Mapping[str, object]) -> bytes:
        raise NotImplementedError


def _copy_deployment_expectation(
    value: object, expected_type: str
) -> DeploymentExpectation:
    if type(value) is not DeploymentExpectation or value.attestation_type != expected_type:
        raise ExperimentError(f"{expected_type} expectation type is invalid")
    try:
        if expected_type == "rollout-stage":
            if type(value.subject) is not RolloutStageSubject or type(
                value.scope
            ) is not RolloutStageScope:
                raise ExperimentError("rollout-stage expectation subject/scope is invalid")
            subject = RolloutStageSubject(
                value.subject.rsi_package_digest,
                value.subject.rollout_manifest_digest,
                value.subject.stage_id,
                value.subject.provider_contract_digest,
                value.subject.provider_version_digest,
            )
            scope = RolloutStageScope(
                value.scope.mode,
                value.scope.environment_identity_digest,
                tuple(value.scope.allowed_target_entry_digests),
            )
        else:
            if type(value.subject) is not OrchestrationHookSubject or type(
                value.scope
            ) is not OrchestrationHookScope:
                raise ExperimentError(
                    "orchestration-hook expectation subject/scope is invalid"
                )
            subject = OrchestrationHookSubject(
                value.subject.rsi_package_digest,
                value.subject.rollout_manifest_digest,
                value.subject.hook_id,
                value.subject.provider_contract_digest,
                value.subject.provider_version_digest,
            )
            scope = OrchestrationHookScope(
                value.scope.hook_mode,
                value.scope.environment_identity_digest,
                tuple(value.scope.allowed_target_entry_digests),
            )
        return DeploymentExpectation(
            expected_type,
            value.issuer,
            subject,
            scope,
            value.predecessor_attestation_digest,
        )
    except (AttestationError, TypeError, AttributeError, ValueError):
        raise ExperimentError(f"{expected_type} expectation schema is invalid") from None


@dataclass(frozen=True, slots=True)
class ExperimentRequest:
    schema_version: int
    operation_id: str
    candidate: CandidateBinding
    target: TargetBinding
    artifact: ArtifactProposal
    stage_attestation: bytes
    hook_attestation: bytes
    stage_expectation: DeploymentExpectation
    hook_expectation: DeploymentExpectation
    control_plane: ValidationControlPlane
    harness: HarnessBinding
    sandbox_policy: SandboxPolicy
    rollout_manifest_digest: str
    provider_contract_digest: str
    provider_version_digest: str
    rsi_package_digest: str
    environment_identity_digest: str
    created_at: str
    expires_at: str
    _canonical_snapshot: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema_version != 1 or type(self.schema_version) is not int:
            raise ExperimentError("experiment request schema version is invalid")
        _require_id(self.operation_id, "experiment operation ID")
        if not all(
            type(item) is expected
            for item, expected in (
                (self.candidate, CandidateBinding),
                (self.target, TargetBinding),
                (self.artifact, ArtifactProposal),
                (self.stage_expectation, DeploymentExpectation),
                (self.hook_expectation, DeploymentExpectation),
                (self.control_plane, ValidationControlPlane),
                (self.harness, HarnessBinding),
                (self.sandbox_policy, SandboxPolicy),
            )
        ):
            raise ExperimentError("experiment request nested schema is invalid")
        candidate = CandidateBinding(
            self.candidate.candidate_id,
            self.candidate.provider_request_digest,
            self.candidate.capture_operation_id,
            self.candidate.capture_binding_digest,
            self.candidate.evaluation_id,
            self.candidate.target_skill,
            self.candidate.target_skill_version_hash,
            self.candidate.task_class,
            self.candidate.owner_skill,
            self.candidate.change_class,
            self.candidate.destination_class,
            tuple(self.candidate.evidence_refs),
        )
        target = self.target.replace()
        artifact = ArtifactProposal(
            self.artifact.relative_path,
            bytes(self.artifact.post_image),
            self.artifact.post_hash,
        )
        stage_expectation = _copy_deployment_expectation(
            self.stage_expectation, "rollout-stage"
        )
        hook_expectation = _copy_deployment_expectation(
            self.hook_expectation, "orchestration-hook"
        )
        control_plane = ValidationControlPlane(
            self.control_plane.policy_version,
            self.control_plane.evaluator_version,
            self.control_plane.metric_registry_version,
            self.control_plane.harness_version,
            self.control_plane.holdout_digest,
        )
        harness = HarnessBinding(
            self.harness.path,
            self.harness.bytes_digest,
            self.harness.version,
            self.harness.holdout_digest,
            tuple(self.harness.expected_case_ids),
            tuple(self.harness.expected_invariant_ids),
        )
        sandbox_policy = SandboxPolicy(
            self.sandbox_policy.backend,
            self.sandbox_policy.timeout_seconds,
            self.sandbox_policy.cpu_seconds,
            self.sandbox_policy.memory_bytes,
            self.sandbox_policy.process_limit,
            self.sandbox_policy.file_descriptor_limit,
            self.sandbox_policy.file_size_bytes,
            self.sandbox_policy.output_bytes,
        )
        for name, value in (
            ("candidate", candidate),
            ("target", target),
            ("artifact", artifact),
            ("stage_expectation", stage_expectation),
            ("hook_expectation", hook_expectation),
            ("control_plane", control_plane),
            ("harness", harness),
            ("sandbox_policy", sandbox_policy),
        ):
            object.__setattr__(self, name, value)
        if (
            type(self.stage_attestation) is not bytes
            or type(self.hook_attestation) is not bytes
            or not self.stage_attestation
            or not self.hook_attestation
            or len(self.stage_attestation) > 128 * 1024
            or len(self.hook_attestation) > 128 * 1024
        ):
            raise ExperimentError("deployment attestation refs must be exact bytes")
        try:
            parsed_stage = parse_deployment_attestation(self.stage_attestation)
            parsed_hook = parse_deployment_attestation(self.hook_attestation)
        except AttestationError as error:
            raise ExperimentError("deployment attestation framing is invalid") from error
        if (
            parsed_stage.attestation_type != "rollout-stage"
            or parsed_hook.attestation_type != "orchestration-hook"
        ):
            raise ExperimentError("deployment attestation stage/hook types are invalid")
        for label, digest in (
            ("rollout manifest", self.rollout_manifest_digest),
            ("provider contract", self.provider_contract_digest),
            ("provider version", self.provider_version_digest),
            ("RSI package", self.rsi_package_digest),
            ("environment identity", self.environment_identity_digest),
        ):
            _require_digest(digest, label)
        try:
            created = parse_timestamp(self.created_at)
            expires = parse_timestamp(self.expires_at)
        except AttestationError as error:
            raise ExperimentError("experiment request time binding is invalid") from error
        if created >= expires or expires - created > timedelta(days=1):
            raise ExperimentError("experiment request created/expires interval is invalid")
        if (
            candidate.target_skill != target.skill_name
            or candidate.owner_skill != target.skill_name
            or candidate.target_skill_version_hash != target.manifest_pre_hash
        ):
            raise ExperimentError("candidate target/owner/version binding is invalid")
        if candidate.destination_class == "skill" and artifact.relative_path != "SKILL.md":
            raise ExperimentError("candidate skill destination does not bind exact SKILL.md artifact")
        if candidate.destination_class == "reference" and not artifact.relative_path.startswith(
            "references/"
        ):
            raise ExperimentError("candidate reference destination does not bind artifact")
        target_allowlist_digest = allowlist_entry_digest(target.allowlist_entry)
        stage_subject = stage_expectation.subject
        hook_subject = hook_expectation.subject
        stage_scope = stage_expectation.scope
        hook_scope = hook_expectation.scope
        if (
            stage_subject.rsi_package_digest != self.rsi_package_digest
            or hook_subject.rsi_package_digest != self.rsi_package_digest
            or stage_subject.rollout_manifest_digest != self.rollout_manifest_digest
            or hook_subject.rollout_manifest_digest != self.rollout_manifest_digest
            or stage_subject.provider_contract_digest != self.provider_contract_digest
            or hook_subject.provider_contract_digest != self.provider_contract_digest
            or stage_subject.provider_version_digest != self.provider_version_digest
            or hook_subject.provider_version_digest != self.provider_version_digest
            or stage_scope.environment_identity_digest != self.environment_identity_digest
            or hook_scope.environment_identity_digest != self.environment_identity_digest
            or stage_scope.allowed_target_entry_digests
            != hook_scope.allowed_target_entry_digests
            or target_allowlist_digest not in stage_scope.allowed_target_entry_digests
        ):
            raise ExperimentError("deployment expectation/request common binding is invalid")
        if raw_sha256(self.stage_attestation) == raw_sha256(self.hook_attestation):
            raise ExperimentError("deployment attestation raw refs must be distinct")
        encoded = canonical_json_bytes(self._live_mapping())
        if len(encoded) > _MAX_REQUEST_BYTES:
            raise ExperimentError("experiment request exceeds its byte bound")
        object.__setattr__(self, "_canonical_snapshot", encoded)

    def replace(self, **changes: object) -> "ExperimentRequest":
        return dataclass_replace(self, **changes)

    def _live_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "domain": "rsi-isolated-experiment-request-v1",
            "operationId": self.operation_id,
            "candidate": self.candidate.to_mapping(),
            "target": self.target.to_mapping(),
            "artifact": self.artifact.to_mapping(),
            "stageAttestationRawDigest": raw_sha256(self.stage_attestation),
            "hookAttestationRawDigest": raw_sha256(self.hook_attestation),
            "stageExpectation": _expectation_mapping(self.stage_expectation),
            "hookExpectation": _expectation_mapping(self.hook_expectation),
            "controlPlane": self.control_plane.to_mapping(),
            "harness": self.harness.to_mapping(),
            "sandboxPolicy": self.sandbox_policy.to_mapping(),
            "rolloutManifestDigest": self.rollout_manifest_digest,
            "providerContractDigest": self.provider_contract_digest,
            "providerVersionDigest": self.provider_version_digest,
            "rsiPackageDigest": self.rsi_package_digest,
            "environmentIdentityDigest": self.environment_identity_digest,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at,
        }

    def to_mapping(self) -> dict[str, object]:
        return json.loads(self._canonical_snapshot.decode("utf-8"))

    def assert_admitted(self) -> None:
        self.candidate.assert_admitted()
        if (
            type(self._canonical_snapshot) is not bytes
            or canonical_json_bytes(self._live_mapping()) != self._canonical_snapshot
        ):
            raise ExperimentError("experiment request model changed after admission")

    @property
    def canonical_bytes(self) -> bytes:
        self.assert_admitted()
        return self._canonical_snapshot

    @property
    def digest(self) -> str:
        return raw_sha256(self.canonical_bytes)


class TrustedClock(ABC):
    """Host-owned resampled UTC clock; request timestamps cannot stand in for time."""

    @abstractmethod
    def now_utc(self) -> datetime:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class CurrentTrustedState:
    candidate_digest: str
    provider_candidate_status: str
    provider_candidate_record_digest: str
    canonical_root: str
    registration_manifest_digest: str
    canonical_root_identity_digest: str
    owner_contract_hash: str
    allowlist_entry_digest: str
    target_manifest_digest: str
    rsi_package_digest: str
    rollout_manifest_digest: str
    provider_contract_digest: str
    provider_version_digest: str
    environment_identity_digest: str
    stage_attestation_digest: str
    hook_attestation_digest: str
    stage_expectation_digest: str
    hook_expectation_digest: str
    allowed_target_entry_digests: tuple[str, ...]
    control_plane_binding_digest: str
    policy_artifact_digest: str
    evaluator_artifact_digest: str
    metric_registry_artifact_digest: str
    harness_path: str
    harness_bytes_digest: str
    harness_binding_digest: str
    control_plane_roots_digest: str
    sandbox_policy_digest: str
    sandbox_executor_identity_digest: str
    sandbox_capability_report_digest: str

    def __post_init__(self) -> None:
        _canonical_existing_directory(
            self.canonical_root, "trusted current canonical root"
        )
        for label, digest in (
            ("candidate", self.candidate_digest),
            ("provider candidate record", self.provider_candidate_record_digest),
            ("registration manifest", self.registration_manifest_digest),
            ("canonical root identity", self.canonical_root_identity_digest),
            ("owner contract", self.owner_contract_hash),
            ("allowlist entry", self.allowlist_entry_digest),
            ("target manifest", self.target_manifest_digest),
            ("RSI package", self.rsi_package_digest),
            ("rollout manifest", self.rollout_manifest_digest),
            ("provider contract", self.provider_contract_digest),
            ("provider version", self.provider_version_digest),
            ("environment identity", self.environment_identity_digest),
            ("stage attestation", self.stage_attestation_digest),
            ("hook attestation", self.hook_attestation_digest),
            ("stage expectation", self.stage_expectation_digest),
            ("hook expectation", self.hook_expectation_digest),
            ("control-plane binding", self.control_plane_binding_digest),
            ("policy artifact", self.policy_artifact_digest),
            ("evaluator artifact", self.evaluator_artifact_digest),
            ("metric registry artifact", self.metric_registry_artifact_digest),
            ("harness bytes", self.harness_bytes_digest),
            ("harness binding", self.harness_binding_digest),
            ("control-plane roots", self.control_plane_roots_digest),
            ("sandbox policy", self.sandbox_policy_digest),
            ("sandbox executor identity", self.sandbox_executor_identity_digest),
            ("sandbox capability report", self.sandbox_capability_report_digest),
        ):
            _require_digest(digest, f"trusted current {label}")
        if self.provider_candidate_status != "pending" or type(
            self.provider_candidate_status
        ) is not str:
            raise ExperimentError("trusted provider candidate status is not pending")
        expected_provider_record = canonical_json_digest(
            {
                "candidateDigest": self.candidate_digest,
                "providerContractDigest": self.provider_contract_digest,
                "providerVersionDigest": self.provider_version_digest,
                "status": self.provider_candidate_status,
            }
        )
        if self.provider_candidate_record_digest != expected_provider_record:
            raise ExperimentError("trusted provider candidate record/status binding is invalid")
        try:
            expected_root_identity = canonical_root_identity_digest(
                self.canonical_root, self.registration_manifest_digest
            )
        except AttestationError as error:
            raise ExperimentError("trusted current root identity is invalid") from error
        if self.canonical_root_identity_digest != expected_root_identity:
            raise ExperimentError(
                "trusted current canonical root/registration identity does not match"
            )
        if type(self.harness_path) is not str:
            raise ExperimentError("trusted current harness path is invalid")
        harness = Path(self.harness_path)
        try:
            harness_metadata = harness.lstat()
            resolved_harness = harness.resolve(strict=True)
            harness_payload = harness.read_bytes()
        except (OSError, RuntimeError):
            raise ExperimentError("trusted current harness path is unavailable") from None
        if (
            not harness.is_absolute()
            or resolved_harness != harness
            or stat.S_ISLNK(harness_metadata.st_mode)
            or not stat.S_ISREG(harness_metadata.st_mode)
            or harness_metadata.st_nlink != 1
            or raw_sha256(harness_payload) != self.harness_bytes_digest
        ):
            raise ExperimentError("trusted current harness identity is invalid")
        if (
            type(self.allowed_target_entry_digests) is not tuple
            or not self.allowed_target_entry_digests
            or len(set(self.allowed_target_entry_digests))
            != len(self.allowed_target_entry_digests)
            or self.allowed_target_entry_digests
            != tuple(sorted(self.allowed_target_entry_digests))
        ):
            raise ExperimentError("trusted current allowed-target set is invalid")
        for digest in self.allowed_target_entry_digests:
            _require_digest(digest, "trusted current allowed-target entry")
        if self.allowlist_entry_digest not in self.allowed_target_entry_digests:
            raise ExperimentError(
                "trusted current allowlist entry is not in the active allowed-target set"
            )
        if self.stage_attestation_digest == self.hook_attestation_digest:
            raise ExperimentError("trusted current deployment attestations are not distinct")

    @property
    def control_plane_digest(self) -> str:
        return canonical_json_digest(
            {
                "schemaVersion": 1,
                "domain": "rsi-current-control-plane-v1",
                "bindingDigest": self.control_plane_binding_digest,
                "policyArtifactDigest": self.policy_artifact_digest,
                "evaluatorArtifactDigest": self.evaluator_artifact_digest,
                "metricRegistryArtifactDigest": self.metric_registry_artifact_digest,
                "harnessBytesDigest": self.harness_bytes_digest,
                "harnessBindingDigest": self.harness_binding_digest,
                "harnessPath": self.harness_path,
                "controlPlaneRootsDigest": self.control_plane_roots_digest,
                "sandboxPolicyDigest": self.sandbox_policy_digest,
                "sandboxExecutorIdentityDigest": self.sandbox_executor_identity_digest,
                "sandboxCapabilityReportDigest": self.sandbox_capability_report_digest,
                "rsiPackageDigest": self.rsi_package_digest,
                "rolloutManifestDigest": self.rollout_manifest_digest,
                "stageAttestationDigest": self.stage_attestation_digest,
                "hookAttestationDigest": self.hook_attestation_digest,
                "stageExpectationDigest": self.stage_expectation_digest,
                "hookExpectationDigest": self.hook_expectation_digest,
                "allowedTargetEntryDigests": list(
                    self.allowed_target_entry_digests
                ),
                "providerContractDigest": self.provider_contract_digest,
                "providerVersionDigest": self.provider_version_digest,
                "providerCandidateRecordDigest": self.provider_candidate_record_digest,
                "environmentIdentityDigest": self.environment_identity_digest,
            }
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "candidateDigest": self.candidate_digest,
            "providerCandidateStatus": self.provider_candidate_status,
            "providerCandidateRecordDigest": self.provider_candidate_record_digest,
            "canonicalRoot": self.canonical_root,
            "registrationManifestDigest": self.registration_manifest_digest,
            "canonicalRootIdentityDigest": self.canonical_root_identity_digest,
            "ownerContractHash": self.owner_contract_hash,
            "allowlistEntryDigest": self.allowlist_entry_digest,
            "targetManifestDigest": self.target_manifest_digest,
            "rsiPackageDigest": self.rsi_package_digest,
            "rolloutManifestDigest": self.rollout_manifest_digest,
            "providerContractDigest": self.provider_contract_digest,
            "providerVersionDigest": self.provider_version_digest,
            "environmentIdentityDigest": self.environment_identity_digest,
            "stageAttestationDigest": self.stage_attestation_digest,
            "hookAttestationDigest": self.hook_attestation_digest,
            "stageExpectationDigest": self.stage_expectation_digest,
            "hookExpectationDigest": self.hook_expectation_digest,
            "allowedTargetEntryDigests": list(self.allowed_target_entry_digests),
            "controlPlaneBindingDigest": self.control_plane_binding_digest,
            "policyArtifactDigest": self.policy_artifact_digest,
            "evaluatorArtifactDigest": self.evaluator_artifact_digest,
            "metricRegistryArtifactDigest": self.metric_registry_artifact_digest,
            "harnessPath": self.harness_path,
            "harnessBytesDigest": self.harness_bytes_digest,
            "harnessBindingDigest": self.harness_binding_digest,
            "controlPlaneRootsDigest": self.control_plane_roots_digest,
            "sandboxPolicyDigest": self.sandbox_policy_digest,
            "sandboxExecutorIdentityDigest": self.sandbox_executor_identity_digest,
            "sandboxCapabilityReportDigest": self.sandbox_capability_report_digest,
            "controlPlaneDigest": self.control_plane_digest,
        }

    @property
    def fingerprint(self) -> str:
        return canonical_json_digest(self.to_mapping())


class TrustedCurrentStateProvider(ABC):
    """Host-owned authoritative identity sampler."""

    @abstractmethod
    def current(self) -> CurrentTrustedState:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class ExperimentContext:
    home: Path
    verifier: TrustedSignatureVerifier
    replay: TrustedReplayBinding
    stage_chain: TrustedAttestationChain
    hook_chain: TrustedAttestationChain
    issuer: TrustedValidationIssuer
    sandbox_executor: TrustedSandboxExecutor
    validation_issuer: str
    clock: TrustedClock
    current_state_provider: TrustedCurrentStateProvider
    maximum_attestation_ttl: timedelta
    control_plane_roots: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.home) is not Path:
            object.__setattr__(self, "home", Path(self.home))
        if not isinstance(self.verifier, TrustedSignatureVerifier):
            raise ExperimentError("trusted signature verifier is required")
        if not isinstance(self.replay, TrustedReplayBinding):
            raise ExperimentError("trusted replay binding is required")
        if not isinstance(self.stage_chain, TrustedAttestationChain) or not isinstance(
            self.hook_chain, TrustedAttestationChain
        ):
            raise ExperimentError("trusted deployment chains are required")
        if not isinstance(self.issuer, TrustedValidationIssuer):
            raise ExperimentError("trusted validation issuer is required")
        if not isinstance(self.sandbox_executor, TrustedSandboxExecutor):
            raise ExperimentError("trusted sandbox executor is required")
        if type(self.validation_issuer) is not str or re.fullmatch(
            r"trusted-validator:[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
            self.validation_issuer,
        ) is None:
            raise ExperimentError("trusted validation issuer identity is invalid")
        if not isinstance(self.clock, TrustedClock):
            raise ExperimentError("trusted experiment clock is required")
        if not isinstance(self.current_state_provider, TrustedCurrentStateProvider):
            raise ExperimentError("trusted current state provider is required")
        try:
            sampled_now = self.clock.now_utc()
        except Exception as error:
            raise ExperimentError("trusted experiment clock failed") from error
        if (
            type(sampled_now) is not datetime
            or sampled_now.tzinfo is None
            or sampled_now.utcoffset() != timedelta(0)
        ):
            raise ExperimentError("experiment clock must return UTC")
        try:
            sampled_state = self.current_state_provider.current()
        except Exception as error:
            raise ExperimentError("trusted current state provider failed") from error
        if type(sampled_state) is not CurrentTrustedState:
            raise ExperimentError("trusted current state sample is invalid")
        sampled_state.__post_init__()
        try:
            executor_identity = self.sandbox_executor.identity_digest
            capability_digest = self.sandbox_executor.capability_report_digest
            _require_digest(executor_identity, "sandbox executor identity")
            _require_digest(capability_digest, "sandbox capability report")
        except (ExperimentError, TypeError, ValueError, AttributeError) as error:
            raise ExperimentError("trusted sandbox executor identity is invalid") from error
        if (
            sampled_state.sandbox_executor_identity_digest != executor_identity
            or sampled_state.sandbox_capability_report_digest != capability_digest
        ):
            raise ExperimentError(
                "trusted sandbox executor identity/capability does not match current state"
            )
        if (
            type(self.maximum_attestation_ttl) is not timedelta
            or self.maximum_attestation_ttl <= timedelta(0)
            or self.maximum_attestation_ttl > timedelta(days=1)
            or self.maximum_attestation_ttl.microseconds != 0
        ):
            raise ExperimentError("experiment attestation TTL policy is invalid")
        if type(self.control_plane_roots) is not tuple or not self.control_plane_roots:
            raise ExperimentError("trusted control-plane identity roots are required")
        home = self.home
        if (
            not home.is_absolute()
            or os.path.normpath(str(home)) != str(home)
            or home in {Path(home.anchor), Path.home(), Path.cwd()}
        ):
            raise ExperimentError("experiment home is a broad or noncanonical topology")
        try:
            if home.exists():
                metadata = home.lstat()
                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISDIR(metadata.st_mode)
                    or home.resolve(strict=True) != home
                ):
                    raise ExperimentError("experiment home topology is unsafe")
            else:
                parent = home.parent.resolve(strict=True)
                if parent != home.parent or not parent.is_dir():
                    raise ExperimentError("experiment home parent is noncanonical")
        except (OSError, RuntimeError):
            raise ExperimentError("experiment home topology is unavailable") from None
        admitted_roots: list[Path] = []
        for root in self.control_plane_roots:
            admitted_roots.append(
                _canonical_existing_directory(root, "control-plane identity root")
            )
        if len(set(admitted_roots)) != len(admitted_roots):
            raise ExperimentError("control-plane roots contain duplicates")
        target = Path(sampled_state.canonical_root)
        harness = Path(sampled_state.harness_path)
        topology = (("home", home), ("target", target), ("harness", harness))
        for left_index, (left_label, left) in enumerate(topology):
            for right_label, right in topology[left_index + 1 :]:
                if _paths_overlap(left, right):
                    raise ExperimentError(
                        f"{left_label}/{right_label} topology overlaps"
                    )
        for index, root in enumerate(admitted_roots):
            if any(_paths_overlap(root, item) for _, item in topology):
                raise ExperimentError("control-plane root overlaps home/target/harness")
            if any(_paths_overlap(root, other) for other in admitted_roots[index + 1 :]):
                raise ExperimentError("control-plane roots are duplicate or nested")
        expected_control_roots_digest = control_plane_roots_digest(
            tuple(str(item) for item in admitted_roots)
        )
        if sampled_state.control_plane_roots_digest != expected_control_roots_digest:
            raise ExperimentError("control-plane roots do not match trusted current state")

    def replace(self, **changes: object) -> "ExperimentContext":
        return dataclass_replace(self, **changes)


def build_experiment_reservation(
    request: ExperimentRequest,
    *,
    current_state: CurrentTrustedState,
    trusted_now: datetime,
    maximum_attestation_ttl: timedelta,
) -> bytes:
    """Build the durable pre-work binding without sampling nondeterministic signer data."""

    if type(request) is not ExperimentRequest or type(current_state) is not CurrentTrustedState:
        raise ExperimentError("experiment reservation requires exact trusted request/state models")
    request.assert_admitted()
    current_state.__post_init__()
    if (
        type(maximum_attestation_ttl) is not timedelta
        or maximum_attestation_ttl <= timedelta(0)
        or maximum_attestation_ttl > timedelta(days=1)
        or maximum_attestation_ttl.microseconds != 0
    ):
        raise ExperimentError("experiment reservation TTL policy is invalid")
    if (
        type(trusted_now) is not datetime
        or trusted_now.tzinfo is None
        or trusted_now.utcoffset() != timedelta(0)
        or trusted_now.microsecond != 0
    ):
        raise ExperimentError("experiment trusted T0 must be a whole-second UTC clock sample")
    created = parse_timestamp(request.created_at)
    expires = parse_timestamp(request.expires_at)
    if not (created <= trusted_now < expires):
        raise ExperimentError("experiment trusted T0 is outside request time window")
    state_mapping = current_state.to_mapping()
    mapping = {
        "schemaVersion": 1,
        "domain": "rsi-isolated-experiment-reservation-v1",
        "operationId": request.operation_id,
        "request": request.to_mapping(),
        "requestDigest": request.digest,
        "initialTrustedState": state_mapping,
        "initialTrustedStateFingerprint": current_state.fingerprint,
        "trustedT0": trusted_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "maximumAttestationTtlSeconds": int(
            maximum_attestation_ttl.total_seconds()
        ),
    }
    encoded = canonical_json_bytes(mapping)
    if len(encoded) > _MAX_REQUEST_BYTES:
        raise ExperimentError("experiment reservation exceeds its byte bound")
    try:
        _validate_reservation_request(request.operation_id, encoded)
    except ExperimentStoreError as error:
        raise ExperimentError(
            "experiment reservation request/state/TTL relation is invalid"
        ) from error
    return encoded


def _admit_existing_experiment_reservation(
    payload: bytes,
    *,
    request: ExperimentRequest,
    current_state: CurrentTrustedState,
    trusted_now: datetime,
    maximum_attestation_ttl: timedelta,
) -> dict[str, object]:
    """Validate stable operation semantics while preserving the original T0."""

    try:
        stored = _validate_reservation_request(request.operation_id, payload)
    except ExperimentStoreError as error:
        raise ExperimentConflict(
            "existing experiment reservation is malformed or rebound"
        ) from error
    if (
        type(trusted_now) is not datetime
        or trusted_now.tzinfo is None
        or trusted_now.utcoffset() != timedelta(0)
        or trusted_now.microsecond != 0
        or type(maximum_attestation_ttl) is not timedelta
        or maximum_attestation_ttl <= timedelta(0)
        or maximum_attestation_ttl > timedelta(days=1)
        or maximum_attestation_ttl.microseconds != 0
    ):
        raise ExperimentError("existing experiment reservation clock/TTL policy is invalid")
    try:
        stored_t0 = parse_timestamp(stored["trustedT0"])
    except (AttestationError, TypeError, KeyError) as error:
        raise ExperimentConflict("existing experiment reservation T0 is invalid") from error
    if trusted_now < stored_t0:
        raise ExperimentConflict(
            "trusted experiment clock precedes the reserved T0"
        )
    expected_ttl = int(maximum_attestation_ttl.total_seconds())
    if (
        stored["request"] != request.to_mapping()
        or stored["requestDigest"] != request.digest
        or stored["initialTrustedState"] != current_state.to_mapping()
        or stored["initialTrustedStateFingerprint"] != current_state.fingerprint
        or stored["maximumAttestationTtlSeconds"] != expected_ttl
    ):
        raise ExperimentConflict(
            "existing experiment operation reservation stable authority conflicts"
        )
    return stored


@dataclass(frozen=True, slots=True)
class CaseCounts:
    total: int
    passed_baseline: int
    passed_variant: int

    def __post_init__(self) -> None:
        if (
            type(self.total) is not int
            or type(self.passed_baseline) is not int
            or type(self.passed_variant) is not int
            or self.total < 0
            or self.passed_baseline < 0
            or self.passed_variant < 0
            or self.passed_baseline > self.total
            or self.passed_variant > self.total
        ):
            raise ExperimentError("experiment case counts are impossible")

    def to_mapping(self) -> dict[str, int]:
        return {
            "total": self.total,
            "passedBaseline": self.passed_baseline,
            "passedVariant": self.passed_variant,
        }


@dataclass(frozen=True, slots=True)
class ExperimentResult:
    candidate_id: str
    baseline_revision: str
    variant_revision: str
    harness_version: str
    cases: CaseCounts
    baseline_invariants_passed: bool
    variant_invariants_passed: bool
    regressions: tuple[str, ...]
    improvements: tuple[str, ...]
    decision: str
    artifacts: tuple[str, ...]
    external_mutation_performed: bool

    def __post_init__(self) -> None:
        _require_id(self.candidate_id, "experiment result candidate")
        _require_digest(self.baseline_revision, "experiment baseline revision")
        _require_digest(self.variant_revision, "experiment variant revision")
        if type(self.harness_version) is not str or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", self.harness_version
        ) is None:
            raise ExperimentError("experiment result harness version is invalid")
        if type(self.cases) is not CaseCounts:
            raise ExperimentError("experiment result case counts are invalid")
        self.cases.__post_init__()
        if (
            type(self.baseline_invariants_passed) is not bool
            or type(self.variant_invariants_passed) is not bool
            or type(self.external_mutation_performed) is not bool
        ):
            raise ExperimentError("experiment result invariant/mutation state is invalid")
        for label, values in (
            ("regression", self.regressions),
            ("improvement", self.improvements),
        ):
            if (
                type(values) is not tuple
                or len(set(values)) != len(values)
                or values != tuple(sorted(values))
            ):
                raise ExperimentError(f"experiment result {label} identities are invalid")
            for value in values:
                if type(value) is not str or _CASE_RE.fullmatch(value) is None:
                    raise ExperimentError(f"experiment result {label} identity is invalid")
        if self.decision not in {"eligible", "rejected"} or type(self.decision) is not str:
            raise ExperimentError("experiment result decision is invalid")
        if set(self.regressions).intersection(self.improvements):
            raise ExperimentError("experiment result regression/improvement sets overlap")
        if self.external_mutation_performed:
            raise ExperimentError("experiment result reports forbidden external mutation")
        if self.decision == "eligible" and (
            self.cases.total == 0
            or
            self.regressions
            or not self.baseline_invariants_passed
            or not self.variant_invariants_passed
            or self.cases.passed_variant < self.cases.passed_baseline
        ):
            raise ExperimentError(
                "eligible experiment result has regression, invariant, or mutation conflict"
            )
        if (
            type(self.artifacts) is not tuple
            or not self.artifacts
            or len(set(self.artifacts)) != len(self.artifacts)
            or self.artifacts != tuple(sorted(self.artifacts))
        ):
            raise ExperimentError("experiment result artifacts are invalid")
        for digest in self.artifacts:
            _require_digest(digest, "experiment result artifact")

    def to_mapping(self) -> dict[str, object]:
        return {
            "candidateId": self.candidate_id,
            "baselineRevision": self.baseline_revision,
            "variantRevision": self.variant_revision,
            "harnessVersion": self.harness_version,
            "cases": self.cases.to_mapping(),
            "hardInvariants": {
                "baselinePassed": self.baseline_invariants_passed,
                "variantPassed": self.variant_invariants_passed,
            },
            "regressions": list(self.regressions),
            "improvements": list(self.improvements),
            "decision": self.decision,
            "artifacts": list(self.artifacts),
            "externalMutationPerformed": self.external_mutation_performed,
        }


@dataclass(frozen=True, slots=True)
class PromotionPlanTarget:
    skill_name: str
    owner_contract_hash: str
    manifest_pre_hash: str
    manifest_post_hash: str

    def __post_init__(self) -> None:
        _require_id(self.skill_name, "promotion target skill")
        _require_digest(self.owner_contract_hash, "promotion target contract")
        _require_digest(self.manifest_pre_hash, "promotion target pre-manifest")
        _require_digest(self.manifest_post_hash, "promotion target post-manifest")

    def to_mapping(self) -> dict[str, str]:
        return {
            "skillName": self.skill_name,
            "ownerContractHash": self.owner_contract_hash,
            "manifestPreHash": self.manifest_pre_hash,
            "manifestPostHash": self.manifest_post_hash,
        }


@dataclass(frozen=True, slots=True)
class PromotionPlanArtifact:
    relative_path: str
    type: str
    pre_hash: str
    post_hash: str
    diff_digest: str
    post_image_ref: str

    def __post_init__(self) -> None:
        _canonical_relative_path(self.relative_path)
        if self.type != "regular-file":
            raise ExperimentError("promotion plan artifact type is invalid")
        for label, digest in (
            ("pre", self.pre_hash),
            ("post", self.post_hash),
            ("diff", self.diff_digest),
        ):
            _require_digest(digest, f"promotion artifact {label}")
        if type(self.post_image_ref) is not str or _REF_RE.fullmatch(self.post_image_ref) is None:
            raise ExperimentError("promotion plan post-image ref is invalid")
        if self.post_image_ref != "object:" + self.post_hash:
            raise ExperimentError("promotion plan post-image ref does not bind post hash")

    def to_mapping(self) -> dict[str, str]:
        return {
            "relativePath": self.relative_path,
            "type": self.type,
            "preHash": self.pre_hash,
            "postHash": self.post_hash,
            "diffDigest": self.diff_digest,
            "postImageRef": self.post_image_ref,
        }


@dataclass(frozen=True, slots=True)
class ProviderOperationIds:
    snapshot: str
    resolve: str

    def __post_init__(self) -> None:
        if (
            type(self.snapshot) is not str
            or type(self.resolve) is not str
            or re.fullmatch(r"op_snapshot_[0-9a-f]{32}", self.snapshot) is None
            or re.fullmatch(r"op_resolve_[0-9a-f]{32}", self.resolve) is None
        ):
            raise ExperimentError("promotion plan provider operation IDs are invalid")

    def to_mapping(self) -> dict[str, str]:
        return {"snapshot": self.snapshot, "resolve": self.resolve}


_PROMOTION_AUTHORITY_V2_FIELDS = {
    "schemaVersion", "domain", "candidateId", "task7CandidateBindingDigest",
    "candidateCaptureLineageBindingDigest", "candidateFullRecordDigest",
    "providerAuthorityBindingDigest", "candidateStateBindingDigest",
    "providerContractDigest", "providerVersionDigest", "providerRuntimeIdentityDigest",
    "providerExecutionIdentityDigest", "verifierExecutionBaseIdentityDigest",
    "namespaceMutationLeaseBackendIdentityDigest", "namespaceMutationLeaseCapabilityDigest",
    "policyVersion", "policyArtifactDigest", "artifactStoreIdentityDigest",
    "task8ControlPlaneVersion", "task8AddendumDigest", "task8AddendumMarkdownDigest",
}
_CURRENT_TRUSTED_STATE_V2_FIELDS = {
    "schemaVersion", "domain", "candidateDigest", "providerCandidateStatus",
    "providerCandidateRecordDigest", "canonicalRoot", "registrationManifestDigest",
    "canonicalRootIdentityDigest", "ownerContractHash", "allowlistEntryDigest",
    "targetManifestDigest", "rsiPackageDigest", "rolloutManifestDigest",
    "providerContractDigest", "providerVersionDigest", "environmentIdentityDigest",
    "stageAttestationDigest", "hookAttestationDigest", "stageExpectationDigest",
    "hookExpectationDigest", "allowedTargetEntryDigests", "controlPlaneBindingDigest",
    "policyArtifactDigest", "evaluatorArtifactDigest", "metricRegistryArtifactDigest",
    "harnessPath", "harnessBytesDigest", "harnessBindingDigest", "controlPlaneRootsDigest",
    "sandboxPolicyDigest", "sandboxExecutorIdentityDigest", "sandboxCapabilityReportDigest",
    "controlPlaneDigest", "promotionAuthority",
}
_EXPERIMENT_REQUEST_V2_FIELDS = _EXPERIMENT_REQUEST_FIELDS | {"promotionAuthority"} if "_EXPERIMENT_REQUEST_FIELDS" in globals() else {
    "schemaVersion", "domain", "operationId", "candidate", "target", "artifact",
    "stageAttestationRawDigest", "hookAttestationRawDigest", "stageExpectation", "hookExpectation",
    "controlPlane", "harness", "sandboxPolicy", "rolloutManifestDigest", "providerContractDigest",
    "providerVersionDigest", "rsiPackageDigest", "environmentIdentityDigest", "createdAt", "expiresAt",
    "promotionAuthority",
}
_EXPERIMENT_RESERVATION_V2_FIELDS = {
    "schemaVersion", "domain", "operationId", "request", "requestDigest",
    "initialTrustedState", "initialTrustedStateFingerprint", "trustedT0",
    "maximumAttestationTtlSeconds",
}
_VALIDATION_ATTESTATION_V2_FIELDS = {
    "schemaVersion", "domain", "attestationId", "issuer", "signatureAlgorithm", "signature",
    "candidateId", "candidateDigest", "diffDigest", "targetPreHash", "ownerContractHash",
    "evidenceRefs", "controlPlane", "testArtifactDigests", "sandboxPolicyDigest",
    "createdAt", "expiresAt", "decision", "promotionAuthority",
}
_PROMOTION_PLAN_V2_FIELDS = {
    "schemaVersion", "domain", "planId", "candidateId", "candidateDigest",
    "validationAttestationDigest", "allowlistEntryId", "allowlistEntryDigest",
    "canonicalRootIdentityDigest", "rolloutManifestDigest", "stageAttestationDigest",
    "hookAttestationDigest", "providerContractDigest", "providerVersionDigest", "target",
    "artifact", "providerOperationIds", "controlPlaneDigest", "controlPlane", "createdAt",
    "expiresAt", "promotionAuthority",
}
_TASK8_ADDENDUM_DIGEST = "sha256:ef84059ca0df0d3804dc090616cef3e4abbe3ce7f11ec6f8535e74aa3afe02c0"
_TASK8_ADDENDUM_MARKDOWN_DIGEST = "sha256:6fd2ab2a1d45e678f7eaf237c462c49e6dcf3ad133e30c41e28326b9d5f909b6"


@dataclass(frozen=True, slots=True)
class Task8WireModel:
    _mapping: Mapping[str, object]
    canonical_bytes: bytes
    digest: str
    raw_digest: str | None = None
    signed_body_bytes: bytes | None = None
    fingerprint: str | None = None
    request_digest: str | None = None
    reservation_digest: str | None = None

    def to_mapping(self) -> dict[str, object]:
        return json.loads(self.canonical_bytes.decode("utf-8"))


def _task8_parse_object(payload: bytes, label: str, fields: set[str], *, domain: str) -> tuple[dict[str, object], bytes]:
    source = _canonical_store_object(payload, label)
    if set(source) != fields or source.get("schemaVersion") != 2 or source.get("domain") != domain:
        raise ExperimentError(f"{label} V2 schema/domain is invalid")
    if any(value is None for value in source.values()):
        raise ExperimentError(f"{label} V2 null fields are forbidden")
    return source, canonical_json_bytes(source)


def parse_promotion_authority_v2(payload: bytes) -> Task8WireModel:
    source, canonical = _task8_parse_object(
        payload, "promotion authority", _PROMOTION_AUTHORITY_V2_FIELDS,
        domain="rsi-promotion-authority-v2",
    )
    if (
        source["task8ControlPlaneVersion"] != "1.1.0"
        or source["task8AddendumDigest"] != _TASK8_ADDENDUM_DIGEST
        or source["task8AddendumMarkdownDigest"] != _TASK8_ADDENDUM_MARKDOWN_DIGEST
    ):
        raise ExperimentError("promotion authority addendum binding is invalid")
    for key, value in source.items():
        if key.endswith("Digest") and (not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None):
            raise ExperimentError(f"promotion authority {key} is invalid")
    return Task8WireModel(MappingProxyType(source), canonical, raw_sha256(canonical))


def _authority_mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ExperimentError("nested promotion authority is invalid")
    return parse_promotion_authority_v2(canonical_json_bytes(value)).to_mapping()


def parse_current_trusted_state_v2(payload: bytes) -> Task8WireModel:
    source, canonical = _task8_parse_object(
        payload, "current trusted state", _CURRENT_TRUSTED_STATE_V2_FIELDS,
        domain="rsi-current-trusted-state-v2",
    )
    authority = _authority_mapping(source["promotionAuthority"])
    relations = {
        "candidateDigest": "task7CandidateBindingDigest",
        "providerCandidateRecordDigest": "candidateFullRecordDigest",
        "providerContractDigest": "providerContractDigest",
        "providerVersionDigest": "providerVersionDigest",
        "policyArtifactDigest": "policyArtifactDigest",
    }
    if any(source[left] != authority[right] for left, right in relations.items()):
        raise ExperimentError("current trusted state authority relation is invalid")
    if source["providerCandidateStatus"] not in {"pending", "deferred"}:
        raise ExperimentError("current trusted candidate status is invalid")
    return Task8WireModel(
        MappingProxyType(source), canonical, raw_sha256(canonical),
        fingerprint=raw_sha256(canonical),
    )


def parse_experiment_request_v2(payload: bytes) -> Task8WireModel:
    source, canonical = _task8_parse_object(
        payload, "experiment request", _EXPERIMENT_REQUEST_V2_FIELDS,
        domain="rsi-isolated-experiment-request-v2",
    )
    authority = _authority_mapping(source["promotionAuthority"])
    candidate = source.get("candidate")
    control = source.get("controlPlane")
    if not isinstance(candidate, dict) or not isinstance(control, dict):
        raise ExperimentError("experiment request nested schema is invalid")
    if (
        candidate.get("candidateDigest") != authority["task7CandidateBindingDigest"]
        or source["providerContractDigest"] != authority["providerContractDigest"]
        or source["providerVersionDigest"] != authority["providerVersionDigest"]
        or control.get("policyVersion") != authority["policyVersion"]
    ):
        raise ExperimentError("experiment request authority relation is invalid")
    return Task8WireModel(MappingProxyType(source), canonical, raw_sha256(canonical))


def parse_experiment_reservation_v2(payload: bytes) -> Task8WireModel:
    source, canonical = _task8_parse_object(
        payload, "experiment reservation", _EXPERIMENT_RESERVATION_V2_FIELDS,
        domain="rsi-isolated-experiment-reservation-v2",
    )
    request = source.get("request")
    state = source.get("initialTrustedState")
    if not isinstance(request, dict) or not isinstance(state, dict):
        raise ExperimentError("experiment reservation nested schema is invalid")
    parsed_request = parse_experiment_request_v2(canonical_json_bytes(request))
    parsed_state = parse_current_trusted_state_v2(canonical_json_bytes(state))
    if (
        source["operationId"] != request.get("operationId")
        or source["requestDigest"] != parsed_request.digest
        or source["initialTrustedStateFingerprint"] != parsed_state.fingerprint
        or request["promotionAuthority"] != state["promotionAuthority"]
    ):
        raise ExperimentError("experiment reservation binding is invalid")
    return Task8WireModel(
        MappingProxyType(source), canonical, raw_sha256(canonical),
        request_digest=parsed_request.digest,
        reservation_digest=raw_sha256(canonical),
    )


def parse_validation_attestation_v2(payload: bytes) -> Task8WireModel:
    source, canonical = _task8_parse_object(
        payload, "validation attestation", _VALIDATION_ATTESTATION_V2_FIELDS,
        domain="rsi-validation-attestation-v2",
    )
    authority = _authority_mapping(source["promotionAuthority"])
    if source["candidateId"] != authority["candidateId"] or source["candidateDigest"] != authority["task7CandidateBindingDigest"]:
        raise ExperimentError("validation attestation authority relation is invalid")
    if source["signatureAlgorithm"] != "platform-attestation-v1":
        raise ExperimentError("validation attestation signature algorithm is invalid")
    signature = source["signature"]
    try:
        if not isinstance(signature, str) or not signature.startswith("base64:"):
            raise ValueError
        encoded = signature[7:]
        decoded = base64.b64decode(encoded, validate=True)
        if not decoded or base64.b64encode(decoded).decode("ascii") != encoded:
            raise ValueError
    except (ValueError, binascii.Error):
        raise ExperimentError("validation attestation signature is invalid") from None
    signed = {key: value for key, value in source.items() if key != "signature"}
    signed_bytes = canonical_json_bytes(signed)
    return Task8WireModel(
        MappingProxyType(source), canonical, raw_sha256(signed_bytes),
        raw_digest=raw_sha256(canonical), signed_body_bytes=signed_bytes,
    )


def derive_provider_operation_ids(
    plan_core: Mapping[str, object],
) -> ProviderOperationIds:
    if type(plan_core) is not dict or not plan_core:
        raise ExperimentError("provider operation plan core is invalid")
    version2 = plan_core.get("schemaVersion") == 2 and plan_core.get("domain") == "rsi-promotion-plan-v2"
    try:
        core_digest = canonical_json_digest(
            {
                "schemaVersion": 2 if version2 else 1,
                "domain": "rsi-promotion-plan-core-v2" if version2 else "rsi-promotion-plan-core-v1",
                "planCore": plan_core,
            }
        )
    except (ManifestError, TypeError, ValueError, RecursionError):
        raise ExperimentError("provider operation plan core is invalid") from None

    def operation_id(operation_type: str) -> str:
        seed = canonical_json_bytes(
            {
                "schemaVersion": 2 if version2 else 1,
                "domain": "rsi-provider-operation-id-v2" if version2 else "rsi-provider-operation-id-v1",
                "operationType": operation_type,
                "planCoreDigest": core_digest,
            }
        )
        return hashlib.sha256(seed).hexdigest()[:32]

    return ProviderOperationIds(
        "op_snapshot_" + operation_id("snapshot"),
        "op_resolve_" + operation_id("resolve"),
    )


@dataclass(frozen=True, slots=True)
class PromotionPlan:
    schema_version: int
    plan_id: str
    candidate_id: str
    candidate_digest: str
    validation_attestation_digest: str
    allowlist_entry_id: str
    allowlist_entry_digest: str
    canonical_root_identity_digest: str
    rollout_manifest_digest: str
    stage_attestation_digest: str
    hook_attestation_digest: str
    provider_contract_digest: str
    provider_version_digest: str
    target: PromotionPlanTarget
    artifact: PromotionPlanArtifact
    provider_operation_ids: ProviderOperationIds
    control_plane_digest: str
    created_at: str
    expires_at: str
    _canonical_snapshot: bytes = field(init=False, repr=False, compare=False)
    _snapshot_digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ExperimentError("promotion plan schema version is invalid")
        if type(self.target) is not PromotionPlanTarget or type(
            self.artifact
        ) is not PromotionPlanArtifact or type(
            self.provider_operation_ids
        ) is not ProviderOperationIds:
            raise ExperimentError("promotion plan nested schema is invalid")
        self.target.__post_init__()
        self.artifact.__post_init__()
        self.provider_operation_ids.__post_init__()
        object.__setattr__(
            self,
            "target",
            PromotionPlanTarget(
                self.target.skill_name,
                self.target.owner_contract_hash,
                self.target.manifest_pre_hash,
                self.target.manifest_post_hash,
            ),
        )
        object.__setattr__(
            self,
            "artifact",
            PromotionPlanArtifact(
                self.artifact.relative_path,
                self.artifact.type,
                self.artifact.pre_hash,
                self.artifact.post_hash,
                self.artifact.diff_digest,
                self.artifact.post_image_ref,
            ),
        )
        object.__setattr__(
            self,
            "provider_operation_ids",
            ProviderOperationIds(
                self.provider_operation_ids.snapshot,
                self.provider_operation_ids.resolve,
            ),
        )
        _require_id(self.plan_id, "promotion plan ID")
        _require_id(self.candidate_id, "plan candidate ID")
        _require_id(self.allowlist_entry_id, "plan allowlist entry ID")
        for label, value in (
            ("candidate", self.candidate_digest),
            ("validation attestation", self.validation_attestation_digest),
            ("allowlist entry", self.allowlist_entry_digest),
            ("root identity", self.canonical_root_identity_digest),
            ("rollout manifest", self.rollout_manifest_digest),
            ("stage attestation", self.stage_attestation_digest),
            ("hook attestation", self.hook_attestation_digest),
            ("provider contract", self.provider_contract_digest),
            ("provider version", self.provider_version_digest),
            ("control plane", self.control_plane_digest),
            ("target contract", self.target.owner_contract_hash),
            ("manifest pre", self.target.manifest_pre_hash),
            ("manifest post", self.target.manifest_post_hash),
            ("artifact pre", self.artifact.pre_hash),
            ("artifact post", self.artifact.post_hash),
            ("artifact diff", self.artifact.diff_digest),
        ):
            _require_digest(value, label)
        _canonical_relative_path(self.artifact.relative_path)
        if self.artifact.type != "regular-file" or _REF_RE.fullmatch(self.artifact.post_image_ref) is None:
            raise ExperimentError("promotion plan artifact is invalid")
        if self.artifact.post_image_ref != "object:" + self.artifact.post_hash:
            raise ExperimentError("promotion plan post-image ref is invalid")
        if not self.provider_operation_ids.snapshot.startswith("op_snapshot_") or not self.provider_operation_ids.resolve.startswith("op_resolve_"):
            raise ExperimentError("promotion plan provider operation IDs are invalid")
        parse_timestamp(self.created_at)
        parse_timestamp(self.expires_at)
        created = parse_timestamp(self.created_at)
        expires = parse_timestamp(self.expires_at)
        if created >= expires or expires - created > timedelta(days=1):
            raise ExperimentError("promotion plan created/expires interval is invalid")
        if (
            self.target.manifest_pre_hash == self.target.manifest_post_hash
            or self.artifact.pre_hash == self.artifact.post_hash
        ):
            raise ExperimentError("promotion plan cannot contain a no-op pre/post image")
        core = self._live_core_mapping()
        expected_operations = derive_provider_operation_ids(core)
        if self.provider_operation_ids != expected_operations:
            raise ExperimentError(
                "promotion plan provider operation IDs are not deterministically derived"
            )
        if self.stage_attestation_digest == self.hook_attestation_digest:
            raise ExperimentError("promotion plan deployment attestations must be distinct")
        identity = {
            **core,
            "providerOperationIds": self.provider_operation_ids.to_mapping(),
        }
        snapshot = canonical_json_bytes(identity)
        snapshot_digest = raw_sha256(snapshot)
        if self.plan_id != "plan_" + snapshot_digest[7:]:
            raise ExperimentError("promotion plan ID does not match its immutable body")
        object.__setattr__(self, "_canonical_snapshot", snapshot)
        object.__setattr__(self, "_snapshot_digest", snapshot_digest)

    @classmethod
    def build(
        cls,
        *,
        candidate_id: str,
        candidate_digest: str,
        validation_attestation_digest: str,
        allowlist_entry_id: str,
        allowlist_entry_digest: str,
        canonical_root_identity_digest: str,
        rollout_manifest_digest: str,
        stage_attestation_digest: str,
        hook_attestation_digest: str,
        provider_contract_digest: str,
        provider_version_digest: str,
        target: PromotionPlanTarget,
        artifact: PromotionPlanArtifact,
        control_plane_digest: str,
        created_at: str,
        expires_at: str,
    ) -> "PromotionPlan":
        if type(target) is not PromotionPlanTarget or type(
            artifact
        ) is not PromotionPlanArtifact:
            raise ExperimentError("promotion plan factory nested models are invalid")
        core = {
            "schemaVersion": 1,
            "candidateId": candidate_id,
            "candidateDigest": candidate_digest,
            "validationAttestationDigest": validation_attestation_digest,
            "allowlistEntryId": allowlist_entry_id,
            "allowlistEntryDigest": allowlist_entry_digest,
            "canonicalRootIdentityDigest": canonical_root_identity_digest,
            "rolloutManifestDigest": rollout_manifest_digest,
            "stageAttestationDigest": stage_attestation_digest,
            "hookAttestationDigest": hook_attestation_digest,
            "providerContractDigest": provider_contract_digest,
            "providerVersionDigest": provider_version_digest,
            "target": target.to_mapping(),
            "artifact": artifact.to_mapping(),
            "controlPlaneDigest": control_plane_digest,
            "createdAt": created_at,
            "expiresAt": expires_at,
        }
        operations = derive_provider_operation_ids(core)
        identity = {**core, "providerOperationIds": operations.to_mapping()}
        return cls(
            1,
            "plan_" + canonical_json_digest(identity)[7:],
            candidate_id,
            candidate_digest,
            validation_attestation_digest,
            allowlist_entry_id,
            allowlist_entry_digest,
            canonical_root_identity_digest,
            rollout_manifest_digest,
            stage_attestation_digest,
            hook_attestation_digest,
            provider_contract_digest,
            provider_version_digest,
            PromotionPlanTarget(
                target.skill_name,
                target.owner_contract_hash,
                target.manifest_pre_hash,
                target.manifest_post_hash,
            ),
            PromotionPlanArtifact(
                artifact.relative_path,
                artifact.type,
                artifact.pre_hash,
                artifact.post_hash,
                artifact.diff_digest,
                artifact.post_image_ref,
            ),
            operations,
            control_plane_digest,
            created_at,
            expires_at,
        )

    def _live_core_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "candidateId": self.candidate_id,
            "candidateDigest": self.candidate_digest,
            "validationAttestationDigest": self.validation_attestation_digest,
            "allowlistEntryId": self.allowlist_entry_id,
            "allowlistEntryDigest": self.allowlist_entry_digest,
            "canonicalRootIdentityDigest": self.canonical_root_identity_digest,
            "rolloutManifestDigest": self.rollout_manifest_digest,
            "stageAttestationDigest": self.stage_attestation_digest,
            "hookAttestationDigest": self.hook_attestation_digest,
            "providerContractDigest": self.provider_contract_digest,
            "providerVersionDigest": self.provider_version_digest,
            "target": self.target.to_mapping(),
            "artifact": self.artifact.to_mapping(),
            "controlPlaneDigest": self.control_plane_digest,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at,
        }

    def core_mapping(self) -> dict[str, object]:
        self.assert_admitted()
        mapping = json.loads(self._canonical_snapshot.decode("utf-8"))
        mapping.pop("providerOperationIds")
        return mapping

    def identity_mapping(self) -> dict[str, object]:
        self.assert_admitted()
        return json.loads(self._canonical_snapshot.decode("utf-8"))

    def assert_admitted(self) -> None:
        try:
            self.target.__post_init__()
            self.artifact.__post_init__()
            self.provider_operation_ids.__post_init__()
            live = canonical_json_bytes(
                {
                    **self._live_core_mapping(),
                    "providerOperationIds": self.provider_operation_ids.to_mapping(),
                }
            )
            if (
                type(self._canonical_snapshot) is not bytes
                or type(self._snapshot_digest) is not str
                or live != self._canonical_snapshot
                or raw_sha256(self._canonical_snapshot) != self._snapshot_digest
                or self.plan_id != "plan_" + self._snapshot_digest[7:]
            ):
                raise ExperimentError("promotion plan changed after admission")
        except (ExperimentError, ManifestError, TypeError, ValueError, AttributeError):
            raise ExperimentError("promotion plan changed after admission") from None

    @property
    def digest(self) -> str:
        self.assert_admitted()
        return self._snapshot_digest

    def to_mapping(self) -> dict[str, object]:
        return {**self.identity_mapping(), "planId": self.plan_id}


_PROMOTION_PLAN_FIELDS = {
    "schemaVersion",
    "planId",
    "candidateId",
    "candidateDigest",
    "validationAttestationDigest",
    "allowlistEntryId",
    "allowlistEntryDigest",
    "canonicalRootIdentityDigest",
    "rolloutManifestDigest",
    "stageAttestationDigest",
    "hookAttestationDigest",
    "providerContractDigest",
    "providerVersionDigest",
    "target",
    "artifact",
    "providerOperationIds",
    "controlPlaneDigest",
    "createdAt",
    "expiresAt",
}
_PROMOTION_PLAN_TARGET_FIELDS = {
    "skillName",
    "ownerContractHash",
    "manifestPreHash",
    "manifestPostHash",
}
_PROMOTION_PLAN_ARTIFACT_FIELDS = {
    "relativePath",
    "type",
    "preHash",
    "postHash",
    "diffDigest",
    "postImageRef",
}


def _parse_promotion_plan_v2(source: dict[str, object], payload: bytes) -> Task8WireModel:
    if set(source) != _PROMOTION_PLAN_V2_FIELDS or source.get("domain") != "rsi-promotion-plan-v2":
        raise ExperimentError("promotion plan V2 schema is invalid")
    if any(value is None for value in source.values()):
        raise ExperimentError("promotion plan V2 null fields are forbidden")
    authority = _authority_mapping(source["promotionAuthority"])
    control = source.get("controlPlane")
    target = source.get("target")
    artifact = source.get("artifact")
    operations = source.get("providerOperationIds")
    if (
        not isinstance(control, dict)
        or not isinstance(target, dict)
        or not isinstance(artifact, dict)
        or not isinstance(operations, dict)
        or set(operations) != {"snapshot", "resolve"}
    ):
        raise ExperimentError("promotion plan V2 nested schema is invalid")
    if (
        source["candidateId"] != authority["candidateId"]
        or source["candidateDigest"] != authority["task7CandidateBindingDigest"]
        or source["providerContractDigest"] != authority["providerContractDigest"]
        or source["providerVersionDigest"] != authority["providerVersionDigest"]
        or control.get("policyVersion") != authority["policyVersion"]
    ):
        raise ExperimentError("promotion plan V2 authority relation is invalid")
    core = {key: value for key, value in source.items() if key not in {"planId", "providerOperationIds"}}
    expected_operations = derive_provider_operation_ids(core)
    if operations != expected_operations.to_mapping():
        raise ExperimentError("promotion plan V2 provider operations are invalid")
    identity = {**core, "providerOperationIds": operations}
    digest = canonical_json_digest(identity)
    if source["planId"] != "plan_" + digest[7:]:
        raise ExperimentError("promotion plan V2 identity is invalid")
    return Task8WireModel(MappingProxyType(source), payload, digest)


def parse_promotion_plan(payload: bytes) -> PromotionPlan | Task8WireModel:
    """Strictly re-admit canonical immutable PromotionPlan bytes."""

    try:
        source = _canonical_store_object(payload, "promotion plan")
        if source.get("schemaVersion") == 2:
            return _parse_promotion_plan_v2(source, payload)
        if set(source) != _PROMOTION_PLAN_FIELDS:
            raise ExperimentError("promotion plan schema is invalid")
        target = source["target"]
        artifact = source["artifact"]
        operations = source["providerOperationIds"]
        if (
            type(target) is not dict
            or set(target) != _PROMOTION_PLAN_TARGET_FIELDS
            or type(artifact) is not dict
            or set(artifact) != _PROMOTION_PLAN_ARTIFACT_FIELDS
            or type(operations) is not dict
            or set(operations) != {"snapshot", "resolve"}
        ):
            raise ExperimentError("promotion plan nested schema is invalid")
        plan = PromotionPlan(
            schema_version=source["schemaVersion"],
            plan_id=source["planId"],
            candidate_id=source["candidateId"],
            candidate_digest=source["candidateDigest"],
            validation_attestation_digest=source["validationAttestationDigest"],
            allowlist_entry_id=source["allowlistEntryId"],
            allowlist_entry_digest=source["allowlistEntryDigest"],
            canonical_root_identity_digest=source["canonicalRootIdentityDigest"],
            rollout_manifest_digest=source["rolloutManifestDigest"],
            stage_attestation_digest=source["stageAttestationDigest"],
            hook_attestation_digest=source["hookAttestationDigest"],
            provider_contract_digest=source["providerContractDigest"],
            provider_version_digest=source["providerVersionDigest"],
            target=PromotionPlanTarget(
                target["skillName"],
                target["ownerContractHash"],
                target["manifestPreHash"],
                target["manifestPostHash"],
            ),
            artifact=PromotionPlanArtifact(
                artifact["relativePath"],
                artifact["type"],
                artifact["preHash"],
                artifact["postHash"],
                artifact["diffDigest"],
                artifact["postImageRef"],
            ),
            provider_operation_ids=ProviderOperationIds(
                operations["snapshot"], operations["resolve"]
            ),
            control_plane_digest=source["controlPlaneDigest"],
            created_at=source["createdAt"],
            expires_at=source["expiresAt"],
        )
        if plan.to_mapping() != source:
            raise ExperimentError("promotion plan canonical re-admission changed semantics")
        return plan
    except ExperimentError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError, ManifestError) as error:
        raise ExperimentError("promotion plan schema or canonical framing is invalid") from error


@dataclass(frozen=True, slots=True)
class ExperimentBundle:
    result: ExperimentResult
    validation_attestation: VerifiedValidationAttestation
    plan: PromotionPlan | None
    request_digest: str

    def __post_init__(self) -> None:
        if (
            type(self.result) is not ExperimentResult
            or type(self.validation_attestation) is not VerifiedValidationAttestation
            or (self.plan is not None and type(self.plan) is not PromotionPlan)
        ):
            raise ExperimentError("experiment bundle nested authority is invalid")
        self.result.__post_init__()
        self.validation_attestation.__post_init__()
        try:
            self.validation_attestation.attestation.__post_init__()
            if (
                attestation_body_digest(
                    self.validation_attestation.attestation
                )
                != self.validation_attestation.digest
            ):
                raise ExperimentError(
                    "experiment bundle validation attestation digest changed"
                )
        except (AttestationError, TypeError, ValueError, AttributeError) as error:
            raise ExperimentError(
                "experiment bundle validation attestation is invalid"
            ) from error
        result = ExperimentResult(
            self.result.candidate_id,
            self.result.baseline_revision,
            self.result.variant_revision,
            self.result.harness_version,
            CaseCounts(
                self.result.cases.total,
                self.result.cases.passed_baseline,
                self.result.cases.passed_variant,
            ),
            self.result.baseline_invariants_passed,
            self.result.variant_invariants_passed,
            tuple(self.result.regressions),
            tuple(self.result.improvements),
            self.result.decision,
            tuple(self.result.artifacts),
            self.result.external_mutation_performed,
        )
        object.__setattr__(self, "result", result)
        _require_digest(self.request_digest, "experiment bundle request")
        attestation = self.validation_attestation.attestation
        if (
            result.candidate_id != attestation.candidate_id
            or result.baseline_revision != attestation.target_pre_hash
            or result.harness_version != attestation.control_plane.harness_version
            or result.artifacts != attestation.test_artifact_digests
            or result.decision != attestation.decision
        ):
            raise ExperimentError(
                "experiment bundle result/validation attestation bindings conflict"
            )
        if self.result.decision == "eligible":
            if self.plan is None:
                raise ExperimentError("eligible experiment bundle requires one plan")
            self.plan.assert_admitted()
            if (
                self.plan.candidate_id != result.candidate_id
                or self.plan.candidate_digest != attestation.candidate_digest
                or self.plan.target.manifest_pre_hash
                != result.baseline_revision
                or self.plan.target.manifest_post_hash
                != result.variant_revision
                or self.plan.target.owner_contract_hash
                != attestation.owner_contract_hash
                or self.plan.artifact.diff_digest != attestation.diff_digest
                or self.plan.created_at != attestation.created_at
                or self.plan.expires_at != attestation.expires_at
                or self.plan.validation_attestation_digest
                != self.validation_attestation.digest
            ):
                raise ExperimentError("eligible experiment bundle bindings conflict")
        elif self.plan is not None:
            raise ExperimentError("rejected experiment bundle cannot contain a plan")
        elif self.validation_attestation.attestation.decision != "rejected":
            raise ExperimentError("rejected experiment bundle attestation conflicts")


@dataclass(frozen=True, slots=True)
class ExperimentReservation:
    status: str
    directory: Path
    request_digest: str


@dataclass(frozen=True, slots=True)
class _HeldStoreLock:
    descriptor: int
    directory_descriptor: int
    name: str
    device: int
    inode: int


def _fsync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        tolerated = {errno.EINVAL}
        if hasattr(errno, "ENOTSUP"):
            tolerated.add(errno.ENOTSUP)
        if error.errno not in tolerated:
            raise


def _canonical_store_object(payload: bytes, label: str) -> dict[str, object]:
    if type(payload) is not bytes or not payload or len(payload) > _MAX_BUNDLE_BYTES:
        raise ExperimentStoreError(f"{label} bundle payload is invalid")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError):
        raise ExperimentStoreError(f"{label} bundle is not strict canonical JSON") from None
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise ExperimentStoreError(f"{label} bundle is not a canonical object")
    return value


_EXPERIMENT_REQUEST_FIELDS = {
    "schemaVersion",
    "domain",
    "operationId",
    "candidate",
    "target",
    "artifact",
    "stageAttestationRawDigest",
    "hookAttestationRawDigest",
    "stageExpectation",
    "hookExpectation",
    "controlPlane",
    "harness",
    "sandboxPolicy",
    "rolloutManifestDigest",
    "providerContractDigest",
    "providerVersionDigest",
    "rsiPackageDigest",
    "environmentIdentityDigest",
    "createdAt",
    "expiresAt",
}

_RESERVATION_REQUEST_FIELDS = {
    "schemaVersion",
    "domain",
    "operationId",
    "request",
    "requestDigest",
    "initialTrustedState",
    "initialTrustedStateFingerprint",
    "trustedT0",
    "maximumAttestationTtlSeconds",
}

_CANDIDATE_BINDING_FIELDS = {
    "schemaVersion",
    "domain",
    "lineage",
    "changeClass",
    "destinationClass",
    "evidenceRefs",
    "candidateDigest",
}
_CANDIDATE_LINEAGE_FIELDS = {
    "schemaVersion",
    "domain",
    "candidateId",
    "providerRequestDigest",
    "captureOperationId",
    "captureBindingDigest",
    "evaluationId",
    "targetSkill",
    "targetSkillVersionHash",
    "taskClass",
    "ownerSkill",
}
_TARGET_BINDING_FIELDS = {
    "skillName",
    "canonicalRoot",
    "ownerContractHash",
    "registrationManifest",
    "allowlistEntry",
    "manifestPreHash",
}
_REGISTRATION_MANIFEST_FIELDS = {
    "schemaVersion",
    "entryId",
    "skillName",
    "canonicalRoot",
    "aliases",
    "dependencies",
    "files",
}
_ALLOWLIST_ENTRY_FIELDS = {
    "entryId",
    "skillName",
    "canonicalRootIdentityDigest",
    "contractHash",
}
_ARTIFACT_PROPOSAL_FIELDS = {
    "relativePath",
    "postHash",
    "postImageRef",
    "byteSize",
}
_DEPLOYMENT_EXPECTATION_FIELDS = {
    "attestationType",
    "issuer",
    "subject",
    "scope",
    "predecessorAttestationDigest",
}
_STAGE_SUBJECT_FIELDS = {
    "rsiPackageDigest",
    "rolloutManifestDigest",
    "stageId",
    "providerContractDigest",
    "providerVersionDigest",
}
_HOOK_SUBJECT_FIELDS = {
    "rsiPackageDigest",
    "rolloutManifestDigest",
    "hookId",
    "providerContractDigest",
    "providerVersionDigest",
}
_STAGE_SCOPE_FIELDS = {
    "mode",
    "environmentIdentityDigest",
    "allowedTargetEntryDigests",
}
_HOOK_SCOPE_FIELDS = {
    "hookMode",
    "environmentIdentityDigest",
    "allowedTargetEntryDigests",
}
_CONTROL_PLANE_FIELDS = {
    "policyVersion",
    "evaluatorVersion",
    "metricRegistryVersion",
    "harnessVersion",
    "holdoutDigest",
}
_HARNESS_BINDING_FIELDS = {
    "path",
    "bytesDigest",
    "version",
    "holdoutDigest",
    "expectedCaseIds",
    "expectedInvariantIds",
}
_SANDBOX_POLICY_FIELDS = {
    "schemaVersion",
    "backend",
    "timeoutSeconds",
    "cpuSeconds",
    "memoryBytes",
    "processLimit",
    "fileDescriptorLimit",
    "fileSizeBytes",
    "outputBytes",
    "network",
    "dns",
    "subprocess",
    "environment",
}
_CURRENT_TRUSTED_STATE_FIELDS = {
    "candidateDigest",
    "providerCandidateStatus",
    "providerCandidateRecordDigest",
    "canonicalRoot",
    "registrationManifestDigest",
    "canonicalRootIdentityDigest",
    "ownerContractHash",
    "allowlistEntryDigest",
    "targetManifestDigest",
    "rsiPackageDigest",
    "rolloutManifestDigest",
    "providerContractDigest",
    "providerVersionDigest",
    "environmentIdentityDigest",
    "stageAttestationDigest",
    "hookAttestationDigest",
    "stageExpectationDigest",
    "hookExpectationDigest",
    "allowedTargetEntryDigests",
    "controlPlaneBindingDigest",
    "policyArtifactDigest",
    "evaluatorArtifactDigest",
    "metricRegistryArtifactDigest",
    "harnessPath",
    "harnessBytesDigest",
    "harnessBindingDigest",
    "controlPlaneRootsDigest",
    "sandboxPolicyDigest",
    "sandboxExecutorIdentityDigest",
    "sandboxCapabilityReportDigest",
    "controlPlaneDigest",
}
_DEPLOYMENT_EXPECTATION_ISSUER_RE = re.compile(
    r"trusted-deployment-controller:[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z"
)

_BUNDLE_ARTIFACT_DOMAINS = {
    "manifest": "rsi-experiment-manifest-artifact-v1",
    "attestation": "rsi-experiment-attestation-artifact-v1",
    "plan": "rsi-experiment-plan-artifact-v1",
}


def _closed_reservation_mapping(
    value: object, expected_fields: set[str], label: str
) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected_fields:
        raise ExperimentStoreError(f"experiment reservation {label} schema is invalid")
    return value


def _admit_reserved_candidate(value: object) -> CandidateBinding:
    source = _closed_reservation_mapping(
        value, _CANDIDATE_BINDING_FIELDS, "candidate"
    )
    lineage = _closed_reservation_mapping(
        source["lineage"], _CANDIDATE_LINEAGE_FIELDS, "candidate lineage"
    )
    evidence_refs = source["evidenceRefs"]
    if (
        type(source["schemaVersion"]) is not int
        or source["schemaVersion"] != 1
        or source["domain"] != "rsi-captured-candidate-binding-v1"
        or type(lineage["schemaVersion"]) is not int
        or lineage["schemaVersion"] != 1
        or lineage["domain"] != "rsi-captured-candidate-lineage-v1"
        or type(evidence_refs) is not list
    ):
        raise ExperimentStoreError("experiment reservation candidate schema is invalid")
    try:
        candidate = CandidateBinding(
            candidate_id=lineage["candidateId"],
            provider_request_digest=lineage["providerRequestDigest"],
            capture_operation_id=lineage["captureOperationId"],
            capture_binding_digest=lineage["captureBindingDigest"],
            evaluation_id=lineage["evaluationId"],
            target_skill=lineage["targetSkill"],
            target_skill_version_hash=lineage["targetSkillVersionHash"],
            task_class=lineage["taskClass"],
            owner_skill=lineage["ownerSkill"],
            change_class=source["changeClass"],
            destination_class=source["destinationClass"],
            evidence_refs=tuple(evidence_refs),
        )
    except (ExperimentError, TypeError, ValueError, AttributeError):
        raise ExperimentStoreError("experiment reservation candidate schema is invalid") from None
    if candidate.to_mapping() != source:
        raise ExperimentStoreError("experiment reservation candidate digest is invalid")
    return candidate


def _reserved_absolute_path(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
        or Path(value) == Path(Path(value).anchor)
        or "\x00" in value
    ):
        raise ExperimentStoreError(f"experiment reservation {label} path is invalid")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise ExperimentStoreError(
            f"experiment reservation {label} path is invalid"
        ) from None
    return value


def _reserved_string_array(value: object, label: str) -> list[str]:
    if type(value) is not list or len(value) > 256:
        raise ExperimentStoreError(
            f"experiment reservation {label} array is invalid"
        )
    result: list[str] = []
    for item in value:
        if type(item) is not str or not item or len(item) > 1024 or "\x00" in item:
            raise ExperimentStoreError(
                f"experiment reservation {label} array is invalid"
            )
        try:
            item.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise ExperimentStoreError(
                f"experiment reservation {label} array is invalid"
            ) from None
        result.append(item)
    if len(set(result)) != len(result):
        raise ExperimentStoreError(
            f"experiment reservation {label} array is invalid"
        )
    return result


def _admit_reserved_target(value: object) -> dict[str, object]:
    source = _closed_reservation_mapping(value, _TARGET_BINDING_FIELDS, "target")
    allowlist = _closed_reservation_mapping(
        source["allowlistEntry"], _ALLOWLIST_ENTRY_FIELDS, "allowlist entry"
    )
    registration = _closed_reservation_mapping(
        source["registrationManifest"],
        _REGISTRATION_MANIFEST_FIELDS,
        "target registration manifest",
    )
    root = _reserved_absolute_path(source["canonicalRoot"], "target canonical root")
    registration_root = _reserved_absolute_path(
        registration["canonicalRoot"], "registration canonical root"
    )
    aliases = _reserved_string_array(registration["aliases"], "registration aliases")
    dependencies = _reserved_string_array(
        registration["dependencies"], "registration dependencies"
    )
    files = _reserved_string_array(registration["files"], "registration files")
    for label, identifier in (
        ("target skill", source["skillName"]),
        ("registration entry", registration["entryId"]),
        ("registration skill", registration["skillName"]),
        ("allowlist entry", allowlist["entryId"]),
        ("allowlist skill", allowlist["skillName"]),
    ):
        if type(identifier) is not str or _ID_RE.fullmatch(identifier) is None:
            raise ExperimentStoreError(
                f"experiment reservation {label} identity is invalid"
            )
    for label, digest in (
        ("owner contract", source["ownerContractHash"]),
        ("target manifest", source["manifestPreHash"]),
        ("allowlist root identity", allowlist["canonicalRootIdentityDigest"]),
        ("allowlist contract", allowlist["contractHash"]),
    ):
        if type(digest) is not str or _DIGEST_RE.fullmatch(digest) is None:
            raise ExperimentStoreError(
                f"experiment reservation target {label} is invalid"
            )
    if (
        type(registration["schemaVersion"]) is not int
        or registration["schemaVersion"] != 1
        or registration["entryId"] != allowlist["entryId"]
        or registration["skillName"] != source["skillName"]
        or allowlist["skillName"] != source["skillName"]
        or registration_root != root
        or allowlist["contractHash"] != source["ownerContractHash"]
        or "SKILL.md" not in files
        or "skill-contract.json" not in files
    ):
        raise ExperimentStoreError("experiment reservation target binding is invalid")
    semantic_registration = {
        "schemaVersion": 1,
        "entryId": registration["entryId"],
        "skillName": registration["skillName"],
        "canonicalRoot": registration_root,
        "aliases": aliases,
        "dependencies": dependencies,
        "files": files,
    }
    registration_digest = canonical_json_digest(semantic_registration)
    expected_root_identity = canonical_json_digest(
        {
            "canonicalRoot": root,
            "registrationManifestDigest": registration_digest,
        }
    )
    if allowlist["canonicalRootIdentityDigest"] != expected_root_identity:
        raise ExperimentStoreError(
            "experiment reservation target root identity binding is invalid"
        )
    return source


def _admit_reserved_artifact(value: object) -> dict[str, object]:
    source = _closed_reservation_mapping(
        value, _ARTIFACT_PROPOSAL_FIELDS, "artifact"
    )
    try:
        relative_path = _canonical_relative_path(source["relativePath"])
        post_hash = _require_digest(source["postHash"], "reserved post-image")
    except (ExperimentError, TypeError, ValueError):
        raise ExperimentStoreError("experiment reservation artifact schema is invalid") from None
    if (
        type(source["postImageRef"]) is not str
        or source["postImageRef"] != f"object:{post_hash}"
        or _REF_RE.fullmatch(source["postImageRef"]) is None
        or type(source["byteSize"]) is not int
        or not (1 <= source["byteSize"] <= _MAX_POST_IMAGE_BYTES)
        or relative_path != source["relativePath"]
    ):
        raise ExperimentStoreError("experiment reservation artifact binding is invalid")
    return source


def _admit_reserved_expectation(
    value: object, expected_type: str
) -> DeploymentExpectation:
    source = _closed_reservation_mapping(
        value, _DEPLOYMENT_EXPECTATION_FIELDS, f"{expected_type} expectation"
    )
    subject_fields = (
        _STAGE_SUBJECT_FIELDS
        if expected_type == "rollout-stage"
        else _HOOK_SUBJECT_FIELDS
    )
    scope_fields = (
        _STAGE_SCOPE_FIELDS if expected_type == "rollout-stage" else _HOOK_SCOPE_FIELDS
    )
    subject = _closed_reservation_mapping(
        source["subject"], subject_fields, f"{expected_type} subject"
    )
    scope = _closed_reservation_mapping(
        source["scope"], scope_fields, f"{expected_type} scope"
    )
    allowed = scope["allowedTargetEntryDigests"]
    if (
        source["attestationType"] != expected_type
        or type(source["issuer"]) is not str
        or _DEPLOYMENT_EXPECTATION_ISSUER_RE.fullmatch(source["issuer"]) is None
        or type(allowed) is not list
    ):
        raise ExperimentStoreError(
            f"experiment reservation {expected_type} expectation schema is invalid"
        )
    try:
        if expected_type == "rollout-stage":
            admitted_subject = RolloutStageSubject(
                subject["rsiPackageDigest"],
                subject["rolloutManifestDigest"],
                subject["stageId"],
                subject["providerContractDigest"],
                subject["providerVersionDigest"],
            )
            admitted_scope = RolloutStageScope(
                scope["mode"],
                scope["environmentIdentityDigest"],
                tuple(allowed),
            )
        else:
            admitted_subject = OrchestrationHookSubject(
                subject["rsiPackageDigest"],
                subject["rolloutManifestDigest"],
                subject["hookId"],
                subject["providerContractDigest"],
                subject["providerVersionDigest"],
            )
            admitted_scope = OrchestrationHookScope(
                scope["hookMode"],
                scope["environmentIdentityDigest"],
                tuple(allowed),
            )
        expectation = DeploymentExpectation(
            expected_type,
            source["issuer"],
            admitted_subject,
            admitted_scope,
            source["predecessorAttestationDigest"],
        )
        expectation = _copy_deployment_expectation(expectation, expected_type)
        _require_digest(
            expectation.predecessor_attestation_digest,
            f"reserved {expected_type} predecessor",
        )
    except (ExperimentError, AttestationError, TypeError, ValueError, AttributeError):
        raise ExperimentStoreError(
            f"experiment reservation {expected_type} expectation schema is invalid"
        ) from None
    if _expectation_mapping(expectation) != source:
        raise ExperimentStoreError(
            f"experiment reservation {expected_type} expectation binding is invalid"
        )
    return expectation


def _admit_reserved_control_plane(value: object) -> ValidationControlPlane:
    source = _closed_reservation_mapping(
        value, _CONTROL_PLANE_FIELDS, "control-plane"
    )
    try:
        admitted = ValidationControlPlane(
            source["policyVersion"],
            source["evaluatorVersion"],
            source["metricRegistryVersion"],
            source["harnessVersion"],
            source["holdoutDigest"],
        )
    except (AttestationError, TypeError, ValueError, AttributeError):
        raise ExperimentStoreError(
            "experiment reservation control-plane schema is invalid"
        ) from None
    if admitted.to_mapping() != source:
        raise ExperimentStoreError(
            "experiment reservation control-plane binding is invalid"
        )
    return admitted


def _admit_reserved_harness(value: object) -> dict[str, object]:
    source = _closed_reservation_mapping(value, _HARNESS_BINDING_FIELDS, "harness")
    _reserved_absolute_path(source["path"], "harness")
    expected_cases = source["expectedCaseIds"]
    expected_invariants = source["expectedInvariantIds"]
    if (
        type(source["bytesDigest"]) is not str
        or _DIGEST_RE.fullmatch(source["bytesDigest"]) is None
        or type(source["holdoutDigest"]) is not str
        or _DIGEST_RE.fullmatch(source["holdoutDigest"]) is None
        or type(source["version"]) is not str
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", source["version"])
        is None
    ):
        raise ExperimentStoreError("experiment reservation harness schema is invalid")
    for label, values in (
        ("case", expected_cases),
        ("invariant", expected_invariants),
    ):
        if (
            type(values) is not list
            or not values
            or len(values) > 256
            or any(
                type(item) is not str or _CASE_RE.fullmatch(item) is None
                for item in values
            )
        ):
            raise ExperimentStoreError(
                f"experiment reservation harness expected {label} schema is invalid"
            )
        if len(set(values)) != len(values) or values != sorted(
            values, key=lambda item: item.encode("utf-8")
        ):
            raise ExperimentStoreError(
                f"experiment reservation harness expected {label} schema is invalid"
            )
    return source


def _admit_reserved_sandbox_policy(value: object) -> SandboxPolicy:
    source = _closed_reservation_mapping(
        value, _SANDBOX_POLICY_FIELDS, "sandbox policy"
    )
    if (
        type(source["schemaVersion"]) is not int
        or source["schemaVersion"] != 1
        or source["network"] != "deny"
        or source["dns"] != "deny"
        or source["subprocess"] != "deny"
        or source["environment"] != "minimal-allowlist"
    ):
        raise ExperimentStoreError("experiment reservation sandbox schema is invalid")
    try:
        admitted = SandboxPolicy(
            source["backend"],
            source["timeoutSeconds"],
            source["cpuSeconds"],
            source["memoryBytes"],
            source["processLimit"],
            source["fileDescriptorLimit"],
            source["fileSizeBytes"],
            source["outputBytes"],
        )
    except (ExperimentError, TypeError, ValueError, AttributeError):
        raise ExperimentStoreError("experiment reservation sandbox schema is invalid") from None
    if admitted.to_mapping() != source:
        raise ExperimentStoreError("experiment reservation sandbox binding is invalid")
    return admitted


def _admit_reserved_current_state(value: object) -> dict[str, object]:
    source = _closed_reservation_mapping(
        value, _CURRENT_TRUSTED_STATE_FIELDS, "initial trusted state"
    )
    allowed = source["allowedTargetEntryDigests"]
    if type(allowed) is not list:
        raise ExperimentStoreError(
            "experiment reservation initial trusted state schema is invalid"
        )
    digest_fields = _CURRENT_TRUSTED_STATE_FIELDS - {
        "providerCandidateStatus",
        "canonicalRoot",
        "harnessPath",
        "allowedTargetEntryDigests",
    }
    if any(
        type(source[field_name]) is not str
        or _DIGEST_RE.fullmatch(source[field_name]) is None
        for field_name in digest_fields
    ):
        raise ExperimentStoreError(
            "experiment reservation initial trusted state digest schema is invalid"
        )
    root = _reserved_absolute_path(source["canonicalRoot"], "trusted target root")
    _reserved_absolute_path(source["harnessPath"], "trusted harness")
    if (
        source["providerCandidateStatus"] != "pending"
        or not allowed
        or len(allowed) > 256
        or any(
            type(item) is not str or _DIGEST_RE.fullmatch(item) is None
            for item in allowed
        )
        or len(set(allowed)) != len(allowed)
        or allowed != sorted(allowed, key=lambda item: item.encode("utf-8"))
        or source["allowlistEntryDigest"] not in allowed
        or source["stageAttestationDigest"] == source["hookAttestationDigest"]
    ):
        raise ExperimentStoreError(
            "experiment reservation initial trusted state schema is invalid"
        )
    expected_provider_record = canonical_json_digest(
        {
            "candidateDigest": source["candidateDigest"],
            "providerContractDigest": source["providerContractDigest"],
            "providerVersionDigest": source["providerVersionDigest"],
            "status": "pending",
        }
    )
    expected_root_identity = canonical_json_digest(
        {
            "canonicalRoot": root,
            "registrationManifestDigest": source["registrationManifestDigest"],
        }
    )
    expected_control_plane = canonical_json_digest(
        {
            "schemaVersion": 1,
            "domain": "rsi-current-control-plane-v1",
            "bindingDigest": source["controlPlaneBindingDigest"],
            "policyArtifactDigest": source["policyArtifactDigest"],
            "evaluatorArtifactDigest": source["evaluatorArtifactDigest"],
            "metricRegistryArtifactDigest": source[
                "metricRegistryArtifactDigest"
            ],
            "harnessBytesDigest": source["harnessBytesDigest"],
            "harnessBindingDigest": source["harnessBindingDigest"],
            "harnessPath": source["harnessPath"],
            "controlPlaneRootsDigest": source["controlPlaneRootsDigest"],
            "sandboxPolicyDigest": source["sandboxPolicyDigest"],
            "sandboxExecutorIdentityDigest": source[
                "sandboxExecutorIdentityDigest"
            ],
            "sandboxCapabilityReportDigest": source[
                "sandboxCapabilityReportDigest"
            ],
            "rsiPackageDigest": source["rsiPackageDigest"],
            "rolloutManifestDigest": source["rolloutManifestDigest"],
            "stageAttestationDigest": source["stageAttestationDigest"],
            "hookAttestationDigest": source["hookAttestationDigest"],
            "stageExpectationDigest": source["stageExpectationDigest"],
            "hookExpectationDigest": source["hookExpectationDigest"],
            "allowedTargetEntryDigests": allowed,
            "providerContractDigest": source["providerContractDigest"],
            "providerVersionDigest": source["providerVersionDigest"],
            "providerCandidateRecordDigest": source[
                "providerCandidateRecordDigest"
            ],
            "environmentIdentityDigest": source["environmentIdentityDigest"],
        }
    )
    if (
        source["providerCandidateRecordDigest"] != expected_provider_record
        or source["canonicalRootIdentityDigest"] != expected_root_identity
        or source["controlPlaneDigest"] != expected_control_plane
    ):
        raise ExperimentStoreError(
            "experiment reservation initial trusted state binding is invalid"
        )
    return source


def _assert_reserved_state_matches_request(
    *,
    inner: dict[str, object],
    candidate: CandidateBinding,
    target: dict[str, object],
    stage_expectation: DeploymentExpectation,
    hook_expectation: DeploymentExpectation,
    control_plane: ValidationControlPlane,
    harness: dict[str, object],
    sandbox_policy: SandboxPolicy,
    current_state: dict[str, object],
) -> None:
    registration = target["registrationManifest"]
    allowlist = target["allowlistEntry"]
    registration_digest = canonical_json_digest(registration)
    target_allowlist_digest = canonical_json_digest(allowlist)
    stage_mapping = _expectation_mapping(stage_expectation)
    hook_mapping = _expectation_mapping(hook_expectation)
    stage_scope = stage_expectation.scope
    hook_scope = hook_expectation.scope
    expected = (
        (current_state["candidateDigest"], candidate.digest),
        (current_state["canonicalRoot"], target["canonicalRoot"]),
        (current_state["registrationManifestDigest"], registration_digest),
        (
            current_state["canonicalRootIdentityDigest"],
            allowlist["canonicalRootIdentityDigest"],
        ),
        (current_state["ownerContractHash"], target["ownerContractHash"]),
        (current_state["allowlistEntryDigest"], target_allowlist_digest),
        (current_state["targetManifestDigest"], target["manifestPreHash"]),
        (current_state["rsiPackageDigest"], inner["rsiPackageDigest"]),
        (current_state["rolloutManifestDigest"], inner["rolloutManifestDigest"]),
        (current_state["providerContractDigest"], inner["providerContractDigest"]),
        (current_state["providerVersionDigest"], inner["providerVersionDigest"]),
        (
            current_state["environmentIdentityDigest"],
            inner["environmentIdentityDigest"],
        ),
        (current_state["stageExpectationDigest"], canonical_json_digest(stage_mapping)),
        (current_state["hookExpectationDigest"], canonical_json_digest(hook_mapping)),
        (
            tuple(current_state["allowedTargetEntryDigests"]),
            tuple(stage_scope.allowed_target_entry_digests),
        ),
        (
            current_state["controlPlaneBindingDigest"],
            canonical_json_digest(control_plane.to_mapping()),
        ),
        (current_state["harnessPath"], harness["path"]),
        (current_state["harnessBytesDigest"], harness["bytesDigest"]),
        (current_state["harnessBindingDigest"], canonical_json_digest(harness)),
        (current_state["sandboxPolicyDigest"], sandbox_policy.digest),
    )
    if (
        any(actual != wanted for actual, wanted in expected)
        or stage_scope.allowed_target_entry_digests
        != hook_scope.allowed_target_entry_digests
        or control_plane.harness_version != harness["version"]
        or control_plane.holdout_digest != harness["holdoutDigest"]
    ):
        raise ExperimentStoreError(
            "experiment reservation request/state relation is invalid"
        )


def _validate_reservation_request(operation_id: str, payload: bytes) -> dict[str, object]:
    if type(payload) is not bytes or not payload or len(payload) > _MAX_REQUEST_BYTES:
        raise ExperimentStoreError("experiment request reservation is invalid")
    request = _canonical_store_object(payload, "request")
    if request.get("schemaVersion") == 2:
        try:
            parsed = parse_experiment_reservation_v2(payload)
        except ExperimentError as error:
            raise ExperimentStoreError(f"experiment V2 reservation is invalid: {error}") from None
        result = parsed.to_mapping()
        if result.get("operationId") != operation_id:
            raise ExperimentStoreError("experiment request schema/domain/operation binding is invalid")
        return result
    if (
        set(request) != _RESERVATION_REQUEST_FIELDS
        or type(request.get("schemaVersion")) is not int
        or request.get("schemaVersion") != 1
        or request.get("domain") != "rsi-isolated-experiment-reservation-v1"
        or type(request.get("operationId")) is not str
        or request.get("operationId") != operation_id
    ):
        raise ExperimentStoreError("experiment request schema/domain/operation binding is invalid")
    inner = request["request"]
    trusted_state = request["initialTrustedState"]
    if (
        type(inner) is not dict
        or set(inner) != _EXPERIMENT_REQUEST_FIELDS
        or inner.get("schemaVersion") != 1
        or type(inner.get("schemaVersion")) is not int
        or inner.get("domain") != "rsi-isolated-experiment-request-v1"
        or inner.get("operationId") != operation_id
        or type(request["requestDigest"]) is not str
        or request["requestDigest"] != canonical_json_digest(inner)
        or type(trusted_state) is not dict
        or not trusted_state
        or type(request["initialTrustedStateFingerprint"]) is not str
        or request["initialTrustedStateFingerprint"]
        != canonical_json_digest(trusted_state)
        or type(request["maximumAttestationTtlSeconds"]) is not int
        or not (1 <= request["maximumAttestationTtlSeconds"] <= 86400)
    ):
        raise ExperimentStoreError(
            "experiment reservation request/state/TTL binding is invalid"
        )
    for field_name in (
        "stageAttestationRawDigest",
        "hookAttestationRawDigest",
        "rolloutManifestDigest",
        "providerContractDigest",
        "providerVersionDigest",
        "rsiPackageDigest",
        "environmentIdentityDigest",
    ):
        value = inner[field_name]
        if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
            raise ExperimentStoreError("experiment request digest binding is invalid")
    if inner["stageAttestationRawDigest"] == inner["hookAttestationRawDigest"]:
        raise ExperimentStoreError(
            "experiment request deployment attestation refs are not distinct"
        )
    candidate = _admit_reserved_candidate(inner["candidate"])
    target = _admit_reserved_target(inner["target"])
    artifact = _admit_reserved_artifact(inner["artifact"])
    stage_expectation = _admit_reserved_expectation(
        inner["stageExpectation"], "rollout-stage"
    )
    hook_expectation = _admit_reserved_expectation(
        inner["hookExpectation"], "orchestration-hook"
    )
    control_plane = _admit_reserved_control_plane(inner["controlPlane"])
    harness = _admit_reserved_harness(inner["harness"])
    sandbox_policy = _admit_reserved_sandbox_policy(inner["sandboxPolicy"])
    current_state = _admit_reserved_current_state(trusted_state)
    target_allowlist_digest = canonical_json_digest(target["allowlistEntry"])
    stage_subject = stage_expectation.subject
    hook_subject = hook_expectation.subject
    stage_scope = stage_expectation.scope
    hook_scope = hook_expectation.scope
    if (
        candidate.target_skill != target["skillName"]
        or candidate.owner_skill != target["skillName"]
        or candidate.target_skill_version_hash != target["manifestPreHash"]
        or (
            candidate.destination_class == "skill"
            and artifact["relativePath"] != "SKILL.md"
        )
        or (
            candidate.destination_class == "reference"
            and not artifact["relativePath"].startswith("references/")
        )
        or stage_subject.rsi_package_digest != inner["rsiPackageDigest"]
        or hook_subject.rsi_package_digest != inner["rsiPackageDigest"]
        or stage_subject.rollout_manifest_digest != inner["rolloutManifestDigest"]
        or hook_subject.rollout_manifest_digest != inner["rolloutManifestDigest"]
        or stage_subject.provider_contract_digest != inner["providerContractDigest"]
        or hook_subject.provider_contract_digest != inner["providerContractDigest"]
        or stage_subject.provider_version_digest != inner["providerVersionDigest"]
        or hook_subject.provider_version_digest != inner["providerVersionDigest"]
        or stage_scope.environment_identity_digest
        != inner["environmentIdentityDigest"]
        or hook_scope.environment_identity_digest
        != inner["environmentIdentityDigest"]
        or stage_scope.allowed_target_entry_digests
        != hook_scope.allowed_target_entry_digests
        or target_allowlist_digest not in stage_scope.allowed_target_entry_digests
        or control_plane.harness_version != harness["version"]
        or control_plane.holdout_digest != harness["holdoutDigest"]
    ):
        raise ExperimentStoreError(
            "experiment reservation nested request relation is invalid"
        )
    _assert_reserved_state_matches_request(
        inner=inner,
        candidate=candidate,
        target=target,
        stage_expectation=stage_expectation,
        hook_expectation=hook_expectation,
        control_plane=control_plane,
        harness=harness,
        sandbox_policy=sandbox_policy,
        current_state=current_state,
    )
    try:
        created = parse_timestamp(inner["createdAt"])
        expires = parse_timestamp(inner["expiresAt"])
        trusted_t0 = parse_timestamp(request["trustedT0"])
    except (AttestationError, TypeError, ValueError, OverflowError):
        raise ExperimentStoreError("experiment request time binding is invalid") from None
    if (
        created >= expires
        or not (created <= trusted_t0 < expires)
        or trusted_t0.microsecond != 0
        or expires - created
        > timedelta(seconds=request["maximumAttestationTtlSeconds"])
    ):
        raise ExperimentStoreError("experiment request time binding is invalid")
    return request


def _validate_bundle_artifact(
    payload: bytes,
    label: str,
    *,
    operation_id: str,
    request_digest: str,
) -> dict[str, object]:
    artifact = _canonical_store_object(payload, label)
    if (
        set(artifact)
        != {
            "schemaVersion",
            "domain",
            "operationId",
            "requestDigest",
            "payloadDigest",
            "payload",
        }
        or type(artifact.get("schemaVersion")) is not int
        or artifact.get("schemaVersion") != 1
        or artifact.get("domain") != _BUNDLE_ARTIFACT_DOMAINS[label]
        or artifact.get("operationId") != operation_id
        or artifact.get("requestDigest") != request_digest
        or type(artifact.get("payload")) is not dict
        or not artifact.get("payload")
        or type(artifact.get("payloadDigest")) is not str
        or artifact.get("payloadDigest")
        != canonical_json_digest(artifact["payload"])
    ):
        raise ExperimentStoreError(f"{label} bundle artifact schema is invalid")
    return artifact


_BUNDLE_ARTIFACT_V2_DOMAINS = {
    "manifest": "rsi-experiment-manifest-artifact-v2",
    "attestation": "rsi-experiment-attestation-artifact-v2",
    "plan": "rsi-experiment-plan-artifact-v2",
}
_BUNDLE_PAYLOAD_V2_FIELDS = {
    "manifest": {"decision", "requestDigest", "result", "resultDigest", "manifestPre", "manifestPreDigest", "manifestPost", "manifestPostDigest", "replacement", "sandboxExecution", "sandboxExecutionDigest", "promotionAuthority"},
    "attestation": {"decision", "validationAttestation", "validationAttestationDigest", "validationAttestationRawDigest", "promotionAuthority"},
    "plan": {"decision", "plan", "planDigest", "promotionAuthority"},
}
_RESULT_MARKER_V2_FIELDS = {
    "schemaVersion", "domain", "operationId", "operationKey", "requestDigest",
    "manifestArtifactDigest", "attestationArtifactDigest", "planArtifactDigest", "decision",
    "stageDeploymentAttestationRef", "stageDeploymentAttestationRawDigest",
    "hookDeploymentAttestationRef", "hookDeploymentAttestationRawDigest",
    "artifactStoreIdentityDigest", "task7CandidateBindingDigest",
    "candidateCaptureLineageBindingDigest", "candidateFullRecordDigest",
    "providerAuthorityBindingDigest", "candidateStateBindingDigest", "task8ControlPlaneVersion",
    "task8AddendumDigest", "task8AddendumMarkdownDigest", "controlPlaneDigest",
}


def _validate_bundle_artifact_v2(
    payload: bytes, label: str, *, operation_id: str, reservation_digest: str
) -> dict[str, object]:
    artifact = _canonical_store_object(payload, label)
    expected = {"schemaVersion", "domain", "operationId", "requestDigest", "payloadDigest", "payload"}
    nested = artifact.get("payload")
    if (
        set(artifact) != expected
        or artifact.get("schemaVersion") != 2
        or artifact.get("domain") != _BUNDLE_ARTIFACT_V2_DOMAINS[label]
        or artifact.get("operationId") != operation_id
        or artifact.get("requestDigest") != reservation_digest
        or not isinstance(nested, dict)
        or set(nested) != _BUNDLE_PAYLOAD_V2_FIELDS[label]
        or artifact.get("payloadDigest") != canonical_json_digest(nested)
    ):
        raise ExperimentStoreError(f"{label} V2 bundle artifact schema is invalid")
    _authority_mapping(nested["promotionAuthority"])
    return artifact


def _artifact_store_identity_mapping(home: Path) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "domain": "rsi-experiment-store-identity-v1",
        "canonicalPath": str(home.resolve(strict=False)),
        "markerName": _STORE_MARKER,
        "markerDigest": raw_sha256(_STORE_MARKER_BYTES),
        "requiredTopology": [
            "experiments", "locks", "locks/experiments", "locks/objects",
            "objects", "objects/post-images",
        ],
    }


class ExperimentArtifactStore:
    """Private, descriptor-relative, write-once experiment artifact namespace."""

    def __init__(
        self,
        home: Path | str,
        *,
        fault_injector: Callable[[str], None] | None = None,
        _read_only: bool = False,
    ) -> None:
        self.home = Path(os.path.abspath(os.fspath(home)))
        if self.home in {Path(self.home.anchor), Path.home(), Path.cwd()}:
            raise ExperimentStoreError("unsafe experiment store topology: broad home")
        self._fault_injector = fault_injector
        self._read_only = _read_only
        if _read_only:
            self._verify_owned_home(
                wait_for_initializer=False,
                wait_for_marker_publication=True,
            )
            self._verify_required_topology()
            return
        self._initialize_owned_home()

    @classmethod
    def open_existing(cls, home: Path | str) -> "ExperimentArtifactStore":
        """Open an initialized store without creating or changing any metadata."""

        return cls(home, _read_only=True)

    def _initialize_owned_home(self) -> None:
        parent_fd = self._open_absolute(self.home.parent, create=False)
        created = False
        try:
            try:
                os.mkdir(self.home.name, 0o700, dir_fd=parent_fd)
                created = True
                _fsync_directory(parent_fd)
            except FileExistsError:
                pass
        finally:
            os.close(parent_fd)
        if created:
            home_fd = self._open_absolute(self.home, create=False)
            try:
                metadata = os.fstat(home_fd)
                if stat.S_IMODE(metadata.st_mode) != 0o700:
                    raise ExperimentStoreError("experiment store home is not private")
                for relative in _STORE_REQUIRED_DIRECTORIES:
                    descriptor = self._initialize_relative_directory_at(
                        home_fd, relative
                    )
                    os.close(descriptor)
                _fsync_directory(home_fd)
                self._write_once(home_fd, _STORE_MARKER, _STORE_MARKER_BYTES)
            except BaseException:
                os.close(home_fd)
                raise
            os.close(home_fd)
        self._verify_owned_home(wait_for_initializer=not created)
        self._verify_required_topology()

    @staticmethod
    def _initialize_relative_directory_at(
        home_descriptor: int, relative: str
    ) -> int:
        """Create fixed infrastructure beneath an unmarked pinned new home."""

        descriptor = os.dup(home_descriptor)
        try:
            for part in PurePosixPath(relative).parts:
                if part in {"", ".", ".."}:
                    raise ExperimentStoreError(
                        "unsafe experiment store initialization path"
                    )
                try:
                    metadata = os.stat(
                        part, dir_fd=descriptor, follow_symlinks=False
                    )
                except FileNotFoundError:
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                        _fsync_directory(descriptor)
                    except FileExistsError:
                        pass
                    metadata = os.stat(
                        part, dir_fd=descriptor, follow_symlinks=False
                    )
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise ExperimentStoreError(
                        "experiment store initialization topology is unsafe"
                    )
                child = os.open(
                    part,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=descriptor,
                )
                opened = os.fstat(child)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or stat.S_IMODE(opened.st_mode) != 0o700
                    or (opened.st_dev, opened.st_ino)
                    != (metadata.st_dev, metadata.st_ino)
                ):
                    os.close(child)
                    raise ExperimentStoreError(
                        "experiment store initialization directory changed"
                    )
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _verify_required_topology(self) -> None:
        """Require the complete fixed infrastructure authorized by the marker."""

        home_descriptor = self._open_verified_home()
        try:
            expected_root = {
                _STORE_MARKER,
                "locks",
                "objects",
                "experiments",
            }
            if self._closed_directory_names(home_descriptor) != expected_root:
                raise ExperimentStoreError(
                    "experiment store fixed topology is incomplete or unclosed"
                )
            for relative in _STORE_REQUIRED_DIRECTORIES:
                descriptor = self._open_relative_directory_at(
                    home_descriptor, relative
                )
                try:
                    if relative == "locks" and self._closed_directory_names(
                        descriptor
                    ) != {"experiments", "objects"}:
                        raise ExperimentStoreError(
                            "experiment store lock topology is incomplete or unclosed"
                        )
                    if relative == "objects" and self._closed_directory_names(
                        descriptor
                    ) != {"post-images"}:
                        raise ExperimentStoreError(
                            "experiment store object topology is incomplete or unclosed"
                        )
                finally:
                    os.close(descriptor)
            self._assert_pinned_home(home_descriptor)
        finally:
            os.close(home_descriptor)

    @staticmethod
    def _is_marker_publication_transient(home_fd: int) -> bool:
        """Recognize only `_write_once`'s exact marker/temp hard-link window."""

        marker_fd: int | None = None
        temporary_fd: int | None = None
        try:
            with os.scandir(home_fd) as entries:
                names: list[str] = []
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > 5:
                        return False
            temporary_names = [
                name for name in names if _STORE_MARKER_TEMP_RE.fullmatch(name)
            ]
            if (
                len(temporary_names) != 1
                or set(names)
                != {
                    _STORE_MARKER,
                    temporary_names[0],
                    "locks",
                    "objects",
                    "experiments",
                }
            ):
                return False
            temporary_name = temporary_names[0]
            marker_named = os.stat(
                _STORE_MARKER, dir_fd=home_fd, follow_symlinks=False
            )
            temporary_named = os.stat(
                temporary_name, dir_fd=home_fd, follow_symlinks=False
            )
            marker_fd = os.open(
                _STORE_MARKER,
                os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=home_fd,
            )
            temporary_fd = os.open(
                temporary_name,
                os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=home_fd,
            )
            marker_opened = os.fstat(marker_fd)
            temporary_opened = os.fstat(temporary_fd)
            identities = {
                (metadata.st_dev, metadata.st_ino)
                for metadata in (
                    marker_named,
                    temporary_named,
                    marker_opened,
                    temporary_opened,
                )
            }
            if (
                len(identities) != 1
                or any(
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_nlink != 2
                    or metadata.st_size != len(_STORE_MARKER_BYTES)
                    for metadata in (
                        marker_named,
                        temporary_named,
                        marker_opened,
                        temporary_opened,
                    )
                )
            ):
                return False
            payload = os.read(marker_fd, len(_STORE_MARKER_BYTES) + 1)
            return payload == _STORE_MARKER_BYTES
        except (OSError, ExperimentStoreError):
            return False
        finally:
            if marker_fd is not None:
                os.close(marker_fd)
            if temporary_fd is not None:
                os.close(temporary_fd)

    def _verify_owned_home(
        self,
        *,
        wait_for_initializer: bool,
        wait_for_marker_publication: bool = False,
    ) -> None:
        try:
            metadata = self.home.lstat()
        except FileNotFoundError:
            raise ExperimentStoreError("experiment store is absent") from None
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ExperimentStoreError("unsafe or unowned experiment store topology")
        attempts = (
            _STORE_INITIALIZER_ATTEMPTS
            if wait_for_initializer or wait_for_marker_publication
            else 1
        )
        for attempt in range(attempts):
            retryable = False
            home_fd = self._open_absolute(self.home, create=False)
            try:
                try:
                    marker = self._read_named(home_fd, _STORE_MARKER)
                except FileNotFoundError:
                    marker = None
                    retryable = wait_for_initializer
                except ExperimentStoreError as error:
                    if wait_for_initializer:
                        marker = None
                        retryable = True
                    elif (
                        wait_for_marker_publication
                        and self._is_marker_publication_transient(home_fd)
                    ):
                        marker = None
                        retryable = True
                    elif wait_for_marker_publication:
                        try:
                            marker = self._read_named(home_fd, _STORE_MARKER)
                        except (FileNotFoundError, ExperimentStoreError):
                            raise error
                    else:
                        raise
            finally:
                os.close(home_fd)
            if marker is not None:
                if marker != _STORE_MARKER_BYTES:
                    raise ExperimentStoreError("experiment store ownership marker is invalid")
                return
            if not retryable:
                break
            if attempt + 1 < attempts:
                time.sleep(_STORE_INITIALIZER_RETRY_SECONDS)
        raise ExperimentStoreError("existing directory is not an owned experiment store")

    @staticmethod
    def _parts(path: Path) -> tuple[str, ...]:
        return tuple(part for part in path.parts if part not in {path.anchor, ""})

    @classmethod
    def _open_absolute(
        cls, path: Path, *, create: bool, private_final: bool = False
    ) -> int:
        absolute = Path(os.path.abspath(os.fspath(path)))
        descriptor = os.open(absolute.anchor, os.O_RDONLY | _DIRECTORY)
        parts = cls._parts(absolute)
        try:
            for index, part in enumerate(parts):
                try:
                    metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    if not create:
                        raise ExperimentStoreError("unsafe experiment store topology: directory is absent") from None
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                        _fsync_directory(descriptor)
                    except FileExistsError:
                        pass
                    metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    raise ExperimentStoreError("unsafe experiment store topology: symlink or non-directory")
                try:
                    child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=descriptor)
                except OSError as error:
                    raise ExperimentStoreError("unsafe experiment store topology: no-follow open failed") from error
                opened = os.fstat(child)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                ):
                    os.close(child)
                    raise ExperimentStoreError("unsafe experiment store topology: directory changed")
                os.close(descriptor)
                descriptor = child
                if private_final and index == len(parts) - 1:
                    opened = os.fstat(descriptor)
                    if stat.S_IMODE(opened.st_mode) != 0o700:
                        raise ExperimentStoreError("experiment store home is not private")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _open_home(self) -> int:
        return self._open_absolute(self.home, create=False)

    def _open_verified_home(self) -> int:
        self._verify_owned_home(wait_for_initializer=False)
        descriptor = self._open_home()
        try:
            self._assert_pinned_home(descriptor)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _assert_pinned_home(self, descriptor: int) -> None:
        try:
            opened = os.fstat(descriptor)
            named = self.home.lstat()
            marker = self._read_named(descriptor, _STORE_MARKER)
        except (FileNotFoundError, OSError) as error:
            raise ExperimentStoreError("experiment store home identity changed") from error
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o700
            or stat.S_IMODE(named.st_mode) != 0o700
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or marker != _STORE_MARKER_BYTES
        ):
            raise ExperimentStoreError("experiment store home identity changed")

    def _open_relative_directory_at(
        self,
        home_descriptor: int,
        relative: str,
        *,
        create: bool = False,
    ) -> int:
        self._assert_pinned_home(home_descriptor)
        descriptor = os.dup(home_descriptor)
        try:
            for part in PurePosixPath(relative).parts:
                if part in {"", ".", ".."}:
                    raise ExperimentStoreError("unsafe experiment store relative directory")
                try:
                    metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    if not create:
                        raise ExperimentStoreError("experiment store directory is absent") from None
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                        _fsync_directory(descriptor)
                    except FileExistsError:
                        pass
                    metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    raise ExperimentStoreError("unsafe experiment store topology: internal symlink")
                child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=descriptor)
                opened = os.fstat(child)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                ):
                    os.close(child)
                    raise ExperimentStoreError("unsafe experiment store topology: directory changed")
                os.close(descriptor)
                descriptor = child
                if stat.S_IMODE(opened.st_mode) != 0o700:
                    raise ExperimentStoreError("experiment store directory is not private")
            self._assert_pinned_home(home_descriptor)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _open_relative_directory(self, relative: str, *, create: bool = False) -> int:
        home_descriptor = self._open_verified_home()
        try:
            return self._open_relative_directory_at(
                home_descriptor, relative, create=create
            )
        finally:
            os.close(home_descriptor)

    @staticmethod
    def _operation_key(operation_id: str) -> str:
        _require_id(operation_id, "experiment operation ID")
        return hashlib.sha256(operation_id.encode("utf-8")).hexdigest()

    def _named_lock_descriptor(
        self,
        relative_directory: str,
        name: str,
        *,
        home_descriptor: int | None = None,
    ) -> _HeldStoreLock:
        if (
            type(name) is not str
            or not name.endswith(".lock")
            or re.fullmatch(r"[0-9a-f]{64}\.lock", name) is None
        ):
            raise ExperimentStoreError("experiment store lock name is invalid")
        directory = (
            self._open_relative_directory(relative_directory)
            if home_descriptor is None
            else self._open_relative_directory_at(
                home_descriptor, relative_directory
            )
        )
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(
                    name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
                _fsync_directory(directory)
            except FileExistsError:
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDWR | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=directory,
                    )
                except OSError as error:
                    raise ExperimentStoreError(
                        "experiment operation lock cannot be opened safely"
                    ) from error
            except OSError as error:
                raise ExperimentStoreError("experiment operation lock cannot be opened safely") from error
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                os.close(descriptor)
                descriptor = None
                raise ExperimentStoreError("experiment operation lock topology is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            held = _HeldStoreLock(
                descriptor=descriptor,
                directory_descriptor=directory,
                name=name,
                device=metadata.st_dev,
                inode=metadata.st_ino,
            )
            self._assert_held_lock(held)
            return held
        except BaseException:
            if descriptor is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(descriptor)
            os.close(directory)
            raise

    def _lock_descriptor(
        self, operation_id: str, *, home_descriptor: int | None = None
    ) -> _HeldStoreLock:
        key = self._operation_key(operation_id)
        return self._named_lock_descriptor(
            "locks/experiments",
            key + ".lock",
            home_descriptor=home_descriptor,
        )

    @staticmethod
    def _assert_held_lock(lock: _HeldStoreLock) -> None:
        try:
            named = os.stat(
                lock.name,
                dir_fd=lock.directory_descriptor,
                follow_symlinks=False,
            )
            opened = os.fstat(lock.descriptor)
        except OSError as error:
            raise ExperimentStoreError("experiment operation lock topology changed") from error
        if (
            not stat.S_ISREG(named.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or named.st_nlink != 1
            or opened.st_nlink != 1
            or stat.S_IMODE(named.st_mode) != 0o600
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
            or (opened.st_dev, opened.st_ino) != (lock.device, lock.inode)
        ):
            raise ExperimentStoreError("experiment operation lock topology changed")

    @classmethod
    def _close_lock(cls, lock: _HeldStoreLock) -> None:
        validation_error: BaseException | None = None
        try:
            cls._assert_held_lock(lock)
        except BaseException as error:
            validation_error = error
        finally:
            try:
                fcntl.flock(lock.descriptor, fcntl.LOCK_UN)
            finally:
                os.close(lock.descriptor)
                os.close(lock.directory_descriptor)
        if validation_error is not None:
            raise validation_error

    def _read_named(self, directory: int, name: str, *, max_bytes: int = _MAX_BUNDLE_BYTES) -> bytes:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory,
            )
        except FileNotFoundError:
            raise
        except OSError as error:
            raise ExperimentStoreError("immutable experiment artifact cannot be opened safely") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size < 0
                or metadata.st_size > max_bytes
            ):
                raise ExperimentStoreError("immutable experiment artifact topology is unsafe")
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            if len(payload) > max_bytes or len(payload) != metadata.st_size:
                raise ExperimentStoreError("immutable experiment artifact exceeds its byte bound")
            return payload
        finally:
            os.close(descriptor)

    def _inject(self, point: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(point)

    def _require_writable(self) -> None:
        if self._read_only:
            raise ExperimentStoreError(
                "read-only experiment store cannot perform mutation or publish"
            )

    def _write_once(
        self,
        directory: int,
        name: str,
        payload: bytes,
        *,
        inject_faults: bool = False,
        max_bytes: int = _MAX_BUNDLE_BYTES,
    ) -> None:
        if type(payload) is not bytes or not payload or len(payload) > max_bytes:
            raise ExperimentStoreError("immutable experiment artifact payload is invalid")
        try:
            existing = self._read_named(directory, name, max_bytes=max_bytes)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if existing != payload:
                raise ExperimentConflict("immutable experiment artifact conflicts with existing bytes")
            _fsync_directory(directory)
            published = self._read_named(directory, name, max_bytes=max_bytes)
            if published != payload:
                raise ExperimentStoreError(
                    "immutable experiment artifact equal-existing readback is tampered"
                )
            return
        temporary = ".tmp-" + secrets.token_hex(16)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            os.fchmod(descriptor, 0o600)
            if inject_faults:
                self._inject("short-write")
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short write")
                offset += written
            if inject_faults:
                self._inject("fsync")
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            try:
                if inject_faults:
                    self._inject("link")
                os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            except FileExistsError:
                existing = self._read_named(directory, name, max_bytes=max_bytes)
                if existing != payload:
                    raise ExperimentConflict("immutable experiment artifact publish conflict")
            finally:
                try:
                    if inject_faults:
                        self._inject("temp-unlink")
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
            if inject_faults:
                self._inject("dir-fsync")
            _fsync_directory(directory)
            if inject_faults:
                self._inject("readback")
            published = self._read_named(directory, name, max_bytes=max_bytes)
            if published != payload:
                raise ExperimentStoreError(
                    "immutable experiment artifact readback is tampered"
                )
        except (ExperimentError, OSError) as error:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            if isinstance(error, ExperimentError):
                raise
            raise ExperimentStoreError("immutable experiment artifact publish failed") from error

    def reserve(self, operation_id: str, request_bytes: bytes) -> ExperimentReservation:
        self._require_writable()
        _validate_reservation_request(operation_id, request_bytes)
        key = self._operation_key(operation_id)
        home_descriptor = self._open_verified_home()
        lock: _HeldStoreLock | None = None
        try:
            lock = self._lock_descriptor(
                operation_id, home_descriptor=home_descriptor
            )
            directory = self._open_relative_directory_at(
                home_descriptor, f"experiments/{key}", create=True
            )
            try:
                self._assert_pinned_home(home_descriptor)
                self._assert_held_lock(lock)
                try:
                    prior = self._read_named(directory, "request.json", max_bytes=_MAX_REQUEST_BYTES)
                except FileNotFoundError:
                    self._assert_pinned_home(home_descriptor)
                    self._assert_held_lock(lock)
                    self._write_once(directory, "request.json", request_bytes)
                    status = "reserved"
                else:
                    if prior != request_bytes:
                        raise ExperimentConflict("experiment operation ID conflicts with another request")
                    status = "replay"
                self._assert_pinned_home(home_descriptor)
                self._assert_held_lock(lock)
            finally:
                os.close(directory)
        finally:
            try:
                if lock is not None:
                    self._close_lock(lock)
                self._assert_pinned_home(home_descriptor)
            finally:
                os.close(home_descriptor)
        return ExperimentReservation(status, self.home / "experiments" / key, raw_sha256(request_bytes))

    def read_reservation(self, operation_id: str) -> bytes | None:
        """Read one existing canonical reservation without locks or mutation."""

        key = self._operation_key(operation_id)
        home_descriptor = self._open_verified_home()
        try:
            experiments = self._open_relative_directory_at(
                home_descriptor, "experiments"
            )
            try:
                try:
                    before = os.stat(
                        key, dir_fd=experiments, follow_symlinks=False
                    )
                except FileNotFoundError:
                    self._assert_pinned_home(home_descriptor)
                    return None
                if (
                    not stat.S_ISDIR(before.st_mode)
                    or stat.S_ISLNK(before.st_mode)
                    or stat.S_IMODE(before.st_mode) != 0o700
                ):
                    raise ExperimentStoreError(
                        "experiment reservation directory topology is unsafe"
                    )
                directory = os.open(
                    key,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=experiments,
                )
                try:
                    opened = os.fstat(directory)
                    if not _same_open_identity(before, opened):
                        raise ExperimentStoreError(
                            "experiment reservation directory changed during open"
                        )
                    try:
                        payload = self._read_named(
                            directory,
                            "request.json",
                            max_bytes=_MAX_REQUEST_BYTES,
                        )
                    except FileNotFoundError:
                        self._assert_pinned_home(home_descriptor)
                        return None
                    rebound = os.stat(
                        key, dir_fd=experiments, follow_symlinks=False
                    )
                    if not _same_open_identity(opened, rebound):
                        raise ExperimentStoreError(
                            "experiment reservation directory path was rebound"
                        )
                    _validate_reservation_request(operation_id, payload)
                    self._assert_pinned_home(home_descriptor)
                    return payload
                finally:
                    os.close(directory)
            finally:
                os.close(experiments)
        finally:
            os.close(home_descriptor)

    def _validate_result_marker(
        self,
        directory: int,
        *,
        operation_id: str,
        operation_key: str,
        manifest: bytes,
        attestation: bytes,
        plan: bytes,
        result: bytes,
        stage_deployment_attestation: bytes | None = None,
        hook_deployment_attestation: bytes | None = None,
    ) -> dict[str, object]:
        marker = _canonical_store_object(result, "result")
        if marker.get("schemaVersion") == 2:
            if (
                set(marker) != _RESULT_MARKER_V2_FIELDS
                or marker.get("domain") != "rsi-experiment-result-marker-v2"
                or marker.get("decision") not in {"eligible", "rejected"}
                or marker.get("operationId") != operation_id
                or marker.get("operationKey") != operation_key
                or stage_deployment_attestation is None
                or hook_deployment_attestation is None
            ):
                raise ExperimentStoreError("authoritative V2 result marker schema is invalid")
            request = self._read_named(directory, "request.json", max_bytes=_MAX_REQUEST_BYTES)
            reservation = parse_experiment_reservation_v2(request)
            reservation_digest = raw_sha256(request)
            artifacts = {
                label: _validate_bundle_artifact_v2(
                    value, label, operation_id=operation_id,
                    reservation_digest=reservation_digest,
                )
                for label, value in (("manifest", manifest), ("attestation", attestation), ("plan", plan))
            }
            authorities = [artifact["payload"]["promotionAuthority"] for artifact in artifacts.values()]
            authority = authorities[0]
            if any(value != authority for value in authorities[1:]):
                raise ExperimentStoreError("V2 bundle promotion authority mismatch")
            parsed_authority = parse_promotion_authority_v2(canonical_json_bytes(authority))
            plan_model = parse_promotion_plan(canonical_json_bytes(artifacts["plan"]["payload"]["plan"]))
            if not isinstance(plan_model, Task8WireModel):
                raise ExperimentStoreError("V2 bundle plan is ineligible")
            if artifacts["plan"]["payload"]["planDigest"] != plan_model.digest:
                raise ExperimentStoreError("V2 bundle plan digest is invalid")
            expected = {
                "requestDigest": reservation_digest,
                "manifestArtifactDigest": raw_sha256(manifest),
                "attestationArtifactDigest": raw_sha256(attestation),
                "planArtifactDigest": raw_sha256(plan),
                "stageDeploymentAttestationRawDigest": raw_sha256(stage_deployment_attestation),
                "hookDeploymentAttestationRawDigest": raw_sha256(hook_deployment_attestation),
                "artifactStoreIdentityDigest": canonical_json_digest(_artifact_store_identity_mapping(self.home)),
                "task7CandidateBindingDigest": authority["task7CandidateBindingDigest"],
                "candidateCaptureLineageBindingDigest": authority["candidateCaptureLineageBindingDigest"],
                "candidateFullRecordDigest": authority["candidateFullRecordDigest"],
                "providerAuthorityBindingDigest": authority["providerAuthorityBindingDigest"],
                "candidateStateBindingDigest": authority["candidateStateBindingDigest"],
                "task8ControlPlaneVersion": authority["task8ControlPlaneVersion"],
                "task8AddendumDigest": authority["task8AddendumDigest"],
                "task8AddendumMarkdownDigest": authority["task8AddendumMarkdownDigest"],
                "controlPlaneDigest": artifacts["plan"]["payload"]["plan"]["controlPlaneDigest"],
            }
            if marker.get("artifactStoreIdentityDigest") != expected["artifactStoreIdentityDigest"]:
                raise ExperimentStoreError("V2 artifact store identity/path binding is invalid")
            if any(marker.get(key) != value for key, value in expected.items()):
                raise ExperimentStoreError("V2 result marker binding is invalid")
            if (
                marker["stageDeploymentAttestationRef"] != "stage-deployment-attestation.json"
                or marker["hookDeploymentAttestationRef"] != "hook-deployment-attestation.json"
                or reservation.to_mapping()["request"]["promotionAuthority"] != parsed_authority.to_mapping()
            ):
                raise ExperimentStoreError("V2 result marker authority or raw ref is invalid")
            return marker
        expected_fields = {
            "schemaVersion",
            "domain",
            "operationId",
            "operationKey",
            "requestDigest",
            "manifestArtifactDigest",
            "attestationArtifactDigest",
            "planArtifactDigest",
            "decision",
        }
        if (
            set(marker) != expected_fields
            or type(marker["schemaVersion"]) is not int
            or marker["schemaVersion"] != 1
            or marker["domain"] != "rsi-experiment-result-marker-v1"
            or type(marker["decision"]) is not str
            or marker["decision"] not in {"eligible", "rejected"}
        ):
            raise ExperimentStoreError("authoritative result marker schema is invalid")
        if (
            marker["operationId"] != operation_id
            or marker["operationKey"] != operation_key
        ):
            raise ExperimentStoreError(
                "authoritative result operation/key binding is invalid"
            )
        try:
            request = self._read_named(directory, "request.json", max_bytes=_MAX_REQUEST_BYTES)
        except FileNotFoundError:
            raise ExperimentStoreError("authoritative result has no reserved request") from None
        _validate_reservation_request(operation_id, request)
        request_digest = raw_sha256(request)
        artifact_objects: dict[str, dict[str, object]] = {}
        for label, payload in (
            ("manifest", manifest),
            ("attestation", attestation),
            ("plan", plan),
        ):
            artifact_objects[label] = _validate_bundle_artifact(
                payload,
                label,
                operation_id=operation_id,
                request_digest=request_digest,
            )
        decisions = {
            artifact_objects[label]["payload"].get("decision")
            for label in ("manifest", "attestation", "plan")
        }
        if decisions != {marker["decision"]}:
            raise ExperimentStoreError(
                "authoritative result decision conflicts with manifest, attestation, or plan"
            )
        expected = {
            "requestDigest": request_digest,
            "manifestArtifactDigest": raw_sha256(manifest),
            "attestationArtifactDigest": raw_sha256(attestation),
            "planArtifactDigest": raw_sha256(plan),
        }
        for field_name, digest in expected.items():
            if type(marker[field_name]) is not str or marker[field_name] != digest:
                raise ExperimentStoreError(
                    "authoritative result marker does not bind its request and sidecar digests"
                )
        return marker

    @staticmethod
    def _closed_directory_names(directory: int, *, maximum: int = 8) -> set[str]:
        names: list[str] = []
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    if type(entry.name) is not str or not entry.name:
                        raise ExperimentStoreError(
                            "authoritative experiment bundle membership is invalid"
                        )
                    names.append(entry.name)
                    if len(names) > maximum:
                        raise ExperimentStoreError(
                            "authoritative experiment bundle has unbound membership"
                        )
        except OSError as error:
            raise ExperimentStoreError(
                "authoritative experiment bundle membership cannot be read"
            ) from error
        return set(names)

    def _read_and_validate_bundle(
        self,
        directory: int,
        result: bytes,
        *,
        operation_id: str,
        operation_key: str,
    ) -> dict[str, bytes]:
        marker = _canonical_store_object(result, "result")
        for field_name in (
            "attestationArtifactDigest",
            "planArtifactDigest",
        ):
            if (
                field_name not in marker
                or type(marker[field_name]) is not str
                or _DIGEST_RE.fullmatch(marker[field_name]) is None
            ):
                raise ExperimentStoreError("authoritative result marker schema is invalid")
        try:
            manifest = self._read_named(directory, "manifest.json")
            attestation = self._read_named(
                directory,
                "attestation-" + str(marker["attestationArtifactDigest"])[7:] + ".json",
            )
            plan = self._read_named(
                directory,
                "plan-" + str(marker["planArtifactDigest"])[7:] + ".json",
            )
            if marker.get("schemaVersion") == 2:
                stage = self._read_named(directory, "stage-deployment-attestation.json")
                hook = self._read_named(directory, "hook-deployment-attestation.json")
            else:
                stage = hook = None
        except (FileNotFoundError, ExperimentError):
            raise ExperimentStoreError("authoritative experiment bundle sidecar is missing or unsafe") from None
        expected_names = {
            "request.json",
            "manifest.json",
            "attestation-" + str(marker["attestationArtifactDigest"])[7:] + ".json",
            "plan-" + str(marker["planArtifactDigest"])[7:] + ".json",
            "result.json",
        }
        if marker.get("schemaVersion") == 2:
            expected_names |= {
                "stage-deployment-attestation.json",
                "hook-deployment-attestation.json",
            }
        if self._closed_directory_names(directory) != expected_names:
            raise ExperimentStoreError(
                "authoritative experiment bundle contains unbound membership"
            )
        self._validate_result_marker(
            directory,
            operation_id=operation_id,
            operation_key=operation_key,
            manifest=manifest,
            attestation=attestation,
            plan=plan,
            result=result,
            stage_deployment_attestation=stage,
            hook_deployment_attestation=hook,
        )
        payloads = {
            "manifest": manifest,
            "attestation": attestation,
            "plan": plan,
            "result": result,
        }
        if stage is not None and hook is not None:
            payloads["stage_deployment_attestation"] = stage
            payloads["hook_deployment_attestation"] = hook
        return payloads

    def publish_bundle(
        self,
        operation_id: str,
        *,
        manifest: bytes,
        attestation: bytes,
        plan: bytes,
        result: bytes,
        stage_deployment_attestation: bytes | None = None,
        hook_deployment_attestation: bytes | None = None,
    ) -> None:
        self._require_writable()
        for label, payload in (
            ("manifest", manifest),
            ("attestation", attestation),
            ("plan", plan),
            ("result", result),
        ):
            _canonical_store_object(payload, label)
        result_mapping = _canonical_store_object(result, "result")
        task8 = result_mapping.get("schemaVersion") == 2
        if task8:
            if stage_deployment_attestation is None or hook_deployment_attestation is None:
                raise ExperimentStoreError("Task 8 bundle requires both raw deployment attestations")
            _canonical_store_object(stage_deployment_attestation, "stage deployment attestation")
            _canonical_store_object(hook_deployment_attestation, "hook deployment attestation")
        elif stage_deployment_attestation is not None or hook_deployment_attestation is not None:
            raise ExperimentStoreError("V1 bundle cannot contain Task 8 deployment members")
        key = self._operation_key(operation_id)
        home_descriptor = self._open_verified_home()
        lock: _HeldStoreLock | None = None
        try:
            lock = self._lock_descriptor(
                operation_id, home_descriptor=home_descriptor
            )
            try:
                directory = self._open_relative_directory_at(
                    home_descriptor, f"experiments/{key}"
                )
                try:
                    self._assert_pinned_home(home_descriptor)
                    self._assert_held_lock(lock)
                    self._validate_result_marker(
                        directory,
                        operation_id=operation_id,
                        operation_key=key,
                        manifest=manifest,
                        attestation=attestation,
                        plan=plan,
                        result=result,
                        stage_deployment_attestation=stage_deployment_attestation,
                        hook_deployment_attestation=hook_deployment_attestation,
                    )
                    try:
                        existing_result = self._read_named(directory, "result.json")
                    except FileNotFoundError:
                        existing_result = None
                    if existing_result is not None:
                        if existing_result != result:
                            raise ExperimentConflict("authoritative experiment result conflicts")
                        self._assert_pinned_home(home_descriptor)
                        self._assert_held_lock(lock)
                        _fsync_directory(directory)
                        existing_result = self._read_named(directory, "result.json")
                        if existing_result != result:
                            raise ExperimentConflict(
                                "authoritative experiment result changed during durability repair"
                            )
                        persisted = self._read_and_validate_bundle(
                            directory,
                            existing_result,
                            operation_id=operation_id,
                            operation_key=key,
                        )
                        expected_payloads = {
                            "manifest": manifest,
                            "attestation": attestation,
                            "plan": plan,
                            "result": result,
                        }
                        if task8:
                            expected_payloads.update(
                                stage_deployment_attestation=stage_deployment_attestation,
                                hook_deployment_attestation=hook_deployment_attestation,
                            )
                        if persisted != expected_payloads:
                            raise ExperimentConflict(
                                "authoritative experiment bundle conflicts with persisted bytes"
                            )
                        self._assert_pinned_home(home_descriptor)
                        self._assert_held_lock(lock)
                        return
                    expected_names = {
                        "request.json",
                        "manifest.json",
                        "attestation-" + raw_sha256(attestation)[7:] + ".json",
                        "plan-" + raw_sha256(plan)[7:] + ".json",
                    }
                    if task8:
                        expected_names |= {
                            "stage-deployment-attestation.json",
                            "hook-deployment-attestation.json",
                        }
                    if not self._closed_directory_names(directory).issubset(expected_names):
                        raise ExperimentStoreError(
                            "experiment bundle contains an unbound orphan sidecar"
                        )
                    self._assert_pinned_home(home_descriptor)
                    self._assert_held_lock(lock)
                    self._write_once(directory, "manifest.json", manifest, inject_faults=True)
                    self._assert_pinned_home(home_descriptor)
                    self._assert_held_lock(lock)
                    self._write_once(
                        directory,
                        "attestation-" + raw_sha256(attestation)[7:] + ".json",
                        attestation,
                        inject_faults=True,
                    )
                    self._assert_pinned_home(home_descriptor)
                    self._assert_held_lock(lock)
                    self._write_once(
                        directory,
                        "plan-" + raw_sha256(plan)[7:] + ".json",
                        plan,
                        inject_faults=True,
                    )
                    if task8:
                        self._assert_pinned_home(home_descriptor)
                        self._assert_held_lock(lock)
                        self._write_once(
                            directory, "stage-deployment-attestation.json",
                            stage_deployment_attestation, inject_faults=True,
                        )
                        self._assert_pinned_home(home_descriptor)
                        self._assert_held_lock(lock)
                        self._write_once(
                            directory, "hook-deployment-attestation.json",
                            hook_deployment_attestation, inject_faults=True,
                        )
                    self._inject("publish-before-result")
                    self._assert_pinned_home(home_descriptor)
                    self._assert_held_lock(lock)
                    self._write_once(directory, "result.json", result, inject_faults=True)
                    _fsync_directory(directory)
                    persisted_result = self._read_named(directory, "result.json")
                    persisted = self._read_and_validate_bundle(
                        directory,
                        persisted_result,
                        operation_id=operation_id,
                        operation_key=key,
                    )
                    expected_persisted = {
                        "manifest": manifest,
                        "attestation": attestation,
                        "plan": plan,
                        "result": result,
                    }
                    if task8:
                        expected_persisted.update(
                            stage_deployment_attestation=stage_deployment_attestation,
                            hook_deployment_attestation=hook_deployment_attestation,
                        )
                    if persisted != expected_persisted:
                        raise ExperimentConflict(
                            "authoritative experiment bundle readback conflicts"
                        )
                    self._assert_pinned_home(home_descriptor)
                    self._assert_held_lock(lock)
                finally:
                    os.close(directory)
            except OSError as error:
                raise ExperimentStoreError("immutable experiment bundle publish failed") from error
        finally:
            try:
                if lock is not None:
                    self._close_lock(lock)
                self._assert_pinned_home(home_descriptor)
            finally:
                os.close(home_descriptor)

    def read_result(self, operation_id: str) -> bytes:
        key = self._operation_key(operation_id)
        home_descriptor = self._open_verified_home()
        try:
            directory = self._open_relative_directory_at(
                home_descriptor, f"experiments/{key}"
            )
            try:
                try:
                    result = self._read_named(directory, "result.json")
                except FileNotFoundError:
                    raise ExperimentStoreError("experiment bundle is incomplete or contains an orphan") from None
                self._read_and_validate_bundle(
                    directory,
                    result,
                    operation_id=operation_id,
                    operation_key=key,
                )
                self._assert_pinned_home(home_descriptor)
                return result
            finally:
                os.close(directory)
        finally:
            os.close(home_descriptor)

    def publish_post_image(self, payload: bytes) -> str:
        self._require_writable()
        if type(payload) is not bytes or not payload or len(payload) > _MAX_POST_IMAGE_BYTES:
            raise ExperimentStoreError("post-image payload exceeds its byte bound")
        reference = post_image_ref(payload)
        name = reference.rsplit(":", 1)[1] + ".bin"
        home_descriptor = self._open_verified_home()
        lock: _HeldStoreLock | None = None
        try:
            lock = self._named_lock_descriptor(
                "locks/objects",
                name[:-4] + ".lock",
                home_descriptor=home_descriptor,
            )
            directory = self._open_relative_directory_at(
                home_descriptor, "objects/post-images"
            )
            try:
                self._assert_pinned_home(home_descriptor)
                self._assert_held_lock(lock)
                self._write_once(
                    directory,
                    name,
                    payload,
                    inject_faults=True,
                    max_bytes=_MAX_POST_IMAGE_BYTES,
                )
                persisted = self._read_named(
                    directory, name, max_bytes=_MAX_POST_IMAGE_BYTES
                )
                try:
                    verify_post_image(reference, persisted)
                except ManifestError as error:
                    raise ExperimentStoreError(
                        "post-image publish readback is tampered"
                    ) from error
                self._assert_pinned_home(home_descriptor)
                self._assert_held_lock(lock)
            finally:
                os.close(directory)
        finally:
            try:
                if lock is not None:
                    self._close_lock(lock)
                self._assert_pinned_home(home_descriptor)
            finally:
                os.close(home_descriptor)
        return reference

    def read_post_image(self, reference: str) -> bytes:
        if type(reference) is not str or _REF_RE.fullmatch(reference) is None:
            raise ExperimentStoreError("post-image reference is invalid")
        name = reference.rsplit(":", 1)[1] + ".bin"
        home_descriptor = self._open_verified_home()
        try:
            directory = self._open_relative_directory_at(
                home_descriptor, "objects/post-images"
            )
            try:
                try:
                    payload = self._read_named(directory, name, max_bytes=_MAX_POST_IMAGE_BYTES)
                except FileNotFoundError:
                    raise ExperimentStoreError("post-image object is unavailable") from None
                self._assert_pinned_home(home_descriptor)
            finally:
                os.close(directory)
        finally:
            os.close(home_descriptor)
        try:
            return verify_post_image(reference, payload)
        except ManifestError as error:
            raise ExperimentStoreError("post-image object is tampered") from error

    def read_bundle_payloads(self, operation_id: str) -> dict[str, bytes]:
        """Return a fully revalidated authoritative bundle without mutation."""

        key = self._operation_key(operation_id)
        home_descriptor = self._open_verified_home()
        try:
            directory = self._open_relative_directory_at(
                home_descriptor, f"experiments/{key}"
            )
            try:
                try:
                    result = self._read_named(directory, "result.json")
                except FileNotFoundError:
                    raise ExperimentStoreError("experiment bundle is incomplete") from None
                payloads = self._read_and_validate_bundle(
                    directory,
                    result,
                    operation_id=operation_id,
                    operation_key=key,
                )
                self._assert_pinned_home(home_descriptor)
                return payloads
            finally:
                os.close(directory)
        finally:
            os.close(home_descriptor)


@dataclass(frozen=True, slots=True)
class PromotionPlanRefInputs:
    plan: Task8WireModel
    promotion_authority: Task8WireModel
    reservation_digest: str
    experiment_request_digest: str


def load_promotion_plan_ref_inputs(
    store: ExperimentArtifactStore, operation_id: str
) -> PromotionPlanRefInputs:
    if not isinstance(store, ExperimentArtifactStore) or not store._read_only:
        raise ExperimentError("Task 8 plan loader requires an existing-only artifact store")
    reservation_bytes = store.read_reservation(operation_id)
    if reservation_bytes is None:
        raise ExperimentError("Task 8 reservation is unavailable")
    try:
        reservation_mapping = _canonical_store_object(reservation_bytes, "reservation")
        if reservation_mapping.get("schemaVersion") != 2:
            raise ExperimentError("V1 experiment bundle is Task 8 ineligible")
        reservation = parse_experiment_reservation_v2(reservation_bytes)
        payloads = store.read_bundle_payloads(operation_id)
        plan_envelope = _validate_bundle_artifact_v2(
            payloads["plan"], "plan", operation_id=operation_id,
            reservation_digest=reservation.reservation_digest or "",
        )
        plan = parse_promotion_plan(canonical_json_bytes(plan_envelope["payload"]["plan"]))
        if not isinstance(plan, Task8WireModel):
            raise ExperimentError("V1 experiment bundle is Task 8 ineligible")
        authority = parse_promotion_authority_v2(
            canonical_json_bytes(plan_envelope["payload"]["promotionAuthority"])
        )
        if plan_envelope["payload"]["planDigest"] != plan.digest:
            raise ExperimentError("Task 8 plan artifact digest is invalid")
        return PromotionPlanRefInputs(
            plan, authority, reservation.reservation_digest or "",
            reservation.request_digest or "",
        )
    except ExperimentStoreError:
        raise
    except ExperimentError:
        raise
    except (KeyError, TypeError, ValueError):
        raise ExperimentError("Task 8 promotion plan inputs are malformed") from None


def read_post_image(home: Path | str, reference: str) -> bytes:
    return ExperimentArtifactStore.open_existing(home).read_post_image(reference)


_RUN_MAX_TREE_RECORDS = 8192
_RUN_MAX_TREE_BYTES = 64 * 1024 * 1024
_RUN_MAX_FILE_BYTES = 16 * 1024 * 1024
_RUN_MAX_TREE_DEPTH = 32
_RUN_MAX_DIRECTORY_NAMES = 8192
_SENSITIVE_RUNTIME_NAMES = frozenset(
    {
        ".env",
        ".credentials",
        "credentials",
        "credentials.json",
        "secrets.json",
    }
)


def _is_sensitive_runtime_name(name: str) -> bool:
    folded = name.casefold()
    return (
        folded in _SENSITIVE_RUNTIME_NAMES
        or folded.startswith(".env.")
    )


def _bounded_exact_name(parent: int, expected: str, label: str) -> None:
    exact = False
    equivalent = False
    folded = unicodedata.normalize("NFC", expected).casefold()
    try:
        with os.scandir(os.dup(parent)) as iterator:
            for count, entry in enumerate(iterator, start=1):
                if count > _RUN_MAX_DIRECTORY_NAMES:
                    raise ExperimentError(f"{label} directory enumeration is unbounded")
                actual = entry.name
                if actual == expected:
                    exact = True
                elif unicodedata.normalize("NFC", actual).casefold() == folded:
                    equivalent = True
    except OSError as error:
        raise ExperimentError(f"{label} directory cannot be enumerated safely") from error
    if not exact or equivalent:
        raise ExperimentError(f"{label} path spelling or identity is ambiguous")


@dataclass(frozen=True, slots=True)
class _TreeRecord:
    path: str
    kind: str
    mode: int
    device: int
    inode: int
    links: int
    byte_size: int
    modified_ns: int
    changed_ns: int
    digest: str | None


@dataclass(frozen=True, slots=True)
class _TreeSnapshot:
    records: tuple[_TreeRecord, ...]


def _tree_record(
    relative: str,
    metadata: os.stat_result,
    *,
    kind: str,
    digest: str | None = None,
) -> _TreeRecord:
    return _TreeRecord(
        relative,
        kind,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        digest,
    )


def _same_open_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        stat.S_IFMT(first.st_mode),
        first.st_dev,
        first.st_ino,
    ) == (
        stat.S_IFMT(second.st_mode),
        second.st_dev,
        second.st_ino,
    )


class _PinnedTree:
    """One canonical directory tree held by ancestry/root descriptors for one run."""

    def __init__(
        self,
        path: Path | str,
        *,
        label: str,
        reject_sensitive: bool,
        capture_tree: bool = True,
    ) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.label = label
        self.reject_sensitive = reject_sensitive
        self._descriptors: list[int] = []
        self._names: list[str] = []
        self._closed = False
        try:
            self._open_ancestry()
            self.snapshot = self._scan() if capture_tree else None
        except BaseException:
            self.close()
            raise

    @property
    def root_descriptor(self) -> int:
        if self._closed or not self._descriptors:
            raise ExperimentError(f"{self.label} pinned descriptor is closed")
        return self._descriptors[-1]

    def _open_ancestry(self) -> None:
        if self.path in {Path(self.path.anchor), Path.home(), Path.cwd()}:
            raise ExperimentError(f"{self.label} uses a broad root")
        try:
            self._descriptors.append(
                os.open(self.path.anchor, os.O_RDONLY | _DIRECTORY)
            )
            for part in self.path.parts[1:]:
                parent = self._descriptors[-1]
                _bounded_exact_name(parent, part, self.label)
                before = os.stat(part, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                    raise ExperimentError(f"{self.label} ancestry is not a regular directory")
                child = os.open(
                    part,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=parent,
                )
                opened = os.fstat(child)
                if not stat.S_ISDIR(opened.st_mode) or not _same_open_identity(
                    before, opened
                ):
                    os.close(child)
                    raise ExperimentError(f"{self.label} ancestry changed during open")
                self._descriptors.append(child)
                self._names.append(part)
        except OSError as error:
            raise ExperimentError(f"{self.label} cannot be pinned safely") from error

    def _assert_path_binding(self) -> None:
        if self._closed:
            raise ExperimentConflict(f"{self.label} pinned identity is unavailable")
        for index, name in enumerate(self._names):
            parent = self._descriptors[index]
            child = self._descriptors[index + 1]
            try:
                _bounded_exact_name(parent, name, self.label)
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                opened = os.fstat(child)
            except (OSError, ExperimentError) as error:
                raise ExperimentConflict(
                    f"{self.label} path or ancestry identity changed"
                ) from error
            if (
                not stat.S_ISDIR(named.st_mode)
                or not stat.S_ISDIR(opened.st_mode)
                or not _same_open_identity(named, opened)
            ):
                raise ExperimentConflict(f"{self.label} path or root identity changed")

    def _read_regular(
        self,
        parent: int,
        name: str,
        relative: str,
        before: os.stat_result,
    ) -> tuple[bytes, os.stat_result]:
        if before.st_nlink != 1 or before.st_size < 0 or before.st_size > _RUN_MAX_FILE_BYTES:
            raise ExperimentError(f"{self.label} contains an unsafe hardlink or oversized file")
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent,
            )
        except OSError as error:
            raise ExperimentError(f"{self.label} regular file cannot be opened safely") from error
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size < 0
                or opened.st_size > _RUN_MAX_FILE_BYTES
                or not _same_open_identity(before, opened)
            ):
                raise ExperimentError(f"{self.label} entry changed or is not one regular file")
            chunks: list[bytes] = []
            remaining = _RUN_MAX_FILE_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
            try:
                rebound = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except OSError as error:
                raise ExperimentError(f"{self.label} entry path changed while reading") from error
            stable = (
                opened.st_mode,
                opened.st_dev,
                opened.st_ino,
                opened.st_nlink,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            if (
                len(payload) > _RUN_MAX_FILE_BYTES
                or len(payload) != opened.st_size
                or stable
                != (
                    after.st_mode,
                    after.st_dev,
                    after.st_ino,
                    after.st_nlink,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
                or stable
                != (
                    rebound.st_mode,
                    rebound.st_dev,
                    rebound.st_ino,
                    rebound.st_nlink,
                    rebound.st_size,
                    rebound.st_mtime_ns,
                    rebound.st_ctime_ns,
                )
            ):
                raise ExperimentError(f"{self.label} entry changed while reading")
            return payload, after
        finally:
            os.close(descriptor)

    def _scan(self) -> _TreeSnapshot:
        records: list[_TreeRecord] = []
        locator_folded: set[str] = set()
        total_bytes = 0
        root_metadata = os.fstat(self.root_descriptor)
        records.append(_tree_record("", root_metadata, kind="directory"))

        def consume(relative: str) -> None:
            if len(records) >= _RUN_MAX_TREE_RECORDS:
                raise ExperimentError(f"{self.label} exceeds the tree record bound")
            folded = unicodedata.normalize("NFC", relative).casefold()
            if folded in locator_folded:
                raise ExperimentError(f"{self.label} has a normalization/case collision")
            locator_folded.add(folded)

        def scan_directory(parent: int, parts: tuple[str, ...], depth: int) -> None:
            nonlocal total_bytes
            if depth > _RUN_MAX_TREE_DEPTH:
                raise ExperimentError(f"{self.label} exceeds the tree depth bound")
            try:
                names: list[str] = []
                local_folded: set[str] = set()
                with os.scandir(os.dup(parent)) as iterator:
                    for entry in iterator:
                        if len(names) >= _RUN_MAX_DIRECTORY_NAMES:
                            raise ExperimentError(
                                f"{self.label} exceeds the directory entry bound"
                            )
                        name = entry.name
                        try:
                            name.encode("utf-8", "strict")
                        except UnicodeEncodeError:
                            raise ExperimentError(
                                f"{self.label} contains an invalid UTF-8 name"
                            ) from None
                        if (
                            not name
                            or name in {".", ".."}
                            or "/" in name
                            or "\x00" in name
                            or unicodedata.normalize("NFC", name) != name
                        ):
                            raise ExperimentError(
                                f"{self.label} contains a noncanonical path"
                            )
                        folded = name.casefold()
                        if folded in local_folded:
                            raise ExperimentError(
                                f"{self.label} has a normalization/case collision"
                            )
                        local_folded.add(folded)
                        names.append(name)
                names.sort(key=lambda item: item.encode("utf-8"))
            except OSError as error:
                raise ExperimentError(f"{self.label} cannot be enumerated safely") from error

            for name in names:
                relative = "/".join((*parts, name))
                consume(relative)
                if self.reject_sensitive and _is_sensitive_runtime_name(name):
                    raise ExperimentError(
                        f"{self.label} contains a forbidden sensitive runtime file"
                    )
                try:
                    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except OSError as error:
                    raise ExperimentError(f"{self.label} entry cannot be inspected") from error
                if stat.S_ISLNK(before.st_mode):
                    raise ExperimentError(f"{self.label} contains a symlink")
                if stat.S_ISDIR(before.st_mode):
                    try:
                        child = os.open(
                            name,
                            os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                            dir_fd=parent,
                        )
                    except OSError as error:
                        raise ExperimentError(
                            f"{self.label} directory cannot be opened safely"
                        ) from error
                    try:
                        opened = os.fstat(child)
                        if not stat.S_ISDIR(opened.st_mode) or not _same_open_identity(
                            before, opened
                        ):
                            raise ExperimentError(
                                f"{self.label} directory changed during open"
                            )
                        records.append(
                            _tree_record(relative, opened, kind="directory")
                        )
                        scan_directory(child, (*parts, name), depth + 1)
                        rebound = os.stat(
                            name, dir_fd=parent, follow_symlinks=False
                        )
                        after = os.fstat(child)
                        stable = (
                            opened.st_mode,
                            opened.st_dev,
                            opened.st_ino,
                            opened.st_nlink,
                            opened.st_size,
                            opened.st_mtime_ns,
                            opened.st_ctime_ns,
                        )
                        if stable != (
                            rebound.st_mode,
                            rebound.st_dev,
                            rebound.st_ino,
                            rebound.st_nlink,
                            rebound.st_size,
                            rebound.st_mtime_ns,
                            rebound.st_ctime_ns,
                        ) or stable != (
                            after.st_mode,
                            after.st_dev,
                            after.st_ino,
                            after.st_nlink,
                            after.st_size,
                            after.st_mtime_ns,
                            after.st_ctime_ns,
                        ):
                            raise ExperimentError(
                                f"{self.label} directory changed during scan"
                            )
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(before.st_mode):
                    raise ExperimentError(
                        f"{self.label} contains a special or unsupported entry"
                    )
                payload, after = self._read_regular(parent, name, relative, before)
                total_bytes += len(payload)
                if total_bytes > _RUN_MAX_TREE_BYTES:
                    raise ExperimentError(f"{self.label} exceeds the tree byte bound")
                records.append(
                    _tree_record(
                        relative,
                        after,
                        kind="regular-file",
                        digest=raw_sha256(payload),
                    )
                )

        scan_directory(self.root_descriptor, (), 0)
        self._assert_path_binding()
        return _TreeSnapshot(tuple(records))

    def assert_unchanged(self) -> None:
        if self.snapshot is None:
            raise ExperimentError(f"{self.label} has no captured tree witness")
        try:
            self._assert_path_binding()
            current = self._scan()
        except ExperimentConflict:
            raise
        except ExperimentError as error:
            raise ExperimentConflict(f"{self.label} changed or became unsafe") from error
        if current != self.snapshot:
            raise ExperimentConflict(f"{self.label} content, metadata, or identity changed")

    def read_regular(self, relative: str) -> tuple[bytes, os.stat_result]:
        relative = _canonical_relative_path(relative)
        parts = relative.split("/")
        descriptor = os.dup(self.root_descriptor)
        try:
            for part in parts[:-1]:
                before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                    raise ExperimentError(f"{self.label} managed path is not a directory")
                child = os.open(
                    part,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=descriptor,
                )
                opened = os.fstat(child)
                if not stat.S_ISDIR(opened.st_mode) or not _same_open_identity(
                    before, opened
                ):
                    os.close(child)
                    raise ExperimentError(f"{self.label} managed directory changed")
                os.close(descriptor)
                descriptor = child
            before = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                raise ExperimentError(f"{self.label} managed artifact is not regular")
            return self._read_regular(descriptor, parts[-1], relative, before)
        except OSError as error:
            raise ExperimentError(f"{self.label} managed artifact is unavailable") from error
        finally:
            os.close(descriptor)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for descriptor in reversed(self._descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._descriptors.clear()

    def __enter__(self) -> "_PinnedTree":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _portable_control_roots_digest(pins: Sequence[_PinnedTree]) -> str:
    roots: list[dict[str, object]] = []
    for pin in pins:
        if pin.snapshot is None:
            raise ExperimentError("control-plane root has no content witness")
        entries = []
        for record in pin.snapshot.records:
            entries.append(
                {
                    "path": record.path,
                    "type": record.kind,
                    "mode": record.mode,
                    "byteSize": record.byte_size
                    if record.kind == "regular-file"
                    else 0,
                    "digest": record.digest,
                }
            )
        roots.append({"canonicalRoot": str(pin.path), "entries": entries})
    roots.sort(key=lambda item: str(item["canonicalRoot"]).encode("utf-8"))
    return canonical_json_digest(
        {
            "schemaVersion": 1,
            "domain": "rsi-control-plane-root-set-v1",
            "roots": roots,
        }
    )


def control_plane_roots_digest(paths: Sequence[str]) -> str:
    """Compute the portable no-follow byte/mode identity of trusted control roots."""

    if type(paths) not in {tuple, list} or not paths:
        raise ExperimentError("control-plane root set is invalid")
    pins: list[_PinnedTree] = []
    try:
        for path in paths:
            pins.append(
                _PinnedTree(
                    path,
                    label="control-plane identity root",
                    reject_sensitive=True,
                )
            )
        return _portable_control_roots_digest(pins)
    finally:
        for pin in reversed(pins):
            pin.close()


class _PinnedRegularFile:
    def __init__(self, path: Path | str, *, label: str) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.label = label
        self.parent = _PinnedTree(
            self.path.parent,
            label=f"{label} parent",
            reject_sensitive=False,
            capture_tree=False,
        )
        self._descriptor: int | None = None
        try:
            _bounded_exact_name(
                self.parent.root_descriptor, self.path.name, self.label
            )
            before = os.stat(
                self.path.name,
                dir_fd=self.parent.root_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size < 0
                or before.st_size > _MAX_BUNDLE_BYTES
            ):
                raise ExperimentError(f"{self.label} is not one bounded regular file")
            self._descriptor = os.open(
                self.path.name,
                os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=self.parent.root_descriptor,
            )
            opened = os.fstat(self._descriptor)
            if not _same_open_identity(before, opened):
                raise ExperimentError(f"{self.label} changed during open")
            self._initial = self._sample()
        except BaseException:
            self.close()
            raise

    def _sample(self) -> tuple[tuple[object, ...], bytes]:
        if self._descriptor is None:
            raise ExperimentConflict(f"{self.label} descriptor is unavailable")
        descriptor = self._descriptor
        try:
            _bounded_exact_name(
                self.parent.root_descriptor, self.path.name, self.label
            )
            named = os.stat(
                self.path.name,
                dir_fd=self.parent.root_descriptor,
                follow_symlinks=False,
            )
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(named.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or named.st_nlink != 1
                or opened.st_nlink != 1
                or not _same_open_identity(named, opened)
                or opened.st_size > _MAX_BUNDLE_BYTES
            ):
                raise ExperimentConflict(f"{self.label} identity changed")
            os.lseek(descriptor, 0, os.SEEK_SET)
            payload = b""
            while len(payload) <= _MAX_BUNDLE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(1024 * 1024, _MAX_BUNDLE_BYTES + 1 - len(payload)),
                )
                if not chunk:
                    break
                payload += chunk
            after = os.fstat(descriptor)
            identity = (
                opened.st_mode,
                opened.st_dev,
                opened.st_ino,
                opened.st_nlink,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            if (
                len(payload) > _MAX_BUNDLE_BYTES
                or len(payload) != opened.st_size
                or identity
                != (
                    after.st_mode,
                    after.st_dev,
                    after.st_ino,
                    after.st_nlink,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
            ):
                raise ExperimentConflict(f"{self.label} changed while reading")
            return identity, payload
        except OSError as error:
            raise ExperimentConflict(f"{self.label} changed or became unavailable") from error

    @property
    def payload(self) -> bytes:
        return self._initial[1]

    def assert_unchanged(self) -> None:
        try:
            self.parent._assert_path_binding()
            current = self._sample()
        except ExperimentError as error:
            raise ExperimentConflict(f"{self.label} identity or bytes changed") from error
        if current != self._initial:
            raise ExperimentConflict(f"{self.label} identity or bytes changed")

    def close(self) -> None:
        if self._descriptor is not None:
            try:
                os.close(self._descriptor)
            except OSError:
                pass
            self._descriptor = None
        self.parent.close()

    def __enter__(self) -> "_PinnedRegularFile":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise ExperimentError("staged artifact write made no progress")
        offset += written


def _stage_file(
    root_descriptor: int,
    relative: str,
    payload: bytes,
    *,
    executable: bool,
) -> None:
    parts = relative.split("/")
    directory = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=directory)
            except FileExistsError:
                pass
            before = os.stat(part, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise ExperimentError("staging parent is not one regular directory")
            child = os.open(
                part,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                dir_fd=directory,
            )
            opened = os.fstat(child)
            if not stat.S_ISDIR(opened.st_mode) or not _same_open_identity(
                before, opened
            ):
                os.close(child)
                raise ExperimentError("staging parent changed during open")
            os.close(directory)
            directory = child
        mode = 0o700 if executable else 0o600
        descriptor = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
            mode,
            dir_fd=directory,
        )
        try:
            os.fchmod(descriptor, mode)
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size != len(payload)
            ):
                raise ExperimentError("staged artifact is not one exact regular file")
        finally:
            os.close(descriptor)
        named = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        if not _same_open_identity(opened, named) or named.st_nlink != 1:
            raise ExperimentError("staged artifact path was rebound")
    except OSError as error:
        raise ExperimentError("staged artifact cannot be created safely") from error
    finally:
        os.close(directory)


def _remove_directory_contents(
    directory: int, *, sealed_snapshot: _TreeSnapshot
) -> None:
    """Remove only the exact descriptor tree sealed before untrusted execution.

    A whole-tree pre-scan is insufficient: an attacker can insert or rebind an
    entry after that scan and before recursive deletion.  This routine derives
    the complete expected child graph from the sealed snapshot, rejects unknown
    membership before touching a directory, and rechecks type/device/inode at
    every open and immediately before every unlink/rmdir.
    """

    if type(sealed_snapshot) is not _TreeSnapshot:
        raise ExperimentError("staging cleanup lacks an exact sealed snapshot")
    records: dict[str, _TreeRecord] = {}
    children: dict[str, dict[str, _TreeRecord]] = {}
    for record in sealed_snapshot.records:
        if type(record) is not _TreeRecord or record.path in records:
            raise ExperimentError("staging cleanup snapshot is malformed")
        records[record.path] = record
        if record.path:
            parent, _, name = record.path.rpartition("/")
            children.setdefault(parent, {})[name] = record
    root_record = records.get("")
    if root_record is None or root_record.kind != "directory":
        raise ExperimentError("staging cleanup snapshot lacks its root identity")
    for path, record in records.items():
        if path and (
            path.rpartition("/")[0] not in records
            or records[path.rpartition("/")[0]].kind != "directory"
        ):
            raise ExperimentError("staging cleanup snapshot has an orphan entry")
        if record.kind not in {"directory", "regular-file"}:
            raise ExperimentError("staging cleanup snapshot has an unsafe entry type")

    def matches(record: _TreeRecord, metadata: os.stat_result) -> bool:
        expected_type = (
            stat.S_ISDIR(metadata.st_mode)
            if record.kind == "directory"
            else stat.S_ISREG(metadata.st_mode)
        )
        return (
            expected_type
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_dev == record.device
            and metadata.st_ino == record.inode
        )

    def require_exact_membership(
        parent: int, expected_names: Sequence[str]
    ) -> list[str]:
        try:
            names: list[str] = []
            with os.scandir(os.dup(parent)) as iterator:
                for entry in iterator:
                    if len(names) >= len(expected_names):
                        raise ExperimentConflict(
                            "staging cleanup found unknown directory membership"
                        )
                    name = entry.name
                    if (
                        type(name) is not str
                        or not name
                        or name in {".", ".."}
                        or "/" in name
                        or "\x00" in name
                        or unicodedata.normalize("NFC", name) != name
                    ):
                        raise ExperimentError(
                            "staging cleanup found an invalid entry name"
                        )
                    names.append(name)
            names.sort(key=lambda item: item.encode("utf-8", "strict"))
        except (OSError, UnicodeEncodeError) as error:
            raise ExperimentError(
                "staging cleanup cannot enumerate its pinned directory"
            ) from error
        canonical_expected = sorted(
            expected_names, key=lambda item: item.encode("utf-8")
        )
        if names != canonical_expected:
            raise ExperimentConflict(
                "staging cleanup found unknown, missing, or rebound membership"
            )
        return names

    def remove_directory(parent: int, relative: str, depth: int) -> None:
        if depth > _RUN_MAX_TREE_DEPTH:
            raise ExperimentError("staging cleanup exceeds its depth bound")
        expected_directory = records[relative]
        opened_parent = os.fstat(parent)
        if not matches(expected_directory, opened_parent):
            raise ExperimentConflict(
                "staging cleanup directory descriptor is not sealed identity"
            )
        names = require_exact_membership(parent, tuple(children.get(relative, {})))
        for name in names:
            path = f"{relative}/{name}" if relative else name
            expected = records[path]
            try:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not matches(expected, before):
                    raise ExperimentConflict(
                        "staging cleanup entry no longer has its sealed identity"
                    )
                if expected.kind == "directory":
                    child = os.open(
                        name,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=parent,
                    )
                    try:
                        opened = os.fstat(child)
                        if not matches(expected, opened) or not _same_open_identity(
                            before, opened
                        ):
                            raise ExperimentConflict(
                                "staging cleanup directory changed during open"
                            )
                        remove_directory(child, path, depth + 1)
                        rebound = os.stat(
                            name, dir_fd=parent, follow_symlinks=False
                        )
                        final_opened = os.fstat(child)
                        if (
                            not matches(expected, rebound)
                            or not matches(expected, final_opened)
                            or not _same_open_identity(final_opened, rebound)
                        ):
                            raise ExperimentConflict(
                                "staging cleanup directory changed before rmdir"
                            )
                        os.rmdir(name, dir_fd=parent)
                    finally:
                        os.close(child)
                else:
                    child = os.open(
                        name,
                        os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=parent,
                    )
                    try:
                        opened = os.fstat(child)
                        if not matches(expected, opened) or not _same_open_identity(
                            before, opened
                        ):
                            raise ExperimentConflict(
                                "staging cleanup file changed during open"
                            )
                        rebound = os.stat(
                            name, dir_fd=parent, follow_symlinks=False
                        )
                        if not matches(expected, rebound) or not _same_open_identity(
                            opened, rebound
                        ):
                            raise ExperimentConflict(
                                "staging cleanup file changed before unlink"
                            )
                        os.unlink(name, dir_fd=parent)
                    finally:
                        os.close(child)
            except OSError as error:
                raise ExperimentError(
                    "staging cleanup failed inside its pinned workspace"
                ) from error
        require_exact_membership(parent, ())
        if not matches(expected_directory, os.fstat(parent)):
            raise ExperimentConflict("staging cleanup directory identity changed")
        _fsync_directory(parent)

    remove_directory(directory, "", 0)


def _assert_staged_modes(pin: _PinnedTree, manifest: SkillManifest) -> None:
    if pin.snapshot is None:
        raise ExperimentError("staged tree has no identity/mode witness")
    expected_files = {
        entry.path: 0o700 if entry.executable else 0o600
        for entry in manifest.entries
    }
    for record in pin.snapshot.records:
        if record.kind == "directory":
            if record.mode != 0o700:
                raise ExperimentError("staged directory mode is not private 0700")
        elif expected_files.get(record.path) != record.mode:
            raise ExperimentError("staged file mode is not the exact safe mode")


class _StagedTrees:
    def __init__(
        self,
        *,
        source: _PinnedTree,
        pre_manifest: SkillManifest,
        post_manifest: SkillManifest,
        replacement: ArtifactReplacement,
        post_image: bytes,
        disjoint_from: Sequence[Path],
    ) -> None:
        self.root: Path | None = None
        self._root_pin: _PinnedTree | None = None
        self._cleanup_snapshot: _TreeSnapshot | None = None
        self.baseline: _PinnedTree | None = None
        self.variant: _PinnedTree | None = None
        try:
            transient = Path(tempfile.mkdtemp(prefix="rsi-isolated-stage-"))
            transient.chmod(0o700)
            transient = transient.resolve(strict=True)
            for protected in disjoint_from:
                if _paths_overlap(transient, protected):
                    raise ExperimentError("staging topology overlaps a trusted root")
            self.root = transient
            self._root_pin = _PinnedTree(
                transient,
                label="owned staging workspace",
                reject_sensitive=False,
                capture_tree=False,
            )
            if stat.S_IMODE(os.fstat(self._root_pin.root_descriptor).st_mode) != 0o700:
                raise ExperimentError("owned staging workspace mode is not private 0700")
            baseline_path = transient / "baseline"
            variant_path = transient / "variant"
            root_fd = self._root_pin.root_descriptor
            for name in ("baseline", "variant"):
                os.mkdir(name, 0o700, dir_fd=root_fd)
            baseline_before = os.stat(
                "baseline", dir_fd=root_fd, follow_symlinks=False
            )
            variant_before = os.stat(
                "variant", dir_fd=root_fd, follow_symlinks=False
            )
            baseline_fd = os.open(
                "baseline", os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=root_fd
            )
            variant_fd = os.open(
                "variant", os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=root_fd
            )
            try:
                if (
                    not _same_open_identity(baseline_before, os.fstat(baseline_fd))
                    or not _same_open_identity(variant_before, os.fstat(variant_fd))
                ):
                    raise ExperimentError("staging roots changed during descriptor open")
                source_payloads: dict[str, bytes] = {}
                for entry in pre_manifest.entries:
                    if entry.type != "regular-file":
                        raise ExperimentError(
                            "Task 7 staging does not admit manifest symlinks"
                        )
                    payload, metadata = source.read_regular(entry.path)
                    if (
                        len(payload) != entry.byte_size
                        or raw_sha256(payload) != entry.digest
                        or bool(metadata.st_mode & 0o111) != entry.executable
                    ):
                        raise ExperimentConflict(
                            "source managed artifact does not match the trusted manifest"
                        )
                    source_payloads[entry.path] = payload
                if replacement.relative_path not in source_payloads:
                    raise ExperimentError("replacement artifact is outside the managed manifest")
                for entry in pre_manifest.entries:
                    _stage_file(
                        baseline_fd,
                        entry.path,
                        source_payloads[entry.path],
                        executable=entry.executable,
                    )
                    _stage_file(
                        variant_fd,
                        entry.path,
                        post_image
                        if entry.path == replacement.relative_path
                        else source_payloads[entry.path],
                        executable=entry.executable,
                    )
                os.fsync(baseline_fd)
                os.fsync(variant_fd)
                try:
                    staged_pre = build_skill_manifest(baseline_path)
                    staged_post = build_skill_manifest(variant_path)
                except ManifestError as error:
                    raise ExperimentError("staged manifest cannot be built safely") from error
                if (
                    staged_pre.canonical_bytes != pre_manifest.canonical_bytes
                    or staged_post.canonical_bytes != post_manifest.canonical_bytes
                ):
                    raise ExperimentConflict("staged baseline/variant manifest binding changed")
                self._root_pin._assert_path_binding()
                self.baseline = _PinnedTree(
                    baseline_path,
                    label="staged baseline",
                    reject_sensitive=True,
                )
                self.variant = _PinnedTree(
                    variant_path,
                    label="staged variant",
                    reject_sensitive=True,
                )
                if (
                    not _same_open_identity(
                        os.fstat(baseline_fd),
                        os.fstat(self.baseline.root_descriptor),
                    )
                    or not _same_open_identity(
                        os.fstat(variant_fd),
                        os.fstat(self.variant.root_descriptor),
                    )
                ):
                    raise ExperimentConflict(
                        "staged baseline/variant root identity changed before pin"
                    )
                _assert_staged_modes(self.baseline, pre_manifest)
                _assert_staged_modes(self.variant, post_manifest)
            finally:
                os.close(baseline_fd)
                os.close(variant_fd)
            source.assert_unchanged()
        except BaseException:
            self.close()
            raise

    @property
    def baseline_root(self) -> Path:
        if self.baseline is None:
            raise ExperimentError("staged baseline is unavailable")
        return self.baseline.path

    @property
    def variant_root(self) -> Path:
        if self.variant is None:
            raise ExperimentError("staged variant is unavailable")
        return self.variant.path

    def assert_unchanged(self) -> None:
        if (
            self.baseline is None
            or self.variant is None
            or self._root_pin is None
            or self._cleanup_snapshot is None
        ):
            raise ExperimentConflict("staged trees are unavailable")
        self.baseline.assert_unchanged()
        self.variant.assert_unchanged()
        try:
            self._root_pin._assert_path_binding()
            current = self._root_pin._scan()
        except ExperimentError as error:
            raise ExperimentConflict("staged workspace changed or became unsafe") from error
        if current != self._cleanup_snapshot:
            raise ExperimentConflict("staged workspace content or identity changed")

    def create_scratch_and_seal(self) -> Path:
        if self._root_pin is None or self.root is None:
            raise ExperimentError("staging workspace is unavailable")
        root_fd = self._root_pin.root_descriptor
        try:
            os.mkdir("scratch", 0o700, dir_fd=root_fd)
            before = os.stat("scratch", dir_fd=root_fd, follow_symlinks=False)
            scratch_fd = os.open(
                "scratch", os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=root_fd
            )
            try:
                opened = os.fstat(scratch_fd)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or not _same_open_identity(before, opened)
                    or stat.S_IMODE(opened.st_mode) != 0o700
                ):
                    raise ExperimentError("staging scratch identity/mode is invalid")
                output_fd = os.open(
                    "declared-output.json",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600,
                    dir_fd=scratch_fd,
                )
                try:
                    os.fchmod(output_fd, 0o600)
                    os.fsync(output_fd)
                    output_metadata = os.fstat(output_fd)
                    if (
                        not stat.S_ISREG(output_metadata.st_mode)
                        or output_metadata.st_nlink != 1
                        or stat.S_IMODE(output_metadata.st_mode) != 0o600
                        or output_metadata.st_size != 0
                    ):
                        raise ExperimentError(
                            "staging declared output identity is invalid"
                        )
                finally:
                    os.close(output_fd)
                os.fsync(scratch_fd)
            finally:
                os.close(scratch_fd)
            self._root_pin._assert_path_binding()
            self._cleanup_snapshot = self._root_pin._scan()
            if any(
                record.kind == "directory" and record.mode != 0o700
                for record in self._cleanup_snapshot.records
            ):
                raise ExperimentError("staging workspace contains an unsafe directory mode")
            return self.root / "scratch"
        except OSError as error:
            raise ExperimentError("staging scratch cannot be created descriptor-relatively") from error

    def admit_scratch_output(self, *, maximum_bytes: int) -> tuple[str, ...]:
        """Admit only the one host-precreated output inode, then reseal cleanup."""

        if (
            self._root_pin is None
            or self._cleanup_snapshot is None
            or type(maximum_bytes) is not int
            or maximum_bytes < 1
            or maximum_bytes > _MAX_BUNDLE_BYTES
        ):
            raise ExperimentError("sandbox scratch output is unsafe")
        self.baseline.assert_unchanged() if self.baseline is not None else None
        self.variant.assert_unchanged() if self.variant is not None else None
        try:
            self._root_pin._assert_path_binding()
            current = self._root_pin._scan()
            sealed = {record.path: record for record in self._cleanup_snapshot.records}
            observed = {record.path: record for record in current.records}
            if set(sealed) != set(observed):
                raise ExperimentConflict(
                    "sandbox scratch output changed the sealed membership"
                )
            output_path = "scratch/declared-output.json"
            for path, expected in sealed.items():
                actual = observed[path]
                if path != output_path:
                    if actual != expected:
                        raise ExperimentConflict(
                            "sandbox changed a non-output staging identity"
                        )
                    continue
                if (
                    expected.kind != "regular-file"
                    or actual.kind != "regular-file"
                    or expected.device != actual.device
                    or expected.inode != actual.inode
                    or expected.links != 1
                    or actual.links != 1
                    or expected.mode != 0o600
                    or actual.mode != 0o600
                    or actual.byte_size < 0
                    or actual.byte_size > maximum_bytes
                    or type(actual.digest) is not str
                ):
                    raise ExperimentConflict(
                        "sandbox scratch output inode or bound is invalid"
                    )
            payload, metadata = self._root_pin.read_regular(output_path)
            output_record = observed[output_path]
            if (
                len(payload) != output_record.byte_size
                or len(payload) > maximum_bytes
                or raw_sha256(payload) != output_record.digest
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise ExperimentConflict("sandbox scratch output changed while reading")
            final = self._root_pin._scan()
            if final != current:
                raise ExperimentConflict("sandbox scratch output changed during admission")
            self._cleanup_snapshot = final
            return () if not payload else (raw_sha256(payload),)
        except (ExperimentError, OSError) as error:
            raise ExperimentError("sandbox scratch output is unsafe") from error

    def close(self) -> None:
        if self.baseline is not None:
            self.baseline.close()
            self.baseline = None
        if self.variant is not None:
            self.variant.close()
            self.variant = None
        cleanup_error: ExperimentError | None = None
        root_pin = self._root_pin
        self._root_pin = None
        root = self.root
        self.root = None
        if root_pin is not None:
            try:
                try:
                    root_pin._assert_path_binding()
                except ExperimentConflict as error:
                    cleanup_error = ExperimentConflict(
                        "staging cleanup topology was rebound; stale pathname was not touched"
                    )
                    cleanup_error.__cause__ = error
                else:
                    if self._cleanup_snapshot is None:
                        cleanup_error = ExperimentConflict(
                            "staging cleanup was not sealed before execution"
                        )
                    else:
                        current = root_pin._scan()
                        sealed_identity = tuple(
                            (item.path, item.kind, item.device, item.inode)
                            for item in self._cleanup_snapshot.records
                        )
                        current_identity = tuple(
                            (item.path, item.kind, item.device, item.inode)
                            for item in current.records
                        )
                        if current_identity != sealed_identity:
                            cleanup_error = ExperimentConflict(
                                "staging cleanup found unknown or rebound descendant identity; workspace leaked fail-closed"
                            )
                        else:
                            _remove_directory_contents(
                                root_pin.root_descriptor,
                                sealed_snapshot=self._cleanup_snapshot,
                            )
                            parent = root_pin._descriptors[-2]
                            name = root_pin._names[-1]
                            opened = os.fstat(root_pin.root_descriptor)
                            named = os.stat(
                                name, dir_fd=parent, follow_symlinks=False
                            )
                            if not _same_open_identity(opened, named):
                                cleanup_error = ExperimentConflict(
                                    "staging cleanup identity changed before final removal"
                                )
                            else:
                                os.rmdir(name, dir_fd=parent)
                                _fsync_directory(parent)
            except (ExperimentError, OSError) as error:
                if cleanup_error is None:
                    cleanup_error = ExperimentConflict(
                        "staging cleanup failed closed without following a pathname"
                    )
                    cleanup_error.__cause__ = error
            finally:
                root_pin.close()
        elif root is not None:
            cleanup_error = ExperimentConflict(
                "staging cleanup lacks its pinned workspace identity"
            )
        if cleanup_error is not None:
            raise cleanup_error

    def __enter__(self) -> "_StagedTrees":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _trusted_time_sample(
    request: ExperimentRequest,
    context: ExperimentContext,
    *,
    label: str,
    prior: datetime | None,
) -> datetime:
    try:
        current = context.clock.now_utc()
    except Exception as error:
        raise ExperimentError(f"trusted experiment clock failed at {label}") from error
    if (
        type(current) is not datetime
        or current.tzinfo is None
        or current.utcoffset() != timedelta(0)
        or current.microsecond != 0
    ):
        raise ExperimentError(f"trusted experiment clock is invalid at {label}")
    try:
        created = parse_timestamp(request.created_at)
        expires = parse_timestamp(request.expires_at)
    except AttestationError as error:
        raise ExperimentError("experiment request time binding is invalid") from error
    if prior is not None and current < prior:
        raise ExperimentConflict("trusted experiment clock moved backwards")
    if not (created <= current < expires):
        raise ExperimentError("experiment clock is expired or outside the request window")
    return current


def _trusted_state_sample(
    context: ExperimentContext,
    *,
    label: str,
    expected_fingerprint: str | None,
) -> CurrentTrustedState:
    try:
        value = context.current_state_provider.current()
    except Exception as error:
        raise ExperimentError(f"trusted current state provider failed at {label}") from error
    if type(value) is not CurrentTrustedState:
        raise ExperimentConflict(f"trusted current state is invalid at {label}")
    try:
        value.__post_init__()
        executor_identity = context.sandbox_executor.identity_digest
        capability_digest = context.sandbox_executor.capability_report_digest
        _require_digest(executor_identity, "sandbox executor identity")
        _require_digest(capability_digest, "sandbox capability report")
    except (ExperimentError, TypeError, ValueError, AttributeError) as error:
        raise ExperimentConflict(
            f"trusted current state identity is invalid at {label}"
        ) from error
    if (
        value.sandbox_executor_identity_digest != executor_identity
        or value.sandbox_capability_report_digest != capability_digest
    ):
        raise ExperimentConflict(
            f"trusted sandbox executor identity/capability drifted at {label}"
        )
    if expected_fingerprint is not None and value.fingerprint != expected_fingerprint:
        raise ExperimentConflict(f"trusted current state drifted at {label}")
    return value


def _strict_semantic_json_digest(payload: bytes, label: str) -> str:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON")
            ),
        )
        if type(value) is not dict:
            raise ValueError("root must be an object")
        return canonical_json_digest(value)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
        ManifestError,
        RecursionError,
    ) as error:
        raise ExperimentError(f"{label} is not strict semantic JSON") from error


class _ReadOnlyReplayBinding(TrustedReplayBinding):
    """Ephemeral collision checker for pure re-verification of persisted authority.

    A completed immutable bundle was replay-bound before result-last publication.
    Re-verification must authenticate it again without mutating the live replay
    ledger.  This adapter keeps only call-local collision state and therefore
    cannot grant authority outside the enclosing verification call.
    """

    def __init__(self) -> None:
        self._values: dict[str, tuple[str, str, str]] = {}

    def bind(
        self,
        *,
        attestation_id: str,
        attestation_type: str,
        scope_digest: str,
        body_digest: str,
    ) -> str:
        value = (attestation_type, scope_digest, body_digest)
        prior = self._values.get(attestation_id)
        if prior is not None and prior != value:
            raise AttestationError("persisted attestation replay identity conflicts")
        self._values[attestation_id] = value
        return "replay"


def _verify_current_deployments(
    request: ExperimentRequest,
    context: ExperimentContext,
    state: CurrentTrustedState,
    now: datetime,
    *,
    replay_binding: TrustedReplayBinding | None = None,
) -> VerifiedDeploymentPair:
    try:
        pair = verify_deployment_pair(
            request.stage_attestation,
            request.hook_attestation,
            stage_expectation=request.stage_expectation,
            hook_expectation=request.hook_expectation,
            verifier=context.verifier,
            replay=context.replay if replay_binding is None else replay_binding,
            stage_chain=context.stage_chain,
            hook_chain=context.hook_chain,
            now=now,
            maximum_ttl=context.maximum_attestation_ttl,
        )
    except AttestationError as error:
        raise ExperimentError("deployment attestation verification failed") from error
    if (
        pair.stage.digest != state.stage_attestation_digest
        or pair.hook.digest != state.hook_attestation_digest
    ):
        raise ExperimentConflict("deployment attestation authority drifted")
    return pair


def _admit_sandbox_execution(
    value: object,
    *,
    invocation: SandboxInvocation,
    context: ExperimentContext,
) -> SandboxExecution:
    if type(value) is not SandboxExecution:
        raise SandboxExecutionError("sandbox result is not an exact trusted receipt")
    try:
        baseline = SuiteOutcome(
            tuple(CaseOutcome(item.case_id, item.passed) for item in value.baseline.cases),
            tuple(
                CaseOutcome(item.case_id, item.passed)
                for item in value.baseline.hard_invariants
            ),
        )
        variant = SuiteOutcome(
            tuple(CaseOutcome(item.case_id, item.passed) for item in value.variant.cases),
            tuple(
                CaseOutcome(item.case_id, item.passed)
                for item in value.variant.hard_invariants
            ),
        )
        admitted = SandboxExecution(
            baseline,
            variant,
            tuple(value.artifact_digests),
            value.sandbox_policy_digest,
            value.external_mutation_performed,
            value.invocation_digest,
            value.executor_identity_digest,
            value.capability_report_digest,
        )
    except (ExperimentError, TypeError, ValueError, AttributeError) as error:
        raise SandboxExecutionError("sandbox result receipt schema is invalid") from error
    if admitted.to_mapping() != value.to_mapping():
        raise SandboxExecutionError("sandbox result receipt changed after admission")
    if (
        admitted.invocation_digest != invocation.digest
        or admitted.sandbox_policy_digest != invocation.sandbox_policy.digest
        or admitted.executor_identity_digest != context.sandbox_executor.identity_digest
        or admitted.capability_report_digest
        != context.sandbox_executor.capability_report_digest
    ):
        raise SandboxExecutionError(
            "sandbox result receipt does not bind this invocation/executor"
        )
    return admitted


def _evaluate_execution(
    request: ExperimentRequest,
    *,
    pre_manifest: SkillManifest,
    post_manifest: SkillManifest,
    execution: SandboxExecution,
) -> ExperimentResult:
    expected_cases = request.harness.expected_case_ids
    expected_invariants = request.harness.expected_invariant_ids
    baseline_cases = {item.case_id: item.passed for item in execution.baseline.cases}
    variant_cases = {item.case_id: item.passed for item in execution.variant.cases}
    baseline_invariants = {
        item.case_id: item.passed for item in execution.baseline.hard_invariants
    }
    variant_invariants = {
        item.case_id: item.passed for item in execution.variant.hard_invariants
    }
    exact_case_ids = (
        tuple(sorted(baseline_cases, key=lambda item: item.encode("utf-8")))
        == expected_cases
        and tuple(sorted(variant_cases, key=lambda item: item.encode("utf-8")))
        == expected_cases
    )
    exact_invariant_ids = (
        tuple(sorted(baseline_invariants, key=lambda item: item.encode("utf-8")))
        == expected_invariants
        and tuple(sorted(variant_invariants, key=lambda item: item.encode("utf-8")))
        == expected_invariants
    )
    observed_case_ids = tuple(
        sorted(
            set(baseline_cases).union(variant_cases),
            key=lambda item: item.encode("utf-8"),
        )
    )
    regressions = tuple(
        sorted(
            (
                case_id
                for case_id in observed_case_ids
                if baseline_cases.get(case_id) is True
                and variant_cases.get(case_id) is False
            ),
            key=lambda item: item.encode("utf-8"),
        )
    )
    improvements = tuple(
        sorted(
            (
                case_id
                for case_id in observed_case_ids
                if baseline_cases.get(case_id) is False
                and variant_cases.get(case_id) is True
            ),
            key=lambda item: item.encode("utf-8"),
        )
    )
    baseline_invariants_passed = exact_invariant_ids and all(
        baseline_invariants.get(item) is True for item in expected_invariants
    )
    variant_invariants_passed = exact_invariant_ids and all(
        variant_invariants.get(item) is True for item in expected_invariants
    )
    passed_baseline = sum(
        baseline_cases.get(item) is True for item in observed_case_ids
    )
    passed_variant = sum(
        variant_cases.get(item) is True for item in observed_case_ids
    )
    eligible = (
        exact_case_ids
        and exact_invariant_ids
        and not regressions
        and baseline_invariants_passed
        and variant_invariants_passed
        and passed_variant >= passed_baseline
        and not execution.external_mutation_performed
    )
    artifacts = tuple(sorted(set((*execution.artifact_digests, execution.digest))))
    return ExperimentResult(
        candidate_id=request.candidate.candidate_id,
        baseline_revision=pre_manifest.digest,
        variant_revision=post_manifest.digest,
        harness_version=request.harness.version,
        cases=CaseCounts(len(observed_case_ids), passed_baseline, passed_variant),
        baseline_invariants_passed=baseline_invariants_passed,
        variant_invariants_passed=variant_invariants_passed,
        regressions=regressions,
        improvements=improvements,
        decision="eligible" if eligible else "rejected",
        artifacts=artifacts,
        external_mutation_performed=False,
    )


def _validation_signed_body(
    request: ExperimentRequest,
    result: ExperimentResult,
    replacement: ArtifactReplacement,
    *,
    issuer: str,
) -> dict[str, object]:
    identity_digest = canonical_json_digest(
        {
            "schemaVersion": 1,
            "domain": "rsi-validation-attestation-id-v1",
            "operationId": request.operation_id,
            "requestDigest": request.digest,
            "result": result.to_mapping(),
            "diffDigest": replacement.diff_digest,
        }
    )
    return {
        "schemaVersion": 1,
        "attestationId": "validation_" + identity_digest[7:39],
        "issuer": issuer,
        "signatureAlgorithm": "platform-attestation-v1",
        "candidateId": request.candidate.candidate_id,
        "candidateDigest": request.candidate.digest,
        "diffDigest": replacement.diff_digest,
        "targetPreHash": request.target.manifest_pre_hash,
        "ownerContractHash": request.target.owner_contract_hash,
        "evidenceRefs": list(request.candidate.evidence_refs),
        "controlPlane": request.control_plane.to_mapping(),
        "testArtifactDigests": list(result.artifacts),
        "sandboxPolicyDigest": request.sandbox_policy.digest,
        "createdAt": request.created_at,
        "expiresAt": request.expires_at,
        "decision": result.decision,
    }


def _issue_and_verify_validation(
    request: ExperimentRequest,
    context: ExperimentContext,
    result: ExperimentResult,
    replacement: ArtifactReplacement,
    *,
    now: datetime,
) -> tuple[bytes, VerifiedValidationAttestation]:
    signed_body = _validation_signed_body(
        request,
        result,
        replacement,
        issuer=context.validation_issuer,
    )
    try:
        raw = context.issuer.issue(signed_body)
    except Exception as error:
        raise ExperimentError("trusted validation issuer failed") from error
    if type(raw) is not bytes or not raw or len(raw) > 128 * 1024:
        raise ExperimentError("trusted validation issuer returned invalid bytes")
    try:
        parsed_issuer_value = parse_validation_attestation(raw)
        issuer_canonical = canonical_json_bytes(parsed_issuer_value.to_mapping())
    except (AttestationError, ManifestError, TypeError, ValueError) as error:
        raise ExperimentError(
            "trusted validation issuer returned invalid canonical framing"
        ) from error
    if issuer_canonical != raw:
        raise ExperimentError(
            "trusted validation issuer returned noncanonical framing"
        )
    expectation = ValidationExpectation(
        issuer=context.validation_issuer,
        candidate_id=request.candidate.candidate_id,
        candidate_digest=request.candidate.digest,
        diff_digest=replacement.diff_digest,
        target_pre_hash=request.target.manifest_pre_hash,
        owner_contract_hash=request.target.owner_contract_hash,
        evidence_refs=request.candidate.evidence_refs,
        control_plane=request.control_plane,
        test_artifact_digests=result.artifacts,
        sandbox_policy_digest=request.sandbox_policy.digest,
        decision=result.decision,
    )
    try:
        verified = verify_validation_attestation(
            raw,
            expectation=expectation,
            verifier=context.verifier,
            replay=context.replay,
            now=now,
            maximum_ttl=context.maximum_attestation_ttl,
            require_eligible=False,
        )
    except AttestationError as error:
        raise ExperimentError("validation attestation signature or binding is invalid") from error
    return raw, verified


def _reverify_validation(
    raw: bytes,
    request: ExperimentRequest,
    context: ExperimentContext,
    result: ExperimentResult,
    replacement: ArtifactReplacement,
    *,
    now: datetime,
    replay_binding: TrustedReplayBinding | None = None,
) -> VerifiedValidationAttestation:
    expectation = ValidationExpectation(
        context.validation_issuer,
        request.candidate.candidate_id,
        request.candidate.digest,
        replacement.diff_digest,
        request.target.manifest_pre_hash,
        request.target.owner_contract_hash,
        request.candidate.evidence_refs,
        request.control_plane,
        result.artifacts,
        request.sandbox_policy.digest,
        result.decision,
    )
    try:
        return verify_validation_attestation(
            raw,
            expectation=expectation,
            verifier=context.verifier,
            replay=context.replay if replay_binding is None else replay_binding,
            now=now,
            maximum_ttl=context.maximum_attestation_ttl,
            require_eligible=False,
        )
    except AttestationError as error:
        raise ExperimentError("validation attestation recheck failed") from error


def _bundle_artifact_bytes(
    label: str,
    *,
    operation_id: str,
    reservation_digest: str,
    payload: dict[str, object],
) -> bytes:
    mapping = {
        "schemaVersion": 1,
        "domain": _BUNDLE_ARTIFACT_DOMAINS[label],
        "operationId": operation_id,
        "requestDigest": reservation_digest,
        "payloadDigest": canonical_json_digest(payload),
        "payload": payload,
    }
    return canonical_json_bytes(mapping)


def _result_marker_bytes(
    *,
    store: ExperimentArtifactStore,
    operation_id: str,
    reservation_digest: str,
    decision: str,
    manifest: bytes,
    attestation: bytes,
    plan: bytes,
) -> bytes:
    return canonical_json_bytes(
        {
            "schemaVersion": 1,
            "domain": "rsi-experiment-result-marker-v1",
            "operationId": operation_id,
            "operationKey": store._operation_key(operation_id),
            "requestDigest": reservation_digest,
            "manifestArtifactDigest": raw_sha256(manifest),
            "attestationArtifactDigest": raw_sha256(attestation),
            "planArtifactDigest": raw_sha256(plan),
            "decision": decision,
        }
    )


def _publish_experiment_bundle(
    *,
    store: ExperimentArtifactStore,
    reservation: ExperimentReservation,
    request: ExperimentRequest,
    result: ExperimentResult,
    execution: SandboxExecution,
    replacement: ArtifactReplacement,
    pre_manifest: SkillManifest,
    post_manifest: SkillManifest,
    validation_raw: bytes,
    validation: VerifiedValidationAttestation,
    plan: PromotionPlan | None,
) -> None:
    manifest_payload: dict[str, object] = {
        "decision": result.decision,
        "requestDigest": request.digest,
        "result": result.to_mapping(),
        "resultDigest": canonical_json_digest(result.to_mapping()),
        "manifestPre": pre_manifest.to_mapping(),
        "manifestPreDigest": pre_manifest.digest,
        "manifestPost": post_manifest.to_mapping(),
        "manifestPostDigest": post_manifest.digest,
        "replacement": {
            "relativePath": replacement.relative_path,
            "preHash": replacement.pre_hash,
            "postHash": replacement.post_hash,
            "postByteSize": replacement.post_byte_size,
            "executable": replacement.executable,
            "diffDigest": replacement.diff_digest,
        },
        "sandboxExecution": execution.to_mapping(),
        "sandboxExecutionDigest": execution.digest,
    }
    attestation_payload: dict[str, object] = {
        "decision": result.decision,
        "validationAttestation": validation.attestation.to_mapping(),
        "validationAttestationDigest": validation.digest,
        "validationAttestationRawDigest": raw_sha256(validation_raw),
    }
    plan_payload: dict[str, object] = {
        "decision": result.decision,
        "plan": None if plan is None else plan.to_mapping(),
        "planDigest": None if plan is None else plan.digest,
    }
    manifest_bytes = _bundle_artifact_bytes(
        "manifest",
        operation_id=request.operation_id,
        reservation_digest=reservation.request_digest,
        payload=manifest_payload,
    )
    attestation_bytes = _bundle_artifact_bytes(
        "attestation",
        operation_id=request.operation_id,
        reservation_digest=reservation.request_digest,
        payload=attestation_payload,
    )
    plan_bytes = _bundle_artifact_bytes(
        "plan",
        operation_id=request.operation_id,
        reservation_digest=reservation.request_digest,
        payload=plan_payload,
    )
    marker = _result_marker_bytes(
        store=store,
        operation_id=request.operation_id,
        reservation_digest=reservation.request_digest,
        decision=result.decision,
        manifest=manifest_bytes,
        attestation=attestation_bytes,
        plan=plan_bytes,
    )
    store.publish_bundle(
        request.operation_id,
        manifest=manifest_bytes,
        attestation=attestation_bytes,
        plan=plan_bytes,
        result=marker,
    )


def _closed_bundle_mapping(
    value: object, fields: set[str], label: str
) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise ExperimentStoreError(f"authoritative {label} bundle schema is invalid")
    return value


def _parse_skill_manifest_mapping(value: object) -> SkillManifest:
    source = _closed_bundle_mapping(
        value,
        {"schemaVersion", "domain", "algorithm", "entries"},
        "skill manifest",
    )
    entries = source["entries"]
    if (
        type(source["schemaVersion"]) is not int
        or source["schemaVersion"] != 1
        or source["domain"] != "rsi-skill-manifest-v1"
        or source["algorithm"] != "sha256"
        or type(entries) is not list
        or len(entries) > _RUN_MAX_TREE_RECORDS
    ):
        raise ExperimentStoreError("authoritative skill manifest schema is invalid")
    admitted: list[ManifestEntry] = []
    try:
        for raw in entries:
            item = _closed_bundle_mapping(
                raw,
                {"path", "type", "byteSize", "executable", "digest"},
                "skill manifest entry",
            )
            admitted.append(
                ManifestEntry(
                    item["path"],
                    item["type"],
                    item["byteSize"],
                    item["executable"],
                    item["digest"],
                )
            )
        manifest = SkillManifest(tuple(admitted))
    except (ManifestError, TypeError, ValueError, AttributeError) as error:
        raise ExperimentStoreError("authoritative skill manifest is invalid") from error
    if manifest.to_mapping() != source:
        raise ExperimentStoreError("authoritative skill manifest changed on admission")
    return manifest


def _parse_result_mapping(value: object) -> ExperimentResult:
    source = _closed_bundle_mapping(
        value,
        {
            "candidateId",
            "baselineRevision",
            "variantRevision",
            "harnessVersion",
            "cases",
            "hardInvariants",
            "regressions",
            "improvements",
            "decision",
            "artifacts",
            "externalMutationPerformed",
        },
        "experiment result",
    )
    cases = _closed_bundle_mapping(
        source["cases"],
        {"total", "passedBaseline", "passedVariant"},
        "experiment result cases",
    )
    invariants = _closed_bundle_mapping(
        source["hardInvariants"],
        {"baselinePassed", "variantPassed"},
        "experiment result invariants",
    )
    if (
        type(source["regressions"]) is not list
        or type(source["improvements"]) is not list
        or type(source["artifacts"]) is not list
    ):
        raise ExperimentStoreError("authoritative experiment result arrays are invalid")
    try:
        result = ExperimentResult(
            source["candidateId"],
            source["baselineRevision"],
            source["variantRevision"],
            source["harnessVersion"],
            CaseCounts(
                cases["total"], cases["passedBaseline"], cases["passedVariant"]
            ),
            invariants["baselinePassed"],
            invariants["variantPassed"],
            tuple(source["regressions"]),
            tuple(source["improvements"]),
            source["decision"],
            tuple(source["artifacts"]),
            source["externalMutationPerformed"],
        )
    except (ExperimentError, TypeError, ValueError, AttributeError) as error:
        raise ExperimentStoreError("authoritative experiment result is invalid") from error
    if result.to_mapping() != source:
        raise ExperimentStoreError("authoritative experiment result changed on admission")
    return result


def _parse_suite_mapping(value: object, label: str) -> SuiteOutcome:
    source = _closed_bundle_mapping(value, {"cases", "hardInvariants"}, label)
    if type(source["cases"]) is not list or type(source["hardInvariants"]) is not list:
        raise ExperimentStoreError(f"authoritative {label} arrays are invalid")

    def outcomes(values: list[object], nested_label: str) -> tuple[CaseOutcome, ...]:
        result: list[CaseOutcome] = []
        for raw in values:
            item = _closed_bundle_mapping(
                raw, {"id", "passed"}, f"{label} {nested_label}"
            )
            result.append(CaseOutcome(item["id"], item["passed"]))
        return tuple(result)

    try:
        return SuiteOutcome(
            outcomes(source["cases"], "case"),
            outcomes(source["hardInvariants"], "invariant"),
        )
    except (ExperimentError, TypeError, ValueError, AttributeError) as error:
        raise ExperimentStoreError(f"authoritative {label} is invalid") from error


def _parse_execution_mapping(value: object) -> SandboxExecution:
    source = _closed_bundle_mapping(
        value,
        {
            "schemaVersion",
            "domain",
            "invocationDigest",
            "executorIdentityDigest",
            "capabilityReportDigest",
            "baseline",
            "variant",
            "artifactDigests",
            "sandboxPolicyDigest",
            "externalMutationPerformed",
        },
        "sandbox execution",
    )
    if (
        type(source["schemaVersion"]) is not int
        or source["schemaVersion"] != 1
        or source["domain"] != "rsi-sandbox-execution-receipt-v1"
        or type(source["artifactDigests"]) is not list
    ):
        raise ExperimentStoreError("authoritative sandbox execution schema is invalid")
    try:
        execution = SandboxExecution(
            _parse_suite_mapping(source["baseline"], "baseline suite"),
            _parse_suite_mapping(source["variant"], "variant suite"),
            tuple(source["artifactDigests"]),
            source["sandboxPolicyDigest"],
            source["externalMutationPerformed"],
            source["invocationDigest"],
            source["executorIdentityDigest"],
            source["capabilityReportDigest"],
        )
    except (ExperimentError, TypeError, ValueError, AttributeError) as error:
        raise ExperimentStoreError("authoritative sandbox execution is invalid") from error
    if execution.to_mapping() != source:
        raise ExperimentStoreError("authoritative sandbox execution changed on admission")
    return execution


@dataclass(frozen=True, slots=True)
class _DecodedExperimentArtifacts:
    result: ExperimentResult
    execution: SandboxExecution
    pre_manifest: SkillManifest
    post_manifest: SkillManifest
    replacement: ArtifactReplacement
    validation_raw: bytes
    validation_attestation: ValidationAttestation
    validation_digest: str
    plan: PromotionPlan | None


def _decode_experiment_artifacts(
    payloads: Mapping[str, bytes],
    *,
    request: ExperimentRequest,
    reservation_digest: str,
) -> _DecodedExperimentArtifacts:
    if type(payloads) is not dict or set(payloads) != {
        "manifest",
        "attestation",
        "plan",
        "result",
    }:
        raise ExperimentStoreError("authoritative experiment bundle set is invalid")
    envelopes: dict[str, dict[str, object]] = {}
    for label in ("manifest", "attestation", "plan"):
        envelopes[label] = _validate_bundle_artifact(
            payloads[label],
            label,
            operation_id=request.operation_id,
            request_digest=reservation_digest,
        )
    manifest_payload = _closed_bundle_mapping(
        envelopes["manifest"]["payload"],
        {
            "decision",
            "requestDigest",
            "result",
            "resultDigest",
            "manifestPre",
            "manifestPreDigest",
            "manifestPost",
            "manifestPostDigest",
            "replacement",
            "sandboxExecution",
            "sandboxExecutionDigest",
        },
        "manifest artifact payload",
    )
    attestation_payload = _closed_bundle_mapping(
        envelopes["attestation"]["payload"],
        {
            "decision",
            "validationAttestation",
            "validationAttestationDigest",
            "validationAttestationRawDigest",
        },
        "attestation artifact payload",
    )
    plan_payload = _closed_bundle_mapping(
        envelopes["plan"]["payload"],
        {"decision", "plan", "planDigest"},
        "plan artifact payload",
    )
    result = _parse_result_mapping(manifest_payload["result"])
    pre_manifest = _parse_skill_manifest_mapping(manifest_payload["manifestPre"])
    post_manifest = _parse_skill_manifest_mapping(manifest_payload["manifestPost"])
    replacement_mapping = _closed_bundle_mapping(
        manifest_payload["replacement"],
        {
            "relativePath",
            "preHash",
            "postHash",
            "postByteSize",
            "executable",
            "diffDigest",
        },
        "artifact replacement",
    )
    try:
        replacement = ArtifactReplacement(
            replacement_mapping["relativePath"],
            replacement_mapping["preHash"],
            replacement_mapping["postHash"],
            replacement_mapping["executable"],
            replacement_mapping["diffDigest"],
            replacement_mapping["postByteSize"],
        )
    except (ManifestError, TypeError, ValueError, AttributeError) as error:
        raise ExperimentStoreError("authoritative artifact replacement is invalid") from error
    execution = _parse_execution_mapping(manifest_payload["sandboxExecution"])
    try:
        validation_raw = canonical_json_bytes(
            attestation_payload["validationAttestation"]
        )
        validation_attestation = parse_validation_attestation(validation_raw)
        validation_digest = attestation_body_digest(validation_attestation)
    except (AttestationError, ManifestError, TypeError, ValueError) as error:
        raise ExperimentStoreError("authoritative validation attestation is invalid") from error
    plan_value = plan_payload["plan"]
    if plan_value is None:
        plan = None
    elif type(plan_value) is dict:
        plan = parse_promotion_plan(canonical_json_bytes(plan_value))
    else:
        raise ExperimentStoreError("authoritative promotion plan payload is invalid")

    decision = result.decision
    expected_post = manifest_with_replacement(pre_manifest, replacement)
    recomputed_result = _evaluate_execution(
        request,
        pre_manifest=pre_manifest,
        post_manifest=post_manifest,
        execution=execution,
    )
    if (
        manifest_payload["decision"] != decision
        or attestation_payload["decision"] != decision
        or plan_payload["decision"] != decision
        or manifest_payload["requestDigest"] != request.digest
        or manifest_payload["resultDigest"]
        != canonical_json_digest(result.to_mapping())
        or manifest_payload["manifestPreDigest"] != pre_manifest.digest
        or manifest_payload["manifestPostDigest"] != post_manifest.digest
        or manifest_payload["sandboxExecutionDigest"] != execution.digest
        or attestation_payload["validationAttestationDigest"]
        != validation_digest
        or attestation_payload["validationAttestationRawDigest"]
        != raw_sha256(validation_raw)
        or expected_post.canonical_bytes != post_manifest.canonical_bytes
        or recomputed_result != result
        or result.candidate_id != request.candidate.candidate_id
        or result.baseline_revision != pre_manifest.digest
        or result.variant_revision != post_manifest.digest
        or result.harness_version != request.harness.version
        or replacement.relative_path != request.artifact.relative_path
        or replacement.post_hash != request.artifact.post_hash
        or replacement.post_byte_size != len(request.artifact.post_image)
        or validation_attestation.decision != decision
        or validation_attestation.candidate_id != request.candidate.candidate_id
        or validation_attestation.candidate_digest != request.candidate.digest
        or validation_attestation.diff_digest != replacement.diff_digest
        or validation_attestation.target_pre_hash != pre_manifest.digest
        or validation_attestation.owner_contract_hash
        != request.target.owner_contract_hash
        or validation_attestation.evidence_refs != request.candidate.evidence_refs
        or validation_attestation.control_plane != request.control_plane
        or validation_attestation.test_artifact_digests != result.artifacts
        or validation_attestation.sandbox_policy_digest
        != request.sandbox_policy.digest
    ):
        raise ExperimentStoreError("authoritative experiment bundle bindings conflict")
    if decision == "eligible":
        if (
            plan is None
            or plan_payload["planDigest"] != plan.digest
            or plan.candidate_id != request.candidate.candidate_id
            or plan.candidate_digest != request.candidate.digest
            or plan.validation_attestation_digest != validation_digest
            or plan.target.manifest_pre_hash != pre_manifest.digest
            or plan.target.manifest_post_hash != post_manifest.digest
            or plan.artifact.relative_path != replacement.relative_path
            or plan.artifact.pre_hash != replacement.pre_hash
            or plan.artifact.post_hash != replacement.post_hash
            or plan.artifact.diff_digest != replacement.diff_digest
        ):
            raise ExperimentStoreError("eligible authoritative bundle has no exact plan")
    elif plan is not None or plan_payload["planDigest"] is not None:
        raise ExperimentStoreError("rejected authoritative bundle contains a plan")
    return _DecodedExperimentArtifacts(
        result,
        execution,
        pre_manifest,
        post_manifest,
        replacement,
        validation_raw,
        validation_attestation,
        validation_digest,
        plan,
    )


def _read_completed_payloads_if_present(
    store: ExperimentArtifactStore, operation_id: str
) -> dict[str, bytes] | None:
    try:
        return store.read_bundle_payloads(operation_id)
    except ExperimentStoreError as error:
        if str(error) == "experiment bundle is incomplete":
            return None
        raise


def _persisted_reservation_digest(payloads: Mapping[str, bytes]) -> str:
    if type(payloads) is not dict or type(payloads.get("result")) is not bytes:
        raise ExperimentStoreError("authoritative experiment result is unavailable")
    marker = _canonical_store_object(payloads["result"], "result")
    value = marker.get("requestDigest")
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ExperimentStoreError(
            "authoritative experiment result reservation binding is invalid"
        )
    return value


def _assert_signed_authorities_current(
    authorities: Sequence[object], *, now: datetime
) -> None:
    for authority in authorities:
        try:
            created = parse_timestamp(authority.created_at)
            expires = parse_timestamp(authority.expires_at)
        except (AttestationError, AttributeError, TypeError) as error:
            raise ExperimentError("signed authority time binding is invalid") from error
        if not (created <= now < expires):
            raise ExperimentError("signed authority is expired or not yet current")


def _assert_plan_matches_current_authority(
    plan: PromotionPlan,
    *,
    request: ExperimentRequest,
    state: CurrentTrustedState,
    deployments: VerifiedDeploymentPair,
    validation: VerifiedValidationAttestation,
    replacement: ArtifactReplacement,
    pre_manifest: SkillManifest,
    post_manifest: SkillManifest,
) -> None:
    plan.assert_admitted()
    expected = (
        (plan.candidate_id, request.candidate.candidate_id),
        (plan.candidate_digest, request.candidate.digest),
        (plan.validation_attestation_digest, validation.digest),
        (plan.allowlist_entry_id, request.target.allowlist_entry.entry_id),
        (
            plan.allowlist_entry_digest,
            allowlist_entry_digest(request.target.allowlist_entry),
        ),
        (
            plan.canonical_root_identity_digest,
            state.canonical_root_identity_digest,
        ),
        (plan.rollout_manifest_digest, request.rollout_manifest_digest),
        (plan.stage_attestation_digest, deployments.stage.digest),
        (plan.hook_attestation_digest, deployments.hook.digest),
        (plan.provider_contract_digest, request.provider_contract_digest),
        (plan.provider_version_digest, request.provider_version_digest),
        (plan.target.skill_name, request.target.skill_name),
        (plan.target.owner_contract_hash, request.target.owner_contract_hash),
        (plan.target.manifest_pre_hash, pre_manifest.digest),
        (plan.target.manifest_post_hash, post_manifest.digest),
        (plan.artifact.relative_path, replacement.relative_path),
        (plan.artifact.pre_hash, replacement.pre_hash),
        (plan.artifact.post_hash, replacement.post_hash),
        (plan.artifact.diff_digest, replacement.diff_digest),
        (plan.artifact.post_image_ref, post_image_ref(request.artifact.post_image)),
        (plan.control_plane_digest, state.control_plane_digest),
        (plan.created_at, request.created_at),
        (plan.expires_at, request.expires_at),
    )
    if any(actual != wanted for actual, wanted in expected):
        raise ExperimentConflict(
            "promotion plan no longer matches current target/control authority"
        )


def _admit_completed_bundle(
    payloads: Mapping[str, bytes],
    *,
    reservation_digest: str,
    request: ExperimentRequest,
    context: ExperimentContext,
    store: ExperimentArtifactStore,
    state: CurrentTrustedState,
    deployments: VerifiedDeploymentPair,
    replay_binding: TrustedReplayBinding,
    now: datetime,
    pre_manifest: SkillManifest,
    post_manifest: SkillManifest,
    replacement: ArtifactReplacement,
) -> ExperimentBundle:
    decoded = _decode_experiment_artifacts(
        payloads,
        request=request,
        reservation_digest=reservation_digest,
    )
    if (
        decoded.pre_manifest.canonical_bytes != pre_manifest.canonical_bytes
        or decoded.post_manifest.canonical_bytes != post_manifest.canonical_bytes
        or decoded.replacement != replacement
        or decoded.execution.sandbox_policy_digest != request.sandbox_policy.digest
        or decoded.execution.executor_identity_digest
        != state.sandbox_executor_identity_digest
        or decoded.execution.capability_report_digest
        != state.sandbox_capability_report_digest
        or decoded.execution.external_mutation_performed
    ):
        raise ExperimentConflict(
            "completed experiment bundle no longer matches current execution authority"
        )
    validation = _reverify_validation(
        decoded.validation_raw,
        request,
        context,
        decoded.result,
        replacement,
        now=now,
        replay_binding=replay_binding,
    )
    if validation.digest != decoded.validation_digest:
        raise ExperimentStoreError(
            "authoritative validation attestation digest changed during verification"
        )
    if decoded.result.decision == "eligible":
        if decoded.plan is None:
            raise ExperimentStoreError("eligible authoritative bundle has no plan")
        _assert_plan_matches_current_authority(
            decoded.plan,
            request=request,
            state=state,
            deployments=deployments,
            validation=validation,
            replacement=replacement,
            pre_manifest=pre_manifest,
            post_manifest=post_manifest,
        )
        persisted_post = store.read_post_image(decoded.plan.artifact.post_image_ref)
        if persisted_post != request.artifact.post_image:
            raise ExperimentStoreError(
                "authoritative promotion post-image bytes conflict"
            )
    elif decoded.plan is not None:
        raise ExperimentStoreError("rejected authoritative bundle contains a plan")
    return ExperimentBundle(
        decoded.result,
        validation,
        decoded.plan,
        request.digest,
    )


def _assert_runtime_witnesses(
    *,
    source: _PinnedTree,
    harness: _PinnedRegularFile,
    control_roots: Sequence[_PinnedTree],
    staged: _StagedTrees | None,
) -> None:
    source.assert_unchanged()
    harness.assert_unchanged()
    for control in control_roots:
        control.assert_unchanged()
    if staged is not None:
        staged.assert_unchanged()


def verify_promotion_plan(
    plan: PromotionPlan,
    *,
    request: ExperimentRequest,
    context: ExperimentContext,
) -> bool:
    """Purely revalidate one persisted Task 7 plan for Task 8 consumption.

    This seam opens only an already-owned artifact store, never reserves,
    publishes, signs, executes, or binds the live replay ledger.  All mutable
    authorities and target bytes are sampled again around strict bundle reads.
    """

    if (
        type(plan) is not PromotionPlan
        or type(request) is not ExperimentRequest
        or type(context) is not ExperimentContext
    ):
        raise ExperimentError("promotion plan verification inputs are invalid")
    plan.assert_admitted()
    request.assert_admitted()
    source: _PinnedTree | None = None
    harness: _PinnedRegularFile | None = None
    controls: list[_PinnedTree] = []
    try:
        source = _PinnedTree(
            request.target.canonical_root,
            label="promotion target source tree",
            reject_sensitive=True,
        )
        harness = _PinnedRegularFile(
            request.harness.path, label="promotion test harness"
        )
        for path in context.control_plane_roots:
            controls.append(
                _PinnedTree(
                    path,
                    label="promotion control-plane root",
                    reject_sensitive=True,
                )
            )
        initial_time = _trusted_time_sample(
            request, context, label="promotion-verify", prior=None
        )
        initial_state = _trusted_state_sample(
            context, label="promotion-verify", expected_fingerprint=None
        )
        _assert_runtime_witnesses(
            source=source,
            harness=harness,
            control_roots=controls,
            staged=None,
        )
        if (
            _portable_control_roots_digest(controls)
            != initial_state.control_plane_roots_digest
        ):
            raise ExperimentConflict(
                "promotion control-plane root authority drifted"
            )
        try:
            build_experiment_reservation(
                request,
                current_state=initial_state,
                trusted_now=initial_time,
                maximum_attestation_ttl=context.maximum_attestation_ttl,
            )
        except ExperimentError as error:
            raise ExperimentConflict(
                "promotion request/current authority relation drifted"
            ) from error
        replay_binding = _ReadOnlyReplayBinding()
        deployments = _verify_current_deployments(
            request,
            context,
            initial_state,
            initial_time,
            replay_binding=replay_binding,
        )

        try:
            pre_manifest = build_skill_manifest(request.target.canonical_root)
        except ManifestError as error:
            raise ExperimentError("promotion target manifest is unsafe") from error
        source.assert_unchanged()
        if (
            pre_manifest.digest != request.target.manifest_pre_hash
            or pre_manifest.digest != request.candidate.target_skill_version_hash
            or pre_manifest.digest != initial_state.target_manifest_digest
            or any(entry.type != "regular-file" for entry in pre_manifest.entries)
        ):
            raise ExperimentConflict("promotion target manifest authority drifted")

        registration_bytes, _ = source.read_regular("registration-manifest.json")
        contract_bytes, _ = source.read_regular("skill-contract.json")
        try:
            registration_digest = registration_manifest_digest_bytes(
                registration_bytes
            )
        except AttestationError as error:
            raise ExperimentError(
                "promotion registration manifest bytes are invalid"
            ) from error
        if (
            registration_digest != initial_state.registration_manifest_digest
            or registration_digest
            != registration_manifest_digest(
                _plain(request.target.registration_manifest)
            )
            or _strict_semantic_json_digest(
                contract_bytes, "promotion target skill contract"
            )
            != request.target.owner_contract_hash
        ):
            raise ExperimentConflict(
                "promotion target registration/contract authority drifted"
            )

        entries = {entry.path: entry for entry in pre_manifest.entries}
        before_entry = entries.get(request.artifact.relative_path)
        if before_entry is None or before_entry.type != "regular-file":
            raise ExperimentError(
                "promotion artifact is not one existing managed regular file"
            )
        pre_image, pre_metadata = source.read_regular(
            request.artifact.relative_path
        )
        if raw_sha256(pre_image) != before_entry.digest:
            raise ExperimentConflict("promotion artifact pre-image drifted")
        try:
            replacement = ArtifactReplacement.build(
                relative_path=request.artifact.relative_path,
                pre_bytes=pre_image,
                post_bytes=request.artifact.post_image,
                executable=bool(pre_metadata.st_mode & 0o111),
            )
            post_manifest = manifest_with_replacement(pre_manifest, replacement)
        except ManifestError as error:
            raise ExperimentError(
                "promotion artifact replacement binding is invalid"
            ) from error
        if (
            raw_sha256(harness.payload) != request.harness.bytes_digest
            or request.harness.bytes_digest != initial_state.harness_bytes_digest
            or request.harness.digest != initial_state.harness_binding_digest
        ):
            raise ExperimentConflict("promotion test harness authority drifted")

        store = ExperimentArtifactStore.open_existing(context.home)
        payloads = store.read_bundle_payloads(request.operation_id)
        reservation_digest = _persisted_reservation_digest(payloads)
        bundle = _admit_completed_bundle(
            payloads,
            reservation_digest=reservation_digest,
            request=request,
            context=context,
            store=store,
            state=initial_state,
            deployments=deployments,
            replay_binding=replay_binding,
            now=initial_time,
            pre_manifest=pre_manifest,
            post_manifest=post_manifest,
            replacement=replacement,
        )
        if (
            bundle.plan is None
            or bundle.plan.digest != plan.digest
            or bundle.plan.identity_mapping() != plan.identity_mapping()
        ):
            raise ExperimentConflict(
                "promotion plan does not match the authoritative persisted bundle"
            )

        final_time = _trusted_time_sample(
            request,
            context,
            label="promotion-verify-final",
            prior=initial_time,
        )
        final_state = _trusted_state_sample(
            context,
            label="promotion-verify-final",
            expected_fingerprint=initial_state.fingerprint,
        )
        _assert_runtime_witnesses(
            source=source,
            harness=harness,
            control_roots=controls,
            staged=None,
        )
        if (
            _portable_control_roots_digest(controls)
            != final_state.control_plane_roots_digest
        ):
            raise ExperimentConflict(
                "promotion control-plane root authority drifted during verification"
            )
        _assert_signed_authorities_current(
            (
                deployments.stage.attestation,
                deployments.hook.attestation,
                bundle.validation_attestation.attestation,
            ),
            now=final_time,
        )
        return True
    finally:
        for control in reversed(controls):
            control.close()
        if harness is not None:
            harness.close()
        if source is not None:
            source.close()


def _url_decoded_artifact_variant(value: str) -> str | None:
    try:
        decoded = unquote(value, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    return decoded if decoded != value else None


def _contains_credential_assignment(value: str) -> bool:
    """Detect bounded raw, URL-encoded, or Base64 credential assignments."""

    url_variant = _url_decoded_artifact_variant(value)
    variants = (value,) if url_variant is None else (value, url_variant)
    for variant in variants:
        if _CREDENTIAL_ASSIGNMENT_RE.search(variant) is not None:
            return True
        for match in _BASE64_ARTIFACT_TOKEN_RE.finditer(variant):
            token = match.group(1)
            if len(token) % 4:
                continue
            try:
                decoded = base64.b64decode(token, validate=True).decode(
                    "utf-8", "strict"
                )
            except (UnicodeDecodeError, ValueError):
                continue
            if _CREDENTIAL_ASSIGNMENT_RE.search(decoded) is not None:
                return True
            decoded_url = _url_decoded_artifact_variant(decoded)
            if (
                decoded_url is not None
                and _CREDENTIAL_ASSIGNMENT_RE.search(decoded_url) is not None
            ):
                return True
    return False


def _assert_artifact_safety(
    payload: bytes, *, trusted_prefix_bytes: int = 0
) -> None:
    """Scan every bounded UTF-8 character without retaining rejected evidence."""

    try:
        if (
            type(trusted_prefix_bytes) is not int
            or trusted_prefix_bytes < 0
            or trusted_prefix_bytes > len(payload)
        ):
            raise UnicodeDecodeError("utf-8", b"", 0, 1, "invalid prefix")
        text = payload[trusted_prefix_bytes:].decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise ExperimentError("artifact-safety-rejected") from None
    if "\x00" in text or any(
        ord(character) < 32 and character not in {"\n", "\r", "\t"}
        for character in text
    ):
        raise ExperimentError("artifact-safety-rejected")
    # sanitize_evidence scans its complete source value before it truncates an
    # accepted summary. Repeated overlapping windows therefore reuse the same
    # secret/PII/instruction semantics while covering the entire 4 MiB artifact.
    window = 3500
    step = 3000
    for offset in range(0, max(1, len(text)), step):
        chunk = text[offset : offset + window]
        if _contains_credential_assignment(chunk):
            raise ExperimentError("artifact-safety-rejected")
        result = sanitize_evidence(
            ({"kind": "artifact", "summary": chunk},),
            max_items=1,
            max_chars=1200,
        )
        if result.rejected_count:
            raise ExperimentError("artifact-safety-rejected")
        if offset + window >= len(text):
            break


def _strict_contract_object(payload: bytes) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise ValueError("duplicate or invalid key")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON")
            ),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
        RecursionError,
    ):
        raise ExperimentError("artifact-compatibility-rejected") from None
    if type(value) is not dict:
        raise ExperimentError("artifact-compatibility-rejected")
    return value


def _assert_v1_artifact_compatibility(
    request: ExperimentRequest,
    source: _PinnedTree,
) -> None:
    candidate = request.candidate
    relative = request.artifact.relative_path
    if (
        candidate.change_class != "knowledge"
        or candidate.destination_class not in {"reference", "skill"}
        or (
            candidate.destination_class == "reference"
            and not relative.startswith("references/")
        )
        or (candidate.destination_class == "skill" and relative != "SKILL.md")
    ):
        raise ExperimentError("artifact-compatibility-rejected")
    try:
        pre_image, _ = source.read_regular(relative)
        contract_bytes, _ = source.read_regular("skill-contract.json")
        contract = _strict_contract_object(contract_bytes)
    except ExperimentError:
        raise ExperimentError("artifact-compatibility-rejected") from None
    post_image = request.artifact.post_image
    if (
        not post_image.startswith(pre_image)
        or len(post_image) <= len(pre_image)
        or not post_image[len(pre_image) :].strip()
        or not post_image.endswith(b"\n")
    ):
        raise ExperimentError("artifact-compatibility-rejected")
    if candidate.destination_class == "reference":
        admission = contract.get("rsiAdmission")
        if (
            type(admission) is not dict
            or type(admission.get(relative)) is not str
            or admission[relative] not in {"fact", "knowledge", "reference"}
        ):
            raise ExperimentError("artifact-compatibility-rejected")
        _assert_artifact_safety(post_image)
        return
    newline = b"\r\n" if pre_image.startswith(b"---\r\n") else b"\n"
    opening = b"---" + newline
    closing = newline + b"---" + newline
    frontmatter_end = pre_image.find(closing, len(opening))
    if not pre_image.startswith(opening) or frontmatter_end < 0:
        raise ExperimentError("artifact-compatibility-rejected")
    _assert_artifact_safety(
        post_image,
        trusted_prefix_bytes=frontmatter_end + len(closing),
    )


def run_experiment(
    request: ExperimentRequest,
    context: ExperimentContext,
) -> ExperimentBundle:
    """Validate one captured candidate without mutating its target/provider/lifecycle."""

    if type(request) is not ExperimentRequest or type(context) is not ExperimentContext:
        raise ExperimentError("run_experiment requires exact request/context models")
    request.assert_admitted()
    if (
        request.candidate.change_class != "knowledge"
        or request.candidate.destination_class not in {"reference", "skill"}
    ):
        raise ExperimentError("artifact-compatibility-rejected")

    source: _PinnedTree | None = None
    harness: _PinnedRegularFile | None = None
    controls: list[_PinnedTree] = []
    staged: _StagedTrees | None = None
    try:
        source = _PinnedTree(
            request.target.canonical_root,
            label="target source tree",
            reject_sensitive=True,
        )
        _assert_v1_artifact_compatibility(request, source)
        harness = _PinnedRegularFile(request.harness.path, label="test harness")
        for path in context.control_plane_roots:
            controls.append(
                _PinnedTree(
                    path,
                    label="control-plane root",
                    reject_sensitive=True,
                )
            )
        t0 = _trusted_time_sample(request, context, label="S0", prior=None)
        state0 = _trusted_state_sample(
            context, label="S0", expected_fingerprint=None
        )
        _assert_runtime_witnesses(
            source=source,
            harness=harness,
            control_roots=controls,
            staged=None,
        )
        if _portable_control_roots_digest(controls) != state0.control_plane_roots_digest:
            raise ExperimentConflict(
                "control-plane root content/mode authority does not match current state"
            )
        lookup_store: ExperimentArtifactStore | None = None
        stored_reservation: bytes | None = None
        try:
            lookup_store = ExperimentArtifactStore.open_existing(context.home)
            stored_reservation = lookup_store.read_reservation(
                request.operation_id
            )
        except ExperimentStoreError as error:
            if str(error) not in {
                "experiment store is absent",
                "existing directory is not an owned experiment store",
            }:
                raise
            lookup_store = None

        if stored_reservation is not None and lookup_store is not None:
            _admit_existing_experiment_reservation(
                stored_reservation,
                request=request,
                current_state=state0,
                trusted_now=t0,
                maximum_attestation_ttl=context.maximum_attestation_ttl,
            )
            reservation = ExperimentReservation(
                "replay",
                context.home
                / "experiments"
                / ExperimentArtifactStore._operation_key(request.operation_id),
                raw_sha256(stored_reservation),
            )
            completed_payloads = _read_completed_payloads_if_present(
                lookup_store, request.operation_id
            )
            store = (
                lookup_store
                if completed_payloads is not None
                else ExperimentArtifactStore(context.home)
            )
        else:
            try:
                reservation_bytes = build_experiment_reservation(
                    request,
                    current_state=state0,
                    trusted_now=t0,
                    maximum_attestation_ttl=context.maximum_attestation_ttl,
                )
            except ExperimentError as error:
                raise ExperimentConflict(
                    "trusted current state does not match the experiment request operation"
                ) from error
            store = ExperimentArtifactStore(context.home)
            try:
                reservation = store.reserve(
                    request.operation_id, reservation_bytes
                )
            except ExperimentConflict as reserve_error:
                concurrent_store = ExperimentArtifactStore.open_existing(
                    context.home
                )
                concurrent_reservation = concurrent_store.read_reservation(
                    request.operation_id
                )
                if concurrent_reservation is None:
                    raise reserve_error
                race_time = _trusted_time_sample(
                    request,
                    context,
                    label="reservation-race",
                    prior=t0,
                )
                _admit_existing_experiment_reservation(
                    concurrent_reservation,
                    request=request,
                    current_state=state0,
                    trusted_now=race_time,
                    maximum_attestation_ttl=context.maximum_attestation_ttl,
                )
                t0 = race_time
                reservation = ExperimentReservation(
                    "replay",
                    context.home
                    / "experiments"
                    / ExperimentArtifactStore._operation_key(
                        request.operation_id
                    ),
                    raw_sha256(concurrent_reservation),
                )
            completed_payloads = _read_completed_payloads_if_present(
                store, request.operation_id
            )
        completed_replay = (
            _ReadOnlyReplayBinding() if completed_payloads is not None else None
        )
        if completed_replay is None:
            _verify_current_deployments(request, context, state0, t0)
        _assert_runtime_witnesses(
            source=source,
            harness=harness,
            control_roots=controls,
            staged=None,
        )
        try:
            pre_manifest = build_skill_manifest(request.target.canonical_root)
        except ManifestError as error:
            raise ExperimentError("target source manifest is unsafe") from error
        source.assert_unchanged()
        if (
            pre_manifest.digest != request.target.manifest_pre_hash
            or pre_manifest.digest != request.candidate.target_skill_version_hash
            or pre_manifest.digest != state0.target_manifest_digest
        ):
            raise ExperimentConflict("target source manifest does not match trusted authority")
        if any(entry.type != "regular-file" for entry in pre_manifest.entries):
            raise ExperimentError("Task 7 does not admit target manifest symlinks")

        registration_bytes, _ = source.read_regular("registration-manifest.json")
        contract_bytes, _ = source.read_regular("skill-contract.json")
        try:
            registration_digest = registration_manifest_digest_bytes(
                registration_bytes
            )
        except AttestationError as error:
            raise ExperimentError("target registration manifest bytes are invalid") from error
        if (
            registration_digest != state0.registration_manifest_digest
            or registration_digest
            != registration_manifest_digest(
                _plain(request.target.registration_manifest)
            )
            or _strict_semantic_json_digest(
                contract_bytes, "target skill contract"
            )
            != request.target.owner_contract_hash
        ):
            raise ExperimentConflict("target registration/contract authority changed")

        target_entries = {
            entry.path: entry for entry in pre_manifest.entries
        }
        before_entry = target_entries.get(request.artifact.relative_path)
        if before_entry is None or before_entry.type != "regular-file":
            raise ExperimentError("candidate artifact is not one existing managed file")
        pre_image, pre_metadata = source.read_regular(
            request.artifact.relative_path
        )
        if raw_sha256(pre_image) != before_entry.digest:
            raise ExperimentConflict("candidate artifact pre-image changed")
        if pre_image == request.artifact.post_image:
            raise ExperimentError("candidate artifact replacement is a no-op")
        try:
            replacement = ArtifactReplacement.build(
                relative_path=request.artifact.relative_path,
                pre_bytes=pre_image,
                post_bytes=request.artifact.post_image,
                executable=bool(pre_metadata.st_mode & 0o111),
            )
            post_manifest = manifest_with_replacement(pre_manifest, replacement)
        except ManifestError as error:
            raise ExperimentError("candidate artifact replacement binding is invalid") from error

        if (
            raw_sha256(harness.payload) != request.harness.bytes_digest
            or request.harness.bytes_digest != state0.harness_bytes_digest
            or request.harness.digest != state0.harness_binding_digest
        ):
            raise ExperimentConflict("test harness authority changed")

        if completed_payloads is not None and completed_replay is not None:
            replay_time = _trusted_time_sample(
                request, context, label="completed-replay", prior=t0
            )
            replay_state = _trusted_state_sample(
                context,
                label="completed-replay",
                expected_fingerprint=state0.fingerprint,
            )
            _assert_runtime_witnesses(
                source=source,
                harness=harness,
                control_roots=controls,
                staged=None,
            )
            if (
                _portable_control_roots_digest(controls)
                != replay_state.control_plane_roots_digest
            ):
                raise ExperimentConflict(
                    "control-plane authority drifted during completed replay"
                )
            replay_deployments = _verify_current_deployments(
                request,
                context,
                replay_state,
                replay_time,
                replay_binding=completed_replay,
            )
            bundle = _admit_completed_bundle(
                completed_payloads,
                reservation_digest=reservation.request_digest,
                request=request,
                context=context,
                store=store,
                state=replay_state,
                deployments=replay_deployments,
                replay_binding=completed_replay,
                now=replay_time,
                pre_manifest=pre_manifest,
                post_manifest=post_manifest,
                replacement=replacement,
            )
            replay_final = _trusted_time_sample(
                request, context, label="completed-replay-final", prior=replay_time
            )
            _trusted_state_sample(
                context,
                label="completed-replay-final",
                expected_fingerprint=state0.fingerprint,
            )
            _assert_runtime_witnesses(
                source=source,
                harness=harness,
                control_roots=controls,
                staged=None,
            )
            _assert_signed_authorities_current(
                (
                    replay_deployments.stage.attestation,
                    replay_deployments.hook.attestation,
                    bundle.validation_attestation.attestation,
                ),
                now=replay_final,
            )
            return bundle

        protected = [
            Path(request.target.canonical_root),
            Path(context.home),
            Path(request.harness.path),
            *(Path(item) for item in context.control_plane_roots),
        ]
        staged = _StagedTrees(
            source=source,
            pre_manifest=pre_manifest,
            post_manifest=post_manifest,
            replacement=replacement,
            post_image=request.artifact.post_image,
            disjoint_from=protected,
        )
        if staged.root is None:
            raise ExperimentError("staging root is unavailable")
        scratch = staged.create_scratch_and_seal()

        t1 = _trusted_time_sample(request, context, label="S1", prior=t0)
        state1 = _trusted_state_sample(
            context,
            label="S1",
            expected_fingerprint=state0.fingerprint,
        )
        _assert_runtime_witnesses(
            source=source,
            harness=harness,
            control_roots=controls,
            staged=staged,
        )
        _verify_current_deployments(request, context, state1, t1)
        t1 = _trusted_time_sample(
            request, context, label="S1-final", prior=t1
        )
        nonce = secrets.token_hex(16)
        invocation = SandboxInvocation(
            baseline_root=staged.baseline_root,
            variant_root=staged.variant_root,
            harness=request.harness,
            sandbox_policy=request.sandbox_policy,
            scratch_parent=scratch,
            artifact_relative_path=request.artifact.relative_path,
            post_image=request.artifact.post_image,
            host_home_probe=str(Path.home()),
            mcp_probe=str(Path(request.target.canonical_root).parent),
            outside_write_probe=str(context.home),
            operation_id=request.operation_id,
            request_digest=request.digest,
            baseline_manifest_digest=pre_manifest.digest,
            variant_manifest_digest=post_manifest.digest,
            replacement_digest=replacement.diff_digest,
            post_image_digest=replacement.post_hash,
            trusted_state_fingerprint=state0.fingerprint,
            control_plane_digest=state0.control_plane_digest,
            harness_binding_digest=request.harness.digest,
            executor_identity_digest=state0.sandbox_executor_identity_digest,
            capability_report_digest=state0.sandbox_capability_report_digest,
            invocation_nonce=nonce,
        )
        try:
            raw_execution = context.sandbox_executor.execute(invocation)
        except (SandboxTimeout, SandboxOutputLimit, SandboxUnavailable):
            raise
        except SandboxExecutionError:
            raise
        except Exception as error:
            raise SandboxExecutionError("sandbox execution crashed") from error
        scratch_artifact_digests = staged.admit_scratch_output(
            maximum_bytes=min(
                request.sandbox_policy.output_bytes,
                request.sandbox_policy.file_size_bytes,
                _MAX_BUNDLE_BYTES,
            )
        )
        execution = _admit_sandbox_execution(
            raw_execution,
            invocation=invocation,
            context=context,
        )
        if scratch_artifact_digests:
            execution = SandboxExecution(
                baseline=execution.baseline,
                variant=execution.variant,
                artifact_digests=tuple(
                    sorted(
                        set(
                            (
                                *execution.artifact_digests,
                                *scratch_artifact_digests,
                            )
                        )
                    )
                ),
                sandbox_policy_digest=execution.sandbox_policy_digest,
                external_mutation_performed=execution.external_mutation_performed,
                invocation_digest=execution.invocation_digest,
                executor_identity_digest=execution.executor_identity_digest,
                capability_report_digest=execution.capability_report_digest,
            )

        t2 = _trusted_time_sample(request, context, label="S2", prior=t1)
        state2 = _trusted_state_sample(
            context,
            label="S2",
            expected_fingerprint=state0.fingerprint,
        )
        _assert_runtime_witnesses(
            source=source,
            harness=harness,
            control_roots=controls,
            staged=staged,
        )
        _verify_current_deployments(request, context, state2, t2)
        t2 = _trusted_time_sample(
            request, context, label="S2-final", prior=t2
        )
        if execution.external_mutation_performed:
            raise SandboxExecutionError("sandbox reports a forbidden external mutation")
        result = _evaluate_execution(
            request,
            pre_manifest=pre_manifest,
            post_manifest=post_manifest,
            execution=execution,
        )
        validation_raw, validation = _issue_and_verify_validation(
            request,
            context,
            result,
            replacement,
            now=t2,
        )

        t3 = _trusted_time_sample(request, context, label="S3", prior=t2)
        state3 = _trusted_state_sample(
            context,
            label="S3",
            expected_fingerprint=state0.fingerprint,
        )
        _assert_runtime_witnesses(
            source=source,
            harness=harness,
            control_roots=controls,
            staged=staged,
        )
        deployment_pair = _verify_current_deployments(
            request, context, state3, t3
        )
        validation = _reverify_validation(
            validation_raw,
            request,
            context,
            result,
            replacement,
            now=t3,
        )

        t_publish = _trusted_time_sample(
            request, context, label="S3-final", prior=t3
        )
        for authority in (
            deployment_pair.stage.attestation,
            deployment_pair.hook.attestation,
            validation.attestation,
        ):
            try:
                authority_created = parse_timestamp(authority.created_at)
                authority_expires = parse_timestamp(authority.expires_at)
            except AttestationError as error:
                raise ExperimentError(
                    "signed authority time binding is invalid before publication"
                ) from error
            if not (authority_created <= t_publish < authority_expires):
                raise ExperimentError(
                    "signed authority expired before experiment publication"
                )

        plan: PromotionPlan | None = None
        if result.decision == "eligible":
            post_reference = post_image_ref(request.artifact.post_image)
            plan = PromotionPlan.build(
                candidate_id=request.candidate.candidate_id,
                candidate_digest=request.candidate.digest,
                validation_attestation_digest=validation.digest,
                allowlist_entry_id=request.target.allowlist_entry.entry_id,
                allowlist_entry_digest=allowlist_entry_digest(
                    request.target.allowlist_entry
                ),
                canonical_root_identity_digest=state3.canonical_root_identity_digest,
                rollout_manifest_digest=request.rollout_manifest_digest,
                stage_attestation_digest=deployment_pair.stage.digest,
                hook_attestation_digest=deployment_pair.hook.digest,
                provider_contract_digest=request.provider_contract_digest,
                provider_version_digest=request.provider_version_digest,
                target=PromotionPlanTarget(
                    request.target.skill_name,
                    request.target.owner_contract_hash,
                    pre_manifest.digest,
                    post_manifest.digest,
                ),
                artifact=PromotionPlanArtifact(
                    replacement.relative_path,
                    "regular-file",
                    replacement.pre_hash,
                    replacement.post_hash,
                    replacement.diff_digest,
                    post_reference,
                ),
                control_plane_digest=state3.control_plane_digest,
                created_at=request.created_at,
                expires_at=request.expires_at,
            )
        # Cleanup is part of validation, not post-publication housekeeping.
        # No post-image or result marker may become authoritative until the
        # exact admitted workspace has been removed successfully.
        staged.close()
        staged = None
        t_publish = _trusted_time_sample(
            request, context, label="post-cleanup", prior=t_publish
        )
        _trusted_state_sample(
            context,
            label="post-cleanup",
            expected_fingerprint=state0.fingerprint,
        )
        _assert_runtime_witnesses(
            source=source,
            harness=harness,
            control_roots=controls,
            staged=None,
        )
        _assert_signed_authorities_current(
            (
                deployment_pair.stage.attestation,
                deployment_pair.hook.attestation,
                validation.attestation,
            ),
            now=t_publish,
        )
        t_publish = _trusted_time_sample(
            request, context, label="publication", prior=t_publish
        )
        if plan is not None:
            persisted_reference = store.publish_post_image(
                request.artifact.post_image
            )
            if persisted_reference != plan.artifact.post_image_ref:
                raise ExperimentConflict("published post-image reference changed")
        _trusted_time_sample(
            request, context, label="bundle-publication", prior=t_publish
        )
        try:
            _publish_experiment_bundle(
                store=store,
                reservation=reservation,
                request=request,
                result=result,
                execution=execution,
                replacement=replacement,
                pre_manifest=pre_manifest,
                post_manifest=post_manifest,
                validation_raw=validation_raw,
                validation=validation,
                plan=plan,
            )
        except ExperimentConflict as publish_error:
            winner_payloads = _read_completed_payloads_if_present(
                store, request.operation_id
            )
            if winner_payloads is None:
                raise publish_error
            winner_replay = _ReadOnlyReplayBinding()
            winner_time = _trusted_time_sample(
                request, context, label="concurrent-winner", prior=t_publish
            )
            winner_state = _trusted_state_sample(
                context,
                label="concurrent-winner",
                expected_fingerprint=state0.fingerprint,
            )
            _assert_runtime_witnesses(
                source=source,
                harness=harness,
                control_roots=controls,
                staged=staged,
            )
            winner_deployments = _verify_current_deployments(
                request,
                context,
                winner_state,
                winner_time,
                replay_binding=winner_replay,
            )
            winner = _admit_completed_bundle(
                winner_payloads,
                reservation_digest=reservation.request_digest,
                request=request,
                context=context,
                store=store,
                state=winner_state,
                deployments=winner_deployments,
                replay_binding=winner_replay,
                now=winner_time,
                pre_manifest=pre_manifest,
                post_manifest=post_manifest,
                replacement=replacement,
            )
            winner_final = _trusted_time_sample(
                request,
                context,
                label="concurrent-winner-final",
                prior=winner_time,
            )
            _trusted_state_sample(
                context,
                label="concurrent-winner-final",
                expected_fingerprint=state0.fingerprint,
            )
            _assert_runtime_witnesses(
                source=source,
                harness=harness,
                control_roots=controls,
                staged=staged,
            )
            _assert_signed_authorities_current(
                (
                    winner_deployments.stage.attestation,
                    winner_deployments.hook.attestation,
                    winner.validation_attestation.attestation,
                ),
                now=winner_final,
            )
            return winner
        return ExperimentBundle(result, validation, plan, request.digest)
    finally:
        try:
            if staged is not None:
                staged.close()
        finally:
            for control in reversed(controls):
                control.close()
            if harness is not None:
                harness.close()
            if source is not None:
                source.close()
