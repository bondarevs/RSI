"""Strict signed attestation models and injected host trust boundaries."""

from __future__ import annotations

from abc import ABC, abstractmethod
import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import islice
import json
import os
from pathlib import Path
import re
from typing import Mapping, Sequence

from .hashing import canonical_json_bytes, canonical_json_digest


class AttestationError(ValueError):
    """An attestation or trust proof failed closed."""


class AttestationReplayConflict(AttestationError):
    """One attestation ID was rebound to a different signed semantic body."""


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
_REFERENCE_RE = re.compile(r"[a-z][a-z0-9-]{0,31}:[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}\Z")
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_MAX_ATTESTATION_BYTES = 128 * 1024
_MAX_ARRAY_ITEMS = 256
_SIGNATURE_ALGORITHM = "platform-attestation-v1"
_DEPLOYMENT_ISSUER_RE = re.compile(
    r"trusted-deployment-controller:[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z"
)
_VALIDATION_ISSUER_RE = re.compile(
    r"trusted-validator:[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z"
)
_MAX_CLOCK_SKEW = timedelta(hours=24)
_VERIFIED_PROVENANCE_TOKEN = object()
ZERO_DIGEST = "sha256:" + "0" * 64


class TrustedSignatureVerifier(ABC):
    """Host-injected cryptographic trust root; callbacks and bools are rejected."""

    @abstractmethod
    def verify_digest(
        self,
        *,
        issuer: str,
        signature_algorithm: str,
        body_digest: str,
        signature: bytes,
    ) -> bool:
        raise NotImplementedError


class TrustedReplayBinding(ABC):
    """Host-injected atomic attestation ID/body/scope replay binding."""

    @abstractmethod
    def bind(
        self,
        *,
        attestation_id: str,
        attestation_type: str,
        scope_digest: str,
        body_digest: str,
    ) -> str:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class AttestationChainLink:
    digest: str
    attestation_type: str
    predecessor_digest: str


class TrustedAttestationChain(ABC):
    """Host-injected immutable deployment predecessor lookup."""

    @abstractmethod
    def resolve_chain(
        self, *, attestation_type: str, predecessor_digest: str, max_depth: int
    ) -> Sequence[AttestationChainLink]:
        raise NotImplementedError


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise AttestationError(f"{label} must be a sha256 digest")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise AttestationError(f"{label} is invalid")
    return value


def _version(value: object, label: str) -> str:
    if not isinstance(value, str) or _VERSION_RE.fullmatch(value) is None:
        raise AttestationError(f"{label} is invalid")
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON value")


def _strict_object(
    payload: bytes, label: str, *, exact_framing: bool = True
) -> dict[str, object]:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > _MAX_ATTESTATION_BYTES
        or (exact_framing and payload.strip() != payload)
        or b"\x00" in payload
    ):
        raise AttestationError(f"{label} has invalid framing")
    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError):
        raise AttestationError(f"{label} is not strict UTF-8 JSON") from None
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8", "strict")
            except UnicodeEncodeError:
                raise AttestationError(f"{label} contains an invalid Unicode scalar") from None
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise AttestationError(f"{label} must be an object")
    return value


def _closed(value: object, fields: set[str] | frozenset[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise AttestationError(f"{label} schema is invalid")
    if any(not isinstance(key, str) for key in value):
        raise AttestationError(f"{label} schema is invalid")
    return value


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise AttestationError(f"{label} timestamp is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise AttestationError(f"{label} timestamp is invalid") from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise AttestationError(f"{label} timestamp is invalid")
    return value


def parse_timestamp(value: str) -> datetime:
    _timestamp(value, "attestation")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _canonical_array(
    value: object,
    label: str,
    admit,
    *,
    nonempty: bool = True,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or (nonempty and not value)
        or len(value) > _MAX_ARRAY_ITEMS
    ):
        raise AttestationError(f"{label} array is invalid")
    admitted = tuple(admit(item, f"{label} entry") for item in value)
    if len(set(admitted)) != len(admitted) or admitted != tuple(
        sorted(admitted, key=lambda item: item.encode("utf-8"))
    ):
        raise AttestationError(f"{label} array is not canonical")
    return admitted


def _reference(value: object, label: str) -> str:
    if not isinstance(value, str) or _REFERENCE_RE.fullmatch(value) is None:
        raise AttestationError(f"{label} is invalid")
    return value


def _signature(value: object) -> bytes:
    if not isinstance(value, str) or not value.startswith("base64:") or len(value) > 4096:
        raise AttestationError("attestation signature is malformed")
    try:
        decoded = base64.b64decode(value[7:].encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError):
        raise AttestationError("attestation signature is malformed") from None
    if not decoded or len(decoded) > 2048:
        raise AttestationError("attestation signature is malformed")
    if _signature_text(decoded) != value:
        raise AttestationError("attestation signature is not canonical base64")
    return decoded


def _signature_text(value: bytes) -> str:
    return "base64:" + base64.b64encode(value).decode("ascii")


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    entry_id: str
    skill_name: str
    canonical_root_identity_digest: str
    contract_hash: str

    def __post_init__(self) -> None:
        _identifier(self.entry_id, "allowlist entryId")
        _identifier(self.skill_name, "allowlist skillName")
        _digest(self.canonical_root_identity_digest, "canonical root identity")
        _digest(self.contract_hash, "allowlist contract")

    def to_mapping(self) -> dict[str, str]:
        return {
            "entryId": self.entry_id,
            "skillName": self.skill_name,
            "canonicalRootIdentityDigest": self.canonical_root_identity_digest,
            "contractHash": self.contract_hash,
        }


def _allowlist_entry(value: AllowlistEntry | Mapping[str, object]) -> AllowlistEntry:
    if isinstance(value, AllowlistEntry):
        return value
    source = _closed(
        value,
        {"entryId", "skillName", "canonicalRootIdentityDigest", "contractHash"},
        "allowlist entry",
    )
    return AllowlistEntry(
        _identifier(source["entryId"], "allowlist entryId"),
        _identifier(source["skillName"], "allowlist skillName"),
        _digest(source["canonicalRootIdentityDigest"], "canonical root identity"),
        _digest(source["contractHash"], "allowlist contract"),
    )


def allowlist_entry_digest(value: AllowlistEntry | Mapping[str, object]) -> str:
    return canonical_json_digest(_allowlist_entry(value).to_mapping())


_REGISTRATION_FIELDS = frozenset(
    {"schemaVersion", "entryId", "skillName", "canonicalRoot", "aliases", "dependencies", "files"}
)


def _string_array(value: object, label: str, *, sort_required: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > _MAX_ARRAY_ITEMS:
        raise AttestationError(f"registration {label} schema is invalid")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 1024 or "\x00" in item:
            raise AttestationError(f"registration {label} schema is invalid")
        try:
            item.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise AttestationError(f"registration {label} schema is invalid") from None
        result.append(item)
    if len(set(result)) != len(result):
        raise AttestationError(f"registration {label} schema is invalid")
    if sort_required and result != sorted(result, key=lambda item: item.encode("utf-8")):
        raise AttestationError(f"registration {label} schema is invalid")
    return tuple(result)


def registration_manifest_digest(value: Mapping[str, object]) -> str:
    source = _closed(value, _REGISTRATION_FIELDS, "registration manifest")
    if type(source["schemaVersion"]) is not int or source["schemaVersion"] != 1:
        raise AttestationError("registration manifest schema is invalid")
    entry_id = _identifier(source["entryId"], "registration entryId")
    skill_name = _identifier(source["skillName"], "registration skillName")
    root = source["canonicalRoot"]
    if not isinstance(root, str) or not os.path.isabs(root) or os.path.normpath(root) != root:
        raise AttestationError("registration canonical root is invalid")
    canonical = Path(root).resolve(strict=False)
    if str(canonical) != root or canonical == Path(canonical.anchor):
        raise AttestationError("registration canonical root is invalid")
    aliases = _string_array(source["aliases"], "aliases")
    dependencies = _string_array(source["dependencies"], "dependencies")
    files = _string_array(source["files"], "files")
    semantic = {
        "schemaVersion": 1,
        "entryId": entry_id,
        "skillName": skill_name,
        "canonicalRoot": root,
        "aliases": list(aliases),
        "dependencies": list(dependencies),
        "files": list(files),
    }
    return canonical_json_digest(semantic)


def registration_manifest_digest_bytes(payload: bytes) -> str:
    """Hash a raw registration only after duplicate-key-strict admission."""

    return registration_manifest_digest(
        _strict_object(payload, "registration manifest", exact_framing=False)
    )


def canonical_root_identity_digest(
    root: Path | str, registration_digest: str
) -> str:
    digest = _digest(registration_digest, "registration manifest")
    absolute = Path(os.path.abspath(os.fspath(root)))
    try:
        canonical = absolute.resolve(strict=True)
    except OSError:
        raise AttestationError("canonical root is unavailable") from None
    if canonical != absolute or not canonical.is_dir() or canonical == Path(canonical.anchor):
        raise AttestationError("canonical root identity uses an alias or broad root")
    return canonical_json_digest(
        {"canonicalRoot": str(canonical), "registrationManifestDigest": digest}
    )


@dataclass(frozen=True, slots=True)
class RolloutStageSubject:
    rsi_package_digest: str
    rollout_manifest_digest: str
    stage_id: str
    provider_contract_digest: str
    provider_version_digest: str

    def __post_init__(self) -> None:
        _digest(self.rsi_package_digest, "RSI package")
        _digest(self.rollout_manifest_digest, "rollout manifest")
        _identifier(self.stage_id, "stage ID")
        _digest(self.provider_contract_digest, "provider contract")
        _digest(self.provider_version_digest, "provider version")

    def to_mapping(self) -> dict[str, str]:
        return {
            "rsiPackageDigest": self.rsi_package_digest,
            "rolloutManifestDigest": self.rollout_manifest_digest,
            "stageId": self.stage_id,
            "providerContractDigest": self.provider_contract_digest,
            "providerVersionDigest": self.provider_version_digest,
        }


@dataclass(frozen=True, slots=True)
class OrchestrationHookSubject:
    rsi_package_digest: str
    rollout_manifest_digest: str
    hook_id: str
    provider_contract_digest: str
    provider_version_digest: str

    def __post_init__(self) -> None:
        _digest(self.rsi_package_digest, "RSI package")
        _digest(self.rollout_manifest_digest, "rollout manifest")
        _identifier(self.hook_id, "hook ID")
        _digest(self.provider_contract_digest, "provider contract")
        _digest(self.provider_version_digest, "provider version")

    def to_mapping(self) -> dict[str, str]:
        return {
            "rsiPackageDigest": self.rsi_package_digest,
            "rolloutManifestDigest": self.rollout_manifest_digest,
            "hookId": self.hook_id,
            "providerContractDigest": self.provider_contract_digest,
            "providerVersionDigest": self.provider_version_digest,
        }


@dataclass(frozen=True, slots=True)
class RolloutStageScope:
    mode: str
    environment_identity_digest: str
    allowed_target_entry_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.mode != "promote-safe":
            raise AttestationError("rollout scope mode is invalid")
        _digest(self.environment_identity_digest, "environment identity")
        _validate_digest_tuple(self.allowed_target_entry_digests, "allowed-target")

    def to_mapping(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "environmentIdentityDigest": self.environment_identity_digest,
            "allowedTargetEntryDigests": list(self.allowed_target_entry_digests),
        }


@dataclass(frozen=True, slots=True)
class OrchestrationHookScope:
    hook_mode: str
    environment_identity_digest: str
    allowed_target_entry_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.hook_mode != "coordinated":
            raise AttestationError("orchestration-hook scope mode is invalid")
        _digest(self.environment_identity_digest, "environment identity")
        _validate_digest_tuple(self.allowed_target_entry_digests, "allowed-target")

    def to_mapping(self) -> dict[str, object]:
        return {
            "hookMode": self.hook_mode,
            "environmentIdentityDigest": self.environment_identity_digest,
            "allowedTargetEntryDigests": list(self.allowed_target_entry_digests),
        }


def _validate_digest_tuple(value: tuple[str, ...], label: str) -> None:
    if type(value) is not tuple or not value or len(value) > _MAX_ARRAY_ITEMS:
        raise AttestationError(f"{label} array is invalid")
    for item in value:
        _digest(item, f"{label} entry")
    if len(set(value)) != len(value) or value != tuple(
        sorted(value, key=lambda item: item.encode("utf-8"))
    ):
        raise AttestationError(f"{label} array is not canonical")


DeploymentSubject = RolloutStageSubject | OrchestrationHookSubject
DeploymentScope = RolloutStageScope | OrchestrationHookScope


@dataclass(frozen=True, slots=True)
class DeploymentAttestation:
    schema_version: int
    attestation_id: str
    attestation_type: str
    issuer: str
    subject: DeploymentSubject
    scope: DeploymentScope
    predecessor_attestation_digest: str
    created_at: str
    expires_at: str
    signature_algorithm: str
    signature: bytes

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise AttestationError("deployment attestation schema version is invalid")
        _identifier(self.attestation_id, "deployment attestation ID")
        if self.attestation_type == "rollout-stage":
            expected_subject = RolloutStageSubject
            expected_scope = RolloutStageScope
        elif self.attestation_type == "orchestration-hook":
            expected_subject = OrchestrationHookSubject
            expected_scope = OrchestrationHookScope
        else:
            raise AttestationError("deployment attestation type is unknown")
        if (
            type(self.subject) is not expected_subject
            or type(self.scope) is not expected_scope
            or type(self.scope.allowed_target_entry_digests) is not tuple
        ):
            raise AttestationError("deployment attestation nested schema is invalid")
        self.subject.__post_init__()
        self.scope.__post_init__()
        if not isinstance(self.issuer, str) or _DEPLOYMENT_ISSUER_RE.fullmatch(self.issuer) is None:
            raise AttestationError("deployment attestation issuer is invalid")
        _digest(self.predecessor_attestation_digest, "deployment predecessor")
        _timestamp(self.created_at, "deployment createdAt")
        _timestamp(self.expires_at, "deployment expiresAt")
        if self.signature_algorithm != _SIGNATURE_ALGORITHM:
            raise AttestationError("deployment signature algorithm is unknown")
        if type(self.signature) is not bytes or not self.signature or len(self.signature) > 2048:
            raise AttestationError("attestation signature is malformed")

    def signed_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "attestationId": self.attestation_id,
            "attestationType": self.attestation_type,
            "issuer": self.issuer,
            "subject": self.subject.to_mapping(),
            "scope": self.scope.to_mapping(),
            "predecessorAttestationDigest": self.predecessor_attestation_digest,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at,
            "signatureAlgorithm": self.signature_algorithm,
        }

    def to_mapping(self) -> dict[str, object]:
        return {**self.signed_mapping(), "signature": _signature_text(self.signature)}


@dataclass(frozen=True, slots=True)
class DeploymentExpectation:
    attestation_type: str
    issuer: str
    subject: DeploymentSubject
    scope: DeploymentScope
    predecessor_attestation_digest: str


@dataclass(frozen=True, slots=True)
class _VerifiedProvenance:
    token: object
    value_identity: int
    digest: str


@dataclass(frozen=True, slots=True)
class VerifiedDeploymentAttestation:
    attestation: DeploymentAttestation
    digest: str
    _provenance: _VerifiedProvenance | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        provenance = self._provenance
        if (
            type(self.attestation) is not DeploymentAttestation
            or type(self.digest) is not str
            or type(provenance) is not _VerifiedProvenance
            or provenance.token is not _VERIFIED_PROVENANCE_TOKEN
            or provenance.value_identity != id(self.attestation)
            or provenance.digest != self.digest
        ):
            raise AttestationError("verified deployment attestation provenance is invalid")


@dataclass(frozen=True, slots=True)
class VerifiedDeploymentPair:
    stage: VerifiedDeploymentAttestation
    hook: VerifiedDeploymentAttestation
    _provenance: tuple[object, int, int, str, str] | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        expected = (
            _VERIFIED_PROVENANCE_TOKEN,
            id(self.stage),
            id(self.hook),
            self.stage.digest,
            self.hook.digest,
        )
        if self._provenance != expected:
            raise AttestationError("verified deployment pair provenance is invalid")


_DEPLOYMENT_FIELDS = frozenset(
    {
        "schemaVersion",
        "attestationId",
        "attestationType",
        "issuer",
        "subject",
        "scope",
        "predecessorAttestationDigest",
        "createdAt",
        "expiresAt",
        "signatureAlgorithm",
        "signature",
    }
)


def parse_deployment_attestation(payload: bytes) -> DeploymentAttestation:
    source = _closed(_strict_object(payload, "deployment attestation"), _DEPLOYMENT_FIELDS, "deployment attestation")
    if type(source["schemaVersion"]) is not int or source["schemaVersion"] != 1:
        raise AttestationError("deployment attestation schema version is invalid")
    attestation_type = source["attestationType"]
    if attestation_type == "rollout-stage":
        raw_subject = _closed(
            source["subject"],
            {"rsiPackageDigest", "rolloutManifestDigest", "stageId", "providerContractDigest", "providerVersionDigest"},
            "rollout-stage subject",
        )
        raw_scope = _closed(
            source["scope"],
            {"mode", "environmentIdentityDigest", "allowedTargetEntryDigests"},
            "rollout-stage scope",
        )
        subject: DeploymentSubject = RolloutStageSubject(
            _digest(raw_subject["rsiPackageDigest"], "RSI package"),
            _digest(raw_subject["rolloutManifestDigest"], "rollout manifest"),
            _identifier(raw_subject["stageId"], "stage ID"),
            _digest(raw_subject["providerContractDigest"], "provider contract"),
            _digest(raw_subject["providerVersionDigest"], "provider version"),
        )
        mode = raw_scope["mode"]
        if not isinstance(mode, str):
            raise AttestationError("rollout-stage scope schema is invalid")
        scope: DeploymentScope = RolloutStageScope(
            mode,
            _digest(raw_scope["environmentIdentityDigest"], "environment identity"),
            _canonical_array(raw_scope["allowedTargetEntryDigests"], "allowed-target", _digest),
        )
    elif attestation_type == "orchestration-hook":
        raw_subject = _closed(
            source["subject"],
            {"rsiPackageDigest", "rolloutManifestDigest", "hookId", "providerContractDigest", "providerVersionDigest"},
            "orchestration-hook subject",
        )
        raw_scope = _closed(
            source["scope"],
            {"hookMode", "environmentIdentityDigest", "allowedTargetEntryDigests"},
            "orchestration-hook scope",
        )
        subject = OrchestrationHookSubject(
            _digest(raw_subject["rsiPackageDigest"], "RSI package"),
            _digest(raw_subject["rolloutManifestDigest"], "rollout manifest"),
            _identifier(raw_subject["hookId"], "hook ID"),
            _digest(raw_subject["providerContractDigest"], "provider contract"),
            _digest(raw_subject["providerVersionDigest"], "provider version"),
        )
        hook_mode = raw_scope["hookMode"]
        if not isinstance(hook_mode, str):
            raise AttestationError("orchestration-hook scope schema is invalid")
        scope = OrchestrationHookScope(
            hook_mode,
            _digest(raw_scope["environmentIdentityDigest"], "environment identity"),
            _canonical_array(raw_scope["allowedTargetEntryDigests"], "allowed-target", _digest),
        )
    else:
        raise AttestationError("deployment attestation type is unknown")
    issuer = source["issuer"]
    if not isinstance(issuer, str) or _DEPLOYMENT_ISSUER_RE.fullmatch(issuer) is None:
        raise AttestationError("deployment attestation issuer is invalid")
    if source["signatureAlgorithm"] != _SIGNATURE_ALGORITHM:
        raise AttestationError("deployment signature algorithm is unknown")
    return DeploymentAttestation(
        1,
        _identifier(source["attestationId"], "deployment attestation ID"),
        str(attestation_type),
        issuer,
        subject,
        scope,
        _digest(source["predecessorAttestationDigest"], "deployment predecessor"),
        _timestamp(source["createdAt"], "deployment createdAt"),
        _timestamp(source["expiresAt"], "deployment expiresAt"),
        _SIGNATURE_ALGORITHM,
        _signature(source["signature"]),
    )


@dataclass(frozen=True, slots=True)
class ValidationControlPlane:
    policy_version: str
    evaluator_version: str
    metric_registry_version: str
    harness_version: str
    holdout_digest: str

    def __post_init__(self) -> None:
        _version(self.policy_version, "policy version")
        _version(self.evaluator_version, "evaluator version")
        _version(self.metric_registry_version, "metric registry version")
        _version(self.harness_version, "harness version")
        _digest(self.holdout_digest, "holdout")

    def to_mapping(self) -> dict[str, str]:
        return {
            "policyVersion": self.policy_version,
            "evaluatorVersion": self.evaluator_version,
            "metricRegistryVersion": self.metric_registry_version,
            "harnessVersion": self.harness_version,
            "holdoutDigest": self.holdout_digest,
        }


@dataclass(frozen=True, slots=True)
class ValidationAttestation:
    schema_version: int
    attestation_id: str
    issuer: str
    signature_algorithm: str
    candidate_id: str
    candidate_digest: str
    diff_digest: str
    target_pre_hash: str
    owner_contract_hash: str
    evidence_refs: tuple[str, ...]
    control_plane: ValidationControlPlane
    test_artifact_digests: tuple[str, ...]
    sandbox_policy_digest: str
    created_at: str
    expires_at: str
    decision: str
    signature: bytes

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise AttestationError("validation attestation schema version is invalid")
        _identifier(self.attestation_id, "validation attestation ID")
        if not isinstance(self.issuer, str) or _VALIDATION_ISSUER_RE.fullmatch(self.issuer) is None:
            raise AttestationError("validation attestation issuer is invalid")
        if self.signature_algorithm != _SIGNATURE_ALGORITHM:
            raise AttestationError("validation signature algorithm is unknown")
        _identifier(self.candidate_id, "candidate ID")
        for label, digest in (
            ("candidate", self.candidate_digest),
            ("diff", self.diff_digest),
            ("target pre-manifest", self.target_pre_hash),
            ("owner contract", self.owner_contract_hash),
            ("sandbox policy", self.sandbox_policy_digest),
        ):
            _digest(digest, label)
        if type(self.evidence_refs) is not tuple:
            raise AttestationError("evidence refs array is invalid")
        admitted_evidence = tuple(_reference(item, "evidence refs entry") for item in self.evidence_refs)
        if (
            not admitted_evidence
            or len(admitted_evidence) > _MAX_ARRAY_ITEMS
            or admitted_evidence
            != tuple(sorted(set(admitted_evidence), key=lambda item: item.encode("utf-8")))
        ):
            raise AttestationError("evidence refs array is not canonical")
        if type(self.control_plane) is not ValidationControlPlane:
            raise AttestationError("validation control-plane is invalid")
        self.control_plane.__post_init__()
        _validate_digest_tuple(self.test_artifact_digests, "test artifacts")
        _timestamp(self.created_at, "validation createdAt")
        _timestamp(self.expires_at, "validation expiresAt")
        if not isinstance(self.decision, str) or self.decision not in {"eligible", "rejected"}:
            raise AttestationError("validation decision is invalid")
        if type(self.signature) is not bytes or not self.signature or len(self.signature) > 2048:
            raise AttestationError("attestation signature is malformed")

    def signed_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "attestationId": self.attestation_id,
            "issuer": self.issuer,
            "signatureAlgorithm": self.signature_algorithm,
            "candidateId": self.candidate_id,
            "candidateDigest": self.candidate_digest,
            "diffDigest": self.diff_digest,
            "targetPreHash": self.target_pre_hash,
            "ownerContractHash": self.owner_contract_hash,
            "evidenceRefs": list(self.evidence_refs),
            "controlPlane": self.control_plane.to_mapping(),
            "testArtifactDigests": list(self.test_artifact_digests),
            "sandboxPolicyDigest": self.sandbox_policy_digest,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at,
            "decision": self.decision,
        }

    def to_mapping(self) -> dict[str, object]:
        return {**self.signed_mapping(), "signature": _signature_text(self.signature)}


@dataclass(frozen=True, slots=True)
class ValidationExpectation:
    issuer: str
    candidate_id: str
    candidate_digest: str
    diff_digest: str
    target_pre_hash: str
    owner_contract_hash: str
    evidence_refs: tuple[str, ...]
    control_plane: ValidationControlPlane
    test_artifact_digests: tuple[str, ...]
    sandbox_policy_digest: str
    decision: str


@dataclass(frozen=True, slots=True)
class VerifiedValidationAttestation:
    attestation: ValidationAttestation
    digest: str
    _provenance: _VerifiedProvenance | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        provenance = self._provenance
        if (
            type(self.attestation) is not ValidationAttestation
            or type(self.digest) is not str
            or type(provenance) is not _VerifiedProvenance
            or provenance.token is not _VERIFIED_PROVENANCE_TOKEN
            or provenance.value_identity != id(self.attestation)
            or provenance.digest != self.digest
        ):
            raise AttestationError("verified validation attestation provenance is invalid")


_VALIDATION_FIELDS = frozenset(
    {
        "schemaVersion", "attestationId", "issuer", "signatureAlgorithm", "signature",
        "candidateId", "candidateDigest", "diffDigest", "targetPreHash", "ownerContractHash",
        "evidenceRefs", "controlPlane", "testArtifactDigests", "sandboxPolicyDigest",
        "createdAt", "expiresAt", "decision",
    }
)


def parse_validation_attestation(payload: bytes) -> ValidationAttestation:
    source = _closed(_strict_object(payload, "validation attestation"), _VALIDATION_FIELDS, "validation attestation")
    if type(source["schemaVersion"]) is not int or source["schemaVersion"] != 1:
        raise AttestationError("validation attestation schema version is invalid")
    raw_control = _closed(
        source["controlPlane"],
        {"policyVersion", "evaluatorVersion", "metricRegistryVersion", "harnessVersion", "holdoutDigest"},
        "validation control-plane",
    )
    control = ValidationControlPlane(
        _version(raw_control["policyVersion"], "policy version"),
        _version(raw_control["evaluatorVersion"], "evaluator version"),
        _version(raw_control["metricRegistryVersion"], "metric registry version"),
        _version(raw_control["harnessVersion"], "harness version"),
        _digest(raw_control["holdoutDigest"], "holdout"),
    )
    issuer = source["issuer"]
    if not isinstance(issuer, str) or _VALIDATION_ISSUER_RE.fullmatch(issuer) is None:
        raise AttestationError("validation attestation issuer is invalid")
    if source["signatureAlgorithm"] != _SIGNATURE_ALGORITHM:
        raise AttestationError("validation signature algorithm is unknown")
    decision = source["decision"]
    if not isinstance(decision, str) or decision not in {"eligible", "rejected"}:
        raise AttestationError("validation decision is invalid")
    return ValidationAttestation(
        1,
        _identifier(source["attestationId"], "validation attestation ID"),
        issuer,
        _SIGNATURE_ALGORITHM,
        _identifier(source["candidateId"], "candidate ID"),
        _digest(source["candidateDigest"], "candidate"),
        _digest(source["diffDigest"], "diff"),
        _digest(source["targetPreHash"], "target pre-manifest"),
        _digest(source["ownerContractHash"], "owner contract"),
        _canonical_array(source["evidenceRefs"], "evidence refs", _reference),
        control,
        _canonical_array(source["testArtifactDigests"], "test artifacts", _digest),
        _digest(source["sandboxPolicyDigest"], "sandbox policy"),
        _timestamp(source["createdAt"], "validation createdAt"),
        _timestamp(source["expiresAt"], "validation expiresAt"),
        decision,
        _signature(source["signature"]),
    )


def _admit_deployment_model(value: object) -> DeploymentAttestation:
    if type(value) is not DeploymentAttestation:
        raise AttestationError("deployment attestation model is invalid")
    if value.attestation_type == "rollout-stage":
        expected_subject = RolloutStageSubject
        expected_scope = RolloutStageScope
    elif value.attestation_type == "orchestration-hook":
        expected_subject = OrchestrationHookSubject
        expected_scope = OrchestrationHookScope
    else:
        raise AttestationError("deployment attestation model is invalid")
    if (
        type(value.subject) is not expected_subject
        or type(value.scope) is not expected_scope
        or type(value.scope.allowed_target_entry_digests) is not tuple
        or type(value.signature) is not bytes
    ):
        raise AttestationError("deployment attestation model is invalid")
    try:
        return parse_deployment_attestation(canonical_json_bytes(value.to_mapping()))
    except (AttestationError, TypeError, ValueError, AttributeError, RecursionError):
        raise AttestationError("deployment attestation model is invalid") from None


def _admit_validation_model(value: object) -> ValidationAttestation:
    if (
        type(value) is not ValidationAttestation
        or type(value.evidence_refs) is not tuple
        or type(value.test_artifact_digests) is not tuple
        or type(value.control_plane) is not ValidationControlPlane
        or type(value.signature) is not bytes
    ):
        raise AttestationError("validation attestation model is invalid")
    try:
        return parse_validation_attestation(canonical_json_bytes(value.to_mapping()))
    except (AttestationError, TypeError, ValueError, AttributeError, RecursionError):
        raise AttestationError("validation attestation model is invalid") from None


def attestation_body_digest(value: DeploymentAttestation | ValidationAttestation) -> str:
    """Digest a signed body only after strict deep re-admission of typed input."""

    if type(value) is DeploymentAttestation:
        admitted: DeploymentAttestation | ValidationAttestation = _admit_deployment_model(value)
    elif type(value) is ValidationAttestation:
        admitted = _admit_validation_model(value)
    else:
        raise AttestationError("attestation model is invalid")
    try:
        return canonical_json_digest(admitted.signed_mapping())
    except (TypeError, ValueError, AttributeError, RecursionError):
        raise AttestationError("attestation body is invalid") from None


def _validate_time_window(
    created_at: str,
    expires_at: str,
    *,
    now: datetime,
    maximum_ttl: timedelta,
    clock_skew: timedelta,
) -> None:
    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() != timedelta(0)
        or not isinstance(maximum_ttl, timedelta)
        or maximum_ttl <= timedelta(0)
        or not isinstance(clock_skew, timedelta)
        or clock_skew < timedelta(0)
        or clock_skew > _MAX_CLOCK_SKEW
    ):
        raise AttestationError("attestation verification clock policy is invalid")
    created = parse_timestamp(created_at)
    expires = parse_timestamp(expires_at)
    try:
        latest_permitted_creation = now + clock_skew
    except OverflowError:
        raise AttestationError("attestation verification clock skew is invalid") from None
    if created > latest_permitted_creation:
        raise AttestationError("attestation was created in the future")
    if now >= expires:
        raise AttestationError("attestation is expired")
    if expires <= created:
        raise AttestationError("attestation expiry window is invalid")
    if expires - created > maximum_ttl:
        raise AttestationError("attestation TTL exceeds policy maximum")


def _verify_signature(
    value: DeploymentAttestation | ValidationAttestation,
    verifier: TrustedSignatureVerifier,
) -> str:
    if not isinstance(verifier, TrustedSignatureVerifier):
        raise AttestationError("trusted signature verifier interface is required")
    body_digest = attestation_body_digest(value)
    try:
        valid = verifier.verify_digest(
            issuer=value.issuer,
            signature_algorithm=value.signature_algorithm,
            body_digest=body_digest,
            signature=value.signature,
        )
    except Exception as error:
        raise AttestationError("attestation signature verifier failed") from error
    if valid is not True:
        raise AttestationError("attestation signature is invalid")
    return body_digest


def _verify_chain(
    *,
    attestation_type: str,
    predecessor_digest: str,
    chain: TrustedAttestationChain,
    maximum_chain_depth: int,
) -> None:
    if not isinstance(chain, TrustedAttestationChain):
        raise AttestationError("trusted deployment chain interface is required")
    if type(maximum_chain_depth) is not int or maximum_chain_depth < 1 or maximum_chain_depth > 128:
        raise AttestationError("deployment chain depth policy is invalid")
    if predecessor_digest == ZERO_DIGEST:
        return
    try:
        resolved = chain.resolve_chain(
            attestation_type=attestation_type,
            predecessor_digest=predecessor_digest,
            max_depth=maximum_chain_depth,
        )
        links = tuple(islice(iter(resolved), maximum_chain_depth + 1))
    except Exception as error:
        raise AttestationError("deployment predecessor chain lookup failed") from error
    if not links or len(links) > maximum_chain_depth:
        raise AttestationError("deployment predecessor chain is detached or exceeds its bound")
    expected = predecessor_digest
    seen: set[str] = set()
    for link in links:
        if type(link) is not AttestationChainLink:
            raise AttestationError("deployment predecessor chain is cyclic or cross-domain")
        _digest(link.digest, "deployment chain digest")
        _digest(link.predecessor_digest, "deployment chain predecessor")
        if (
            link.digest != expected
            or not isinstance(link.attestation_type, str)
            or link.attestation_type != attestation_type
            or link.digest in seen
        ):
            raise AttestationError("deployment predecessor chain is cyclic or cross-domain")
        seen.add(link.digest)
        expected = link.predecessor_digest
    if expected != ZERO_DIGEST:
        raise AttestationError("deployment predecessor chain is detached")


def _admit_deployment_expectation(value: object) -> DeploymentExpectation:
    if type(value) is not DeploymentExpectation:
        raise AttestationError("deployment attestation verification input is invalid")
    if value.attestation_type == "rollout-stage":
        expected_subject = RolloutStageSubject
        expected_scope = RolloutStageScope
    elif value.attestation_type == "orchestration-hook":
        expected_subject = OrchestrationHookSubject
        expected_scope = OrchestrationHookScope
    else:
        raise AttestationError("deployment expectation type is invalid")
    if (
        type(value.subject) is not expected_subject
        or type(value.scope) is not expected_scope
        or type(value.scope.allowed_target_entry_digests) is not tuple
        or not isinstance(value.issuer, str)
        or _DEPLOYMENT_ISSUER_RE.fullmatch(value.issuer) is None
    ):
        raise AttestationError("deployment expectation schema is invalid")
    try:
        value.subject.__post_init__()
        value.scope.__post_init__()
        _digest(value.predecessor_attestation_digest, "deployment expected predecessor")
    except (AttestationError, TypeError, ValueError, AttributeError):
        raise AttestationError("deployment expectation schema is invalid") from None
    return value


def verify_deployment_attestation(
    value: bytes | DeploymentAttestation,
    *,
    expectation: DeploymentExpectation,
    verifier: TrustedSignatureVerifier,
    replay: TrustedReplayBinding,
    chain: TrustedAttestationChain,
    now: datetime,
    maximum_ttl: timedelta,
    clock_skew: timedelta = timedelta(0),
    maximum_chain_depth: int = 16,
) -> VerifiedDeploymentAttestation:
    if isinstance(value, bytes):
        attestation = parse_deployment_attestation(value)
    elif type(value) is DeploymentAttestation:
        attestation = _admit_deployment_model(value)
    else:
        raise AttestationError("deployment attestation verification input is invalid")
    expectation = _admit_deployment_expectation(expectation)
    if attestation.attestation_type != expectation.attestation_type:
        raise AttestationError("deployment attestation type does not match expected authority")
    if attestation.issuer != expectation.issuer:
        raise AttestationError("deployment attestation issuer does not match")
    if attestation.subject != expectation.subject:
        raise AttestationError("deployment attestation subject binding does not match")
    if attestation.scope != expectation.scope:
        raise AttestationError("deployment attestation scope binding does not match")
    if attestation.predecessor_attestation_digest != expectation.predecessor_attestation_digest:
        raise AttestationError("deployment predecessor binding does not match")
    _validate_time_window(
        attestation.created_at,
        attestation.expires_at,
        now=now,
        maximum_ttl=maximum_ttl,
        clock_skew=clock_skew,
    )
    body_digest = _verify_signature(attestation, verifier)
    _verify_chain(
        attestation_type=attestation.attestation_type,
        predecessor_digest=attestation.predecessor_attestation_digest,
        chain=chain,
        maximum_chain_depth=maximum_chain_depth,
    )
    if not isinstance(replay, TrustedReplayBinding):
        raise AttestationError("trusted replay binding interface is required")
    scope_digest = canonical_json_digest(
        {"attestationType": attestation.attestation_type, "scope": attestation.scope.to_mapping()}
    )
    try:
        replay_status = replay.bind(
            attestation_id=attestation.attestation_id,
            attestation_type=attestation.attestation_type,
            scope_digest=scope_digest,
            body_digest=body_digest,
        )
    except AttestationReplayConflict:
        raise
    except Exception as error:
        raise AttestationError("deployment attestation replay binding failed") from error
    if not isinstance(replay_status, str) or replay_status not in {"bound", "replay"}:
        raise AttestationError("deployment attestation replay result is invalid")
    return VerifiedDeploymentAttestation(
        attestation,
        body_digest,
        _VerifiedProvenance(
            _VERIFIED_PROVENANCE_TOKEN, id(attestation), body_digest
        ),
    )


def _pair_verified_deployments(
    stage: VerifiedDeploymentAttestation,
    hook: VerifiedDeploymentAttestation,
) -> VerifiedDeploymentPair:
    if type(stage) is not VerifiedDeploymentAttestation or type(hook) is not VerifiedDeploymentAttestation:
        raise AttestationError("stage and hook attestations must be distinct typed refs and digests")
    if stage.digest == hook.digest:
        raise AttestationError("stage and hook attestations must be distinct typed refs and digests")
    try:
        stage_body_digest = attestation_body_digest(stage.attestation)
        hook_body_digest = attestation_body_digest(hook.attestation)
        _digest(stage.digest, "stage wrapper digest")
        _digest(hook.digest, "hook wrapper digest")
    except (AttestationError, TypeError, ValueError, AttributeError):
        raise AttestationError("deployment attestation wrapper digest is invalid") from None
    if stage.digest != stage_body_digest or hook.digest != hook_body_digest:
        raise AttestationError("deployment attestation wrapper digest does not match its body")
    if (
        stage.attestation.attestation_type != "rollout-stage"
        or hook.attestation.attestation_type != "orchestration-hook"
        or stage.attestation.attestation_id == hook.attestation.attestation_id
    ):
        raise AttestationError("stage and hook attestations must be distinct typed refs and digests")
    stage_subject = stage.attestation.subject
    hook_subject = hook.attestation.subject
    stage_scope = stage.attestation.scope
    hook_scope = hook.attestation.scope
    common_stage = (
        stage.attestation.issuer,
        stage_subject.rsi_package_digest,
        stage_subject.rollout_manifest_digest,
        stage_subject.provider_contract_digest,
        stage_subject.provider_version_digest,
        stage_scope.environment_identity_digest,
        stage_scope.allowed_target_entry_digests,
    )
    common_hook = (
        hook.attestation.issuer,
        hook_subject.rsi_package_digest,
        hook_subject.rollout_manifest_digest,
        hook_subject.provider_contract_digest,
        hook_subject.provider_version_digest,
        hook_scope.environment_identity_digest,
        hook_scope.allowed_target_entry_digests,
    )
    if common_stage != common_hook:
        raise AttestationError("deployment pair common context binding does not match")
    return VerifiedDeploymentPair(
        stage,
        hook,
        (
            _VERIFIED_PROVENANCE_TOKEN,
            id(stage),
            id(hook),
            stage.digest,
            hook.digest,
        ),
    )


def verify_deployment_pair(
    stage: bytes | DeploymentAttestation,
    hook: bytes | DeploymentAttestation,
    *,
    stage_expectation: DeploymentExpectation,
    hook_expectation: DeploymentExpectation,
    verifier: TrustedSignatureVerifier,
    replay: TrustedReplayBinding,
    stage_chain: TrustedAttestationChain,
    hook_chain: TrustedAttestationChain,
    now: datetime,
    maximum_ttl: timedelta,
    clock_skew: timedelta = timedelta(0),
    maximum_chain_depth: int = 16,
) -> VerifiedDeploymentPair:
    """Verify both raw authorities and their common context at one trust boundary."""

    if isinstance(stage, VerifiedDeploymentAttestation) or isinstance(
        hook, VerifiedDeploymentAttestation
    ):
        raise AttestationError("deployment pair requires raw attestations and full trust context")
    verified_stage = verify_deployment_attestation(
        stage,
        expectation=stage_expectation,
        verifier=verifier,
        replay=replay,
        chain=stage_chain,
        now=now,
        maximum_ttl=maximum_ttl,
        clock_skew=clock_skew,
        maximum_chain_depth=maximum_chain_depth,
    )
    verified_hook = verify_deployment_attestation(
        hook,
        expectation=hook_expectation,
        verifier=verifier,
        replay=replay,
        chain=hook_chain,
        now=now,
        maximum_ttl=maximum_ttl,
        clock_skew=clock_skew,
        maximum_chain_depth=maximum_chain_depth,
    )
    return _pair_verified_deployments(verified_stage, verified_hook)


def _admit_validation_expectation(value: object) -> ValidationExpectation:
    if (
        type(value) is not ValidationExpectation
        or not isinstance(value.issuer, str)
        or _VALIDATION_ISSUER_RE.fullmatch(value.issuer) is None
        or type(value.control_plane) is not ValidationControlPlane
        or type(value.evidence_refs) is not tuple
        or type(value.test_artifact_digests) is not tuple
        or not isinstance(value.decision, str)
        or value.decision not in {"eligible", "rejected"}
    ):
        raise AttestationError("validation expectation schema is invalid")
    try:
        value.control_plane.__post_init__()
        _identifier(value.candidate_id, "expected candidate ID")
        for label, digest in (
            ("candidate", value.candidate_digest),
            ("diff", value.diff_digest),
            ("target pre-manifest", value.target_pre_hash),
            ("owner contract", value.owner_contract_hash),
            ("sandbox policy", value.sandbox_policy_digest),
        ):
            _digest(digest, f"expected {label}")
        evidence = tuple(_reference(item, "expected evidence ref") for item in value.evidence_refs)
        if len(evidence) > _MAX_ARRAY_ITEMS or evidence != tuple(
            sorted(set(evidence), key=lambda item: item.encode("utf-8"))
        ):
            raise AttestationError("validation expectation evidence array is not canonical")
        _validate_digest_tuple(value.test_artifact_digests, "expected test artifacts")
    except (AttestationError, TypeError, ValueError, AttributeError):
        raise AttestationError("validation expectation schema is invalid") from None
    return value


def verify_validation_attestation(
    value: bytes | ValidationAttestation,
    *,
    expectation: ValidationExpectation,
    verifier: TrustedSignatureVerifier,
    replay: TrustedReplayBinding,
    now: datetime,
    maximum_ttl: timedelta,
    clock_skew: timedelta = timedelta(0),
    require_eligible: bool = False,
) -> VerifiedValidationAttestation:
    if isinstance(value, bytes):
        attestation = parse_validation_attestation(value)
    elif type(value) is ValidationAttestation:
        attestation = _admit_validation_model(value)
    else:
        raise AttestationError("validation attestation verification input is invalid")
    expectation = _admit_validation_expectation(expectation)
    expected = (
        expectation.issuer,
        expectation.candidate_id,
        expectation.candidate_digest,
        expectation.diff_digest,
        expectation.target_pre_hash,
        expectation.owner_contract_hash,
        expectation.evidence_refs,
        expectation.control_plane,
        expectation.test_artifact_digests,
        expectation.sandbox_policy_digest,
        expectation.decision,
    )
    actual = (
        attestation.issuer,
        attestation.candidate_id,
        attestation.candidate_digest,
        attestation.diff_digest,
        attestation.target_pre_hash,
        attestation.owner_contract_hash,
        attestation.evidence_refs,
        attestation.control_plane,
        attestation.test_artifact_digests,
        attestation.sandbox_policy_digest,
        attestation.decision,
    )
    if actual != expected:
        if attestation.decision != expectation.decision:
            raise AttestationError("validation decision does not match eligibility binding")
        raise AttestationError("validation attestation binding does not match")
    if type(require_eligible) is not bool or (
        require_eligible and attestation.decision != "eligible"
    ):
        raise AttestationError("validation decision is not eligible")
    _validate_time_window(
        attestation.created_at,
        attestation.expires_at,
        now=now,
        maximum_ttl=maximum_ttl,
        clock_skew=clock_skew,
    )
    body_digest = _verify_signature(attestation, verifier)
    if not isinstance(replay, TrustedReplayBinding):
        raise AttestationError("trusted replay binding interface is required")
    scope_digest = canonical_json_digest(
        {
            "attestationType": "validation",
            "candidateId": attestation.candidate_id,
            "targetPreHash": attestation.target_pre_hash,
        }
    )
    try:
        replay_status = replay.bind(
            attestation_id=attestation.attestation_id,
            attestation_type="validation",
            scope_digest=scope_digest,
            body_digest=body_digest,
        )
    except AttestationReplayConflict:
        raise
    except Exception as error:
        raise AttestationError("validation attestation replay binding failed") from error
    if not isinstance(replay_status, str) or replay_status not in {"bound", "replay"}:
        raise AttestationError("validation attestation replay result is invalid")
    return VerifiedValidationAttestation(
        attestation,
        body_digest,
        _VerifiedProvenance(
            _VERIFIED_PROVENANCE_TOKEN, id(attestation), body_digest
        ),
    )
