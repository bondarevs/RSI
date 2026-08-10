"""Fail-closed Task 8 promotion authority and wire models.

The module deliberately keeps parsing, digesting, and classification pure.  A
later orchestration layer may depend on these values, but callers cannot widen
their schemas or self-assert containment capabilities.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, fields
from datetime import datetime, timezone
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, ClassVar, Mapping, Sequence
import threading


class PromotionError(ValueError):
    """A Task 8 document or authority claim is invalid."""


class PromotionConflict(PromotionError):
    """Two immutable Task 8 authorities cannot converge."""


MAX_EVENT_LINE_BYTES = 64 * 1024
MAX_RESOLUTION_READBACK_BYTES = 144 * 1024 * 1024
MAX_TASK8_SIDECAR_BYTES = 200 * 1024 * 1024
PROMOTION_REASON_V1 = "Verified additive knowledge with passing validation"

NAMESPACE_MUTATION_OPERATION_CLASSES = (
    "forward-apply",
    "rollback-apply",
    "verifier-readback",
    "promoted-terminal",
    "unresolved-terminal",
    "incident-classification",
    "prepared-post-cleanup",
    "retained-preimage-cleanup",
    "displaced-post-cleanup",
)

TASK8_PROTECTED_LOCK_ORDER = (
    "namespace-lease",
    "transaction",
    "global",
    "target",
    "provider",
    "event-store",
)

PROVIDER_EVENTSTORE_CALLBACKS = (
    "historical-gate",
    "all-origin-batch",
    "guard-a:apply.started",
    "rollback:apply.completed:applied",
    "new-apply:verification.completed:affirmed",
    "rollback:verification.completed:rollback-armed",
    "not-started-terminal",
    "not-applied-terminal",
    "rollback:apply.reverted",
    "rollback-terminal",
    "terminal-readback:resolution.recorded",
    "promoted-terminal",
    "incident-publication",
    "incident-close",
)

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
_TX_RE = re.compile(r"tx_[0-9a-f]{64}\Z")


def _canonical_no_lf(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError):
        raise PromotionError("Task 8 object is not canonical JSON") from None


def _canonical_final_lf(value: object) -> bytes:
    return _canonical_no_lf(value) + b"\n"


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_final_lf(value)).hexdigest()


def _digest_no_lf(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_no_lf(value)).hexdigest()


def _strict_mapping(value: Mapping[str, Any], keys: Sequence[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PromotionError(f"{label} must be a mapping")
    if set(value) != set(keys):
        raise PromotionError(f"{label.lower()} has an invalid field schema")
    try:
        copied = json.loads(_canonical_no_lf(value))
    except (json.JSONDecodeError, UnicodeError):
        raise PromotionError(f"{label} is not canonical JSON") from None
    if not isinstance(copied, dict):
        raise PromotionError(f"{label} must be a mapping")
    return copied


def _require_digest(value: object, *, label: str = "digest") -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise PromotionError(f"{label} is not a prefixed SHA-256 digest")
    return value


def _parse_utc(value: object, *, label: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise PromotionError(f"{label} is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise PromotionError(f"{label} is not canonical UTC") from None
    if parsed.tzinfo != timezone.utc:
        raise PromotionError(f"{label} is not UTC")
    return parsed


class _LiteralModel:
    KEYS: ClassVar[tuple[str, ...]] = ()
    DOMAIN: ClassVar[str | None] = None

    def __init__(self, mapping: Mapping[str, Any]) -> None:
        object.__setattr__(self, "_mapping", MappingProxyType(deepcopy(dict(mapping))))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Task 8 wire models are immutable")

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]):
        copied = _strict_mapping(mapping, cls.KEYS, label=cls.__name__)
        if cls.DOMAIN is not None and copied.get("domain") != cls.DOMAIN:
            raise PromotionError(f"{cls.__name__} domain is invalid")
        if "schemaVersion" in copied and (
            type(copied["schemaVersion"]) is not int or copied["schemaVersion"] != 1
        ):
            raise PromotionError(f"{cls.__name__} schema version is invalid")
        cls._validate(copied)
        return cls(copied)

    @classmethod
    def _validate(cls, mapping: dict[str, Any]) -> None:
        return None

    def to_mapping(self) -> dict[str, Any]:
        return deepcopy(dict(self._mapping))

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_final_lf(self.to_mapping())

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class PromotionPlanRef:
    experiment_operation_id: str
    reservation_digest: str
    experiment_request_digest: str
    candidate_id: str
    candidate_digest: str
    candidate_full_record_digest: str
    provider_authority_binding_digest: str
    candidate_capture_lineage_binding_digest: str
    candidate_state_binding_digest: str
    provider_contract_digest: str
    provider_version_digest: str
    provider_runtime_identity_digest: str
    provider_execution_identity_digest: str
    verifier_execution_base_identity_digest: str
    namespace_mutation_lease_backend_identity_digest: str
    namespace_mutation_lease_capability_digest: str
    policy_version: str
    policy_artifact_digest: str
    control_plane_digest: str
    task8_control_plane_version: str
    task8_addendum_digest: str
    task8_addendum_markdown_digest: str
    plan_id: str
    plan_digest: str
    validation_attestation_digest: str
    artifact_store_identity_digest: str
    stage_attestation_raw_ref: str
    stage_attestation_raw_digest: str
    hook_attestation_raw_ref: str
    hook_attestation_raw_digest: str

    _WIRE: ClassVar[dict[str, str]] = {
        "experiment_operation_id": "experimentOperationId",
        "reservation_digest": "reservationDigest",
        "experiment_request_digest": "experimentRequestDigest",
        "candidate_id": "candidateId",
        "candidate_digest": "candidateDigest",
        "candidate_full_record_digest": "candidateFullRecordDigest",
        "provider_authority_binding_digest": "providerAuthorityBindingDigest",
        "candidate_capture_lineage_binding_digest": "candidateCaptureLineageBindingDigest",
        "candidate_state_binding_digest": "candidateStateBindingDigest",
        "provider_contract_digest": "providerContractDigest",
        "provider_version_digest": "providerVersionDigest",
        "provider_runtime_identity_digest": "providerRuntimeIdentityDigest",
        "provider_execution_identity_digest": "providerExecutionIdentityDigest",
        "verifier_execution_base_identity_digest": "verifierExecutionBaseIdentityDigest",
        "namespace_mutation_lease_backend_identity_digest": "namespaceMutationLeaseBackendIdentityDigest",
        "namespace_mutation_lease_capability_digest": "namespaceMutationLeaseCapabilityDigest",
        "policy_version": "policyVersion",
        "policy_artifact_digest": "policyArtifactDigest",
        "control_plane_digest": "controlPlaneDigest",
        "task8_control_plane_version": "task8ControlPlaneVersion",
        "task8_addendum_digest": "task8AddendumDigest",
        "task8_addendum_markdown_digest": "task8AddendumMarkdownDigest",
        "plan_id": "planId",
        "plan_digest": "planDigest",
        "validation_attestation_digest": "validationAttestationDigest",
        "artifact_store_identity_digest": "artifactStoreIdentityDigest",
        "stage_attestation_raw_ref": "stageAttestationRawRef",
        "stage_attestation_raw_digest": "stageAttestationRawDigest",
        "hook_attestation_raw_ref": "hookAttestationRawRef",
        "hook_attestation_raw_digest": "hookAttestationRawDigest",
    }

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if type(value) is not str or not value:
                raise PromotionError("promotion plan reference fields must be nonempty strings")
            if item.name.endswith("_digest"):
                _require_digest(value, label=item.name)
        if self.reservation_digest == self.experiment_request_digest:
            raise PromotionError("reservation and experiment request digests are independent")
        if self.candidate_digest == self.candidate_full_record_digest:
            raise PromotionError("candidate and provider full-record digests are independent")
        if self.provider_authority_binding_digest == self.candidate_state_binding_digest:
            raise PromotionError("provider authority and candidate state digests are independent")

    def to_mapping(self) -> dict[str, str]:
        return {self._WIRE[item.name]: getattr(self, item.name) for item in fields(self)}


class PromotionService:
    """Constructor-owned entry point for the only target-mutating workflow.

    Ordinary macOS/Linux hosts intentionally have no qualifying namespace
    mutation backend.  Admission therefore fails before a continuation event,
    provider snapshot, temporary file, or target write.  A future privileged
    integration can be registered only through the attested registry; callers
    cannot supply a backend or capability to ``promote_candidate``.
    """

    __slots__ = ("_lease_registry",)

    def __init__(
        self,
        namespace_lease_registry: "TrustedNamespaceMutationLeaseRegistry | None" = None,
    ) -> None:
        self._lease_registry = (
            namespace_lease_registry
            if namespace_lease_registry is not None
            else TrustedNamespaceMutationLeaseRegistry.empty()
        )
        if not isinstance(self._lease_registry, TrustedNamespaceMutationLeaseRegistry):
            raise PromotionError("trusted namespace lease registry is invalid")

    def promote_candidate(self, plan_ref: PromotionPlanRef):
        if type(plan_ref) is not PromotionPlanRef:
            raise PromotionError("promotion requires an exact immutable plan reference")
        backend = self._lease_registry.resolve(
            plan_ref.namespace_mutation_lease_backend_identity_digest
        )
        if getattr(backend, "available", False) is not True:
            raise PromotionError(
                "attested namespace mutation lease backend is unavailable before apply"
            )
        if (
            getattr(backend, "task8_backend_kind", None)
            != "privileged-promotion-coordinator-v1"
            or getattr(backend, "attested_identity_digest", None)
            != plan_ref.namespace_mutation_lease_backend_identity_digest
            or getattr(backend, "attested_capability_digest", None)
            != plan_ref.namespace_mutation_lease_capability_digest
            or getattr(backend, "complete_task8_protocol", False) is not True
            or not callable(getattr(backend, "execute_guarded_promotion", None))
        ):
            raise PromotionError(
                "attested privileged promotion coordinator is incompatible"
            )
        decision = backend.execute_guarded_promotion(plan_ref)
        if type(decision) is not PromotionDecision:
            raise PromotionError("privileged promotion result schema is invalid")
        if (
            decision.candidate_id != plan_ref.candidate_id
            or decision.promotion_plan_digest != plan_ref.plan_digest
            or decision.validation_attestation_digest
            != plan_ref.validation_attestation_digest
        ):
            raise PromotionError("privileged promotion result authority conflicts")
        return decision


class NamespaceMutationLeaseRequest(_LiteralModel):
    DOMAIN = "rsi-namespace-mutation-lease-request-v1"
    KEYS = (
        "schemaVersion", "domain", "transactionId", "planDigest", "rootIdentityDigest",
        "ancestryWitnessDigest", "artifactParentWitnessDigest", "managedTreePolicyDigest",
        "expectedManifestPreHash", "expectedManifestPostHash", "targetName", "reservedName",
        "operationClass", "acquisitionNonce", "deadline",
    )

    @classmethod
    def _validate(cls, mapping: dict[str, Any]) -> None:
        if type(mapping["transactionId"]) is not str or _TX_RE.fullmatch(mapping["transactionId"]) is None:
            raise PromotionError("lease transaction identifier is invalid")
        for key in (
            "planDigest", "rootIdentityDigest", "ancestryWitnessDigest", "artifactParentWitnessDigest",
            "managedTreePolicyDigest", "expectedManifestPreHash", "expectedManifestPostHash",
        ):
            _require_digest(mapping[key], label=key)
        if mapping["operationClass"] not in NAMESPACE_MUTATION_OPERATION_CLASSES:
            raise PromotionError("lease operation class is invalid")
        if type(mapping["acquisitionNonce"]) is not str or _HEX64_RE.fullmatch(mapping["acquisitionNonce"]) is None:
            raise PromotionError("lease acquisition nonce is invalid")
        _parse_utc(mapping["deadline"], label="lease deadline")
        for key in ("targetName", "reservedName"):
            value = mapping[key]
            if type(value) is not str or not value or "/" in value or "\\" in value or "\x00" in value:
                raise PromotionError("lease target/reserved name is invalid")

    @property
    def acquisition_nonce(self) -> str:
        return str(self._mapping["acquisitionNonce"])


class AncestryEdge(_LiteralModel):
    DOMAIN = "rsi-ancestry-edge-v1"
    KEYS = (
        "schemaVersion", "domain", "componentName", "childRelativePath", "parentDevice", "parentInode",
        "parentType", "parentMode", "parentUid", "parentNlink", "childDevice", "childInode", "childType",
        "childMode", "childUid", "childNlink",
    )


class AncestryWitness(_LiteralModel):
    DOMAIN = "rsi-ancestry-witness-v1"
    KEYS = ("schemaVersion", "domain", "rootIdentityDigest", "parentRelativePath", "edges")


class ArtifactParentWitness(_LiteralModel):
    DOMAIN = "rsi-artifact-parent-witness-v1"
    KEYS = (
        "schemaVersion", "domain", "rootIdentityDigest", "parentRelativePath", "device", "inode", "type",
        "mode", "uid", "nlink", "ancestryWitnessDigest",
    )


class ManagedTreePolicy(_LiteralModel):
    DOMAIN = "rsi-managed-tree-policy-v1"
    KEYS = (
        "schemaVersion", "domain", "rootIdentityDigest", "allowlistEntryDigest", "artifactRelativePath",
        "reservedRelativePath", "manifestPreHash", "manifestPostHash", "scopeMode", "members",
    )


class TargetWitness(_LiteralModel):
    DOMAIN = "rsi-target-witness-v1"
    KEYS = (
        "schemaVersion", "domain", "rootIdentityDigest", "relativePath", "device", "inode", "type", "mode",
        "uid", "nlink", "size", "artifactHash", "manifestHash",
    )


class RetainedNameWitness(_LiteralModel):
    DOMAIN = "rsi-retained-name-witness-v1"
    KEYS = ("schemaVersion", "domain", "name", "role", "classification", "object")


class MemberMetadataWitness(_LiteralModel):
    DOMAIN = "rsi-member-metadata-witness-v1"
    KEYS = (
        "schemaVersion", "domain", "relativePath", "device", "inode", "type", "mode", "uid", "nlink", "size",
        "mtimeNs", "ctimeNs",
    )


class ProtectedReadbackState(_LiteralModel):
    DOMAIN = "rsi-namespace-protected-readback-state-v1"
    KEYS = ("schemaVersion", "domain", "classification", "targetReadbackView", "errorWitness")

    @classmethod
    def _validate(cls, mapping: dict[str, Any]) -> None:
        classification = mapping["classification"]
        view = mapping["targetReadbackView"]
        error = mapping["errorWitness"]
        if classification in {"exact-pre", "exact-post"}:
            if view is None or error is not None:
                raise PromotionError("protected readback exact arm is invalid")
            parsed = TargetReadbackView.from_mapping(view)
            if parsed.to_mapping()["classification"] != classification:
                raise PromotionError("protected readback classification mismatch")
            return
        if classification == "other" and view is not None and error is None:
            parsed = TargetReadbackView.from_mapping(view)
            if parsed.to_mapping()["classification"] != "other":
                raise PromotionError("protected readback other classification mismatch")
            return
        if classification == "other" and view is None and isinstance(error, Mapping):
            if set(error) != {"kind", "observedKind", "rootIdentityDigest", "relativePath", "metadata"} or error.get("kind") != "known-drift":
                raise PromotionError("known-drift readback witness schema is invalid")
            kind = error.get("observedKind")
            metadata = error.get("metadata")
            if kind == "missing":
                if metadata is not None:
                    raise PromotionError("missing known-drift metadata must be null")
            elif kind == "unsafe-link":
                if not isinstance(metadata, Mapping):
                    raise PromotionError("unsafe-link known-drift metadata is invalid")
                observed_type = metadata.get("type")
                if not (observed_type == "symlink" or (observed_type == "regular-file" and metadata.get("nlink") != 1)):
                    raise PromotionError("unsafe-link known-drift type/link predicate is invalid")
            elif kind == "special":
                if not isinstance(metadata, Mapping) or metadata.get("type") not in {
                    "dir", "fifo", "socket", "block", "char", "other-special"
                }:
                    raise PromotionError("special known-drift metadata type is invalid")
            else:
                raise PromotionError("known-drift observed kind is invalid")
            return
        if classification == "unreadable" and view is None and isinstance(error, Mapping):
            if error.get("kind") == "known-drift":
                raise PromotionError("known-drift cannot be mislabeled unreadable")
            return
        raise PromotionError("protected readback state arm is invalid")

    @property
    def classification(self) -> str:
        return str(self._mapping["classification"])


class NamespaceMutationLeaseReceipt(_LiteralModel):
    DOMAIN = "rsi-namespace-mutation-lease-receipt-v1"
    KEYS = (
        "schemaVersion", "domain", "leaseId", "leaseRequestDigest", "backendIdentityDigest", "capabilityDigest",
        "transactionId", "operationClass", "acquisitionNonce", "issuedAt", "expiresAt", "signatureAlgorithm",
        "signature",
    )


class NamespaceMutationBackendResult(_LiteralModel):
    DOMAIN = "rsi-namespace-mutation-backend-result-v1"
    KEYS = (
        "schemaVersion", "domain", "leaseId", "leaseRequestDigest", "backendIdentityDigest", "capabilityDigest",
        "transactionId", "operationClass", "step", "outcome", "possibleMutation", "beforeWitnessDigest",
        "afterWitnessDigest", "directorySynced", "completedAt", "signatureAlgorithm", "signature",
    )


class NamespaceMutationStepWitness(_LiteralModel):
    DOMAIN = "rsi-namespace-mutation-step-witness-v1"
    KEYS = ("schemaVersion", "domain", "step", "before", "after")


class NamespaceMutationLeaseBackendIdentity(_LiteralModel):
    DOMAIN = "rsi-namespace-mutation-lease-backend-v1"
    KEYS = (
        "schemaVersion", "domain", "backendName", "backendVersion", "implementationDigest", "runtimeIdentityDigest",
        "configurationDigest", "leaseSignerKeyId", "leaseSignerPublicKeyDigest", "signatureAlgorithm",
    )


class NamespaceMutationLeaseCapability(_LiteralModel):
    DOMAIN = "rsi-namespace-mutation-lease-capability-v1"
    KEYS = (
        "schemaVersion", "domain", "backendIdentityDigest", "capability", "scope", "atomicAcquire",
        "holderDeathReleases", "enforcerDeathFailClosed", "liveHolderNeverOutlivesProtection", "signedCausalResults",
        "exchangeCovered", "reverseCovered", "unlinkCovered", "preparedPostCreationAndWriteCovered",
        "operandLinkMutationCovered", "operandContentMutationCovered", "operandMetadataMutationCovered",
        "managedTreeMutationCovered", "mountAndAliasMutationCovered", "preopenedHandleMutationCovered",
        "writableMmapMutationCovered", "dirtyWritebackCovered", "fullManifestReadbackCovered",
        "fullVerifierWindowCovered", "eventCallbackCovered", "noSilentExpiry", "backendPerformsMutation",
    )

    @classmethod
    def _validate(cls, mapping: dict[str, Any]) -> None:
        for key in cls.KEYS[5:]:
            if mapping[key] is not True:
                raise PromotionError("namespace lease capability claims must all be true")


class NamespaceMutationScope(_LiteralModel):
    DOMAIN = "rsi-namespace-mutation-scope-v1"
    KEYS = (
        "schemaVersion", "domain", "ancestryWitness", "ancestryWitnessDigest", "artifactParentWitness",
        "artifactParentWitnessDigest", "managedTreePolicy", "managedTreePolicyDigest",
    )

    @classmethod
    def _validate(cls, mapping: dict[str, Any]) -> None:
        pairs = (
            ("ancestryWitness", "ancestryWitnessDigest"),
            ("artifactParentWitness", "artifactParentWitnessDigest"),
            ("managedTreePolicy", "managedTreePolicyDigest"),
        )
        for body, digest in pairs:
            if mapping[digest] != _digest(mapping[body]):
                raise PromotionError("namespace scope witness/policy digest mismatch")
        ancestry = mapping["ancestryWitness"]
        parent = mapping["artifactParentWitness"]
        policy = mapping["managedTreePolicy"]
        if not isinstance(ancestry, Mapping) or not isinstance(parent, Mapping) or not isinstance(policy, Mapping):
            raise PromotionError("namespace scope preimages are invalid")
        if parent.get("ancestryWitnessDigest") != mapping["ancestryWitnessDigest"]:
            raise PromotionError("artifact parent ancestry digest mismatch")
        if len({ancestry.get("rootIdentityDigest"), parent.get("rootIdentityDigest"), policy.get("rootIdentityDigest")}) != 1:
            raise PromotionError("namespace scope root identity mismatch")


class NamespaceMutationLeaseEvidence(_LiteralModel):
    DOMAIN = "rsi-namespace-mutation-lease-evidence-v1"
    KEYS = (
        "schemaVersion", "domain", "request", "requestDigest", "scope", "scopeDigest", "receipt", "receiptDigest",
        "backendResults", "backendResultsDigest", "stepWitnesses", "stepWitnessesDigest",
    )

    @classmethod
    def _validate(cls, mapping: dict[str, Any]) -> None:
        for body, digest in (
            ("request", "requestDigest"), ("scope", "scopeDigest"), ("receipt", "receiptDigest"),
            ("backendResults", "backendResultsDigest"), ("stepWitnesses", "stepWitnessesDigest"),
        ):
            if mapping[digest] != _digest(mapping[body]):
                raise PromotionError("namespace evidence digest mismatch")


class TargetReadbackView(_LiteralModel):
    DOMAIN = "rsi-target-readback-view-v1"
    KEYS = (
        "schemaVersion", "domain", "classification", "target", "retainedNameWitness", "ancestryWitnessDigest",
        "memberMetadataWitnesses", "scanDigest",
    )

    @classmethod
    def _validate(cls, mapping: dict[str, Any]) -> None:
        body = {
            "schemaVersion": mapping["schemaVersion"],
            "domain": "rsi-target-readback-view-body-v1",
            "classification": mapping["classification"],
            "target": mapping["target"],
            "retainedNameWitness": mapping["retainedNameWitness"],
            "ancestryWitnessDigest": mapping["ancestryWitnessDigest"],
            "memberMetadataWitnesses": mapping["memberMetadataWitnesses"],
        }
        if mapping["scanDigest"] != _digest(body):
            raise PromotionError("target readback scan digest mismatch")

    @property
    def scan_digest(self) -> str:
        return str(self._mapping["scanDigest"])


def validate_namespace_scope_request_binding(
    request: Mapping[str, Any], scope: Mapping[str, Any]
) -> None:
    parsed_request = NamespaceMutationLeaseRequest.from_mapping(request)
    parsed_scope = NamespaceMutationScope.from_mapping(scope)
    request_map = parsed_request.to_mapping()
    scope_map = parsed_scope.to_mapping()
    if request_map["rootIdentityDigest"] != scope_map["ancestryWitness"]["rootIdentityDigest"]:
        raise PromotionError("namespace scope root identity mismatch")
    for request_key, scope_key in (
        ("ancestryWitnessDigest", "ancestryWitnessDigest"),
        ("artifactParentWitnessDigest", "artifactParentWitnessDigest"),
        ("managedTreePolicyDigest", "managedTreePolicyDigest"),
    ):
        if request_map[request_key] != scope_map[scope_key]:
            raise PromotionError("namespace parent/path/ancestry scope-request digest mismatch")
    ancestry = scope_map["ancestryWitness"]
    parent = scope_map["artifactParentWitness"]
    if ancestry.get("parentRelativePath") != parent.get("parentRelativePath"):
        raise PromotionError("artifact parent path does not match ancestry")


def validate_managed_tree_policy_projection(
    policy: Mapping[str, Any],
    pre_manifest: Sequence[Mapping[str, Any]],
    post_manifest: Sequence[Mapping[str, Any]],
) -> None:
    parsed = ManagedTreePolicy.from_mapping(policy).to_mapping()
    pre = {item.get("path"): dict(item) for item in pre_manifest}
    post = {item.get("path"): dict(item) for item in post_manifest}
    members = parsed["members"]
    if not isinstance(members, list):
        raise PromotionError("managed tree policy members are invalid")
    expected_paths = sorted(set(pre) | set(post), key=lambda item: str(item).encode("utf-8"))
    actual_paths = [item.get("relativePath") for item in members if isinstance(item, Mapping)]
    if actual_paths != expected_paths:
        raise PromotionError("managed tree policy path projection mismatch")
    for member in members:
        if set(member) != {"relativePath", "pre", "post"}:
            raise PromotionError("managed tree policy member schema is invalid")
        path = member["relativePath"]
        for arm, source in (("pre", pre.get(path)), ("post", post.get(path))):
            expected = None if source is None else {key: value for key, value in source.items() if key != "path"}
            if member[arm] != expected:
                raise PromotionError("managed tree policy fieldwise projection mismatch")


def validate_target_member_projection(
    target: Mapping[str, Any], member: Mapping[str, Any]
) -> None:
    parsed_target = TargetWitness.from_mapping(target).to_mapping()
    parsed_member = MemberMetadataWitness.from_mapping(member).to_mapping()
    if parsed_target["relativePath"] != parsed_member["relativePath"]:
        raise PromotionError("target/member path mismatch")
    for key in ("device", "inode", "type", "mode", "uid", "nlink", "size"):
        if parsed_target[key] != parsed_member[key]:
            raise PromotionError("target/member live field mismatch")


class VerifierRequestCore(_LiteralModel):
    DOMAIN = "rsi-live-verifier-request-core-v1"
    KEYS = (
        "schemaVersion", "domain", "transactionId", "runId", "planDigest", "verifiedPostReadbackDigest",
        "validationAttestationDigest", "verifierExecutionBaseIdentityDigest", "controlPlaneDigest",
        "verifierInvocationNonce", "expiresAt",
    )


class VerifierRequest(_LiteralModel):
    DOMAIN = "rsi-live-verifier-request-v1"
    KEYS = (
        "schemaVersion", "domain", "core", "verifierRequestCoreDigest", "applyCompletedEventId",
        "applyCompletedEventDigest", "applyReadbackRef", "applyReadbackDigest",
    )

    @classmethod
    def _validate(cls, mapping: dict[str, Any]) -> None:
        if mapping["verifierRequestCoreDigest"] != _digest(mapping["core"]):
            raise PromotionError("verifier request core digest mismatch")


class VerifierReceipt(_LiteralModel):
    DOMAIN = "rsi-live-verifier-receipt-v1"
    KEYS = (
        "schemaVersion", "domain", "kind", "verifierRequestDigest", "receiptSignerKeyId",
        "signatureAlgorithm", "issuedAt", "liveReadback", "tests", "attestationMatch", "result", "signature",
    )

    @classmethod
    def _validate(cls, mapping: dict[str, Any]) -> None:
        tests = mapping["tests"]
        if not isinstance(tests, Mapping) or set(tests) != {
            "skillValidationPassed", "contractValidationPassed", "targetTestsPassed"
        }:
            raise PromotionError("verifier test result schema is invalid")
        passed = all(value is True for value in tests.values()) and mapping["attestationMatch"] is True
        if mapping["result"] != ("passed" if passed else "failed"):
            raise PromotionError("verifier result is not the test/attestation conjunction")


class VerifierNonIssuanceEvidence(_LiteralModel):
    DOMAIN = "rsi-verifier-non-issuance-evidence-v1"
    KEYS = (
        "schemaVersion", "domain", "verifierRequestDigest", "receiptSignerKeyId", "receiptSignerPublicKeyDigest",
        "receiptSignerCapabilityDigest", "receiptRef", "receiptPathAbsent", "result", "code", "completedAt",
        "signatureAlgorithm", "signature",
    )

    @classmethod
    def _validate(cls, mapping: dict[str, Any]) -> None:
        if mapping["result"] != "not-issued" or mapping["receiptPathAbsent"] is not True:
            raise PromotionError("verifier non-issuance terminal evidence is invalid")


class VerifierCommitment(_LiteralModel):
    KEYS = (
        "state", "verifierInvocationNonce", "verifierRequestCoreDigest",
        "verifierExecutionBaseIdentityDigest", "controlPlaneDigest",
    )

    @classmethod
    def _validate(cls, mapping: dict[str, Any]) -> None:
        if mapping["state"] == "not-reached":
            if any(mapping[key] is not None for key in cls.KEYS[1:]):
                raise PromotionError("verifier commitment not-reached arm requires nulls")
        elif mapping["state"] == "committed":
            if any(mapping[key] is None for key in cls.KEYS[1:]):
                raise PromotionError("verifier commitment committed arm requires values")
        else:
            raise PromotionError("verifier commitment state is invalid")


class VerifierReceiptAvailability(_LiteralModel):
    KEYS = ("availability", "ref", "digest", "errorCode", "nonIssuanceEvidence")

    @classmethod
    def _validate(cls, mapping: dict[str, Any]) -> None:
        if mapping["availability"] == "present":
            if mapping["ref"] is None or mapping["digest"] is None or mapping["errorCode"] is not None or mapping["nonIssuanceEvidence"] is not None:
                raise PromotionError("present verifier receipt availability has invalid null fields")
        elif mapping["availability"] == "unavailable":
            if mapping["ref"] is not None or mapping["digest"] is not None or mapping["errorCode"] is None or mapping["nonIssuanceEvidence"] is None:
                raise PromotionError("unavailable verifier receipt availability has invalid ref/null fields")
            VerifierNonIssuanceEvidence.from_mapping(mapping["nonIssuanceEvidence"])
        else:
            raise PromotionError("verifier receipt availability cannot be unknown")


def validate_verifier_request_binding(
    request: Mapping[str, Any], *, applied_readback: Mapping[str, Any], expected_nonce: str,
    apply_completed_event_id: str, apply_completed_event_digest: str,
    apply_readback_ref: str, apply_readback_digest: str,
) -> None:
    parsed = VerifierRequest.from_mapping(request).to_mapping()
    core = VerifierRequestCore.from_mapping(parsed["core"]).to_mapping()
    expected = {
        "applyCompletedEventId": apply_completed_event_id,
        "applyCompletedEventDigest": apply_completed_event_digest,
        "applyReadbackRef": apply_readback_ref,
        "applyReadbackDigest": apply_readback_digest,
    }
    if core["verifierInvocationNonce"] != expected_nonce:
        raise PromotionError("verifier nonce/core binding mismatch")
    if core["verifiedPostReadbackDigest"] != _digest(applied_readback):
        raise PromotionError("verifier applied readback digest mismatch")
    if any(parsed[key] != value for key, value in expected.items()):
        raise PromotionError("verifier request event/sidecar binding mismatch")


def validate_verifier_terminal_pair(
    *, request: Mapping[str, Any], receipt: Mapping[str, Any] | None,
    nonissuance: Mapping[str, Any] | None, receipt_path_absent: bool,
) -> None:
    request_digest = VerifierRequest.from_mapping(request).digest
    if (receipt is None) == (nonissuance is None):
        raise PromotionError("verifier terminal must select receipt or non-issuance")
    if receipt is not None:
        parsed = VerifierReceipt.from_mapping(receipt).to_mapping()
        if parsed["verifierRequestDigest"] != request_digest or receipt_path_absent:
            raise PromotionError("verifier receipt terminal binding is invalid")
    else:
        parsed = VerifierNonIssuanceEvidence.from_mapping(nonissuance or {}).to_mapping()
        if parsed["verifierRequestDigest"] != request_digest or receipt_path_absent is not True:
            raise PromotionError("verifier non-issuance terminal binding is invalid")


def validate_namespace_evidence_placement(document: Mapping[str, Any], *, require_complete: bool) -> None:
    if not isinstance(document, Mapping):
        raise PromotionError("namespace evidence document is invalid")
    evidence = document.get("namespaceMutationLeaseEvidence")
    if require_complete and evidence is None:
        raise PromotionError("sole namespace evidence is required")
    evidence_digest = None if evidence is None else NamespaceMutationLeaseEvidence.from_mapping(evidence).digest

    def walk(value: object, *, root: bool = False) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if key == "namespaceMutationLeaseEvidence" and not root:
                    raise PromotionError("nested namespace evidence duplicates the sole top-level evidence")
                if key == "namespaceMutationLeaseEvidenceDigest" and item != evidence_digest:
                    raise PromotionError("nested namespace evidence digest mismatch")
                walk(item, root=False)
        elif isinstance(value, list):
            for item in value:
                walk(item, root=False)

    for key, value in document.items():
        if key != "namespaceMutationLeaseEvidence":
            walk(value)


def validate_namespace_lease_time_window(
    *, issuedAt: str, completedAt: str, expiresAt: str, observed_at: str,
    causal_event_bound: bool, authorize_new_step: bool,
) -> None:
    issued = _parse_utc(issuedAt, label="issuedAt")
    completed = _parse_utc(completedAt, label="completedAt")
    expires = _parse_utc(expiresAt, label="expiresAt")
    observed = _parse_utc(observed_at, label="observedAt")
    if not causal_event_bound or not (issued <= completed < expires):
        raise PromotionError("lease causal time window is invalid")
    if authorize_new_step and observed >= expires:
        raise PromotionError("expired lease cannot authorize a fresh live step")


_SIZE_VECTOR_KEYS = (
    "kind", "pathBudgetBytes", "memberCount", "protectedReadbackCount",
    "evidenceAndFramingBytes", "outerEnvelopeBytes",
)


def task8_sidecar_cap(kind: str) -> int:
    if kind == "resolution-readback":
        return MAX_RESOLUTION_READBACK_BYTES
    if kind == "verifier-receipt":
        return MAX_EVENT_LINE_BYTES
    if kind in {
        "promotion-origin",
        "provider-snapshot", "apply-intent", "apply-readback", "live-verification", "rollback-readback",
        "transaction-decision", "incident-record",
    }:
        return MAX_TASK8_SIDECAR_BYTES
    raise PromotionError("Task 8 sidecar kind is invalid")


def compute_task8_preflight_bound(vector: Mapping[str, Any]) -> int:
    copied = _strict_mapping(vector, _SIZE_VECTOR_KEYS, label="size vector")
    kind = copied["kind"]
    cap = task8_sidecar_cap(kind)
    for key, maximum in (
        ("pathBudgetBytes", 4 * 1024 * 1024),
        ("memberCount", 4096),
        ("protectedReadbackCount", 2),
        ("evidenceAndFramingBytes", 16 * 1024 * 1024 if kind != "verifier-receipt" else 64 * 1024),
        ("outerEnvelopeBytes", 16 * 1024 * 1024 if kind != "verifier-receipt" else 64 * 1024),
    ):
        value = copied[key]
        if type(value) is not int or value < 0 or value > maximum:
            raise PromotionError("size vector contains an invalid bounded integer")
    path_copies = 1 + 2 * copied["protectedReadbackCount"]
    if kind == "resolution-readback":
        path_copies += 1
    member_copies = 2 + 2 * copied["protectedReadbackCount"]
    bound = (
        6 * copied["pathBudgetBytes"] * path_copies
        + 2048 * copied["memberCount"] * member_copies
        + copied["evidenceAndFramingBytes"]
        + copied["outerEnvelopeBytes"]
    )
    if bound > cap:
        raise PromotionError("size vector bound exceeds its Task 8 cap")
    return bound


def admit_task8_sidecar_preflight(vector: Mapping[str, Any], *, exact_length: int | None = None) -> int:
    if exact_length is not None:
        raise PromotionError("future exact length is forbidden during preflight")
    return compute_task8_preflight_bound(vector)


def validate_task8_document_length(
    vector: Mapping[str, Any], *, exact_length: int, pipeline_stage: str
) -> int:
    if pipeline_stage not in {"allocation", "write", "fstat", "read", "parse", "readback", "replay", "downstream"}:
        raise PromotionError("document length pipeline stage is invalid")
    bound = compute_task8_preflight_bound(vector)
    if type(exact_length) is not int or exact_length < 0 or exact_length > bound or exact_length > task8_sidecar_cap(str(vector.get("kind"))):
        raise PromotionError("document length exceeds its bound or cap")
    return exact_length


_COMMON_SIDECAR_FIELDS = (
    "schemaVersion", "kind", "transactionId", "runId", "planDigest", "eventBinding",
)

_SIDECAR_FIELDS: dict[str, tuple[str, ...]] = {
    "provider-snapshot": _COMMON_SIDECAR_FIELDS + (
        "originRef", "originDigest", "providerIdentity", "candidateFullRecordDigest",
        "providerAuthorityBindingDigest", "task7CandidateBindingDigest",
        "candidateCaptureLineageBindingDigest", "candidateStateBindingDigest", "snapshot", "targetPre",
    ),
    "apply-intent": _COMMON_SIDECAR_FIELDS + (
        "originRef", "originDigest", "snapshotRef", "snapshotDigest", "candidateFullRecordDigest",
        "providerAuthorityBindingDigest", "task7CandidateBindingDigest",
        "candidateCaptureLineageBindingDigest", "candidateStateBindingDigest", "providerGuardDigest", "target",
        "artifact", "manifestPreHash", "manifestPostHash", "postImageRef", "postImageDigest",
        "retainedPreimageName", "snapshotOperationId", "resolveOperationId", "verifierInvocationNonce",
        "verifierExecutionBaseIdentityDigest", "namespaceMutationLeaseBackendIdentityDigest",
        "namespaceMutationLeaseCapabilityDigest", "controlPlaneDigest", "expiresAt",
    ),
    "apply-readback": _COMMON_SIDECAR_FIELDS + (
        "intentRef", "intentDigest", "outcome", "reasonCode", "target", "retainedPreimage",
        "preparedPostDisposition", "preparedPost", "cleanup", "artifactHash", "manifestHash", "directorySynced",
        "namespaceMutationLeaseEvidence", "verifiedPostReadbackDigest", "verifierCommitment",
        "candidateFullRecordDigest", "providerAuthorityBindingDigest", "task7CandidateBindingDigest",
        "candidateCaptureLineageBindingDigest", "candidateStateBindingDigest",
    ),
    "live-verification": _COMMON_SIDECAR_FIELDS + (
        "readbackRef", "readbackDigest", "outcome", "reasonCode", "verifierReceipt", "liveReadback", "tests",
        "attestationMatch", "target", "retainedPreimage", "verifierExecutionBaseIdentityDigest",
        "verifierInvocationNonce", "verifierRequestDigest", "controlPlaneDigest", "namespaceMutationLeaseEvidence",
        "candidateFullRecordDigest", "providerAuthorityBindingDigest", "task7CandidateBindingDigest",
        "candidateCaptureLineageBindingDigest", "candidateStateBindingDigest",
    ),
    "rollback-readback": _COMMON_SIDECAR_FIELDS + (
        "intentRef", "intentDigest", "readbackRef", "readbackDigest", "verificationRef", "verificationDigest",
        "providerFullRecordDigest", "providerAuthorityBindingDigest", "task7CandidateBindingDigest",
        "candidateCaptureLineageBindingDigest", "candidateStateBindingDigest", "beforeTarget", "afterTarget",
        "retainedPreimage", "displacedPost", "cleanup", "namespaceMutationLeaseEvidence",
    ),
    "resolution-readback": _COMMON_SIDECAR_FIELDS + (
        "verificationRef", "verificationDigest", "providerOperationId", "resolutionId",
        "providerResolutionRequestDigest", "providerResolutionRecord", "candidateFullRecordBeforeDigest",
        "providerAuthorityBindingBeforeDigest", "task7CandidateBindingDigest",
        "candidateCaptureLineageBindingDigest", "candidateStateBindingBeforeDigest",
        "candidateFullRecordAfterDigest", "providerAuthorityBindingAfterDigest", "candidateStateBindingAfterDigest",
        "providerResolutionRecordDigest", "target", "retainedPreimage", "namespaceMutationLeaseEvidence",
    ),
}

_DECISION_CLEAN_FIELDS = _COMMON_SIDECAR_FIELDS + (
    "outcome", "terminalReasonCode", "closeStatus", "terminalEventId", "terminalEvidenceRef",
    "terminalEvidenceDigest", "targetDisposition", "target", "providerStateDigest", "cleanup", "latchAbsent",
    "promotionDecision", "namespaceMutationLeaseEvidence",
)
_DECISION_INCIDENT_FIELDS = _COMMON_SIDECAR_FIELDS + (
    "outcome", "terminalReasonCode", "closeStatus", "terminalEventId", "terminalEvidenceRef",
    "terminalEvidenceDigest", "targetDisposition", "targetWitness", "providerStateDigest", "cleanup", "latchAbsent",
    "promotionDecision", "incidentClosure",
)
_INCIDENT_FIELDS = _COMMON_SIDECAR_FIELDS + (
    "incidentId", "reasonCode", "rootIdentityDigest", "artifactPath", "expectedPreHash", "expectedPostHash",
    "intentDigest", "lastDurableEventId", "targetWitness", "providerWitness", "verifierWitness",
    "reservedNameWitness", "ancestryWitness", "exchangeWitness", "phaseWitness",
    "namespaceMutationLeaseEvidence", "quarantineTargets", "requiresOperatorAction",
)


def task8_sidecar_fields(kind: str, *, arm: str | None = None) -> tuple[str, ...]:
    if kind == "transaction-decision":
        if arm == "clean":
            return _DECISION_CLEAN_FIELDS
        if arm == "incident":
            return _DECISION_INCIDENT_FIELDS
        raise PromotionError("transaction decision arm is invalid")
    if kind == "incident-record":
        if arm is not None:
            raise PromotionError("incident record has no arm")
        return _INCIDENT_FIELDS
    if arm is not None or kind not in _SIDECAR_FIELDS:
        raise PromotionError("Task 8 sidecar kind is invalid")
    return _SIDECAR_FIELDS[kind]


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    candidate_id: str
    decision: str
    reason: str
    promotion_plan_digest: str
    validation_attestation_digest: str
    approval_receipt_ref: str | None
    snapshot_ref: str
    target_hash_before: str
    target_hash_after: str
    artifacts: tuple[str, ...]
    verification: Mapping[str, bool]

    _WIRE: ClassVar[tuple[tuple[str, str], ...]] = (
        ("candidate_id", "candidateId"), ("decision", "decision"), ("reason", "reason"),
        ("promotion_plan_digest", "promotionPlanDigest"),
        ("validation_attestation_digest", "validationAttestationDigest"),
        ("approval_receipt_ref", "approvalReceiptRef"), ("snapshot_ref", "snapshotRef"),
        ("target_hash_before", "targetHashBefore"), ("target_hash_after", "targetHashAfter"),
        ("artifacts", "artifacts"), ("verification", "verification"),
    )

    def __post_init__(self) -> None:
        if self.decision != "promoted" or self.reason != PROMOTION_REASON_V1:
            raise PromotionError("promotion decision/reason is invalid")
        for value in (
            self.promotion_plan_digest, self.validation_attestation_digest,
            self.target_hash_before, self.target_hash_after,
        ):
            _require_digest(value)
        if not isinstance(self.verification, Mapping) or set(self.verification) != {
            "skillValidationPassed", "contractValidationPassed", "targetTestsPassed"
        } or any(value is not True for value in self.verification.values()):
            raise PromotionError("promotion decision verification is invalid")
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "verification", MappingProxyType(dict(self.verification)))

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "PromotionDecision":
        keys = tuple(wire for _, wire in cls._WIRE)
        copied = _strict_mapping(mapping, keys, label="promotion decision")
        values = {field: copied[wire] for field, wire in cls._WIRE}
        values["artifacts"] = tuple(values["artifacts"])
        return cls(**values)

    def to_mapping(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for field, wire in self._WIRE:
            value = getattr(self, field)
            if isinstance(value, tuple):
                value = list(value)
            elif isinstance(value, Mapping):
                value = dict(value)
            result[wire] = value
        return result


def derive_promotion_transaction_id(plan_digest: str) -> str:
    _require_digest(plan_digest, label="plan digest")
    seed = {"domain": "rsi-promotion-transaction-v1", "planDigest": plan_digest}
    return "tx_" + _digest_no_lf(seed)[7:]


def derive_promotion_run_id(plan_digest: str) -> str:
    _require_digest(plan_digest, label="plan digest")
    seed = {"domain": "rsi-promotion-continuation-v1", "planDigest": plan_digest}
    return "run_promote_" + _digest_no_lf(seed)[7:]


def derive_promotion_event_id(transaction_id: str, event_type: str) -> str:
    if type(transaction_id) is not str or _TX_RE.fullmatch(transaction_id) is None:
        raise PromotionError("promotion transaction identifier is invalid")
    if type(event_type) is not str or not event_type:
        raise PromotionError("promotion event type is invalid")
    seed = {"domain": "rsi-promotion-event-v1", "eventType": event_type, "transactionId": transaction_id}
    return "evt_" + _digest_no_lf(seed)[7:]


def derive_promotion_incident_id(transaction_id: str) -> str:
    if type(transaction_id) is not str or _TX_RE.fullmatch(transaction_id) is None:
        raise PromotionError("promotion transaction identifier is invalid")
    seed = {"domain": "rsi-promotion-incident-v1", "transactionId": transaction_id}
    return "incident_" + _digest_no_lf(seed)[7:]


def derive_promotion_command_id(plan_digest: str) -> str:
    _require_digest(plan_digest, label="plan digest")
    seed = {"domain": "rsi-promote-cli-v1", "planDigest": plan_digest}
    return "promote_" + _digest_no_lf(seed)[7:]


def validate_task8_lock_trace(trace: Sequence[tuple[str, str]]) -> None:
    held: list[str] = []
    rank = {name: index for index, name in enumerate(TASK8_PROTECTED_LOCK_ORDER)}
    for item in trace:
        if not isinstance(item, tuple) or len(item) != 2:
            raise PromotionConflict("lock trace entry is invalid")
        action, value = item
        if action == "acquire":
            if value not in rank:
                raise PromotionConflict("unknown lock in lock trace")
            if value == "namespace-lease" and held:
                raise PromotionConflict("namespace lease must be outermost and no inner lock may be held")
            if held and rank[value] <= rank[held[-1]]:
                raise PromotionConflict("lock order inversion")
            held.append(value)
        elif action == "release":
            if not held or held[-1] != value:
                raise PromotionConflict("lock release order is invalid")
            held.pop()
        elif action == "heavy":
            if value in {"full-manifest-readback", "trusted-verifier"} and any(
                lock != "namespace-lease" for lock in held
            ):
                raise PromotionConflict("heavy operation spans a forbidden inner lock")
            if value in {"provider-snapshot", "provider-resolve"} and "event-store" in held:
                raise PromotionConflict("provider operation spans EventStore lock")
        elif action == "guard-b":
            if value in {"event-store-append", "historical-batch"}:
                raise PromotionConflict("Guard B cannot append or build a historical batch")
        elif action == "backend-callback-acquire":
            raise PromotionConflict("backend callback cannot reenter the RSI lock graph")
        elif action == "callback":
            validate_provider_eventstore_callback("guard-a:" + value)
        else:
            raise PromotionConflict("lock trace action is invalid")
    if held:
        raise PromotionConflict("lock trace leaves locks held")


def validate_task8_phase_trace(operation_class: str, trace: Sequence[str]) -> None:
    if operation_class not in NAMESPACE_MUTATION_OPERATION_CLASSES:
        raise PromotionConflict("Task 8 phase operation class is invalid")
    if not trace or trace[0] != "acquire:namespace-lease" or trace[-1] != "release:namespace-lease":
        raise PromotionConflict("protected phase must keep one outer namespace lease")
    if operation_class == "forward-apply":
        required = ("backend:forward-exchange", "heavy:full-manifest-readback", "append:apply.completed:applied")
    elif operation_class == "rollback-apply":
        required = ("backend:rollback-exchange", "heavy:full-manifest-readback:exact-pre", "append:apply.reverted")
    elif operation_class.endswith("-cleanup"):
        required = ("bounded:reserved-name-check", "backend:unlink", "backend:parent-sync", "append:run.closed")
        provider_acquires = [item for item in trace if item == "acquire:provider:unresolved-terminal"]
        provider_releases = [item for item in trace if item == "release:provider:unresolved-terminal"]
        if len(provider_acquires) != 1 or len(provider_releases) != 1:
            raise PromotionConflict("cleanup provider guard must be continuous")
        if trace.index(provider_releases[0]) < trace.index("append:run.closed"):
            raise PromotionConflict("cleanup provider guard must cover terminal close")
    else:
        required = ()
    cursor = -1
    for item in required:
        try:
            cursor = trace.index(item, cursor + 1)
        except ValueError:
            raise PromotionConflict("protected phase trace omits or reorders a required step") from None


def validate_provider_eventstore_callback(callback: str) -> None:
    if callback not in PROVIDER_EVENTSTORE_CALLBACKS:
        raise PromotionConflict("provider to EventStore callback is not admitted")


_LEASE_WINDOWS: dict[str, frozenset[str]] = {
    "forward-apply": frozenset({"create-write", "exchange", "emergency-reverse", "parent-sync", "full-readback", "event-callback"}),
    "rollback-apply": frozenset({"reverse-exchange", "parent-sync", "full-readback", "event-callback"}),
    "verifier-readback": frozenset({"full-readback", "trusted-verifier", "event-callback"}),
    "promoted-terminal": frozenset({"full-readback", "provider-resolve", "event-callback"}),
    "unresolved-terminal": frozenset({"full-readback", "event-callback"}),
    "incident-classification": frozenset({"full-readback", "event-callback"}),
    "prepared-post-cleanup": frozenset({"full-readback", "unlink", "parent-sync", "event-callback"}),
    "retained-preimage-cleanup": frozenset({"full-readback", "unlink", "parent-sync", "event-callback"}),
    "displaced-post-cleanup": frozenset({"full-readback", "unlink", "parent-sync", "event-callback"}),
}


def lease_required_windows(operation_class: str) -> frozenset[str]:
    try:
        return _LEASE_WINDOWS[operation_class]
    except KeyError:
        raise PromotionError("namespace lease operation class is invalid") from None


class LocalTrustedNamespaceMutationLeaseBackend:
    available = False
    failure_code = "unsupported"


class TrustedNamespaceMutationLeaseRegistry:
    __slots__ = ("_backends",)

    def __init__(self, backends: Mapping[str, object] | None = None) -> None:
        self._backends = MappingProxyType(dict(backends or {}))

    @classmethod
    def empty(cls) -> "TrustedNamespaceMutationLeaseRegistry":
        return cls()

    def resolve(self, backend_identity_digest: str):
        _require_digest(backend_identity_digest, label="backend identity digest")
        if backend_identity_digest not in self._backends:
            raise PromotionError("attested namespace lease backend is unavailable")
        return self._backends[backend_identity_digest]


class NamespaceLeaseLiveness:
    __slots__ = ("state",)

    def __init__(self, *, initial_state: str) -> None:
        if initial_state != "protected-live":
            raise PromotionError("namespace lease liveness initial state is invalid")
        self.state = initial_state

    def apply(self, event: str) -> None:
        transitions = {
            "holder-died": "released",
            "enforcer-died": "fail-closed",
            "watchdog-expired": "released",
        }
        if self.state != "protected-live" or event not in transitions:
            raise PromotionError("namespace lease liveness transition is invalid")
        self.state = transitions[event]

    @property
    def holder_live(self) -> bool:
        return self.state == "protected-live"

    @property
    def protection_live(self) -> bool:
        return self.state == "protected-live"


@dataclass(frozen=True, slots=True)
class GuardBRaceClassification:
    outcome: str
    reason: str
    exchange_count: int


def classify_guard_b_race(*, exchange_performed: bool, provider_precheck: str, provider_postcheck: str) -> GuardBRaceClassification:
    if exchange_performed is False and provider_precheck == "drift":
        return GuardBRaceClassification("not-applied", "pre-exchange-check-failed", 0)
    if exchange_performed is True and provider_precheck == "exact" and provider_postcheck != "exact":
        return GuardBRaceClassification("incident", "provider-state-unknown", 1)
    raise PromotionError("Guard B race classification is invalid")


@dataclass(frozen=True, slots=True)
class IncidentCASDisposition:
    disposition: str
    blocking_digest: str


class InMemoryIncidentRecordCAS:
    __slots__ = ("incident_id", "_digest", "_lock")

    def __init__(self, incident_id: str) -> None:
        self.incident_id = incident_id
        self._digest: str | None = None
        self._lock = threading.Lock()

    def publish(self, digest: str) -> IncidentCASDisposition:
        _require_digest(digest)
        with self._lock:
            if self._digest is None:
                self._digest = digest
                disposition = "created"
            else:
                disposition = "existing"
            return IncidentCASDisposition(disposition, self._digest)

    def read_digest(self) -> str:
        with self._lock:
            if self._digest is None:
                raise PromotionError("incident CAS is empty")
            return self._digest


@dataclass(frozen=True, slots=True)
class PromotionAdmission:
    root_identity_digest: str
    plan_digest: str


class InMemoryPromotionAdmissionGate:
    __slots__ = ("_claims", "_lock", "snapshot_call_count", "apply_call_count")

    def __init__(self) -> None:
        self._claims: dict[str, PromotionAdmission] = {}
        self._lock = threading.Lock()
        self.snapshot_call_count = 0
        self.apply_call_count = 0

    def claim(self, *, root_identity_digest: str, plan_digest: str) -> PromotionAdmission:
        _require_digest(root_identity_digest, label="root identity digest")
        _require_digest(plan_digest, label="plan digest")
        with self._lock:
            current = self._claims.get(root_identity_digest)
            if current is None:
                current = PromotionAdmission(root_identity_digest, plan_digest)
                self._claims[root_identity_digest] = current
            elif current.plan_digest != plan_digest:
                raise PromotionConflict("root already has an incompatible promotion plan conflict")
            return current


@dataclass(frozen=True, slots=True)
class ProtectedScanClassification:
    arm: str
    observed_kind: str | None = None
    failure_stage: str | None = None
    relative_path: str | None = None


def classify_protected_scan_observation(observation: Mapping[str, Any]) -> ProtectedScanClassification:
    if not isinstance(observation, Mapping):
        raise PromotionError("protected scan observation is invalid")
    path = observation.get("relativePath")
    if type(path) is not str:
        raise PromotionError("protected scan path is invalid")
    observed = observation.get("observedType")
    if observation.get("expectedPresent") is False and observed == "missing":
        return ProtectedScanClassification("expected-absence", relative_path=path)
    proof_order = (
        ("lookupProved", "lookup"), ("kindProved", "kind"), ("metadataProved", "metadata"),
        ("canonicalizationProved", "canonicalization"), ("numericBoundsProved", "numeric-bounds"),
        ("contentReadable", "content-read"), ("contentHashable", "content-hash"),
    )
    for key, stage in proof_order:
        if observation.get(key) is not True:
            return ProtectedScanClassification("unreadable", failure_stage=stage, relative_path=path)
    if observed == "missing":
        return ProtectedScanClassification("known-drift", "missing", relative_path=path)
    if observed == "symlink" or (observed == "regular-file" and observation.get("nlink") != 1):
        return ProtectedScanClassification("known-drift", "unsafe-link", relative_path=path)
    if observed in {"dir", "fifo", "socket", "block", "char", "other-special"}:
        return ProtectedScanClassification("known-drift", "special", relative_path=path)
    if observed == "regular-file":
        return ProtectedScanClassification("full-view", relative_path=path)
    return ProtectedScanClassification("unreadable", failure_stage="kind", relative_path=path)


def select_first_protected_scan_failure(
    observations: Mapping[str, Mapping[str, Any]]
) -> ProtectedScanClassification:
    if not isinstance(observations, Mapping):
        raise PromotionError("protected scan observations are invalid")
    classified = [classify_protected_scan_observation(value) for _, value in sorted(
        observations.items(), key=lambda item: item[0].encode("utf-8")
    )]
    for item in classified:
        if item.arm not in {"full-view", "expected-absence"}:
            return item
    raise PromotionError("protected scan has no failure")


_VALID_RESULT_SEQUENCES: dict[tuple[str, str], tuple[tuple[str, str], ...]] = {
    ("forward-apply", "create-failure"): (("prepared-post-create-write", "not-performed"), ("protected-readback", "exact-pre")),
    ("unresolved-terminal", "post-crash-never-created"): (("protected-readback", "exact-pre"),),
    ("forward-apply", "retained-pre-exchange-failure"): (("prepared-post-create-write", "performed"), ("protected-readback", "exact-pre")),
    ("forward-apply", "prepared-sync-failure"): (("prepared-post-create-write", "performed-unsynced"), ("protected-readback", "exact-pre")),
    ("forward-apply", "commit-check-drift"): (("prepared-post-create-write", "performed"), ("forward-exchange", "not-performed"), ("protected-readback", "exact-pre")),
    ("forward-apply", "applied"): (("prepared-post-create-write", "performed"), ("forward-exchange", "performed"), ("protected-readback", "exact-post")),
    ("forward-apply", "emergency-reverse"): (("prepared-post-create-write", "performed"), ("forward-exchange", "performed"), ("protected-readback", "other"), ("emergency-reverse", "performed"), ("protected-readback", "exact-pre")),
    ("verifier-readback", "affirmed"): (("protected-readback", "exact-post"),),
    ("promoted-terminal", "resolved"): (("protected-readback", "exact-post"),),
    ("incident-classification", "drift"): (("protected-readback", "other"),),
    ("rollback-apply", "rolled-back"): (("protected-readback", "exact-post"), ("rollback-exchange", "performed"), ("protected-readback", "exact-pre")),
    ("prepared-post-cleanup", "removed-now"): (("prepared-post-cleanup", "performed"), ("protected-readback", "exact-pre")),
    ("prepared-post-cleanup", "already-absent-authorized"): (("prepared-post-cleanup", "not-performed"), ("protected-readback", "exact-pre")),
    ("retained-preimage-cleanup", "removed-now"): (("retained-preimage-cleanup", "performed"), ("protected-readback", "exact-post")),
    ("displaced-post-cleanup", "removed-now"): (("displaced-post-cleanup", "performed"), ("protected-readback", "exact-pre")),
    ("forward-apply", "create-failure-incident"): (("prepared-post-create-write", "not-performed"), ("protected-readback", "unreadable")),
    ("forward-apply", "forward-ambiguous"): (("prepared-post-create-write", "performed"), ("forward-exchange", "ambiguous")),
    ("rollback-apply", "rollback-not-performed-incident"): (("protected-readback", "exact-post"), ("rollback-exchange", "not-performed")),
    ("rollback-apply", "rollback-ambiguous"): (("protected-readback", "exact-post"), ("rollback-exchange", "ambiguous")),
    ("rollback-apply", "rollback-post-drift"): (("protected-readback", "exact-post"), ("rollback-exchange", "performed"), ("protected-readback", "other")),
    ("retained-preimage-cleanup", "cleanup-unsynced-readable"): (("retained-preimage-cleanup", "performed-unsynced"), ("protected-readback", "exact-post")),
    ("retained-preimage-cleanup", "cleanup-unsynced-unreadable"): (("retained-preimage-cleanup", "performed-unsynced"),),
    ("retained-preimage-cleanup", "cleanup-refused-drift"): (("retained-preimage-cleanup", "not-performed"), ("protected-readback", "other")),
    ("displaced-post-cleanup", "cleanup-performed-post-drift"): (("displaced-post-cleanup", "performed"), ("protected-readback", "unreadable")),
}


def validate_namespace_result_sequence(
    *, operation_class: str, causal_arm: str, results: Sequence[Mapping[str, str]]
) -> None:
    actual: list[tuple[str, str]] = []
    for result in results:
        if not isinstance(result, Mapping) or set(result) != {"step", "outcome"}:
            raise PromotionError("namespace result sequence entry is invalid")
        actual.append((str(result["step"]), str(result["outcome"])))
    if tuple(actual) != _VALID_RESULT_SEQUENCES.get((operation_class, causal_arm)):
        raise PromotionError("namespace result sequence/step/operation is invalid")


_VALID_TRANSITIONS = {
    ("prepared-post-create-write", "performed", "absent", "present", True, True),
    ("prepared-post-create-write", "performed-unsynced", "absent", "present", False, True),
    ("forward-exchange", "performed", "pre-order", "exchanged-order", True, True),
    ("rollback-exchange", "not-performed", "pre-order", "pre-order", None, False),
    ("prepared-post-cleanup", "performed", "present", "absent", True, True),
    ("prepared-post-cleanup", "performed-unsynced", "present", "absent", False, True),
    ("prepared-post-cleanup", "performed-unsynced", "present", None, False, True),
    ("prepared-post-cleanup", "not-performed", "absent", "absent", True, False),
    ("protected-readback", "exact-pre", "exact-pre", "exact-pre", None, False),
    ("protected-readback", "other", "other", "other", None, False),
    ("protected-readback", "unreadable", "unreadable", "unreadable", None, False),
    ("emergency-reverse", "ambiguous", "exchanged-order", None, None, True),
}


def validate_namespace_backend_transition(
    *, step: str, outcome: str, before_classification: str,
    after_classification: str | None, directory_synced: bool | None,
    possible_mutation: bool,
) -> None:
    candidate = (
        step, outcome, before_classification, after_classification,
        directory_synced, possible_mutation,
    )
    if candidate not in _VALID_TRANSITIONS:
        raise PromotionError("namespace backend transition/outcome/mutation/sync is invalid")


def namespace_result_sequence_disposition(results: Sequence[Mapping[str, str]]) -> str:
    if any(result.get("outcome") == "performed-unsynced" for result in results):
        return "incident-only"
    return "clean"


def classify_namespace_adversary_attempt(attack: str) -> str:
    admitted = {
        "ancestor-rename", "target-name-replacement", "reserved-name-replacement", "incoming-hard-link",
        "write", "truncate", "chmod", "xattr", "preopened-fd-write", "writable-mmap", "dirty-writeback",
        "mount-alias", "unrelated-managed-file-write",
    }
    if attack not in admitted:
        raise PromotionError("namespace adversary class is unknown")
    return "excluded"


def classify_filesystem_witness_change(before: object, after: object) -> str:
    return "exact" if before == after else "other"


def admitted_path_budget_bytes(paths: Sequence[str]) -> int:
    total = 0
    for path in paths:
        if type(path) is not str:
            raise PromotionError("path budget value is invalid")
        total += len(path.encode("utf-8", "strict"))
    if total > 4 * 1024 * 1024:
        raise PromotionError("path budget exceeds the admitted bound")
    return total


def max_json_escaped_path_bytes(raw_utf8_bytes: int) -> int:
    if type(raw_utf8_bytes) is not int or raw_utf8_bytes < 0:
        raise PromotionError("path byte count is invalid")
    return 6 * raw_utf8_bytes


def validate_protected_readback_result(
    result: Mapping[str, Any], state: Mapping[str, Any]
) -> None:
    parsed = ProtectedReadbackState.from_mapping(state)
    if result.get("step") != "protected-readback" or result.get("outcome") != parsed.classification:
        raise PromotionError("protected readback outcome/classification mismatch")
    digest = parsed.digest
    if result.get("beforeWitnessDigest") != digest or result.get("afterWitnessDigest") != digest:
        raise PromotionError("protected readback must bind the complete state digest")


def validate_namespace_evidence_cross_equalities(evidence: Mapping[str, Any]) -> None:
    if not isinstance(evidence, Mapping):
        raise PromotionError("namespace evidence is invalid")
    request_digest = evidence.get("requestDigest")
    receipt = evidence.get("receipt")
    results = evidence.get("backendResults")
    witnesses = evidence.get("stepWitnesses")
    if not isinstance(receipt, Mapping) or receipt.get("leaseRequestDigest") != request_digest:
        raise PromotionError("namespace request/receipt binding mismatch")
    operation = receipt.get("operationClass")
    if not isinstance(results, list) or not isinstance(witnesses, list):
        raise PromotionError("namespace result/step arrays are invalid")
    if any(
        not isinstance(result, Mapping)
        or result.get("leaseRequestDigest") != request_digest
        or result.get("operationClass") != operation
        for result in results
    ):
        raise PromotionError("namespace request/operation result substitution")
    result_steps = [result.get("step") for result in results]
    witness_steps = [witness.get("step") for witness in witnesses if isinstance(witness, Mapping)]
    if result_steps != witness_steps:
        raise PromotionError("namespace result/step witness substitution")
