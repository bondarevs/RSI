from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
import inspect
from typing import Any

import pytest

from task8_support import (
    DIGEST_A,
    DIGEST_B,
    DIGEST_C,
    DIGEST_D,
    canonical_final_lf,
    lazy_module,
    prefixed_digest,
)


PLAN_REF_FIELDS = (
    "experiment_operation_id",
    "reservation_digest",
    "experiment_request_digest",
    "candidate_id",
    "candidate_digest",
    "candidate_full_record_digest",
    "provider_authority_binding_digest",
    "candidate_capture_lineage_binding_digest",
    "candidate_state_binding_digest",
    "provider_contract_digest",
    "provider_version_digest",
    "provider_runtime_identity_digest",
    "provider_execution_identity_digest",
    "verifier_execution_base_identity_digest",
    "namespace_mutation_lease_backend_identity_digest",
    "namespace_mutation_lease_capability_digest",
    "policy_version",
    "policy_artifact_digest",
    "control_plane_digest",
    "task8_control_plane_version",
    "task8_addendum_digest",
    "task8_addendum_markdown_digest",
    "plan_id",
    "plan_digest",
    "validation_attestation_digest",
    "artifact_store_identity_digest",
    "stage_attestation_raw_ref",
    "stage_attestation_raw_digest",
    "hook_attestation_raw_ref",
    "hook_attestation_raw_digest",
)

PLAN_REF_WIRE_FIELDS = tuple(
    {
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
        "namespace_mutation_lease_backend_identity_digest": (
            "namespaceMutationLeaseBackendIdentityDigest"
        ),
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
    }[field]
    for field in PLAN_REF_FIELDS
)


def _promotion():
    return lazy_module("rsi_core.promotion")


def _plan_ref_values() -> dict[str, str]:
    values = {
        field: DIGEST_A
        for field in PLAN_REF_FIELDS
    }
    values.update(
        {
            "experiment_operation_id": "experiment_" + "a" * 32,
            "reservation_digest": DIGEST_A,
            "experiment_request_digest": DIGEST_B,
            "candidate_id": "candidate-1",
            "candidate_digest": DIGEST_B,
            "candidate_full_record_digest": DIGEST_C,
            "provider_authority_binding_digest": DIGEST_C,
            "candidate_state_binding_digest": DIGEST_D,
            "policy_version": "1.0.0",
            "task8_control_plane_version": "1.1.0",
            "plan_id": "plan_" + "b" * 64,
            "stage_attestation_raw_ref": "stage-deployment-attestation.json",
            "hook_attestation_raw_ref": "hook-deployment-attestation.json",
        }
    )
    return values


def _lease_request_mapping() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "domain": "rsi-namespace-mutation-lease-request-v1",
        "transactionId": "tx_" + "a" * 64,
        "planDigest": DIGEST_A,
        "rootIdentityDigest": DIGEST_B,
        "ancestryWitnessDigest": DIGEST_C,
        "artifactParentWitnessDigest": DIGEST_D,
        "managedTreePolicyDigest": DIGEST_A,
        "expectedManifestPreHash": DIGEST_B,
        "expectedManifestPostHash": DIGEST_C,
        "targetName": "SKILL.md",
        "reservedName": ".rsi-promotion-swap-" + "a" * 64,
        "operationClass": "forward-apply",
        "acquisitionNonce": "f" * 64,
        "deadline": "2026-08-09T12:05:00Z",
    }


def _namespace_authority_mapping() -> tuple[dict[str, object], dict[str, object]]:
    backend = {
        "schemaVersion": 1,
        "domain": "rsi-namespace-mutation-lease-backend-v1",
        "backendName": "test-enforcer",
        "backendVersion": "1.0.0",
        "implementationDigest": DIGEST_A,
        "runtimeIdentityDigest": DIGEST_B,
        "configurationDigest": DIGEST_C,
        "leaseSignerKeyId": "test-lease-key",
        "leaseSignerPublicKeyDigest": DIGEST_D,
        "signatureAlgorithm": "platform-attestation-v1",
    }
    capability = {
        "schemaVersion": 1,
        "domain": "rsi-namespace-mutation-lease-capability-v1",
        "backendIdentityDigest": prefixed_digest(backend),
        "capability": "noncooperative-same-uid-namespace-exclusion",
        "scope": "canonical-managed-tree-ancestry-names-and-operand-inodes",
        "atomicAcquire": True,
        "holderDeathReleases": True,
        "enforcerDeathFailClosed": True,
        "liveHolderNeverOutlivesProtection": True,
        "signedCausalResults": True,
        "exchangeCovered": True,
        "reverseCovered": True,
        "unlinkCovered": True,
        "preparedPostCreationAndWriteCovered": True,
        "operandLinkMutationCovered": True,
        "operandContentMutationCovered": True,
        "operandMetadataMutationCovered": True,
        "managedTreeMutationCovered": True,
        "mountAndAliasMutationCovered": True,
        "preopenedHandleMutationCovered": True,
        "writableMmapMutationCovered": True,
        "dirtyWritebackCovered": True,
        "fullManifestReadbackCovered": True,
        "fullVerifierWindowCovered": True,
        "eventCallbackCovered": True,
        "noSilentExpiry": True,
        "backendPerformsMutation": True,
    }
    return backend, capability


def _literal_namespace_graph() -> dict[str, dict[str, Any]]:
    """Independent valid pre-state graph for all literal Task 8 leaf schemas."""

    edge = {
        "schemaVersion": 1,
        "domain": "rsi-ancestry-edge-v1",
        "componentName": "trusted-skill",
        "childRelativePath": "",
        "parentDevice": 9,
        "parentInode": 10,
        "parentType": "directory",
        "parentMode": 0o700,
        "parentUid": 501,
        "parentNlink": 2,
        "childDevice": 9,
        "childInode": 11,
        "childType": "directory",
        "childMode": 0o700,
        "childUid": 501,
        "childNlink": 2,
    }
    ancestry = {
        "schemaVersion": 1,
        "domain": "rsi-ancestry-witness-v1",
        "rootIdentityDigest": DIGEST_A,
        "parentRelativePath": "",
        "edges": [edge],
    }
    ancestry_digest = prefixed_digest(ancestry)
    parent = {
        "schemaVersion": 1,
        "domain": "rsi-artifact-parent-witness-v1",
        "rootIdentityDigest": DIGEST_A,
        "parentRelativePath": "",
        "device": 9,
        "inode": 11,
        "type": "directory",
        "mode": 0o700,
        "uid": 501,
        "nlink": 2,
        "ancestryWitnessDigest": ancestry_digest,
    }
    pre_entry = {
        "type": "regular-file",
        "byteSize": 8,
        "digest": DIGEST_B,
        "executable": False,
    }
    post_entry = {
        "type": "regular-file",
        "byteSize": 9,
        "digest": DIGEST_C,
        "executable": True,
    }
    reserved_name = ".rsi-promotion-swap-" + "a" * 64
    policy = {
        "schemaVersion": 1,
        "domain": "rsi-managed-tree-policy-v1",
        "rootIdentityDigest": DIGEST_A,
        "allowlistEntryDigest": DIGEST_D,
        "artifactRelativePath": "SKILL.md",
        "reservedRelativePath": reserved_name,
        "manifestPreHash": DIGEST_C,
        "manifestPostHash": DIGEST_D,
        "scopeMode": "complete-managed-set-ancestry-names-inodes-and-aliases",
        "members": [
            {
                "relativePath": "SKILL.md",
                "pre": pre_entry,
                "post": post_entry,
            }
        ],
    }
    target = {
        "schemaVersion": 1,
        "domain": "rsi-target-witness-v1",
        "rootIdentityDigest": DIGEST_A,
        "relativePath": "SKILL.md",
        "device": 9,
        "inode": 12,
        "type": "regular-file",
        "mode": 0o600,
        "uid": 501,
        "nlink": 1,
        "size": 8,
        "artifactHash": DIGEST_B,
        "manifestHash": DIGEST_C,
    }
    retained = {
        "schemaVersion": 1,
        "domain": "rsi-retained-name-witness-v1",
        "name": reserved_name,
        "role": "unallocated",
        "classification": "absent",
        "object": None,
    }
    member = {
        "schemaVersion": 1,
        "domain": "rsi-member-metadata-witness-v1",
        "relativePath": "SKILL.md",
        "device": 9,
        "inode": 12,
        "type": "regular-file",
        "mode": 0o600,
        "uid": 501,
        "nlink": 1,
        "size": 8,
        "mtimeNs": 1_000_000_000,
        "ctimeNs": 1_000_000_001,
    }
    view_body = {
        "schemaVersion": 1,
        "domain": "rsi-target-readback-view-body-v1",
        "classification": "exact-pre",
        "target": target,
        "retainedNameWitness": retained,
        "ancestryWitnessDigest": ancestry_digest,
        "memberMetadataWitnesses": [member],
    }
    view = {
        **view_body,
        "domain": "rsi-target-readback-view-v1",
        "scanDigest": prefixed_digest(view_body),
    }
    protected = {
        "schemaVersion": 1,
        "domain": "rsi-namespace-protected-readback-state-v1",
        "classification": "exact-pre",
        "targetReadbackView": view,
        "errorWitness": None,
    }
    request = {
        "schemaVersion": 1,
        "domain": "rsi-namespace-mutation-lease-request-v1",
        "transactionId": "tx_" + "a" * 64,
        "planDigest": DIGEST_B,
        "rootIdentityDigest": DIGEST_A,
        "ancestryWitnessDigest": ancestry_digest,
        "artifactParentWitnessDigest": prefixed_digest(parent),
        "managedTreePolicyDigest": prefixed_digest(policy),
        "expectedManifestPreHash": DIGEST_C,
        "expectedManifestPostHash": DIGEST_D,
        "targetName": "SKILL.md",
        "reservedName": reserved_name,
        "operationClass": "unresolved-terminal",
        "acquisitionNonce": "f" * 64,
        "deadline": "2026-08-09T12:05:00Z",
    }
    scope = {
        "schemaVersion": 1,
        "domain": "rsi-namespace-mutation-scope-v1",
        "ancestryWitness": ancestry,
        "ancestryWitnessDigest": ancestry_digest,
        "artifactParentWitness": parent,
        "artifactParentWitnessDigest": prefixed_digest(parent),
        "managedTreePolicy": policy,
        "managedTreePolicyDigest": prefixed_digest(policy),
    }
    request_digest = prefixed_digest(request)
    backend, capability = _namespace_authority_mapping()
    receipt = {
        "schemaVersion": 1,
        "domain": "rsi-namespace-mutation-lease-receipt-v1",
        "leaseId": "lease_" + request_digest[7:39],
        "leaseRequestDigest": request_digest,
        "backendIdentityDigest": prefixed_digest(backend),
        "capabilityDigest": prefixed_digest(capability),
        "transactionId": request["transactionId"],
        "operationClass": request["operationClass"],
        "acquisitionNonce": request["acquisitionNonce"],
        "issuedAt": "2026-08-09T12:00:00Z",
        "expiresAt": request["deadline"],
        "signatureAlgorithm": "platform-attestation-v1",
        "signature": "base64:YQ==",
    }
    step_witness = {
        "schemaVersion": 1,
        "domain": "rsi-namespace-mutation-step-witness-v1",
        "step": "protected-readback",
        "before": protected,
        "after": protected,
    }
    state_digest = prefixed_digest(protected)
    result = {
        "schemaVersion": 1,
        "domain": "rsi-namespace-mutation-backend-result-v1",
        "leaseId": receipt["leaseId"],
        "leaseRequestDigest": request_digest,
        "backendIdentityDigest": receipt["backendIdentityDigest"],
        "capabilityDigest": receipt["capabilityDigest"],
        "transactionId": request["transactionId"],
        "operationClass": request["operationClass"],
        "step": "protected-readback",
        "outcome": "exact-pre",
        "possibleMutation": False,
        "beforeWitnessDigest": state_digest,
        "afterWitnessDigest": state_digest,
        "directorySynced": None,
        "completedAt": "2026-08-09T12:00:01Z",
        "signatureAlgorithm": "platform-attestation-v1",
        "signature": "base64:YQ==",
    }
    evidence = {
        "schemaVersion": 1,
        "domain": "rsi-namespace-mutation-lease-evidence-v1",
        "request": request,
        "requestDigest": request_digest,
        "scope": scope,
        "scopeDigest": prefixed_digest(scope),
        "receipt": receipt,
        "receiptDigest": prefixed_digest(receipt),
        "backendResults": [result],
        "backendResultsDigest": prefixed_digest([result]),
        "stepWitnesses": [step_witness],
        "stepWitnessesDigest": prefixed_digest([step_witness]),
    }
    return {
        "ancestry_edge": edge,
        "ancestry": ancestry,
        "artifact_parent": parent,
        "managed_policy": policy,
        "target": target,
        "retained_name": retained,
        "member_metadata": member,
        "target_readback": view,
        "protected_readback": protected,
        "lease_request": request,
        "lease_scope": scope,
        "lease_receipt": receipt,
        "backend_result": result,
        "step_witness": step_witness,
        "lease_evidence": evidence,
    }


def test_task8_public_promotion_interface_is_present_and_narrow() -> None:
    module = _promotion()
    assert module.PromotionPlanRef
    assert module.PromotionDecision
    assert module.PromotionService
    parameters = tuple(inspect.signature(module.PromotionService.promote_candidate).parameters)
    assert parameters == ("self", "plan_ref")


def test_builtin_promotion_service_fails_before_apply_without_privileged_namespace_backend() -> None:
    module = _promotion()
    plan_ref = module.PromotionPlanRef(**_plan_ref_values())

    with pytest.raises(module.PromotionError, match="namespace|backend|unavailable"):
        module.PromotionService().promote_candidate(plan_ref)


def test_promotion_service_accepts_only_exact_attested_complete_coordinator_result() -> None:
    module = _promotion()
    values = _plan_ref_values()
    plan_ref = module.PromotionPlanRef(**values)

    class PrivilegedCoordinatorFixture:
        available = True
        task8_backend_kind = "privileged-promotion-coordinator-v1"
        attested_identity_digest = values[
            "namespace_mutation_lease_backend_identity_digest"
        ]
        attested_capability_digest = values[
            "namespace_mutation_lease_capability_digest"
        ]
        complete_task8_protocol = True

        def execute_guarded_promotion(self, admitted):
            assert admitted is plan_ref
            return module.PromotionDecision(
                candidate_id=admitted.candidate_id,
                decision="promoted",
                reason=module.PROMOTION_REASON_V1,
                promotion_plan_digest=admitted.plan_digest,
                validation_attestation_digest=admitted.validation_attestation_digest,
                approval_receipt_ref="transactions/approval.json",
                snapshot_ref="snapshots/pre",
                target_hash_before=DIGEST_A,
                target_hash_after=DIGEST_B,
                artifacts=("references/knowledge.md",),
                verification={
                    "skillValidationPassed": True,
                    "contractValidationPassed": True,
                    "targetTestsPassed": True,
                },
            )

    registry = module.TrustedNamespaceMutationLeaseRegistry(
        {
            values["namespace_mutation_lease_backend_identity_digest"]:
            PrivilegedCoordinatorFixture()
        }
    )
    decision = module.PromotionService(registry).promote_candidate(plan_ref)

    assert decision.decision == "promoted"
    assert decision.promotion_plan_digest == plan_ref.plan_digest


def test_promotion_plan_ref_is_the_exact_deeply_immutable_tuple() -> None:
    module = _promotion()
    values = _plan_ref_values()
    plan_ref = module.PromotionPlanRef(**values)
    assert tuple(
        field for field in plan_ref.__dataclass_fields__ if not field.startswith("_")
    ) == PLAN_REF_FIELDS
    assert tuple(plan_ref.to_mapping()) == PLAN_REF_WIRE_FIELDS
    with pytest.raises((FrozenInstanceError, AttributeError)):
        plan_ref.plan_digest = DIGEST_D
    with pytest.raises(TypeError):
        module.PromotionPlanRef(**values, extra_field="forbidden")


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("reservation_digest", "experiment_request_digest"),
        ("candidate_digest", "candidate_full_record_digest"),
        ("provider_authority_binding_digest", "candidate_state_binding_digest"),
    ],
)
def test_plan_ref_rejects_collapsed_independent_authority_digests(
    left: str, right: str
) -> None:
    module = _promotion()
    values = _plan_ref_values()
    values[right] = values[left]
    with pytest.raises(module.PromotionError, match="digest|authority|distinct"):
        module.PromotionPlanRef(**values)


def test_namespace_lease_request_has_exact_canonical_schema_and_digest() -> None:
    module = _promotion()
    mapping = _lease_request_mapping()
    request = module.NamespaceMutationLeaseRequest.from_mapping(mapping)
    assert request.canonical_bytes == canonical_final_lf(mapping)
    assert request.digest == prefixed_digest(mapping)
    assert request.acquisition_nonce == "f" * 64


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: {**value, "extra": True},
        lambda value: {**value, "schemaVersion": True},
        lambda value: {**value, "targetName": "../SKILL.md"},
        lambda value: {**value, "operationClass": "caller-mutate"},
        lambda value: {**value, "acquisitionNonce": "0" * 62},
    ],
)
def test_namespace_lease_request_rejects_open_or_ambiguous_inputs(mutation) -> None:
    module = _promotion()
    with pytest.raises(module.PromotionError):
        module.NamespaceMutationLeaseRequest.from_mapping(mutation(_lease_request_mapping()))


def test_namespace_lease_operation_class_enum_is_exact_and_closed() -> None:
    module = _promotion()
    expected = (
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
    assert tuple(module.NAMESPACE_MUTATION_OPERATION_CLASSES) == expected
    for operation_class in expected:
        request = _lease_request_mapping()
        request["operationClass"] = operation_class
        module.NamespaceMutationLeaseRequest.from_mapping(request)


def test_task8_sidecar_caps_are_exact_and_publicly_shared() -> None:
    module = _promotion()
    assert module.MAX_EVENT_LINE_BYTES == 64 * 1024
    assert module.MAX_RESOLUTION_READBACK_BYTES == 144 * 1024 * 1024
    assert module.MAX_TASK8_SIDECAR_BYTES == 200 * 1024 * 1024


def test_promotion_reason_is_a_single_fixed_schema_v1_constant() -> None:
    module = _promotion()
    assert module.PROMOTION_REASON_V1 == "Verified additive knowledge with passing validation"


@pytest.mark.parametrize(
    ("class_name", "fixture_name"),
    [
        ("AncestryEdge", "ancestry_edge"),
        ("AncestryWitness", "ancestry"),
        ("ArtifactParentWitness", "artifact_parent"),
        ("ManagedTreePolicy", "managed_policy"),
        ("TargetWitness", "target"),
        ("RetainedNameWitness", "retained_name"),
        ("MemberMetadataWitness", "member_metadata"),
        ("TargetReadbackView", "target_readback"),
        ("ProtectedReadbackState", "protected_readback"),
        ("NamespaceMutationLeaseRequest", "lease_request"),
        ("NamespaceMutationScope", "lease_scope"),
        ("NamespaceMutationLeaseReceipt", "lease_receipt"),
        ("NamespaceMutationBackendResult", "backend_result"),
        ("NamespaceMutationStepWitness", "step_witness"),
        ("NamespaceMutationLeaseEvidence", "lease_evidence"),
    ],
)
def test_literal_namespace_models_round_trip_only_their_exact_cfl_schema(
    class_name: str, fixture_name: str
) -> None:
    module = _promotion()
    mapping = _literal_namespace_graph()[fixture_name]
    model = getattr(module, class_name).from_mapping(mapping)
    assert model.to_mapping() == mapping
    assert model.canonical_bytes == canonical_final_lf(mapping)
    assert model.digest == prefixed_digest(mapping)


def test_namespace_backend_identity_and_capability_have_literal_closed_keys() -> None:
    module = _promotion()
    backend, capability = _namespace_authority_mapping()
    parsed_backend = module.NamespaceMutationLeaseBackendIdentity.from_mapping(backend)
    parsed_capability = module.NamespaceMutationLeaseCapability.from_mapping(capability)
    assert parsed_backend.to_mapping() == backend
    assert parsed_capability.to_mapping() == capability
    assert parsed_backend.digest == prefixed_digest(backend)
    assert parsed_capability.digest == prefixed_digest(capability)


@pytest.mark.parametrize(
    "field",
    [
        "holderDeathReleases",
        "enforcerDeathFailClosed",
        "liveHolderNeverOutlivesProtection",
        "signedCausalResults",
        "preopenedHandleMutationCovered",
        "writableMmapMutationCovered",
        "dirtyWritebackCovered",
        "fullManifestReadbackCovered",
        "fullVerifierWindowCovered",
        "eventCallbackCovered",
        "noSilentExpiry",
        "backendPerformsMutation",
    ],
)
def test_namespace_capability_rejects_each_missing_or_false_security_claim(
    field: str,
) -> None:
    module = _promotion()
    _, capability = _namespace_authority_mapping()
    capability[field] = False
    with pytest.raises(module.PromotionError, match="capability|true|lease"):
        module.NamespaceMutationLeaseCapability.from_mapping(capability)


def test_scope_embeds_complete_preimages_and_recomputes_all_adjacent_digests() -> None:
    module = _promotion()
    graph = _literal_namespace_graph()
    scope = graph["lease_scope"]
    parsed = module.NamespaceMutationScope.from_mapping(scope)
    assert parsed.digest == prefixed_digest(scope)
    assert scope["ancestryWitnessDigest"] == prefixed_digest(scope["ancestryWitness"])
    assert scope["artifactParentWitnessDigest"] == prefixed_digest(
        scope["artifactParentWitness"]
    )
    assert scope["managedTreePolicyDigest"] == prefixed_digest(
        scope["managedTreePolicy"]
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda scope: scope.update(extra=True),
        lambda scope: scope.update(ancestryWitnessDigest=DIGEST_D),
        lambda scope: scope["artifactParentWitness"].update(inode=999),
        lambda scope: scope["managedTreePolicy"].update(rootIdentityDigest=DIGEST_D),
    ],
)
def test_scope_rejects_digest_only_extra_or_cross_preimage_substitution(mutation) -> None:
    module = _promotion()
    scope = deepcopy(_literal_namespace_graph()["lease_scope"])
    mutation(scope)
    with pytest.raises(module.PromotionError, match="scope|digest|witness|policy"):
        module.NamespaceMutationScope.from_mapping(scope)


def test_artifact_parent_relations_are_fieldwise_not_request_field_aliases() -> None:
    module = _promotion()
    graph = _literal_namespace_graph()
    request = graph["lease_request"]
    scope = graph["lease_scope"]
    assert "parentRelativePath" not in request
    module.validate_namespace_scope_request_binding(request, scope)

    changed = deepcopy(scope)
    changed["artifactParentWitness"]["parentRelativePath"] = "nested"
    changed["artifactParentWitnessDigest"] = prefixed_digest(
        changed["artifactParentWitness"]
    )
    with pytest.raises(module.PromotionError, match="parent|path|ancestry"):
        module.validate_namespace_scope_request_binding(request, changed)


def test_managed_policy_projects_task7_entries_fieldwise_without_path_aliasing() -> None:
    module = _promotion()
    policy = _literal_namespace_graph()["managed_policy"]
    pre_manifest = [
        {
            "path": "SKILL.md",
            "type": "regular-file",
            "byteSize": 8,
            "digest": DIGEST_B,
            "executable": False,
        }
    ]
    post_manifest = [
        {
            "path": "SKILL.md",
            "type": "regular-file",
            "byteSize": 9,
            "digest": DIGEST_C,
            "executable": True,
        }
    ]
    module.validate_managed_tree_policy_projection(policy, pre_manifest, post_manifest)
    assert "path" not in policy["members"][0]["pre"]
    assert "path" not in policy["members"][0]["post"]

    invalid = deepcopy(policy)
    invalid["members"][0]["pre"] = pre_manifest[0]
    with pytest.raises(module.PromotionError, match="policy|projection|path"):
        module.validate_managed_tree_policy_projection(
            invalid, pre_manifest, post_manifest
        )


def test_target_and_member_projection_uses_only_defined_common_live_fields() -> None:
    module = _promotion()
    graph = _literal_namespace_graph()
    target = graph["target"]
    member = graph["member_metadata"]
    assert "executable" not in target
    module.validate_target_member_projection(target, member)

    invalid_target = {**target, "executable": False}
    with pytest.raises(module.PromotionError, match="target|executable|field"):
        module.TargetWitness.from_mapping(invalid_target)


def test_target_readback_scan_digest_is_acyclic_and_excludes_itself() -> None:
    module = _promotion()
    view = _literal_namespace_graph()["target_readback"]
    body = {
        "schemaVersion": view["schemaVersion"],
        "domain": "rsi-target-readback-view-body-v1",
        "classification": view["classification"],
        "target": view["target"],
        "retainedNameWitness": view["retainedNameWitness"],
        "ancestryWitnessDigest": view["ancestryWitnessDigest"],
        "memberMetadataWitnesses": view["memberMetadataWitnesses"],
    }
    assert view["scanDigest"] == prefixed_digest(body)
    parsed = module.TargetReadbackView.from_mapping(view)
    assert parsed.scan_digest == prefixed_digest(body)

    recursive = deepcopy(view)
    recursive["scanDigest"] = prefixed_digest(view)
    with pytest.raises(module.PromotionError, match="scan|digest|body"):
        module.TargetReadbackView.from_mapping(recursive)


def _verifier_graph() -> dict[str, dict[str, Any]]:
    graph = _literal_namespace_graph()
    target = {
        **graph["target"],
        "inode": 13,
        "mode": 0o700,
        "size": 9,
        "artifactHash": DIGEST_C,
        "manifestHash": DIGEST_D,
    }
    retained = {
        **graph["retained_name"],
        "role": "retained-preimage",
        "classification": "present",
        "object": {
            "device": 9,
            "inode": 12,
            "type": "regular",
            "mode": 0o600,
            "uid": 501,
            "nlink": 1,
            "size": 8,
            "sha256": DIGEST_B,
        },
    }
    applied_readback = {
        "schemaVersion": 1,
        "domain": "rsi-applied-target-readback-v1",
        "transactionId": "tx_" + "a" * 64,
        "planDigest": DIGEST_A,
        "target": target,
        "retainedPreimage": retained,
        "artifactHash": DIGEST_C,
        "manifestHash": DIGEST_D,
        "directorySynced": True,
    }
    core = {
        "schemaVersion": 1,
        "domain": "rsi-live-verifier-request-core-v1",
        "transactionId": applied_readback["transactionId"],
        "runId": "run_promote_" + "b" * 64,
        "planDigest": applied_readback["planDigest"],
        "verifiedPostReadbackDigest": prefixed_digest(applied_readback),
        "validationAttestationDigest": DIGEST_B,
        "verifierExecutionBaseIdentityDigest": DIGEST_C,
        "controlPlaneDigest": DIGEST_D,
        "verifierInvocationNonce": "e" * 64,
        "expiresAt": "2026-08-09T12:05:00Z",
    }
    request = {
        "schemaVersion": 1,
        "domain": "rsi-live-verifier-request-v1",
        "core": core,
        "verifierRequestCoreDigest": prefixed_digest(core),
        "applyCompletedEventId": "evt_" + "c" * 64,
        "applyCompletedEventDigest": DIGEST_A,
        "applyReadbackRef": (
            "transactions/"
            + core["transactionId"]
            + "-readback-"
            + "d" * 64
            + ".json"
        ),
        "applyReadbackDigest": DIGEST_D,
    }
    request_digest = prefixed_digest(request)
    receipt = {
        "schemaVersion": 1,
        "domain": "rsi-live-verifier-receipt-v1",
        "kind": "verifier-receipt",
        "verifierRequestDigest": request_digest,
        "receiptSignerKeyId": "test-verifier-key",
        "signatureAlgorithm": "platform-attestation-v1",
        "issuedAt": "2026-08-09T12:00:02Z",
        "liveReadback": {
            "artifactHash": DIGEST_C,
            "manifestHash": DIGEST_D,
            "targetWitnessDigest": prefixed_digest(target),
            "ancestryWitnessDigest": prefixed_digest(graph["ancestry"]),
        },
        "tests": {
            "skillValidationPassed": True,
            "contractValidationPassed": True,
            "targetTestsPassed": True,
        },
        "attestationMatch": True,
        "result": "passed",
        "signature": "base64:YQ==",
    }
    nonissuance = {
        "schemaVersion": 1,
        "domain": "rsi-verifier-non-issuance-evidence-v1",
        "verifierRequestDigest": request_digest,
        "receiptSignerKeyId": "test-verifier-key",
        "receiptSignerPublicKeyDigest": DIGEST_A,
        "receiptSignerCapabilityDigest": DIGEST_B,
        "receiptRef": (
            "transactions/"
            + request["core"]["transactionId"]
            + "-verifier-"
            + request_digest[7:]
            + ".json"
        ),
        "receiptPathAbsent": True,
        "result": "not-issued",
        "code": "timeout",
        "completedAt": "2026-08-09T12:00:03Z",
        "signatureAlgorithm": "platform-attestation-v1",
        "signature": "base64:YQ==",
    }
    return {
        "applied_readback": applied_readback,
        "core": core,
        "request": request,
        "receipt": receipt,
        "nonissuance": nonissuance,
    }


@pytest.mark.parametrize(
    ("class_name", "fixture_name"),
    [
        ("VerifierRequestCore", "core"),
        ("VerifierRequest", "request"),
        ("VerifierReceipt", "receipt"),
        ("VerifierNonIssuanceEvidence", "nonissuance"),
    ],
)
def test_verifier_authority_models_use_literal_nonrecursive_cfl_schemas(
    class_name: str, fixture_name: str
) -> None:
    module = _promotion()
    mapping = _verifier_graph()[fixture_name]
    model = getattr(module, class_name).from_mapping(mapping)
    assert model.to_mapping() == mapping
    assert model.canonical_bytes == canonical_final_lf(mapping)
    assert model.digest == prefixed_digest(mapping)


def test_verifier_request_transitively_binds_nonce_core_applied_event_and_sidecar() -> None:
    module = _promotion()
    graph = _verifier_graph()
    request = graph["request"]
    module.validate_verifier_request_binding(
        request,
        applied_readback=graph["applied_readback"],
        expected_nonce="e" * 64,
        apply_completed_event_id=request["applyCompletedEventId"],
        apply_completed_event_digest=request["applyCompletedEventDigest"],
        apply_readback_ref=request["applyReadbackRef"],
        apply_readback_digest=request["applyReadbackDigest"],
    )

    substituted = deepcopy(request)
    substituted["core"]["verifierInvocationNonce"] = "f" * 64
    with pytest.raises(module.PromotionError, match="nonce|core|digest"):
        module.validate_verifier_request_binding(
            substituted,
            applied_readback=graph["applied_readback"],
            expected_nonce="e" * 64,
            apply_completed_event_id=request["applyCompletedEventId"],
            apply_completed_event_digest=request["applyCompletedEventDigest"],
            apply_readback_ref=request["applyReadbackRef"],
            apply_readback_digest=request["applyReadbackDigest"],
        )


def test_verifier_receipt_result_is_the_exact_conjunction() -> None:
    module = _promotion()
    receipt = _verifier_graph()["receipt"]
    module.VerifierReceipt.from_mapping(receipt)
    for field in receipt["tests"]:
        changed = deepcopy(receipt)
        changed["tests"][field] = False
        with pytest.raises(module.PromotionError, match="result|test|conjunction"):
            module.VerifierReceipt.from_mapping(changed)

    changed = deepcopy(receipt)
    changed["attestationMatch"] = False
    with pytest.raises(module.PromotionError, match="result|attestation|conjunction"):
        module.VerifierReceipt.from_mapping(changed)


def test_verifier_commitment_has_exact_committed_and_not_reached_five_key_arms() -> None:
    module = _promotion()
    core = _verifier_graph()["core"]
    committed = {
        "state": "committed",
        "verifierInvocationNonce": core["verifierInvocationNonce"],
        "verifierRequestCoreDigest": prefixed_digest(core),
        "verifierExecutionBaseIdentityDigest": core[
            "verifierExecutionBaseIdentityDigest"
        ],
        "controlPlaneDigest": core["controlPlaneDigest"],
    }
    not_reached = {
        "state": "not-reached",
        "verifierInvocationNonce": None,
        "verifierRequestCoreDigest": None,
        "verifierExecutionBaseIdentityDigest": None,
        "controlPlaneDigest": None,
    }
    assert module.VerifierCommitment.from_mapping(committed).to_mapping() == committed
    assert (
        module.VerifierCommitment.from_mapping(not_reached).to_mapping()
        == not_reached
    )
    with pytest.raises(module.PromotionError, match="commitment|state|null"):
        module.VerifierCommitment.from_mapping(
            {**not_reached, "verifierInvocationNonce": "f" * 64}
        )


def test_live_verifier_receipt_binding_is_only_present_or_signed_unavailable() -> None:
    module = _promotion()
    graph = _verifier_graph()
    receipt_digest = prefixed_digest(graph["receipt"])
    present = {
        "availability": "present",
        "ref": "transactions/"
        + graph["request"]["core"]["transactionId"]
        + "-verifier-"
        + prefixed_digest(graph["request"])[7:]
        + ".json",
        "digest": receipt_digest,
        "errorCode": None,
        "nonIssuanceEvidence": None,
    }
    unavailable = {
        "availability": "unavailable",
        "ref": None,
        "digest": None,
        "errorCode": "timeout",
        "nonIssuanceEvidence": graph["nonissuance"],
    }
    assert (
        module.VerifierReceiptAvailability.from_mapping(present).to_mapping()
        == present
    )
    assert (
        module.VerifierReceiptAvailability.from_mapping(unavailable).to_mapping()
        == unavailable
    )

    unknown = {**unavailable, "availability": "unknown"}
    with pytest.raises(module.PromotionError, match="availability|unknown|receipt"):
        module.VerifierReceiptAvailability.from_mapping(unknown)
    mixed = {**unavailable, "ref": present["ref"]}
    with pytest.raises(module.PromotionError, match="availability|ref|null"):
        module.VerifierReceiptAvailability.from_mapping(mixed)


def test_signed_nonissuance_and_receipt_are_mutually_exclusive_terminal_results() -> None:
    module = _promotion()
    graph = _verifier_graph()
    with pytest.raises(module.PromotionError, match="terminal|receipt|non.issuance"):
        module.validate_verifier_terminal_pair(
            request=graph["request"],
            receipt=graph["receipt"],
            nonissuance=graph["nonissuance"],
            receipt_path_absent=False,
        )


def test_namespace_evidence_is_embedded_once_and_nested_relations_are_digest_only() -> None:
    module = _promotion()
    evidence = _literal_namespace_graph()["lease_evidence"]
    evidence_digest = prefixed_digest(evidence)
    document = {
        "namespaceMutationLeaseEvidence": evidence,
        "cleanup": {"namespaceMutationLeaseEvidenceDigest": evidence_digest},
        "exchangeWitness": None,
    }
    module.validate_namespace_evidence_placement(document, require_complete=True)

    duplicated = deepcopy(document)
    duplicated["cleanup"]["namespaceMutationLeaseEvidence"] = evidence
    with pytest.raises(module.PromotionError, match="sole|nested|evidence"):
        module.validate_namespace_evidence_placement(duplicated, require_complete=True)

    mismatched = deepcopy(document)
    mismatched["cleanup"]["namespaceMutationLeaseEvidenceDigest"] = DIGEST_D
    with pytest.raises(module.PromotionError, match="digest|evidence"):
        module.validate_namespace_evidence_placement(mismatched, require_complete=True)


def test_historical_lease_evidence_survives_expiry_but_cannot_authorize_new_step() -> None:
    module = _promotion()
    timestamps = {
        "issuedAt": "2026-08-09T12:00:00Z",
        "completedAt": "2026-08-09T12:00:01Z",
        "expiresAt": "2026-08-09T12:05:00Z",
    }
    module.validate_namespace_lease_time_window(
        **timestamps,
        observed_at="2027-01-01T00:00:00Z",
        causal_event_bound=True,
        authorize_new_step=False,
    )
    with pytest.raises(module.PromotionError, match="expired|live|fresh"):
        module.validate_namespace_lease_time_window(
            **timestamps,
            observed_at="2027-01-01T00:00:00Z",
            causal_event_bound=True,
            authorize_new_step=True,
        )


def _size_vector(
    kind: str,
    *,
    path_budget: int,
    members: int,
    readbacks: int,
    evidence: int,
    envelope: int,
) -> dict[str, object]:
    return {
        "kind": kind,
        "pathBudgetBytes": path_budget,
        "memberCount": members,
        "protectedReadbackCount": readbacks,
        "evidenceAndFramingBytes": evidence,
        "outerEnvelopeBytes": envelope,
    }


def test_general_sidecar_preflight_formula_reaches_exact_200_mib_closed_maximum() -> None:
    module = _promotion()
    mib = 1024 * 1024
    vector = _size_vector(
        "incident-record",
        path_budget=4 * mib,
        members=4096,
        readbacks=2,
        evidence=16 * mib,
        envelope=16 * mib,
    )
    expected = 6 * (4 * mib) * 5 + 2048 * 4096 * 6 + 16 * mib + 16 * mib
    assert expected == 200 * mib
    assert module.compute_task8_preflight_bound(vector) == expected
    assert module.task8_sidecar_cap("incident-record") == 200 * mib


def test_resolution_preflight_formula_reaches_exact_144_mib_specialized_cap() -> None:
    module = _promotion()
    mib = 1024 * 1024
    vector = _size_vector(
        "resolution-readback",
        path_budget=4 * mib,
        members=4096,
        readbacks=1,
        evidence=8 * mib,
        envelope=8 * mib,
    )
    expected = 6 * (4 * mib) * 4 + 2048 * 4096 * 4 + 8 * mib + 8 * mib
    assert expected == 144 * mib
    assert module.compute_task8_preflight_bound(vector) == expected
    assert module.task8_sidecar_cap("resolution-readback") == 144 * mib


def test_verifier_receipt_vector_is_fixed_at_64_kib() -> None:
    module = _promotion()
    vector = _size_vector(
        "verifier-receipt",
        path_budget=0,
        members=0,
        readbacks=0,
        evidence=48 * 1024,
        envelope=16 * 1024,
    )
    assert module.compute_task8_preflight_bound(vector) == 64 * 1024
    assert module.task8_sidecar_cap("verifier-receipt") == 64 * 1024


def test_preapply_admission_uses_worst_case_not_a_fictional_future_exact_length() -> None:
    module = _promotion()
    vector = _size_vector(
        "apply-readback",
        path_budget=1024,
        members=2,
        readbacks=1,
        evidence=4096,
        envelope=4096,
    )
    bound = module.admit_task8_sidecar_preflight(vector)
    assert bound == 6 * 1024 * 3 + 2048 * 2 * 4 + 4096 + 4096
    with pytest.raises((TypeError, module.PromotionError), match="exact|future|preflight"):
        module.admit_task8_sidecar_preflight(vector, exact_length=1)


@pytest.mark.parametrize(
    "pipeline_stage",
    [
        "allocation",
        "write",
        "fstat",
        "read",
        "parse",
        "readback",
        "replay",
        "downstream",
    ],
)
def test_complete_sidecar_enforces_same_exact_length_bound_at_every_stage(
    pipeline_stage: str,
) -> None:
    module = _promotion()
    vector = _size_vector(
        "transaction-decision",
        path_budget=64,
        members=1,
        readbacks=1,
        evidence=1024,
        envelope=1024,
    )
    bound = module.compute_task8_preflight_bound(vector)
    assert module.validate_task8_document_length(
        vector, exact_length=bound, pipeline_stage=pipeline_stage
    ) == bound
    with pytest.raises(module.PromotionError, match="length|bound|cap"):
        module.validate_task8_document_length(
            vector, exact_length=bound + 1, pipeline_stage=pipeline_stage
        )


def test_size_vector_rejects_unreachable_counts_boolean_integers_and_unknown_kind() -> None:
    module = _promotion()
    base = _size_vector(
        "apply-readback",
        path_budget=1,
        members=1,
        readbacks=1,
        evidence=1,
        envelope=1,
    )
    invalid = [
        {**base, "pathBudgetBytes": 4 * 1024 * 1024 + 1},
        {**base, "memberCount": 4097},
        {**base, "protectedReadbackCount": 3},
        {**base, "memberCount": True},
        {**base, "kind": "caller-sidecar"},
        {**base, "extra": 1},
    ]
    for vector in invalid:
        with pytest.raises(module.PromotionError, match="vector|bound|kind|integer"):
            module.compute_task8_preflight_bound(vector)


COMMON_SIDECAR_FIELDS = (
    "schemaVersion",
    "kind",
    "transactionId",
    "runId",
    "planDigest",
    "eventBinding",
)


TASK8_SIDECAR_FIELDS = {
    "provider-snapshot": COMMON_SIDECAR_FIELDS
    + (
        "originRef",
        "originDigest",
        "providerIdentity",
        "candidateFullRecordDigest",
        "providerAuthorityBindingDigest",
        "task7CandidateBindingDigest",
        "candidateCaptureLineageBindingDigest",
        "candidateStateBindingDigest",
        "snapshot",
        "targetPre",
    ),
    "apply-intent": COMMON_SIDECAR_FIELDS
    + (
        "originRef",
        "originDigest",
        "snapshotRef",
        "snapshotDigest",
        "candidateFullRecordDigest",
        "providerAuthorityBindingDigest",
        "task7CandidateBindingDigest",
        "candidateCaptureLineageBindingDigest",
        "candidateStateBindingDigest",
        "providerGuardDigest",
        "target",
        "artifact",
        "manifestPreHash",
        "manifestPostHash",
        "postImageRef",
        "postImageDigest",
        "retainedPreimageName",
        "snapshotOperationId",
        "resolveOperationId",
        "verifierInvocationNonce",
        "verifierExecutionBaseIdentityDigest",
        "namespaceMutationLeaseBackendIdentityDigest",
        "namespaceMutationLeaseCapabilityDigest",
        "controlPlaneDigest",
        "expiresAt",
    ),
    "apply-readback": COMMON_SIDECAR_FIELDS
    + (
        "intentRef",
        "intentDigest",
        "outcome",
        "reasonCode",
        "target",
        "retainedPreimage",
        "preparedPostDisposition",
        "preparedPost",
        "cleanup",
        "artifactHash",
        "manifestHash",
        "directorySynced",
        "namespaceMutationLeaseEvidence",
        "verifiedPostReadbackDigest",
        "verifierCommitment",
        "candidateFullRecordDigest",
        "providerAuthorityBindingDigest",
        "task7CandidateBindingDigest",
        "candidateCaptureLineageBindingDigest",
        "candidateStateBindingDigest",
    ),
    "live-verification": COMMON_SIDECAR_FIELDS
    + (
        "readbackRef",
        "readbackDigest",
        "outcome",
        "reasonCode",
        "verifierReceipt",
        "liveReadback",
        "tests",
        "attestationMatch",
        "target",
        "retainedPreimage",
        "verifierExecutionBaseIdentityDigest",
        "verifierInvocationNonce",
        "verifierRequestDigest",
        "controlPlaneDigest",
        "namespaceMutationLeaseEvidence",
        "candidateFullRecordDigest",
        "providerAuthorityBindingDigest",
        "task7CandidateBindingDigest",
        "candidateCaptureLineageBindingDigest",
        "candidateStateBindingDigest",
    ),
    "rollback-readback": COMMON_SIDECAR_FIELDS
    + (
        "intentRef",
        "intentDigest",
        "readbackRef",
        "readbackDigest",
        "verificationRef",
        "verificationDigest",
        "providerFullRecordDigest",
        "providerAuthorityBindingDigest",
        "task7CandidateBindingDigest",
        "candidateCaptureLineageBindingDigest",
        "candidateStateBindingDigest",
        "beforeTarget",
        "afterTarget",
        "retainedPreimage",
        "displacedPost",
        "cleanup",
        "namespaceMutationLeaseEvidence",
    ),
    "resolution-readback": (
        "schemaVersion",
        "kind",
        "transactionId",
        "runId",
        "planDigest",
        "eventBinding",
        "verificationRef",
        "verificationDigest",
        "providerOperationId",
        "resolutionId",
        "providerResolutionRequestDigest",
        "providerResolutionRecord",
        "candidateFullRecordBeforeDigest",
        "providerAuthorityBindingBeforeDigest",
        "task7CandidateBindingDigest",
        "candidateCaptureLineageBindingDigest",
        "candidateStateBindingBeforeDigest",
        "candidateFullRecordAfterDigest",
        "providerAuthorityBindingAfterDigest",
        "candidateStateBindingAfterDigest",
        "providerResolutionRecordDigest",
        "target",
        "retainedPreimage",
        "namespaceMutationLeaseEvidence",
    ),
}


@pytest.mark.parametrize("kind", tuple(TASK8_SIDECAR_FIELDS))
def test_transaction_sidecar_kind_has_one_exact_closed_top_level_schema(kind: str) -> None:
    module = _promotion()
    assert set(module.task8_sidecar_fields(kind)) == set(TASK8_SIDECAR_FIELDS[kind])
    assert len(TASK8_SIDECAR_FIELDS[kind]) == len(set(TASK8_SIDECAR_FIELDS[kind]))


def test_decision_clean_and_incident_arms_each_have_exactly_19_opposite_keys() -> None:
    module = _promotion()
    clean = COMMON_SIDECAR_FIELDS + (
        "outcome",
        "terminalReasonCode",
        "closeStatus",
        "terminalEventId",
        "terminalEvidenceRef",
        "terminalEvidenceDigest",
        "targetDisposition",
        "target",
        "providerStateDigest",
        "cleanup",
        "latchAbsent",
        "promotionDecision",
        "namespaceMutationLeaseEvidence",
    )
    incident = COMMON_SIDECAR_FIELDS + (
        "outcome",
        "terminalReasonCode",
        "closeStatus",
        "terminalEventId",
        "terminalEvidenceRef",
        "terminalEvidenceDigest",
        "targetDisposition",
        "targetWitness",
        "providerStateDigest",
        "cleanup",
        "latchAbsent",
        "promotionDecision",
        "incidentClosure",
    )
    assert len(clean) == len(incident) == 19
    assert set(module.task8_sidecar_fields("transaction-decision", arm="clean")) == set(
        clean
    )
    assert set(
        module.task8_sidecar_fields("transaction-decision", arm="incident")
    ) == set(incident)
    assert "targetWitness" not in clean and "target" not in incident
    assert "incidentClosure" not in clean
    assert "namespaceMutationLeaseEvidence" not in incident


def test_incident_record_is_the_exact_24_key_acyclic_schema() -> None:
    module = _promotion()
    fields = (
        "schemaVersion",
        "kind",
        "transactionId",
        "runId",
        "planDigest",
        "eventBinding",
        "incidentId",
        "reasonCode",
        "rootIdentityDigest",
        "artifactPath",
        "expectedPreHash",
        "expectedPostHash",
        "intentDigest",
        "lastDurableEventId",
        "targetWitness",
        "providerWitness",
        "verifierWitness",
        "reservedNameWitness",
        "ancestryWitness",
        "exchangeWitness",
        "phaseWitness",
        "namespaceMutationLeaseEvidence",
        "quarantineTargets",
        "requiresOperatorAction",
    )
    assert len(fields) == 24
    assert set(module.task8_sidecar_fields("incident-record")) == set(fields)
    assert not {
        "incidentDigest",
        "quarantineRef",
        "quarantineDigest",
        "latchRef",
        "latchDigest",
    }.intersection(fields)


def test_promotion_decision_is_exact_section_12_11_shape_and_immutable() -> None:
    module = _promotion()
    mapping = {
        "candidateId": "candidate-1",
        "decision": "promoted",
        "reason": "Verified additive knowledge with passing validation",
        "promotionPlanDigest": DIGEST_A,
        "validationAttestationDigest": DIGEST_B,
        "approvalReceiptRef": None,
        "snapshotRef": "snapshot:test",
        "targetHashBefore": DIGEST_C,
        "targetHashAfter": DIGEST_D,
        "artifacts": ["references/validation.md"],
        "verification": {
            "skillValidationPassed": True,
            "contractValidationPassed": True,
            "targetTestsPassed": True,
        },
    }
    decision = module.PromotionDecision.from_mapping(mapping)
    assert decision.to_mapping() == mapping
    with pytest.raises((FrozenInstanceError, AttributeError)):
        decision.reason = "caller text"
    with pytest.raises(module.PromotionError, match="field|decision|schema"):
        module.PromotionDecision.from_mapping({**mapping, "cleanup": True})
