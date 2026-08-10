from __future__ import annotations

import base64
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import importlib
import json
from pathlib import Path
from typing import Mapping

import pytest


KEY = b"test-only-host-attestation-key"
ZERO_DIGEST = "sha256:" + "0" * 64
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
DIGEST_E = "sha256:" + "e" * 64


def _attestations():
    # Dynamic import makes the initial missing-feature run a genuine failed
    # test instead of aborting collection.
    return importlib.import_module("rsi_core.attestations")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _forge_model(value: object, **changes: object):
    """Bypass a public dataclass constructor to exercise verifier re-admission."""
    forged = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(
            forged,
            field.name,
            changes.get(field.name, getattr(value, field.name)),
        )
    return forged


def _sign(body: Mapping[str, object], *, key: bytes = KEY) -> str:
    body_digest = "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()
    signature = hmac.new(key, body_digest.encode("ascii"), hashlib.sha256).digest()
    return "base64:" + base64.b64encode(signature).decode("ascii")


def _encoded(body: Mapping[str, object], *, key: bytes = KEY) -> bytes:
    return _canonical({**body, "signature": _sign(body, key=key)})


def _times() -> tuple[datetime, str, str]:
    now = datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc)
    return now, "2026-08-09T11:59:00Z", "2026-08-09T12:09:00Z"


def _rollout_body(
    *,
    attestation_id: str = "deploy_stage_1",
    predecessor: str = DIGEST_E,
    created_at: str | None = None,
    expires_at: str | None = None,
    provider_contract: str = DIGEST_C,
    provider_version: str = DIGEST_D,
    allowed_targets: list[str] | None = None,
) -> dict[str, object]:
    _, default_created, default_expires = _times()
    return {
        "schemaVersion": 1,
        "attestationId": attestation_id,
        "attestationType": "rollout-stage",
        "issuer": "trusted-deployment-controller:prod",
        "subject": {
            "rsiPackageDigest": DIGEST_A,
            "rolloutManifestDigest": DIGEST_B,
            "stageId": "stage-3",
            "providerContractDigest": provider_contract,
            "providerVersionDigest": provider_version,
        },
        "scope": {
            "mode": "promote-safe",
            "environmentIdentityDigest": DIGEST_A,
            "allowedTargetEntryDigests": allowed_targets or [DIGEST_B],
        },
        "predecessorAttestationDigest": predecessor,
        "createdAt": created_at or default_created,
        "expiresAt": expires_at or default_expires,
        "signatureAlgorithm": "platform-attestation-v1",
    }


def _hook_body(
    *,
    attestation_id: str = "deploy_hook_1",
    predecessor: str = DIGEST_D,
) -> dict[str, object]:
    _, created, expires = _times()
    return {
        "schemaVersion": 1,
        "attestationId": attestation_id,
        "attestationType": "orchestration-hook",
        "issuer": "trusted-deployment-controller:prod",
        "subject": {
            "rsiPackageDigest": DIGEST_A,
            "rolloutManifestDigest": DIGEST_B,
            "hookId": "coordinated-v1",
            "providerContractDigest": DIGEST_C,
            "providerVersionDigest": DIGEST_D,
        },
        "scope": {
            "hookMode": "coordinated",
            "environmentIdentityDigest": DIGEST_A,
            "allowedTargetEntryDigests": [DIGEST_B],
        },
        "predecessorAttestationDigest": predecessor,
        "createdAt": created,
        "expiresAt": expires,
        "signatureAlgorithm": "platform-attestation-v1",
    }


def _validation_body(*, decision: str = "eligible", attestation_id: str = "validation_1") -> dict[str, object]:
    _, created, expires = _times()
    return {
        "schemaVersion": 1,
        "attestationId": attestation_id,
        "issuer": "trusted-validator:prod",
        "signatureAlgorithm": "platform-attestation-v1",
        "candidateId": "candidate-1",
        "candidateDigest": DIGEST_A,
        "diffDigest": DIGEST_B,
        "targetPreHash": DIGEST_C,
        "ownerContractHash": DIGEST_D,
        "evidenceRefs": ["event:evidence-1"],
        "controlPlane": {
            "policyVersion": "1.0.0",
            "evaluatorVersion": "1.0.0",
            "metricRegistryVersion": "1.0.0",
            "harnessVersion": "1.0.0",
            "holdoutDigest": DIGEST_E,
        },
        "testArtifactDigests": [DIGEST_A, DIGEST_B],
        "sandboxPolicyDigest": DIGEST_C,
        "createdAt": created,
        "expiresAt": expires,
        "decision": decision,
    }


def _trust(attestations):
    class Verifier(attestations.TrustedSignatureVerifier):
        def __init__(self, key: bytes = KEY) -> None:
            self.key = key
            self.calls = 0

        def verify_digest(
            self,
            *,
            issuer: str,
            signature_algorithm: str,
            body_digest: str,
            signature: bytes,
        ) -> bool:
            self.calls += 1
            expected = hmac.new(self.key, body_digest.encode("ascii"), hashlib.sha256).digest()
            return signature_algorithm == "platform-attestation-v1" and hmac.compare_digest(
                signature, expected
            )

    class Replay(attestations.TrustedReplayBinding):
        def __init__(self) -> None:
            self.values: dict[str, tuple[str, str, str]] = {}
            self.calls = 0

        def bind(
            self,
            *,
            attestation_id: str,
            attestation_type: str,
            scope_digest: str,
            body_digest: str,
        ) -> str:
            self.calls += 1
            value = (attestation_type, scope_digest, body_digest)
            prior = self.values.get(attestation_id)
            if prior is not None and prior != value:
                raise attestations.AttestationReplayConflict("attestation replay conflict")
            self.values[attestation_id] = value
            return "replay" if prior is not None else "bound"

    class Chain(attestations.TrustedAttestationChain):
        def __init__(self, links: Mapping[tuple[str, str], tuple[str, str]]) -> None:
            self.links = dict(links)

        def resolve_chain(
            self, *, attestation_type: str, predecessor_digest: str, max_depth: int
        ):
            result = []
            current = predecessor_digest
            # Return one extra item when present so the verifier, rather than
            # the trusted adapter, enforces its depth limit.
            for _ in range(max_depth + 1):
                value = self.links.get((attestation_type, current))
                if value is None:
                    break
                link_type, prior = value
                result.append(attestations.AttestationChainLink(current, link_type, prior))
                current = prior
                if current == ZERO_DIGEST:
                    break
            return tuple(result)

    return Verifier, Replay, Chain


def _stage_expected(attestations):
    return attestations.DeploymentExpectation(
        attestation_type="rollout-stage",
        issuer="trusted-deployment-controller:prod",
        subject=attestations.RolloutStageSubject(
            rsi_package_digest=DIGEST_A,
            rollout_manifest_digest=DIGEST_B,
            stage_id="stage-3",
            provider_contract_digest=DIGEST_C,
            provider_version_digest=DIGEST_D,
        ),
        scope=attestations.RolloutStageScope(
            mode="promote-safe",
            environment_identity_digest=DIGEST_A,
            allowed_target_entry_digests=(DIGEST_B,),
        ),
        predecessor_attestation_digest=DIGEST_E,
    )


def _hook_expected(attestations):
    return attestations.DeploymentExpectation(
        attestation_type="orchestration-hook",
        issuer="trusted-deployment-controller:prod",
        subject=attestations.OrchestrationHookSubject(
            rsi_package_digest=DIGEST_A,
            rollout_manifest_digest=DIGEST_B,
            hook_id="coordinated-v1",
            provider_contract_digest=DIGEST_C,
            provider_version_digest=DIGEST_D,
        ),
        scope=attestations.OrchestrationHookScope(
            hook_mode="coordinated",
            environment_identity_digest=DIGEST_A,
            allowed_target_entry_digests=(DIGEST_B,),
        ),
        predecessor_attestation_digest=DIGEST_D,
    )


def _chain_for(attestations, attestation_type: str, start: str):
    _, _, Chain = _trust(attestations)
    return Chain({(attestation_type, start): (attestation_type, ZERO_DIGEST)})


def test_rollout_and_hook_attestations_verify_as_distinct_closed_types() -> None:
    """Stage and orchestration authority cannot be confused or merged."""
    attestations = _attestations()
    Verifier, Replay, _ = _trust(attestations)
    now, _, _ = _times()
    verifier = Verifier()
    replay = Replay()

    stage = attestations.verify_deployment_attestation(
        _encoded(_rollout_body()),
        expectation=_stage_expected(attestations),
        verifier=verifier,
        replay=replay,
        chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
        now=now,
        maximum_ttl=timedelta(minutes=15),
    )
    hook = attestations.verify_deployment_attestation(
        _encoded(_hook_body()),
        expectation=_hook_expected(attestations),
        verifier=verifier,
        replay=replay,
        chain=_chain_for(attestations, "orchestration-hook", DIGEST_D),
        now=now,
        maximum_ttl=timedelta(minutes=15),
    )

    assert stage.attestation.attestation_type == "rollout-stage"
    assert hook.attestation.attestation_type == "orchestration-hook"
    assert stage.digest != hook.digest
    pair_kwargs = dict(
        stage_expectation=_stage_expected(attestations),
        hook_expectation=_hook_expected(attestations),
        verifier=verifier,
        replay=replay,
        stage_chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
        hook_chain=_chain_for(attestations, "orchestration-hook", DIGEST_D),
        now=now,
        maximum_ttl=timedelta(minutes=15),
    )
    pair = attestations.verify_deployment_pair(
        _encoded(_rollout_body()), _encoded(_hook_body()), **pair_kwargs
    )
    assert pair.stage.digest == stage.digest
    with pytest.raises(attestations.AttestationError, match="raw|trust"):
        attestations.verify_deployment_pair(stage, hook, **pair_kwargs)
    with pytest.raises(attestations.AttestationError, match="type|schema"):
        attestations.verify_deployment_attestation(
            _encoded(_hook_body()),
            expectation=_stage_expected(attestations),
            verifier=verifier,
            replay=replay,
            chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
            now=now,
            maximum_ttl=timedelta(minutes=15),
        )


def test_deployment_pair_rejects_cross_context_stage_and_hook() -> None:
    """Distinct valid leaves must still share package/rollout/provider/env/allowlist bindings."""
    attestations = _attestations()
    Verifier, Replay, Chain = _trust(attestations)
    now, _, _ = _times()
    stage = attestations.verify_deployment_attestation(
        _encoded(_rollout_body()),
        expectation=_stage_expected(attestations),
        verifier=Verifier(),
        replay=Replay(),
        chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
        now=now,
        maximum_ttl=timedelta(minutes=15),
    )
    hook_body = _hook_body()
    hook_body["subject"].update(
        {
            "rsiPackageDigest": DIGEST_B,
            "rolloutManifestDigest": DIGEST_C,
            "providerContractDigest": DIGEST_D,
            "providerVersionDigest": DIGEST_E,
        }
    )
    hook_body["scope"].update(
        {
            "environmentIdentityDigest": DIGEST_B,
            "allowedTargetEntryDigests": [DIGEST_C],
        }
    )
    hook_expectation = attestations.DeploymentExpectation(
        attestation_type="orchestration-hook",
        issuer="trusted-deployment-controller:prod",
        subject=attestations.OrchestrationHookSubject(
            rsi_package_digest=DIGEST_B,
            rollout_manifest_digest=DIGEST_C,
            hook_id="coordinated-v1",
            provider_contract_digest=DIGEST_D,
            provider_version_digest=DIGEST_E,
        ),
        scope=attestations.OrchestrationHookScope(
            hook_mode="coordinated",
            environment_identity_digest=DIGEST_B,
            allowed_target_entry_digests=(DIGEST_C,),
        ),
        predecessor_attestation_digest=DIGEST_D,
    )
    hook = attestations.verify_deployment_attestation(
        _encoded(hook_body),
        expectation=hook_expectation,
        verifier=Verifier(),
        replay=Replay(),
        chain=Chain({("orchestration-hook", DIGEST_D): ("orchestration-hook", ZERO_DIGEST)}),
        now=now,
        maximum_ttl=timedelta(minutes=15),
    )
    with pytest.raises(attestations.AttestationError, match="common|context|binding"):
        attestations.verify_deployment_pair(
            _encoded(_rollout_body()),
            _encoded(hook_body),
            stage_expectation=_stage_expected(attestations),
            hook_expectation=hook_expectation,
            verifier=Verifier(),
            replay=Replay(),
            stage_chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
            hook_chain=Chain(
                {("orchestration-hook", DIGEST_D): ("orchestration-hook", ZERO_DIGEST)}
            ),
            now=now,
            maximum_ttl=timedelta(minutes=15),
        )


def test_verified_attestation_wrappers_require_internal_verification_provenance() -> None:
    """Typed wrappers around parsed but unsigned bodies cannot manufacture authority."""
    attestations = _attestations()
    stage_value = json.loads(_encoded(_rollout_body()))
    stage_value["signature"] = "base64:AA=="
    hook_value = json.loads(_encoded(_hook_body()))
    hook_value["signature"] = "base64:AA=="
    validation_value = json.loads(_encoded(_validation_body()))
    validation_value["signature"] = "base64:AA=="
    stage = attestations.parse_deployment_attestation(_canonical(stage_value))
    hook = attestations.parse_deployment_attestation(_canonical(hook_value))
    validation = attestations.parse_validation_attestation(_canonical(validation_value))

    with pytest.raises((attestations.AttestationError, TypeError)):
        stage_wrapper = attestations.VerifiedDeploymentAttestation(
            stage, attestations.attestation_body_digest(stage)
        )
        hook_wrapper = attestations.VerifiedDeploymentAttestation(
            hook, attestations.attestation_body_digest(hook)
        )
        attestations.verify_deployment_pair(stage_wrapper, hook_wrapper)
    with pytest.raises((attestations.AttestationError, TypeError)):
        attestations.VerifiedValidationAttestation(
            validation, attestations.attestation_body_digest(validation)
        )


def test_deployment_signature_is_checked_before_replay_binding() -> None:
    """An invalid signature must not reserve or poison an attestation ID."""
    attestations = _attestations()
    Verifier, Replay, _ = _trust(attestations)
    now, _, _ = _times()
    replay = Replay()
    verifier = Verifier(key=b"different-key")

    with pytest.raises(attestations.AttestationError, match="signature"):
        attestations.verify_deployment_attestation(
            _encoded(_rollout_body()),
            expectation=_stage_expected(attestations),
            verifier=verifier,
            replay=replay,
            chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
            now=now,
            maximum_ttl=timedelta(minutes=15),
        )

    assert replay.calls == 0
    good = Verifier()
    attestations.verify_deployment_attestation(
        _encoded(_rollout_body()),
        expectation=_stage_expected(attestations),
        verifier=good,
        replay=replay,
        chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
        now=now,
        maximum_ttl=timedelta(minutes=15),
    )
    assert replay.calls == 1


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("issuer", "trusted-deployment-controller:other", "issuer"),
        ("predecessorAttestationDigest", DIGEST_A, "predecessor"),
        ("createdAt", "2026-08-09T12:10:00Z", "future"),
        ("expiresAt", "2026-08-09T11:58:00Z", "expired"),
        ("expiresAt", "2026-08-10T11:59:00Z", "TTL"),
    ],
)
def test_deployment_verification_rejects_issuer_predecessor_and_time_drift(
    field: str, value: str, message: str
) -> None:
    """Issuer, predecessor, current time, skew and maximum TTL are exact gates."""
    attestations = _attestations()
    Verifier, Replay, _ = _trust(attestations)
    now, _, _ = _times()
    body = _rollout_body()
    body[field] = value

    with pytest.raises(attestations.AttestationError, match=message):
        attestations.verify_deployment_attestation(
            _encoded(body),
            expectation=_stage_expected(attestations),
            verifier=Verifier(),
            replay=Replay(),
            chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
            now=now,
            maximum_ttl=timedelta(minutes=15),
            clock_skew=timedelta(seconds=30),
        )


def test_attestation_time_window_accepts_created_boundary_but_excludes_expiry_boundary() -> None:
    """Validity is the half-open interval createdAt <= now < expiresAt."""
    attestations = _attestations()
    Verifier, Replay, _ = _trust(attestations)
    created = datetime(2026, 8, 9, 11, 59, tzinfo=timezone.utc)
    expires = datetime(2026, 8, 9, 12, 9, tzinfo=timezone.utc)
    common = dict(
        expectation=_stage_expected(attestations),
        verifier=Verifier(),
        replay=Replay(),
        chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
        maximum_ttl=timedelta(minutes=15),
        clock_skew=timedelta(0),
    )
    assert attestations.verify_deployment_attestation(
        _encoded(_rollout_body()), now=created, **common
    )
    with pytest.raises(attestations.AttestationError, match="expired"):
        attestations.verify_deployment_attestation(
            _encoded(_rollout_body()), now=expires, **common
        )


def test_deployment_verification_rejects_package_rollout_provider_environment_and_allowlist_drift() -> None:
    """Every deployment subject/scope field is independently security binding."""
    attestations = _attestations()
    Verifier, Replay, _ = _trust(attestations)
    now, _, _ = _times()
    mutations = []
    for field in (
        "rsiPackageDigest",
        "rolloutManifestDigest",
        "stageId",
        "providerContractDigest",
        "providerVersionDigest",
    ):
        body = _rollout_body()
        body["subject"][field] = "stage-4" if field == "stageId" else DIGEST_E
        mutations.append(body)
    for field, value in (
        ("mode", "propose"),
        ("environmentIdentityDigest", DIGEST_E),
        ("allowedTargetEntryDigests", [DIGEST_C]),
    ):
        body = _rollout_body()
        body["scope"][field] = value
        mutations.append(body)

    for body in mutations:
        with pytest.raises(attestations.AttestationError, match="subject|scope"):
            attestations.verify_deployment_attestation(
                _encoded(body),
                expectation=_stage_expected(attestations),
                verifier=Verifier(),
                replay=Replay(),
                chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
                now=now,
                maximum_ttl=timedelta(minutes=15),
            )


def test_provider_contract_and_provider_version_are_not_aliased() -> None:
    """Matching one provider digest cannot satisfy the other provider identity."""
    attestations = _attestations()
    Verifier, Replay, _ = _trust(attestations)
    now, _, _ = _times()
    body = _rollout_body(provider_contract=DIGEST_C, provider_version=DIGEST_C)

    with pytest.raises(attestations.AttestationError, match="subject"):
        attestations.verify_deployment_attestation(
            _encoded(body),
            expectation=_stage_expected(attestations),
            verifier=Verifier(),
            replay=Replay(),
            chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
            now=now,
            maximum_ttl=timedelta(minutes=15),
        )


def test_deployment_chain_rejects_detached_cycle_wrong_domain_and_excess_depth() -> None:
    """A signed leaf is insufficient without a bounded typed predecessor chain."""
    attestations = _attestations()
    Verifier, Replay, Chain = _trust(attestations)
    now, _, _ = _times()
    cases = [
        Chain({}),
        Chain({("rollout-stage", DIGEST_E): ("rollout-stage", DIGEST_E)}),
        Chain({("rollout-stage", DIGEST_E): ("orchestration-hook", ZERO_DIGEST)}),
        Chain(
            {
                ("rollout-stage", DIGEST_E): ("rollout-stage", DIGEST_A),
                ("rollout-stage", DIGEST_A): ("rollout-stage", DIGEST_B),
                ("rollout-stage", DIGEST_B): ("rollout-stage", ZERO_DIGEST),
            }
        ),
    ]
    for chain in cases:
        with pytest.raises(attestations.AttestationError, match="chain"):
            attestations.verify_deployment_attestation(
                _encoded(_rollout_body()),
                expectation=_stage_expected(attestations),
                verifier=Verifier(),
                replay=Replay(),
                chain=chain,
                now=now,
                maximum_ttl=timedelta(minutes=15),
                maximum_chain_depth=2,
            )


def test_exact_replay_is_idempotent_but_same_id_changed_body_conflicts() -> None:
    """Replay identity binds the signed body, type and scope after verification."""
    attestations = _attestations()
    Verifier, Replay, _ = _trust(attestations)
    now, _, _ = _times()
    replay = Replay()
    kwargs = dict(
        expectation=_stage_expected(attestations),
        verifier=Verifier(),
        replay=replay,
        chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
        now=now,
        maximum_ttl=timedelta(minutes=15),
    )
    first = attestations.verify_deployment_attestation(_encoded(_rollout_body()), **kwargs)
    second = attestations.verify_deployment_attestation(_encoded(_rollout_body()), **kwargs)
    assert first == second

    changed = _rollout_body()
    changed["expiresAt"] = "2026-08-09T12:08:00Z"
    with pytest.raises(attestations.AttestationReplayConflict):
        attestations.verify_deployment_attestation(_encoded(changed), **kwargs)


def test_strict_parser_rejects_duplicate_unknown_missing_nonfinite_and_malformed_fields() -> None:
    """Ambiguous JSON, framing, algorithms, digests and signatures fail closed."""
    attestations = _attestations()
    valid = _encoded(_rollout_body())
    malformed = [
        valid + b"\n",
        valid.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1', 1),
        valid[:-1] + b',"unknown":true}',
        valid.replace(b'"issuer":"trusted-deployment-controller:prod",', b"", 1),
        valid.replace(b'"signatureAlgorithm":"platform-attestation-v1"', b'"signatureAlgorithm":"unknown"'),
        valid.replace(b'"signature":"base64:', b'"signature":"base64:not@'),
        valid.replace(DIGEST_A.encode(), b"sha256:BAD", 1),
        valid.replace(b'"schemaVersion":1', b'"schemaVersion":NaN', 1),
        valid.replace(b'"schemaVersion":1', b'"schemaVersion":true', 1),
        b"\xff",
    ]
    for payload in malformed:
        with pytest.raises(attestations.AttestationError):
            attestations.parse_deployment_attestation(payload)

    for noncanonical in ("base64:YR==", "base64:AB=="):
        value = json.loads(valid)
        value["signature"] = noncanonical
        with pytest.raises(attestations.AttestationError, match="signature"):
            attestations.parse_deployment_attestation(_canonical(value))


def test_repeated_or_unsorted_set_like_arrays_are_noncanonical() -> None:
    """Signed set-like arrays have one representation: unique UTF-8 sorted values."""
    attestations = _attestations()
    rollout_duplicate = _rollout_body(allowed_targets=[DIGEST_B, DIGEST_B])
    rollout_unsorted = _rollout_body(allowed_targets=[DIGEST_C, DIGEST_B])
    validation_duplicate = _validation_body()
    validation_duplicate["evidenceRefs"] = ["event:z", "event:z"]
    validation_unsorted = _validation_body()
    validation_unsorted["testArtifactDigests"] = [DIGEST_B, DIGEST_A]
    for payload, parser in (
        (_encoded(rollout_duplicate), attestations.parse_deployment_attestation),
        (_encoded(rollout_unsorted), attestations.parse_deployment_attestation),
        (_encoded(validation_duplicate), attestations.parse_validation_attestation),
        (_encoded(validation_unsorted), attestations.parse_validation_attestation),
    ):
        with pytest.raises(attestations.AttestationError, match="canonical|array"):
            parser(payload)


def test_signed_body_digest_is_semantic_across_json_key_order_and_whitespace() -> None:
    """Transport formatting does not alter the canonical signed-body digest."""
    attestations = _attestations()
    body = _rollout_body()
    compact = _encoded(body)
    value = json.loads(compact)
    reordered = json.dumps(
        dict(reversed(list(value.items()))),
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")
    left = attestations.parse_deployment_attestation(compact)
    right = attestations.parse_deployment_attestation(reordered)
    assert attestations.attestation_body_digest(left) == attestations.attestation_body_digest(right)


def _validation_expected(attestations, *, decision: str = "eligible"):
    return attestations.ValidationExpectation(
        issuer="trusted-validator:prod",
        candidate_id="candidate-1",
        candidate_digest=DIGEST_A,
        diff_digest=DIGEST_B,
        target_pre_hash=DIGEST_C,
        owner_contract_hash=DIGEST_D,
        evidence_refs=("event:evidence-1",),
        control_plane=attestations.ValidationControlPlane(
            policy_version="1.0.0",
            evaluator_version="1.0.0",
            metric_registry_version="1.0.0",
            harness_version="1.0.0",
            holdout_digest=DIGEST_E,
        ),
        test_artifact_digests=(DIGEST_A, DIGEST_B),
        sandbox_policy_digest=DIGEST_C,
        decision=decision,
    )


def test_validation_attestation_is_deeply_immutable_and_exactly_verified() -> None:
    """Eligibility exists only on a trusted signature over every validation binding."""
    attestations = _attestations()
    Verifier, Replay, _ = _trust(attestations)
    now, _, _ = _times()
    verified = attestations.verify_validation_attestation(
        _encoded(_validation_body()),
        expectation=_validation_expected(attestations),
        verifier=Verifier(),
        replay=Replay(),
        now=now,
        maximum_ttl=timedelta(minutes=15),
        require_eligible=True,
    )

    assert verified.attestation.decision == "eligible"
    assert isinstance(verified.attestation.evidence_refs, tuple)
    with pytest.raises((AttributeError, TypeError)):
        verified.attestation.control_plane.policy_version = "changed"


def test_direct_model_construction_cannot_bypass_closed_attestation_admission() -> None:
    """Forged typed objects are re-admitted before signature or replay trust is consulted."""
    attestations = _attestations()
    Verifier, Replay, _ = _trust(attestations)
    verifier = Verifier()
    replay = Replay()
    now, _, _ = _times()
    parsed_deployment = attestations.parse_deployment_attestation(_encoded(_rollout_body()))
    parsed_validation = attestations.parse_validation_attestation(_encoded(_validation_body()))
    deployment_forges = [
        _forge_model(parsed_deployment, schema_version=True),
        _forge_model(parsed_deployment, attestation_id="bad id"),
        _forge_model(parsed_deployment, attestation_type="orchestration-hook"),
        _forge_model(parsed_deployment, signature_algorithm="unknown"),
        _forge_model(parsed_deployment, subject="not-a-subject"),
        _forge_model(parsed_deployment, signature=True),
    ]
    for forged in deployment_forges:
        with pytest.raises(attestations.AttestationError):
            attestations.verify_deployment_attestation(
                forged,
                expectation=_stage_expected(attestations),
                verifier=verifier,
                replay=replay,
                chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
                now=now,
                maximum_ttl=timedelta(minutes=15),
            )
    validation_forges = [
        _forge_model(parsed_validation, schema_version=True),
        _forge_model(parsed_validation, attestation_id="bad id"),
        _forge_model(parsed_validation, signature_algorithm="unknown"),
        _forge_model(parsed_validation, evidence_refs=("event:z", "event:a")),
        _forge_model(parsed_validation, control_plane="not-control-plane"),
        _forge_model(parsed_validation, signature=True),
    ]
    for forged in validation_forges:
        with pytest.raises(attestations.AttestationError):
            attestations.verify_validation_attestation(
                forged,
                expectation=_validation_expected(attestations),
                verifier=verifier,
                replay=replay,
                now=now,
                maximum_ttl=timedelta(minutes=15),
            )

    forged_expectation = replace(_stage_expected(attestations), subject="not-a-subject")
    with pytest.raises(attestations.AttestationError):
        attestations.verify_deployment_attestation(
            parsed_deployment,
            expectation=forged_expectation,
            verifier=verifier,
            replay=replay,
            chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
            now=now,
            maximum_ttl=timedelta(minutes=15),
        )
    assert verifier.calls == 0
    assert replay.calls == 0


def test_attestation_body_digest_readmits_mutable_and_malformed_typed_models() -> None:
    """Digesting a typed model is itself a strict closed-schema boundary."""
    attestations = _attestations()
    parsed = attestations.parse_validation_attestation(_encoded(_validation_body()))
    for forged in (
        _forge_model(parsed, evidence_refs=["event:evidence-1"]),
        _forge_model(parsed, signature=bytearray(parsed.signature)),
        _forge_model(parsed, decision=[]),
    ):
        with pytest.raises(attestations.AttestationError):
            attestations.attestation_body_digest(forged)


def test_public_attestation_models_reject_mutable_or_malformed_construction() -> None:
    """Closed frozen models cannot first exist in a shallow mutable invalid state."""
    attestations = _attestations()
    deployment = attestations.parse_deployment_attestation(_encoded(_rollout_body()))
    validation = attestations.parse_validation_attestation(_encoded(_validation_body()))
    with pytest.raises(attestations.AttestationError):
        replace(deployment, signature=bytearray(deployment.signature))
    with pytest.raises(attestations.AttestationError):
        replace(deployment, schema_version=True)
    with pytest.raises(attestations.AttestationError):
        replace(validation, evidence_refs=["event:evidence-1"])
    with pytest.raises(attestations.AttestationError):
        replace(validation, decision=[])


def test_malformed_replay_and_chain_values_fail_typed_with_bounded_consumption() -> None:
    """Untrusted adapter shapes cannot leak TypeError or force unbounded generator reads."""
    attestations = _attestations()
    Verifier, _, _ = _trust(attestations)
    now, _, _ = _times()

    class BadReplay(attestations.TrustedReplayBinding):
        def bind(self, **_kwargs):
            return []

    with pytest.raises(attestations.AttestationError, match="replay"):
        attestations.verify_deployment_attestation(
            _encoded(_rollout_body()),
            expectation=_stage_expected(attestations),
            verifier=Verifier(),
            replay=BadReplay(),
            chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
            now=now,
            maximum_ttl=timedelta(minutes=15),
        )

    class MalformedChain(attestations.TrustedAttestationChain):
        def resolve_chain(self, **_kwargs):
            return (attestations.AttestationChainLink(DIGEST_E, "rollout-stage", []),)

    with pytest.raises(attestations.AttestationError, match="chain"):
        attestations.verify_deployment_attestation(
            _encoded(_rollout_body()),
            expectation=_stage_expected(attestations),
            verifier=Verifier(),
            replay=_trust(attestations)[1](),
            chain=MalformedChain(),
            now=now,
            maximum_ttl=timedelta(minutes=15),
        )

    consumed = 0

    class EndlessChain(attestations.TrustedAttestationChain):
        def resolve_chain(self, **_kwargs):
            def values():
                nonlocal consumed
                current = DIGEST_E
                while True:
                    consumed += 1
                    yield attestations.AttestationChainLink(
                        current, "rollout-stage", DIGEST_A
                    )
                    current = DIGEST_A
            return values()

    with pytest.raises(attestations.AttestationError, match="chain"):
        attestations.verify_deployment_attestation(
            _encoded(_rollout_body()),
            expectation=_stage_expected(attestations),
            verifier=Verifier(),
            replay=_trust(attestations)[1](),
            chain=EndlessChain(),
            now=now,
            maximum_ttl=timedelta(minutes=15),
            maximum_chain_depth=1,
        )
    assert consumed <= 2


@pytest.mark.parametrize("decision", [[], {}])
def test_non_scalar_validation_decision_fails_typed(decision: object) -> None:
    """Container decisions are schema failures, never unhashable membership errors."""
    attestations = _attestations()
    body = _validation_body()
    body["decision"] = decision
    with pytest.raises(attestations.AttestationError, match="decision"):
        attestations.parse_validation_attestation(_encoded(body))


def test_registration_raw_bytes_reject_duplicate_keys_before_semantic_hash(tmp_path: Path) -> None:
    """Registration identity cannot erase duplicate JSON keys through a pre-parsed mapping."""
    attestations = _attestations()
    root = tmp_path / "skill"
    root.mkdir()
    raw = (
        '{"schemaVersion":1,"schemaVersion":1,"entryId":"production:mail:v1",'
        '"skillName":"mail","canonicalRoot":' + json.dumps(str(root.resolve())) + ','
        '"aliases":[],"dependencies":[],"files":[]}'
    ).encode()
    with pytest.raises(attestations.AttestationError, match="duplicate|registration"):
        attestations.registration_manifest_digest_bytes(raw)


def test_registration_raw_bytes_hash_semantics_across_formatting_and_trailing_newline(
    tmp_path: Path,
) -> None:
    """Registration transport whitespace is ignored while semantic identity stays exact."""
    attestations = _attestations()
    root = tmp_path / "skill"
    root.mkdir()
    value = {
        "schemaVersion": 1,
        "entryId": "production:mail:v1",
        "skillName": "mail",
        "canonicalRoot": str(root.resolve()),
        "aliases": [],
        "dependencies": [],
        "files": ["SKILL.md"],
    }
    compact = json.dumps(value, separators=(",", ":")).encode()
    pretty = json.dumps(dict(reversed(list(value.items()))), indent=2).encode() + b"\n"
    assert attestations.registration_manifest_digest_bytes(compact) == (
        attestations.registration_manifest_digest_bytes(pretty)
    )


@pytest.mark.parametrize(
    "issuer",
    ["trusted-deployment-controller:", "trusted-deployment-controller:prod\nother"],
)
def test_issuer_suffix_requires_closed_printable_identity(issuer: str) -> None:
    """An issuer prefix without a valid non-control identity suffix is not trusted."""
    attestations = _attestations()
    body = _rollout_body()
    body["issuer"] = issuer
    with pytest.raises(attestations.AttestationError, match="issuer"):
        attestations.parse_deployment_attestation(_encoded(body))


def test_escaped_lone_surrogate_and_extreme_clock_skew_fail_typed() -> None:
    """Invalid Unicode scalars and overflowing clock arithmetic remain AttestationError."""
    attestations = _attestations()
    Verifier, Replay, _ = _trust(attestations)
    body = _validation_body()
    body["issuer"] = "trusted-validator:\ud800"
    payload = json.dumps(
        {**body, "signature": "base64:AA=="}, ensure_ascii=True
    ).encode()
    with pytest.raises(attestations.AttestationError):
        attestations.parse_validation_attestation(payload)

    now, _, _ = _times()
    with pytest.raises(attestations.AttestationError, match="clock|skew"):
        attestations.verify_deployment_attestation(
            _encoded(_rollout_body()),
            expectation=_stage_expected(attestations),
            verifier=Verifier(),
            replay=Replay(),
            chain=_chain_for(attestations, "rollout-stage", DIGEST_E),
            now=now,
            maximum_ttl=timedelta(minutes=15),
            clock_skew=timedelta.max,
        )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("candidateDigest",), DIGEST_E),
        (("diffDigest",), DIGEST_E),
        (("targetPreHash",), DIGEST_E),
        (("ownerContractHash",), DIGEST_E),
        (("evidenceRefs",), ["event:other"]),
        (("controlPlane", "harnessVersion"), "2.0.0"),
        (("testArtifactDigests",), [DIGEST_A]),
        (("sandboxPolicyDigest",), DIGEST_E),
        (("decision",), "rejected"),
    ],
)
def test_validation_tamper_and_control_plane_drift_are_rejected(
    path: tuple[str, ...], value: object
) -> None:
    """No candidate, target, evidence, control or decision field may drift."""
    attestations = _attestations()
    Verifier, Replay, _ = _trust(attestations)
    now, _, _ = _times()
    body = _validation_body()
    cursor = body
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value

    with pytest.raises(attestations.AttestationError, match="binding|decision"):
        attestations.verify_validation_attestation(
            _encoded(body),
            expectation=_validation_expected(attestations),
            verifier=Verifier(),
            replay=Replay(),
            now=now,
            maximum_ttl=timedelta(minutes=15),
            require_eligible=True,
        )


def test_allowlist_digest_binds_exact_entry_root_registration_and_contract(tmp_path: Path) -> None:
    """Entry-ID reuse or canonical root/registration/contract drift changes authority."""
    attestations = _attestations()
    root = tmp_path / "skill"
    root.mkdir()
    registration = {
        "schemaVersion": 1,
        "entryId": "production:mail:v1",
        "skillName": "mail",
        "canonicalRoot": str(root.resolve()),
        "aliases": [],
        "dependencies": [],
        "files": ["SKILL.md"],
    }
    registration_digest = attestations.registration_manifest_digest(registration)
    identity = attestations.canonical_root_identity_digest(root, registration_digest)
    entry = {
        "entryId": "production:mail:v1",
        "skillName": "mail",
        "canonicalRootIdentityDigest": identity,
        "contractHash": DIGEST_A,
    }
    original = attestations.allowlist_entry_digest(entry)

    changed_root = tmp_path / "other"
    changed_root.mkdir()
    reassigned_identity = attestations.canonical_root_identity_digest(
        changed_root, registration_digest
    )
    assert reassigned_identity != identity
    assert attestations.allowlist_entry_digest(
        {**entry, "canonicalRootIdentityDigest": reassigned_identity}
    ) != original
    assert attestations.allowlist_entry_digest({**entry, "contractHash": DIGEST_B}) != original
    assert attestations.registration_manifest_digest({**registration, "files": ["SKILL.md", "references/a.md"]}) != registration_digest

    with pytest.raises(attestations.AttestationError, match="schema"):
        attestations.allowlist_entry_digest({**entry, "canonicalRoot": str(root)})
