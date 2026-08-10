# Task 8 Brief — Guarded Promotion, Recovery, and Incident Latch

## Scope and invariants

- Plan: `docs/superpowers/plans/2026-08-07-recursive-self-improvement-v1.md`, Task 8.
- Approved specification: `docs/specs/recursive-self-improvement-spec.md`, especially sections 7 phases 7–9, 11.2, 12.1, 12.10–12.11, 15.1–15.8, 17.1–17.5, and implementation Step 10.
- Baseline commit: `5e1d698a7295ba2390dea7178e46639da3cf7c56`; the approved specification must remain byte-identical with SHA-256 `4d691659fc3f2a97c863fc8153e49227fc152ebe6dcf0c7a6aa8829842dd0b37`.
- Normative Task 8 registry addendum: `task-8-apply-reverted-addendum.md`
  raw SHA-256 `6fd2ab2a1d45e678f7eaf237c462c49e6dcf3ad133e30c41e28326b9d5f909b6`
  plus canonical-final-LF `task-8-registry-addendum-v1.json` SHA-256
  `ef84059ca0df0d3804dc090616cef3e4abbe3ce7f11ec6f8535e74aa3afe02c0`;
  the JSON directionally binds the Markdown digest without a cycle and defines
  `TASK8_CONTROL_PLANE_VERSION=1.1.0`.
- `promote-candidate` is the only RSI path allowed to mutate a production target. Validation, monitoring, reporting, diagnosis, replay inspection, and every non-promotion command remain byte/mode/link/inode-identical for targets and perform no provider write.
- V1 admits exactly one already-existing regular artifact containing additive declarative knowledge. Behavior, scripts, tests, profiles, agents, contracts, multi-file changes, self/RSI/provider/control-plane targets, material changes, stale authority, unsafe bytes, unresolved ownership, and non-allowlisted roots stop before provider snapshot.
- No test may write the real provider ledger or mutate a real skill target. Real-provider integration uses a fresh temporary learning home and disposable target copies. The live provider source and real ledger are immutable before/after witnesses.
- A failure is successful only when it leaves a proven exact pre-state, a proven exact post-state that can be safely resumed, or a durable ambiguous/quarantined state. No branch may report `promoted` while target, provider, lifecycle, or transaction authority is partial or unknown.

## Lifecycle repair: never reopen or counterfeit a closed run

Task 6 proposal runs close immediately after canonical capture. Task 7 deliberately creates immutable validation artifacts without lifecycle writes. `fold_run()` requires same-run causation and rejects every event after `run.closed`; therefore Task 8 must not append to the proposal run or synthesize a second `candidate.captured` event.

Use one explicit continuation run. The approved spec file remains byte-identical,
but its registry has no truthful explicit rollback terminal. As an architecture-
approved Task 8 implementation addendum, add exactly one versioned normative
event type, `apply.reverted`; add no other event type. Existing event types gain
only the closed Task 8 shape/phase arms defined below:

```text
closed proposal run
  └─ candidate.captured + run.closed(completed)

promotion continuation run
  run.started
    ├─ run.closed(failed; decision=not-started/stale-external)
    ├─ incident.latched → run.closed(ambiguous|quarantined) # pre-gate provider/latch incident
    → promotion.gated                      # cross-run cause = prior capture
    → staging.completed
      ├─ incident.latched → run.closed(ambiguous|quarantined)
    → validation.completed
      ├─ incident.latched → run.closed(ambiguous|quarantined)
    → promotion.planned
      ├─ run.closed(blocked|failed|deferred; decision=not-started)
      └─ snapshot.created
         ├─ run.closed(blocked|failed|deferred; decision=not-started)
         └─ apply.started
      ├─ apply.completed(outcome=not-applied) → run.closed(failed|deferred)
      ├─ incident.latched → run.closed(ambiguous|quarantined)
      └─ apply.completed(outcome=applied)
         → verification.completed
           ├─ resolution.recorded → run.closed(completed)
           ├─ apply.reverted → run.closed(failed|deferred)
           └─ incident.latched → run.closed(ambiguous|quarantined)
```

Additive event/FSM changes are intentionally minimal:

- `fold_run(events, external_predecessors=...)` may resolve exactly one external causation: the run-index-1 `promotion.gated` event may point to an earlier `candidate.captured` in another run;
- the registry still requires `promotion.gated <- candidate.captured`; there is no bypass, copied capture, or new bridge event type;
- standalone `fold_run(events)` remains fail-closed when the external predecessor is absent;
- the sole new registry type is `apply.reverted <- verification.completed` only,
  with exact negative-
  verification and rollback semantics; a direct apply-completed-to-rollback edge
  is forbidden;
- `resolution.recorded` after a promotion transaction requires a verified affirmative apply and exact provider resolution;
- `incident.latched <- apply.started` is legal only for the exact matrix-listed
  prepared-temp, preexisting-latch, ancestry, exchange-ambiguous, or emergency-
  reverse reasons; the exact-artifact reverse with a whole-tree `other` state
  remains an incident and cannot masquerade as `not-applied` or
  `apply.reverted`;
- a promote-safe close directly after `promotion.planned` or `snapshot.created`
  is legal only through the bound `transaction-decision(outcome=not-started)`
  arm, exact pre/unresolved proof, and blocked/failed/deferred status;
- the only earlier clean close is `run.started` directly to
  `transaction-decision(outcome=not-started,targetDisposition=stale-external)`
  and failed close, with no gate/apply/temp, provider unresolved, latch absent,
  and the exact non-attribution witness; it preserves the external state;
- a clean close after a completed apply requires either exact promoted resolution or exact verified rollback; ambiguous/quarantined close requires a previously durable latch and `incident.latched`.

`EventStore._validate_lifecycles()` must add a strict cross-run pass. It recomputes, rather than trusts, the external gate:

- the external gate is the first event after `run.started`, unique in the run, and the continuation uses `mode=promote-safe`, `runKind=local`;
- the origin capture exists earlier, belongs to a different closed completed run, follows admission `allow`, and exactly matches provider candidate/capture operation/request/owner/path bindings;
- the Task 7 experiment operation, request, bundle, attestation, plan and post-image form one immutable lineage;
- the imported `promotion.gated → staging.completed → validation.completed → promotion.planned` events bind the same candidate, diff, target, contract, attestation and provider operation IDs;
- the continuation run ID is deterministically derived from the plan digest; one plan digest maps to one run, exact replay converges, and a changed request or second run conflicts;
- every provider snapshot/resolve operation ID and every apply transaction is globally unique in its normative scope.

Imported events contain only bounded canonical IDs, refs and digests. Raw plan, attestation, post-image, findings, provider output, and transaction diagnostics remain in their immutable stores, never inline in JSONL. Their timestamps describe import/revalidation time; they never claim Task 7 originally emitted events.

### Closed Task 8 identifiers, references, and bridge schema

This section is normative for Task 8. New Task 8 EventStore sidecars, decision/
incident documents, provider version/fold-profile documents, and provider V2
snapshot manifests use strict UTF-8, sorted keys, compact separators, no
duplicate keys/non-finite numbers, and one final LF; their document digest covers
those exact bytes including LF and is rendered `sha256:<64 lowercase hex>`.
Existing Task 7 V1 canonical store objects use their current compact no-final-LF
bytes, and every Task 7 V2 canonical object deliberately preserves that same no-
LF store convention; its raw/semantic digest covers the explicitly named exact
preimage bytes. Exact
raw deployment attestations are never newline-normalized. Provider JSONL events
retain native one-event-per-LF framing, while native request digests cover the
provider's existing compact no-LF semantic JSON. Each version's parser rejects
the other framing: adding/removing a final newline is a digest/schema
substitution, never normalization. Every object and nested object has
exactly the named keys; missing or additional keys fail closed. Every ID, ref,
path, array, and document is bounded before allocation or persistence.

For every new object below explicitly governed by `CFL`/`D`, define
`CFL(x)=UTF8(json.dumps(x,sort_keys=true,separators=(",",":"),
ensure_ascii=false,allow_nan=false))+"\n"` and
`D(x)="sha256:"+lowerhex(SHA256(CFL(x)))`. The strict parser rejects a BOM,
CR, duplicate/additional/missing keys, non-NFC strings, floats or non-finite
numbers, booleans in integer slots, disallowed JSON nulls, and any bytes after
the sole final LF. An object never stores its own `D(object)` field. These rules
do not change the explicitly no-final-LF Task 7/provider-native preimages above.

Digest representations are typed, never heuristically normalized. Existing
provider event IDs and request digests use native bare `[0-9a-f]{64}`; fields
that copy them are explicitly named `providerCandidateEventDigest`,
`providerCaptureRequestDigest`, `providerReviewRequestDigest`,
`providerResolutionRequestDigest`, or `providerSnapshotRequestDigest` and retain
those exact bare bytes. Task 8 canonical object, EventStore sidecar, Task 7, plan,
attestation, artifact, and manifest references use `sha256:<64 lowercase hex>`.
The adapter has two narrow field-specific helpers: a validated native provider
digest may be wrapped once as `"sha256:"+value`, and a declared cross-store
digest may be unwrapped once by validating the prefix then taking its 64-hex
suffix. Bare/prefixed confusion, double prefixing, or accepting both forms for
one field is a schema error. Candidate lineage/state objects and provider V2
snapshot/resolve records preserve native provider request-digest fields while
their own canonical object digests use the Task 8 prefixed form.

Given the exact `PromotionPlan.digest`, derive:

```text
transactionId = "tx_" + sha256(canonical({
  "domain":"rsi-promotion-transaction-v1", "planDigest":planDigest
}))[7:]
runId = "run_promote_" + sha256(canonical({
  "domain":"rsi-promotion-continuation-v1", "planDigest":planDigest
}))[7:]
```

The full 256-bit suffix is retained. The continuation `run.started` has
`mode=promote-safe`, `runKind=local`, the exact target
`activeSkills=[skillName+"@"+manifestPreHash]`, `correlationId=planDigest`, and
`payloadRef=null`. Every later continuation event has the same `runId`,
`correlationId=planDigest`, exact target skill, a phase-unique deterministic
logical operation ID, and exactly one causation edge. Event IDs are deterministic
for every Task 8 continuation event, including `run.started` and `run.closed`:

```text
eventId = "evt_" + lowerhex(SHA256(canonical-no-LF({
  "domain":"rsi-promotion-event-v1",
  "eventType":eventType,
  "transactionId":transactionId
})))
```

For `run.started`, `transactionId` is deterministically derived from its exact
correlation/plan digest before constructing the envelope; it need not be a new
caller field. Every Task 8 event has exactly one occurrence of its event type per
transaction. The registry recomputes this formula for every closed Task 8 arm;
legacy/non-promotion event-ID derivation remains byte-for-byte unchanged.

Let `L(phase) = "promote:"+transactionId+":"+phase`. Every Task 8 event's
`logicalOperationId` is the listed `L` value, `targetSkill=skillName`,
`correlationId=planDigest`, and its idempotency key is the existing normative
digest over `(producerVersion,eventType,runId,L,targetSkill)`. `createdAt` is
audit-only and never enters IDs. This closed table fixes the remaining payload/
ref import values; phase-specific transaction fields are the exact unions below:

| Event | `L` phase / causation | Exact Task 8 values and ref |
|---|---|---|
| `run.started` | `run-start` / null | `mode=promote-safe`, `hookMode=coordinated`, `runKind=local`, exact one `activeSkills=[skillName+"@"+manifestPreHash]`, `policyVersion=PromotionPlan.controlPlane.policyVersion`, `controlPlaneVersion=TASK8_CONTROL_PLANE_VERSION=1.1.0`, null ref |
| `promotion.gated` | `gate` / external capture | `decision=allow`, `requiredChecks` exact sorted tuple `allowlist,artifact-store,atomic-exchange,attestation,candidate-authority,contract,incident-latch,namespace-lease,policy,provider,target-hash,ttl`, transaction/plan/origin fields, origin ref |
| `staging.completed` | `staging` / gate | `diffDigest=plan.artifact.diffDigest`, `targetPreHash=plan.target.manifestPreHash`, `stagingRef=experiment.bundleRef`, transaction ID, null ref |
| `validation.completed` | `validation` / staging | exact `attestationRef` and `attestationDigest=validationAttestationDigest`, transaction ID, null ref |
| `promotion.planned` | `plan` / validation | exact plan ref/digest, `candidateHash=candidateDigest`, plan diff digest, `targetHash=manifestPreHash`, owner contract hash, `providerOperationIds={snapshot,resolve}`, transaction ID, null ref |
| `snapshot.created` | `snapshot` / plan | exact provider snapshot operation, deterministic provider snapshot path/ref and prefixed manifest digest, transaction/snapshot digest, snapshot sidecar ref |
| `apply.started` | `apply-start` / snapshot | transaction ID and exact artifact pre/post hashes plus intent digest/ref |
| `apply.completed` | `apply-complete` / apply-start | exact applied/not-applied arm and readback digest/ref |
| `verification.completed` | `verification` / applied | exact affirmed/rollback-armed arm and verification digest/ref |
| `resolution.recorded` | `resolve` / affirmed | exact bounded Task 8 resolution arm and resolution-readback ref |
| `apply.reverted` | `rollback` / rollback-armed | exact rollback payload/digest and rollback-readback ref |
| `incident.latched` | `incident` / last durable mutation event | exact incident/latch disposition arm and incident-record ref |
| `run.closed` | `close` / terminal event | exact terminal status, linked IDs and decision digest/ref |

No caller supplies any table value. A duplicate event type in one transaction,
alternate logical phase string, wrong required-check ordering/member, mismatched
import ref/value, or same plan with different producer/control-plane version is a
typed conflict before append.

`PromotionPlanRef` is the closed tuple:

```text
experimentOperationId, reservationDigest, experimentRequestDigest,
candidateId, candidateDigest, candidateFullRecordDigest,
providerAuthorityBindingDigest, candidateCaptureLineageBindingDigest,
candidateStateBindingDigest, providerContractDigest, providerVersionDigest,
providerRuntimeIdentityDigest, providerExecutionIdentityDigest,
verifierExecutionBaseIdentityDigest, namespaceMutationLeaseBackendIdentityDigest,
namespaceMutationLeaseCapabilityDigest, policyVersion, policyArtifactDigest,
controlPlaneDigest, task8ControlPlaneVersion, task8AddendumDigest,
task8AddendumMarkdownDigest,
planId, planDigest,
validationAttestationDigest, artifactStoreIdentityDigest,
stageAttestationRawRef, stageAttestationRawDigest,
hookAttestationRawRef, hookAttestationRawDigest
```

`reservationDigest` is the outer marker/result `requestDigest` (the exact raw
reservation bytes digest). `experimentRequestDigest` is the inner canonical
`ExperimentRequest.digest` recorded inside reservation `request.json` and the
bundle manifest payload.
They are deliberately distinct. Swapping them, equating them without proof, or
accepting an ambiguous `requestDigest` is a typed conflict.
Every added runtime/execution/policy/control field is reconstructed from the
same strict V2 authority/plan/marker chain; it is not a caller assertion or a
second identity source.

`artifactStoreIdentityDigest` is the canonical digest of exactly:

```json
{"schemaVersion":1,"domain":"rsi-experiment-store-identity-v1",
 "canonicalPath":"<trusted configured canonical absolute path>",
 "markerName":".rsi-experiment-store-v1",
 "markerDigest":"sha256:<raw marker bytes digest>",
 "requiredTopology":["experiments","locks","locks/experiments",
   "locks/objects","objects","objects/post-images"]}
```

The store marker's bytes are frozen literally as
`{"domain":"rsi-experiment-store-v1","schemaVersion":1}` with no final LF;
`markerDigest` is the raw SHA-256 of exactly those bytes. The identity preimage is
the exact strict canonical-no-LF JSON mapping shown; therefore
`artifactStoreIdentityDigest = "sha256:" + lowerhex(SHA256(preimageBytes))`.
The canonical path must equal a constructor-attested allowed Task 7 store; the
marker is strict schema 1 with domain `rsi-experiment-store-v1`, and the topology
is the closed sorted set shown. Durable identity deliberately excludes ephemeral
inode/mtime, while every open still pins and rechecks the current named/opened
inode. Copying an otherwise valid bundle/store to another path changes this
identity and is rejected; a caller cannot substitute a copied store by supplying
its path.

Task 7 reservations currently persist only the raw digests of the stage and hook
deployment attestations, not their raw bytes, so V1 artifacts alone cannot
reconstruct `ExperimentRequest` or rerun `verify_promotion_plan()`. Task 8 closes
that issuance gap with strict V2 arms while leaving every exact V1 parser,
digest, replay and byte layout unchanged. Dispatch is by the complete key set,
integer schema version and domain; an optional-field mix is invalid.

The reusable `PromotionAuthorityV2` is a non-null exact 21-key mapping:

```text
schemaVersion=2, domain="rsi-promotion-authority-v2", candidateId,
task7CandidateBindingDigest, candidateCaptureLineageBindingDigest,
candidateFullRecordDigest, providerAuthorityBindingDigest,
candidateStateBindingDigest, providerContractDigest, providerVersionDigest,
providerRuntimeIdentityDigest, providerExecutionIdentityDigest,
verifierExecutionBaseIdentityDigest, namespaceMutationLeaseBackendIdentityDigest,
namespaceMutationLeaseCapabilityDigest, policyVersion, policyArtifactDigest,
artifactStoreIdentityDigest,
task8ControlPlaneVersion, task8AddendumDigest,
task8AddendumMarkdownDigest
```

Every digest is exactly `sha256:<64 lowercase hex>`. The authority digest is
derived, never self-stored:

```text
promotionAuthorityDigest = SHA256(canonical-no-LF(PromotionAuthorityV2))
```

Typed construction independently re-admits the five candidate/provider binding
preimages, provider runtime/execution identities, verifier execution-base
identity, namespace-mutation lease backend/capability, and policy artifact. It
enforces `candidateId` and Task 7 CandidateBinding equality;
`candidateFullRecordDigest == CurrentTrustedState.providerCandidateRecordDigest`;
provider contract/version equality across current state/request/plan; and
`policyVersion == ExperimentRequest.controlPlane.policyVersion` plus policy-
artifact equality. It independently opens the constructor-attested Task 7 store,
recomputes the frozen marker/path/topology preimage, and requires exact equality
with `artifactStoreIdentityDigest`; the result marker's flat store digest must
equal this nested value. Caller-echoed digests never construct this object.

`CurrentTrustedStateV2` has exactly the following 34 keys, no nulls:

```text
schemaVersion, domain, candidateDigest, providerCandidateStatus,
providerCandidateRecordDigest, canonicalRoot, registrationManifestDigest,
canonicalRootIdentityDigest, ownerContractHash, allowlistEntryDigest,
targetManifestDigest, rsiPackageDigest, rolloutManifestDigest,
providerContractDigest, providerVersionDigest, environmentIdentityDigest,
stageAttestationDigest, hookAttestationDigest, stageExpectationDigest,
hookExpectationDigest, allowedTargetEntryDigests, controlPlaneBindingDigest,
policyArtifactDigest, evaluatorArtifactDigest, metricRegistryArtifactDigest,
harnessPath, harnessBytesDigest, harnessBindingDigest, controlPlaneRootsDigest,
sandboxPolicyDigest, sandboxExecutorIdentityDigest,
sandboxCapabilityReportDigest, controlPlaneDigest, promotionAuthority
```

It requires `schemaVersion=2`, domain `rsi-current-trusted-state-v2`, and status
exactly `pending|deferred`. Pending or only the first/second fully bound,
unresolved, non-escalated deferral is admissible. Its provider record digest is
the complete strict folded record, never V1's synthetic four-field digest. Its
`controlPlaneDigest` is SHA-256 of exact canonical-no-LF bytes with keys:

```text
schemaVersion=2, domain="rsi-current-control-plane-v2", bindingDigest,
policyArtifactDigest, evaluatorArtifactDigest, metricRegistryArtifactDigest,
harnessBytesDigest, harnessBindingDigest, harnessPath,
controlPlaneRootsDigest, sandboxPolicyDigest, sandboxExecutorIdentityDigest,
sandboxCapabilityReportDigest, rsiPackageDigest, rolloutManifestDigest,
stageAttestationDigest, hookAttestationDigest, stageExpectationDigest,
hookExpectationDigest, allowedTargetEntryDigests, providerContractDigest,
providerVersionDigest, providerCandidateRecordDigest,
environmentIdentityDigest, promotionAuthority
```

The state fingerprint is SHA-256 of the full exact 34-key canonical-no-LF state,
including that digest and the byte-identical nested authority.

`ExperimentRequestV2` has exactly the V1 20-key request mapping plus the one
non-null `promotionAuthority` key (21 total), with `schemaVersion=2` and domain
`rsi-isolated-experiment-request-v2`. Its exact keys are:

```text
schemaVersion, domain, operationId, candidate, target, artifact,
stageAttestationRawDigest, hookAttestationRawDigest, stageExpectation,
hookExpectation, controlPlane, harness, sandboxPolicy, rolloutManifestDigest,
providerContractDigest, providerVersionDigest, rsiPackageDigest,
environmentIdentityDigest, createdAt, expiresAt, promotionAuthority
```

`ExperimentRequest.digest` is SHA-256 of those exact canonical-no-LF bytes. The
outer `request.json` reservation V2 remains exactly the nine keys
`{schemaVersion,domain,operationId,request,requestDigest,initialTrustedState,
initialTrustedStateFingerprint,trustedT0,maximumAttestationTtlSeconds}`, with
schema 2/domain `rsi-isolated-experiment-reservation-v2`. Its nested request and
state are strict V2 objects with byte-identical promotion authority;
`requestDigest` is the inner `ExperimentRequest.digest`. The raw SHA-256 of the
whole canonical-no-LF `request.json` is the distinct outer
`reservationDigest`; neither value may substitute for the other.

Every V2 bundle envelope has exactly six keys
`{schemaVersion,domain,operationId,requestDigest,payloadDigest,payload}`, schema
2, and respectively domain `rsi-experiment-manifest-artifact-v2`,
`rsi-experiment-attestation-artifact-v2`, or
`rsi-experiment-plan-artifact-v2`. Envelope `requestDigest` is the outer
reservation digest; `payloadDigest` is the exact canonical-no-LF payload digest.
The manifest payload has exactly 12 keys
`{decision,requestDigest,result,resultDigest,manifestPre,manifestPreDigest,
manifestPost,manifestPostDigest,replacement,sandboxExecution,
sandboxExecutionDigest,promotionAuthority}`; its own nested `requestDigest`
remains the inner request digest. The attestation payload has exactly five keys
`{decision,validationAttestation,validationAttestationDigest,
validationAttestationRawDigest,promotionAuthority}`. The plan payload is exactly
`{decision,plan,planDigest,promotionAuthority}`: eligible has strict non-null
`PromotionPlanV2` and digest; rejected has both `plan` and `planDigest` present as
JSON null. No other V2 field is nullable.

`ValidationAttestationV2` has exactly the V1 17 keys plus `domain` and
`promotionAuthority` (19 total):

```text
schemaVersion, domain, attestationId, issuer, signatureAlgorithm, signature,
candidateId, candidateDigest, diffDigest, targetPreHash, ownerContractHash,
evidenceRefs, controlPlane, testArtifactDigests, sandboxPolicyDigest, createdAt,
expiresAt, decision, promotionAuthority
```

It requires schema 2/domain `rsi-validation-attestation-v2`. Its signed mapping
contains all those fields except only `signature`; its body digest and platform
signature therefore bind the full authority. The deterministic ID seed is exact
canonical-no-LF `{schemaVersion:2,domain:"rsi-validation-attestation-id-v2",
operationId,requestDigest,result,diffDigest,promotionAuthorityDigest}`; the ID is
`validation_` plus the first 32 digest hex. Here `requestDigest` is exactly the
inner `ExperimentRequestV2.digest`, never the outer reservation digest. The
algorithm field is literally `signatureAlgorithm="platform-attestation-v1"`;
the signature text is exactly `"base64:"` plus canonical RFC 4648 standard-
alphabet padded base64, which decodes to 1..2,048 bytes and round-trips to the
same text. `validationAttestationDigest` is the
signed-body digest, whereas the bundle's raw-attestation digest covers the full
canonical bytes including signature; they are distinct typed values.

`PromotionPlanV2` has exactly the V1 19 keys plus `domain`, `controlPlane` and
`promotionAuthority` (22 total):

```text
schemaVersion, domain, planId, candidateId, candidateDigest,
validationAttestationDigest, allowlistEntryId, allowlistEntryDigest,
canonicalRootIdentityDigest, rolloutManifestDigest, stageAttestationDigest,
hookAttestationDigest, providerContractDigest, providerVersionDigest, target,
artifact, providerOperationIds, controlPlaneDigest, controlPlane, createdAt,
expiresAt, promotionAuthority
```

It requires schema 2/domain `rsi-promotion-plan-v2`; `controlPlane` is the exact
five-key `ValidationControlPlane` mapping. `planCore` is every key except only
`planId` and `providerOperationIds`. Deterministic derivation is:

```text
planCoreDigest = SHA256(canonical-no-LF({schemaVersion:2,
  domain:"rsi-promotion-plan-core-v2",planCore}))
operationSeed = canonical-no-LF({schemaVersion:2,
  domain:"rsi-provider-operation-id-v2",operationType,planCoreDigest})
providerOperationId = (`"op_snapshot_"` when operationType=`"snapshot"`,
  `"op_resolve_"` when operationType=`"resolve"`) + first 32 SHA256 hex
planIdentity = planCore plus providerOperationIds
planDigest = SHA256(canonical-no-LF(planIdentity))
planId = "plan_" + planDigest hex suffix
```

`operationType` is exactly the two-member enum `snapshot|resolve`.
`planCoreDigest` and `planDigest` in every mapping/seed are the full prefixed
`sha256:<64 lowercase hex>` strings; only the final operation/plan ID construction
slices the lowercase hex suffix. Bare plan-core input or another operation prefix
is not an alternate representation.

Thus the five candidate authority digests, Task 8 addendum/version, provider
runtime/execution, verifier, namespace-lease, artifact-store, and policy
identities enter attestation signature, plan
digest, and snapshot/resolve IDs. This also makes
`PromotionPlan.controlPlane.policyVersion` the exact run-start policy value;
there is no V1 plan field invented by shorthand.

Before the V2 result marker, the coordinator writes the already admitted exact
raw stage/hook bytes under fixed names `stage-deployment-attestation.json` and
`hook-deployment-attestation.json`. The strict marker has schema 2/domain
`rsi-experiment-result-marker-v2` and exactly these 23 keys, with no nulls:

```text
schemaVersion, domain, operationId, operationKey, requestDigest,
manifestArtifactDigest, attestationArtifactDigest, planArtifactDigest, decision,
stageDeploymentAttestationRef, stageDeploymentAttestationRawDigest,
hookDeploymentAttestationRef, hookDeploymentAttestationRawDigest,
artifactStoreIdentityDigest, task7CandidateBindingDigest,
candidateCaptureLineageBindingDigest, candidateFullRecordDigest,
providerAuthorityBindingDigest, candidateStateBindingDigest,
task8ControlPlaneVersion, task8AddendumDigest,
task8AddendumMarkdownDigest, controlPlaneDigest
```

The refs equal those fixed filenames; raw digests equal both persisted exact bytes
and the request raw-digest fields. The flat artifact-store digest, five flat
candidate digests, and three flat Task 8 control-plane/addendum fields equal the
nested authority; no provider,
runtime, verifier, policy, or namespace-lease authority field is duplicated in
the marker. For an eligible marker, `controlPlaneDigest` equals the current-state/
plan value and the non-null bound plan artifact's `PromotionAuthorityV2`
reconstructs all remaining provider runtime/execution, verifier, policy, and
namespace-lease authority. A rejected V2 marker remains strictly readable but is
Task 8-ineligible because its plan arm is null. The exact V2
operation membership is seven names: `request.json`, `manifest.json`, the one
digest-named attestation artifact, the one digest-named plan artifact, both fixed
raw deployment attestations, and `result.json`. All six prerequisite members are
written, synced and read back first; an eligible post-image is independently
resolved and verified; `result.json` is written last. Missing/extra members,
partial publication, late supplement, or V1/V2 mixture grants no authority. The
marker digest is the raw SHA-256 of its exact canonical-no-LF 23-key bytes.

The read-only Task 7 loader requires this V2 marker, resolves all refs only inside
the attested store, verifies every envelope/payload/authority cross-equality and
post-image, parses and re-admits both raw deployment attestations, and verifies
issuer/signature/scope/predecessor/TTL. Missing, swapped, tampered, wrong-role,
copied-store, or late-injected bytes fail. Caller/CLI bytes or paths are never
accepted and no second deployment-attestation resolver exists. Completed strict
V1 operations and rejected V2 operations remain readable and exactly replayable
but are Task 8-ineligible,
never rewritten, upgraded or supplemented. V2 publication-to-loader tests trap
all writes and compare unchanged full store manifests.

All V2 arms require `task8ControlPlaneVersion="1.1.0"` and the exact current
`task8AddendumDigest`/`task8AddendumMarkdownDigest` declared at the top of this
brief. The canonical registry JSON's `normativeMarkdownRawSha256` must equal the
Markdown digest. A pre-addendum, mismatched-version, tampered Markdown with
unchanged JSON, substituted artifact, or missing-digest plan is promotion-
ineligible until freshly revalidated under V2; the approved specification file
itself remains byte-identical.

The only Task 8 cross-run bridge is the `promotion.gated` origin receipt. Its exact
top-level fields are:

```text
schemaVersion=1, kind="promotion-origin", transactionId, runId, planDigest,
eventBinding, origin, experiment, providerHistoricalAuthority,
semanticBindingDigest
```

Define the exact canonical-final-LF semantic preimage first:

```json
{"schemaVersion":1,"domain":"rsi-promotion-origin-semantic-v1",
 "transactionId":"<tx>","runId":"<run>","planDigest":"sha256:<hex>",
 "origin":{},"experiment":{},"providerHistoricalAuthority":{}}
```

The three object values are the exact closed mappings below, not reduced
projections. `semanticBindingDigest` is SHA-256 of those exact canonical bytes.
The receipt then has exactly the top-level fields listed above, with that digest
and the deterministic event binding, and no `originReceiptDigest` field (which
would create a cycle). `originReceiptDigest` is SHA-256 of the exact complete
canonical-final-LF receipt bytes. The event payload/filename field named
`originDigest`, every later sidecar `originDigest`, and every seal comparison all
equal `originReceiptDigest`; none may equal
the semantic digest by shorthand. Thus:

```text
semanticBindingDigest = SHA256(canonical-final-LF semantic preimage)
originReceiptDigest   = SHA256(canonical-final-LF complete receipt)
originDigest          = originReceiptDigest
```

`eventBinding` is exactly `{eventId,eventType,idempotencyKey}`. `origin` is
exactly:

```text
originRunId, originClosedEventId, proposalReportEventId, admissionEventId,
captureEventId, evaluationEventId, providerCandidateId, captureOperationId,
candidateDraftDigest, providerCaptureRequestDigest,
ownerSkill, ownerPath, matchedScope, routeBinding,
providerBindingRef, providerBindingDigest,
routeReceiptRef, routeReceiptDigest, sourceObjects
```

`sourceObjects` is a sorted non-empty array of exact
`{objectClass,eventId,eventType,ref,digest}` entries. Its closed object classes
are `evaluation`, `observation`, `finding`, `proposal-report`, and
`close-freshness`; it includes the Task 6 evaluation, observation, every finding
used by `CandidateBuilder`, `reports/local-review-<originRunId>.json`, and the
`run.closed.payloadRef` historical-freshness sidecar. Null/missing report or
freshness refs are invalid. The validator reads those existing EventStore
objects, invokes the full ProposalService close-admission semantics, and reads the exact
`proposals/<originRunId>.json` provider binding, and the exact admission route
receipt. It recomputes the candidate draft, capture correlation, provider capture
request, route decision, owner/root/path/scope/binding, and completed origin
lifecycle. Merely naming a closed capture is insufficient.

`candidateDigest` is the independently recomputed Task 7
`CandidateBinding.digest` (also called `task7CandidateBindingDigest` below); it
is not a provider-computed field. `providerHistoricalAuthority` is exactly
`{ledgerIdentityDigest,gateProviderContractDigest,gateProviderVersionDigest,
gateProviderExecutionIdentityDigest,ledgerProtocolVersion,ledgerProtocolDigest,
foldProfileId,foldProfileDigest,ledgerPrefix,
latestAuthorityEventId,candidateId,
candidateFullRecordDigest,providerAuthorityBindingDigest,
task7CandidateBindingDigest,candidateCaptureLineageBindingDigest,
candidateStateBindingDigest}`. `ledgerPrefix` is the
closed nested `ProviderLedgerPrefix={byteLength,eventCount,lastEventId,
prefixSha256}`. `prefixSha256` covers the exact newline-terminated provider
ledger bytes `[0:byteLength]`; parsing that bounded prefix must yield exactly
`eventCount` valid events whose final event ID is `lastEventId`, plus the latest
candidate/review authority event ID and recomputed provider full-record and
provider-authority-binding digests. The adapter combines that provider-native
result with the independently recomputed Task 7 binding and verifies the
combined state-binding digest.
`ProviderHistoricalFoldProfile` is an immutable RSI-owned closed object
`{schemaVersion=1,profileId,supportedProviderEventSchemaVersions,
parserModuleDigest}` whose digest covers exact canonical bytes and whose parser
module is pure, bounded, byte-identical RSI code. `ProviderLedgerProtocol` is the
closed canonical object `{schemaVersion=1,
protocolVersion="skill-learning-ledger-lock-v1",ledgerName="events.jsonl",
lockName="events.lock",appendOnly=true,lockMode="flock-exclusive-writers",
eventFraming="strict-jsonl-final-lf",syncOrder="ledger-then-parent"}`. Its
version/digest are declared by the provider's versioned `skill-learning.guard`
contract and RSI requires the same. It also requires the canonical learning-home
root and both names to be current-UID regular/single-link/private objects and all
capture, review/defer, resolution, snapshot prepare/result/abort, operation-
result, and explicit initializer-repair read-modify-append paths to hold that
exact named lock. `ProviderLedgerIdentityV1` is the exact five-key CFL object
`{schemaVersion=1,domain="rsi-provider-ledger-v1",canonicalLearningHome,
gateProviderContractDigest,gateProviderVersionDigest}` and
`ledgerIdentityDigest=D(ProviderLedgerIdentityV1)`. `canonicalLearningHome` is
the constructor-configured NFC absolute real directory string, 1--4,096 UTF-8
bytes, with no NUL or trailing slash; filesystem root is forbidden and
`abspath(value)==realpath(value)==value`. It is admitted through the retained
nofollow directory descriptor. Both gate digests are prefixed Task 8 digests
byte-equal to the sibling fields in `providerHistoricalAuthority`. Ledger/lock
names, protocol and prefix are deliberately sibling authority and absent from
this acyclic identity object. The gate also records the
gate-time execution identity and the exact fold profile ID/digest. The prefix is historical gate authority.
Later append-only defer/resolve events may change current folded state but cannot
invalidate the unchanged prefix. A shorter, changed, non-newline-terminated,
substituted, or non-prefix ledger fails. Gate creation requires current provider
contract/version/execution identity to equal the plan and proves the selected
profile supports every prefix event schema. Later validation pins current live
contract/source/helper bytes and requires them to match an exact adapter-approved
`ProviderCompatibilityEntry={providerContractDigest,providerVersionDigest,
ledgerProtocolVersion,ledgerProtocolDigest}`; arbitrary current drift fails even
if a protocol string was left unchanged. It then opens the canonical lock/ledger
and folds the fixed prefix with the retained byte-identical old profile. It
compares every prefix/provider/Task7/combined digest but does not require the
approved current entry to equal the old gate source/version identity. A
backward-compatible provider upgrade therefore preserves old origins only if its
current contract still declares the same ledger protocol version/digest. A
protocol-changing upgrade requires an explicit migration outside Task 8 and old
guards fail until migrated. Otherwise a compatible upgrade preserves origins while
making a fresh plan bound to the old version stale. Missing/tampered profiles or
unsupported schemas fail; archived provider code is never executed.

`experiment` is exactly:

```text
artifactStoreIdentityDigest, experimentOperationId, reservationRef,
reservationDigest, experimentRequestDigest, bundleRef, bundleDigest,
attestationRef, validationAttestationDigest, planRef, planId, planDigest,
postImageRef, postImageDigest, stageAttestationRawRef,
stageAttestationRawDigest, hookAttestationRawRef,
hookAttestationRawDigest, task7CandidateBindingDigest,
candidateCaptureLineageBindingDigest, candidateFullRecordDigest,
providerAuthorityBindingDigest, candidateStateBindingDigest,
task8ControlPlaneVersion, task8AddendumDigest,
task8AddendumMarkdownDigest, controlPlaneDigest
```

The read-only Task 7 loader resolves every ref inside the attested artifact store
identity, reconstructs exact `ExperimentRequest`, `ExperimentBundle`,
`ValidationAttestation`, `PromotionPlan`, and post-image bytes, and recomputes the
whole chain. No EventStore sidecar may substitute for a Task 7 object.

The origin receipt is an immutable content-addressed origin seal, not authority
to skip admission during gate creation or an active/recoverable promotion. Task
8 has no closed retention/tombstone protocol for the Task 6 proposal report/
freshness sidecars or Task 7 experiment artifacts and may not invent a second
event type to create one. Therefore every promotion-origin semantic source, the
seal, the fixed provider prefix/profile, and every transaction/terminal evidence
object are permanently pinned in Task 8. A generic or fabricated
`payload.expired`, an unbound filesystem tombstone, or elapsed time never
authorizes their absence.

Gate creation and every active/recovery validation fully load and recompute all
Task 6/Task 7 lineage bytes outside provider and EventStore locks. A bounded
double scan yields an immutable `OriginLineageView`; the batch form covers every
active origin. Its exact in-memory value is
`{schemaVersion=1,originDigest,originReceiptDigest,semanticBindingDigest,
sourceWitnesses}`, where `sourceWitnesses` is the sorted exact array
`{objectClass,ref,rawDigest,device,inode,mode,nlink,byteSize,mtimeNs,ctimeNs}` for
every named source. It retains no caller path and is bounded by the receipt's
closed source count and the Task 6/7 per-object/aggregate byte limits.
`OriginLineageBatch` is the sorted unique map by continuation run/origin digest;
missing, duplicate, or extraneous views fail. Inside a provider→EventStore callback only
bounded digest comparisons and named/opened metadata rechecks occur—never MiB
artifact reads or hashing. After terminal close, a later unrelated append uses
the permanently retained, previously fully admitted terminal origin seal and
historical prefix/profile for structural validation, plus bounded presence/name/
metadata checks on the still-pinned source objects; it performs no source-body
byte reads under either lock. A missing source object remains corruption, while
tampered seal/prefix/profile always fails. The gate event has exact
promotion additions `{transactionId,planDigest,originDigest}` and
`payloadRef="transactions/<tx>-origin-<origin hex>.json"`. Storage requires the
filename digest, `payload.originDigest`, exact receipt bytes, event binding, and
recomputed `semanticBindingDigest`, `originReceiptDigest`, and origin/experiment
lineage all to agree. `staging.completed`,
`validation.completed`, and `promotion.planned` each add the same
`transactionId`; their existing refs/digests must point into that admitted Task 7
lineage and their `payloadRef` is null. No other external predecessor or import
sidecar is legal.

This conservative pinning does not change the approved retention policy or grant
new deletion authority. A later task may define a closed, authenticated
retention protocol and version the fold accordingly; until then no Task 8 origin
source is retention-eligible.

Cross-store validation never opens provider state while holding an EventStore
lock. The adapter exposes a separate read-only context
`guard_historical_prefix(expected: ProviderHistoricalAuthority,
expected_skill: str, task7_binding: CandidateBinding,
purpose: Literal["gate-create","revalidate"])`. The closed expectation
is the complete `providerHistoricalAuthority` object above, not merely its
prefix: the context compares ledger identity/prefix, the deliberately outer
`latestAuthorityEventId`, candidate ID, expected skill/root, both provider-native
digests, the independently admitted complete Task 7 binding/digest, and the
combined state digest. It is not a `new-apply` or `rollback` candidate guard: it
validates only the exact fixed ledger prefix, provider identity, and candidate
authority as folded at that prefix with its retained fold profile, and deliberately
imposes no requirement on the candidate's later current status or resolution.
It never appends, repairs, truncates, chmods, or creates storage. Under the
declared provider-before-EventStore order, this context creates a deeply
immutable `HistoricalProviderAuthorityView` from pinned inherited provider
ledger/lock FDs. It recomputes the exact prefix bytes/length/SHA/event count/final
event ID, ledger identity, latest authority event, provider full record/provider
authority binding, Task 7 candidate binding, and combined state binding. The gate
append receives this pre-admitted view, enters the EventStore lock while the
historical guard remains held, and compares it to the origin receipt;
`_validate_lifecycles()` performs no provider syscall or lock.

The bounded batch form
`guard_historical_prefixes(expectations, purpose) ->
HistoricalProviderAuthorityBatch` validates up to 4,096 sorted unique origins in
one locked bounded ledger read and produces a deeply immutable exact map by
continuation run/origin digest. The singular API delegates to it. Every Task 8
mutating fold/restart supplies exact coverage for all existing continuation
origins plus any gate being appended; missing, duplicate, or extraneous views
fail before a write. Once a store contains a Task 8 gate, every later append,
including an unrelated non-Task8 event, must receive a pre-admitted batch under
provider→EventStore order. A legacy/no-Task8 store uses the exact empty batch.
`_validate_lifecycles()` consumes the historical map plus the exact pre-admitted
`OriginLineageView/Batch` required for gate/active/recovery paths. It performs
only bounded digest/metadata comparisons while locked and never opens provider
state or reads/hashes large lineage bodies there. For already terminal origins on
unrelated appends it validates the permanent seal, historical prefix/profile,
terminal evidence, and pinned-object presence metadata without body reads. It
never accepts an unsealed receipt or treats a tombstone/expiry assertion as a
substitute. Gate-create mode additionally requires current provider
identity; revalidate mode uses the recorded pure fold profile and fixed prefix as
defined above.

The batch is algorithmically bounded rather than performing one full fold per
origin. It groups expectations by exact `(foldProfileId,foldProfileDigest)`,
requires at most 8 unique admitted profiles, sorts each group's requested prefix
boundaries, streams the ledger bytes once, and runs each profile only once up to
its greatest requested boundary while capturing immutable candidate states at
those boundaries. Before acquiring an EventStore lock or appending anything it
preflights `sum(max eventCount per unique profile) <= 200,000` decoded event
applications, in addition to the 100,000-event/64-MiB ledger and 4,096-origin
caps. Exceeding any bound returns typed no-authority; it never falls back to
quadratic folding. Work counters are observable in tests but not caller inputs.

To avoid self-deadlock, new-apply Guard A and every append-capable unresolved,
rollback, terminal-readback, or incident guard also accept all historical
expectations and fold/return the exact
`HistoricalProviderAuthorityBatch` from the same already-locked ledger FD. Their
EventStore callbacks consume that in-lock batch. They never acquire a second
historical flock, and a batch produced after lock release is insufficient for a
mutating callback: the same held guard must revalidate every prefix in its final
pre-callback check and, for current-candidate callbacks, its postcheck.
Historical-only unrelated appends use the batch guard alone. Gate/
Guard A, `apply.completed(applied)`, both `verification.completed` arms, not-
started/not-applied, `apply.reverted`, locked incident, and promoted-terminal
callbacks all follow this one-lock rule. Guard B performs no EventStore append
and therefore does not build or validate the historical batch: it checks only
current approved execution/protocol/candidate authority plus volatile target,
control, clock and latch witnesses, executes/classifies the exchange, and
post-refolds the current candidate before release.
Read-only diagnostics build the same historical-prefix view before opening/
folding EventStore, double-scan provider and event inputs, and report
`state-changing` on drift. Later unrelated EventStore appends validate the fixed
prefix, never mutable current provider status. Current candidate state is sampled
separately only by plan/current-state checks and provider guards.

The Task 4 phase guard is explicitly mode-partitioned. Existing `observe` and
`propose` runs retain their observation/evaluation/candidate terminal rules
unchanged. A `promote-safe` continuation with exact active-skill identity instead
requires the bridge and transaction invariants in this section and must not be
forced through the Task 4 observation/evaluation close rule. All other modes with
hashed active skills remain governed by their existing branch; this is not a
generic bypass.

### Closed event-to-sidecar authority map

Task 8 adds `objects/transactions`, `incidents/records`, and
`incidents/quarantine` to the fixed topology. The path allowlist is keyed by
event type and sidecar kind, not merely by parent directory:

| Event | Required `payloadRef` / exact sidecar kind |
|---|---|
| `promotion.gated` | `transactions/<tx>-origin-<digest>.json` / `promotion-origin` |
| `snapshot.created` | `transactions/<tx>-snapshot-<digest>.json` / `provider-snapshot` |
| `apply.started` | `transactions/<tx>-intent-<digest>.json` / `apply-intent` |
| `apply.completed` | `transactions/<tx>-readback-<digest>.json` / `apply-readback` |
| `verification.completed` | `transactions/<tx>-verification-<digest>.json` / `live-verification` |
| `apply.reverted` | `transactions/<tx>-readback-<digest>.json` / `rollback-readback` |
| `resolution.recorded` | `transactions/<tx>-resolution-<digest>.json` / `resolution-readback` |
| promote-safe `run.closed` | `transactions/<tx>-decision-<digest>.json` / `transaction-decision` |
| `incident.latched` | `incidents/records/<incidentId>.json` / fixed-CAS `incident-record` |

The sole non-event-bound auxiliary transaction object is an immutable authenticated verifier
receipt at
`transactions/<tx>-verifier-<verifierRequestDigest hex>.json` with kind
`verifier-receipt`. Its name is selected by the verifier request already committed
by `apply.completed(outcome=applied)`, not by untrusted directory contents or by
the later receipt digest. It has no direct event mapping and is authoritative only
through the exact live-verification sidecar referenced by
`verification.completed`; an orphan grants nothing. `resolution-readback` is not
an auxiliary exception: it is the one direct event-bound sidecar for
`resolution.recorded` in the table. No other auxiliary kind/name is legal.

In every transaction filename `<digest>` is exactly the 64-lowercase-hex suffix
of the referenced canonical document's `sha256:<hex>` digest; `<tx>` is the
already validated exact transaction ID. There are exactly two explicit
exceptions. The verifier receipt uses the event-bound request-digest suffix just
specified while its sidecar binds the separate exact receipt digest. The incident
record uses its fixed transaction-derived `<incidentId>.json` name as the
create-once selector, while `incidentDigest` in the event/decision binds the
complete exact record bytes. A prefix, truncation, alternate encoding, second
incident name, or digest of semantic JSON without the required framing fails.

For these events, null refs, wrong phase names, wrong directories, wrong
transaction IDs, wrong filename digests, wrong event bindings, and cross-kind
reuse fail closed. `staging.completed`/`validation.completed`/
`promotion.planned` require null `payloadRef`; legacy non-promotion event mappings
remain unchanged. An unreferenced transaction sidecar is an inert orphan. A
fixed incident record without its event selects only resumption of the exact
incident publication chain. Neither authorizes apply, rollback, target cleanup,
resolve, clean close, or a promotion decision. The fixed latch remains conservatively blocking
even if its event is missing; it never authorizes mutation.

EventRegistry implements closed payload-shape unions, never
`additionalProperties=true`. Existing V1/test/non-promotion arms retain their
exact current field sets for `promotion.gated`, `resolution.recorded`,
`incident.latched`, and `run.closed`; the Task 8 arms have the exact transaction
fields stated here. A `promote-safe` continuation must use only the Task 8 arm,
while another run cannot smuggle a transaction field into a legacy arm. Mixed or
partially populated arms fail. Likewise `promotion.planned.providerOperationIds`
is either the exact legacy tuple in a legacy lifecycle or the exact Task 8 object
`{snapshot,resolve}` in the continuation; it is never an open array/object union.

Every transaction evidence sidecar begins with exact common fields
`{schemaVersion,kind,transactionId,runId,planDigest,eventBinding}`. Its remaining
exact fields are:

- `provider-snapshot`: `originRef`, `originDigest`, `providerIdentity`,
  `candidateFullRecordDigest`, `providerAuthorityBindingDigest`,
  `task7CandidateBindingDigest`, `candidateCaptureLineageBindingDigest`,
  `candidateStateBindingDigest`, `snapshot`, `targetPre`.
- `apply-intent`: `originRef`, `originDigest`, `snapshotRef`, `snapshotDigest`,
  `candidateFullRecordDigest`, `providerAuthorityBindingDigest`,
  `task7CandidateBindingDigest`, `candidateCaptureLineageBindingDigest`,
  `candidateStateBindingDigest`,
  `providerGuardDigest`, `target`, `artifact`,
  `manifestPreHash`, `manifestPostHash`, `postImageRef`, `postImageDigest`,
  `retainedPreimageName`, `snapshotOperationId`, `resolveOperationId`,
  `verifierInvocationNonce`, `verifierExecutionBaseIdentityDigest`,
  `namespaceMutationLeaseBackendIdentityDigest`,
  `namespaceMutationLeaseCapabilityDigest`,
  `controlPlaneDigest`, `expiresAt`.
- `apply-readback`: `intentRef`, `intentDigest`, `outcome`, `reasonCode`,
  `target`, `retainedPreimage`, `preparedPostDisposition`, `preparedPost`,
  `cleanup`, `artifactHash`, `manifestHash`, `directorySynced`,
  `namespaceMutationLeaseEvidence`, `verifiedPostReadbackDigest`,
  `verifierCommitment`,
  `candidateFullRecordDigest`, `providerAuthorityBindingDigest`,
  `task7CandidateBindingDigest`, `candidateCaptureLineageBindingDigest`,
  `candidateStateBindingDigest`.
- `live-verification`: `readbackRef`, `readbackDigest`, `outcome`,
  `reasonCode`, `verifierReceipt`, `liveReadback`, `tests`, `attestationMatch`,
  `target`, `retainedPreimage`, `verifierExecutionBaseIdentityDigest`,
  `verifierInvocationNonce`, `verifierRequestDigest`, `controlPlaneDigest`,
  `namespaceMutationLeaseEvidence`,
  `candidateFullRecordDigest`,
  `providerAuthorityBindingDigest`, `task7CandidateBindingDigest`,
  `candidateCaptureLineageBindingDigest`, `candidateStateBindingDigest`.
- `rollback-readback`: `intentRef`, `intentDigest`, `readbackRef`,
  `readbackDigest`, `verificationRef`, `verificationDigest`,
  `providerFullRecordDigest`, `providerAuthorityBindingDigest`,
  `task7CandidateBindingDigest`, `candidateCaptureLineageBindingDigest`,
  `candidateStateBindingDigest`, `beforeTarget`, `afterTarget`,
  `retainedPreimage`, `displacedPost`, `cleanup`,
  `namespaceMutationLeaseEvidence`.
- `resolution-readback`: `verificationRef`, `verificationDigest`,
  `providerOperationId`, `resolutionId`,
  `providerResolutionRequestDigest`, `providerResolutionRecord`,
  `candidateFullRecordBeforeDigest`,
  `providerAuthorityBindingBeforeDigest`, `task7CandidateBindingDigest`,
  `candidateCaptureLineageBindingDigest`, `candidateStateBindingBeforeDigest`,
  `candidateFullRecordAfterDigest`, `providerAuthorityBindingAfterDigest`,
  `candidateStateBindingAfterDigest`, `providerResolutionRecordDigest`,
  `target`, `retainedPreimage`, `namespaceMutationLeaseEvidence`.
- `transaction-decision`: the exact outcome arm table below; there is no common
  optional-field superset.

`apply-readback`, `live-verification`, `rollback-readback`,
`resolution-readback`, every clean `transaction-decision`, and every
`incident-record` each contain exactly one top-level
`namespaceMutationLeaseEvidence` field; every clean arm requires its complete
non-null object, while only the incident null arms defined below may use JSON
null. No nested cleanup, exchange, phase, or other witness repeats a non-null
object: such a witness carries only the exact
`namespaceMutationLeaseEvidenceDigest` null/non-null arm defined below. There is
no lease-evidence auxiliary sidecar or selector; a digest is valid only when it
recomputes from that same containing document's sole top-level object.

Every reachable Task 8 evidence kind is admitted against one immutable
per-kind worst-case size vector before `apply.started`: `promotion-origin`,
`provider-snapshot`, `apply-intent`, both `apply-readback` arms,
`live-verification`, `rollback-readback`, `resolution-readback`, every
`transaction-decision` arm, `incident-record`, and the sole verifier-receipt
auxiliary. The vector is derived only from already admitted scalar bounds, the
aggregate raw UTF-8 path budget `P<=4 MiB`, member count `M<=4,096`, the closed
result sequence for that kind, and fixed schema maxima. Its exact non-persisted
six-key shape is `{kind,pathBudgetBytes,memberCount,protectedReadbackCount,
evidenceAndFramingBytes,outerEnvelopeBytes}`; all fields are nonnegative bounded
integers except the closed kind enum above, and none comes from caller JSON.
`P=pathBudgetBytes`, `M=memberCount`, and
`R(kind)=protectedReadbackCount`, the number of positionally distinct
protected-readback results reachable in one legal evidence sequence; the closed
sequence table proves `R(kind)<=2`. The last two components are bounded by
16 MiB each from their literal schemas.
Preflight never pretends that a future sidecar is complete and never computes
its exact canonical length.

The general bound is `MAX_TASK8_SIDECAR_BYTES=200*1024*1024`. Its closed maximum
is 120 MiB for at most `1+2R<=5` logical path renderings at six-byte JSON
escaping expansion, 48 MiB for at most `2+2R<=6` member-metadata renderings at
4,096 members and 2,048 canonical bytes per member, 16 MiB for the complete
bounded receipt/results/witness/framing vector, and 16 MiB for the outer
sidecar/provider/verifier/decision envelope. `resolution-readback` has the
stricter specialized 144-MiB bound below and `verifier-receipt` retains its
closed 64-KiB bound. Thus `cap(kind)` is exactly 144 MiB for
`resolution-readback`, 64 KiB for `verifier-receipt`, and 200 MiB for each other
listed event-bound sidecar/incident kind; there is no larger fallback.
For every non-resolution kind,
`preflightBound(kind)=6*P*(1+2R)+2048*M*(2+2R)+
evidenceAndFramingBytes+outerEnvelopeBytes`; the resolution kind uses its
stricter closed four-path/four-metadata formula below. The verifier vector has
`P=M=R=0` and its fixed components sum to at most 64 KiB.

Once a complete document exists at publication or replay, the writer/reader
computes its exact canonical-final-LF byte length exactly once and requires
`exactLength <= preflightBound(kind) <= cap(kind)`. The same per-kind cap,
path/member/result counters, and exact-length relation govern allocation,
create/write, `fstat`, nofollow read, strict parse, readback, replay, and every
downstream consumer. No stage silently reparses under a smaller or larger cap.
Any vector that cannot prove every reachable kind terminalizable fails before
`apply.started`; after that marker, an admitted sidecar cannot become oversized
merely because its later closed arm is selected.

`providerResolutionRecord` is the complete exact guarded-v2 raw provider
resolution mapping already defined by the provider fold;
`providerResolutionRecordDigest=D(providerResolutionRecord)` after strict
normalization to that exact closed mapping. Its provider request field remains
native bare 64-hex while this Task 8 digest is prefixed. Its digest and every
operation/request/candidate/authority/expiry field equal the provider ledger and
the before/after binding fields. `ResolutionReadbackV1` is the exact 24-key CFL
mapping
`{schemaVersion=1,kind="resolution-readback",transactionId,runId,planDigest,
eventBinding,verificationRef,verificationDigest,providerOperationId,
resolutionId,providerResolutionRequestDigest,providerResolutionRecord,
candidateFullRecordBeforeDigest,providerAuthorityBindingBeforeDigest,
task7CandidateBindingDigest,candidateCaptureLineageBindingDigest,
candidateStateBindingBeforeDigest,candidateFullRecordAfterDigest,
providerAuthorityBindingAfterDigest,candidateStateBindingAfterDigest,
providerResolutionRecordDigest,target,retainedPreimage,
namespaceMutationLeaseEvidence}` and has no other key.
`resolutionDigest=D(ResolutionReadbackV1)` and
the 64-hex suffix selects
`transactions/<tx>-resolution-<resolutionDigest hex>.json` without a scan.
`eventBinding` is the deterministic `resolution.recorded` event ID and the
sidecar verification ref/digest is its same-transaction affirmed predecessor.

The resolution sidecar is capped by
`MAX_RESOLUTION_READBACK_BYTES=144*1024*1024`. Its pre-apply vector computes
only this kind's closed worst-case length before allocation or target mutation;
its exact CFL length is computed only after the complete publication/replay
document exists under the general relation above. The worst case reserves
96 MiB for four logical copies of the admitted 4-MiB aggregate path budget at
the maximum six-byte JSON escaping expansion, 32 MiB for four copies of 4,096
members at 2,048 canonical metadata bytes each, 8 MiB for fixed
request/receipt/result/provider/envelope fields, and 8 MiB of framing margin.
The same 144-MiB cap and constituent counters govern every general-pipeline
stage. A vector that cannot satisfy the worst-case preflight is blocked before
`apply.started`; once it passes, every valid Task 7 path representation remains
terminalizable without truncating evidence even after provider resolve.

Publication is marker-last: create-once complete-write the exact sidecar, sync
it and `objects/transactions`, nofollow-readback identical bytes/name/inode/
mode/link, then append/fsync/read back the bounded event. Replay first admits the
exact final sidecar and provider record; a conflicting existing file fails and
an orphan grants no resolution, cleanup or close authority. The event payload
contains only the bounded IDs/digests below and `resolutionDigest`, stays below
the 64-KiB event limit, and its `payloadRef` is the exact sidecar ref.

An incident selector is deterministic before any incident observation, object or
event exists and is independent of a race-selected reason:

```text
incidentId = "incident_" + lowerhex(SHA256(canonical-no-LF({
  "domain":"rsi-promotion-incident-v1",
  "transactionId":transactionId
})))
incidentRecordRef = "incidents/records/" + incidentId + ".json"
```

There is exactly one immutable no-replace incident-record CAS per transaction.
Under the transaction lock, an `EEXIST` loser strictly re-admits and adopts the
winner even when its fresh local classifier would choose another reason. A
malformed, unsafe, wrong-transaction or digest-conflicting fixed winner is
corruption and an implicit latch; it is never repaired and no alternate record is
created or scanned for. The event and decision carry the SHA-256 of the winner's
exact canonical-final-LF bytes.

An `incident-record` has exactly 24 fields
`{schemaVersion,kind="incident-record",transactionId,runId,planDigest,
eventBinding,incidentId,reasonCode,rootIdentityDigest,artifactPath,
expectedPreHash,expectedPostHash,intentDigest,lastDurableEventId,targetWitness,
providerWitness,verifierWitness,reservedNameWitness,ancestryWitness,
exchangeWitness,phaseWitness,namespaceMutationLeaseEvidence,quarantineTargets,
requiresOperatorAction=true}`. The record
contains no digest/reference to a future quarantine or latch.

Its witness objects are closed unions:

- `targetWitness` is either `{classification="exact-pre"|"exact-post",target}`
  with the complete exact target witness and no other keys, or
  `{classification="other"|"unreadable",expectedRootIdentityDigest,
  relativePath,observedKind,errorCode}`. `observedKind` is one of
  `manifest-drift`, `named-object-drift`, `missing`, `mode-drift`, `link-drift`,
  `reserved-name-present`, `unreadable`; `errorCode` is null except for the
  sanitized unreadable enum. It stores no unknown bytes/hash/inode.
- `providerWitness` is exactly
  `{classification,candidateFullRecordDigest,providerAuthorityBindingDigest,
  resolutionRecordDigest,errorCode}`. `unresolved` has the first two digests and
  null resolution/error; `terminal` has all three digests and null error;
  `unknown` has all digests null and one sanitized provider error code.
- `verifierWitness` is exactly
  `{classification,receiptRef,receiptDigest,result,errorCode}`. `not-reached`
  has four nulls; `present` has a strict receipt ref/digest and result
  `passed|failed`, null error; `unavailable` has null ref/digest/result and the
  exact unavailable code; `unknown` likewise has only a sanitized unknown code.
- `reservedNameWitness` is exactly `{name,classification,metadata,
  authorityEventId,authorityDigest}`. `absent` has the last three values null;
  `live-fd-bound` has exact regular single-link metadata and null event/digest;
  `event-bound` has metadata plus the exact prior authorizing event/digest;
  `event-bound-absent-unsynced` has null metadata plus the exact prior
  authorizing event/digest and means only that an authorized unlink returned
  success while parent-sync/absence durability remained unproved;
  `event-bound-drift` has bounded observed metadata plus that prior event/digest;
  `event-bound-unknown` has null metadata plus that prior event/digest;
  `unbound-present` has bounded nofollow metadata and null authority; `unknown`
  has all but name/classification null. Recovery can never create
  `live-fd-bound`.
- `ancestryWitness` is exactly `{classification,witnessDigest,failureCode}`:
  `exact` has the digest/null error; `lost|unknown` has null digest and one closed
  failure code.
- `exchangeWitness` is null unless the reason contains `exchange` or
  `emergency-reverse`; then it is exactly the 10-key mapping `{direction,syscallResult,
  firstOperand,secondOperand,forwardClassification,reverseClassification,
  targetAfter,displacedPost,directorySynced,
  namespaceMutationLeaseEvidenceDigest}` with inapplicable reverse fields
  exactly null. The digest is non-null and equals `D` of the incident record's
  sole top-level evidence when an uninterrupted live holder reported the step;
  it is JSON null only for a recovery incident whose last durable event predates
  the possible backend mutation, because orphan receipt/result bytes grant no
  authority.
  `directorySynced` refers only to the one retained descriptor for
  the exact artifact parent, because both exchange operands are names in that
  same directory. It records both operands and never authorizes cleanup.
- `phaseWitness` is always present and is one of seven exact closed arms. Ordinary
  matrix reasons use only `{kind="ordinary"}`.
  `partial-apply-authority` uses
  `{kind="partial-apply-authority",expectedApplyStartedEventId,
  lastCompleteEventId,tailByteLength,tailRawSha256,parseState}` where
  `parseState=partial|corrupt`, the bounded raw digest covers the exact unreadable
  JSONL suffix and is rendered as a prefixed Task 8 digest, and no complete
  durable `apply.started` exists.
  `resolve-authority-expired` uses
  `{kind="resolve-authority-expired",expiresAt,observedAt,clockIdentityDigest}`
  with trusted `observedAt>=expiresAt` at the failed new-resolve boundary.
  `rollback-capability-lost` uses
  `{kind="rollback-capability-lost",expectedCapabilityDigest,
  observedCapabilityDigest,errorCode}`: exact drift has non-null observed digest/
  null error; unavailable or enforcer-loss has null observed digest and one closed
  `unsupported|drift|acquire-timeout|enforcer-lost` code. No other reason accepts
  one of these three arms, and those three reasons reject `ordinary`.
  `namespace-lease-unavailable|namespace-enforcer-lost` uses
  the exact seven-key mapping
  `{kind="namespace-lease-failure",backendIdentityDigest,capabilityDigest,
  operationClass,failureCode,possibleMutation,
  namespaceMutationLeaseEvidenceDigest}`; unavailable has one exact
  `unsupported|acquire-timeout|identity-drift` code and
  `possibleMutation=false` and a null digest, while enforcer loss has
  `failureCode="enforcer-lost"`, `possibleMutation=true`, and either the digest
  of the exact already authenticated top-level evidence (if a signed ambiguous
  backend result was recoverable) or JSON null. A non-null digest must equal
  `D` of that sole top-level object, which must verify completely but can never
  downgrade possible mutation or authorize cleanup.
  `prepared-temp-sync-failed` uses exactly
  `{kind="prepared-temp-sync-failed",preparedPost,originalFdHeld=true,
  fileSyncCompleted,parentSyncCompleted,failureCode}`. `preparedPost` is the
  exact still-live single-link inode/current-bytes witness and cross-equals the
  `live-fd-bound` reserved-name metadata. `failureCode=file-sync-failed`
  requires both booleans false; `parent-sync-failed` requires file true and
  parent false. The original FD and encompassing authenticated forward lease
  remain live through incident publication; recovery can never construct this
  arm.
  A `*-cleanup-absent-unsynced` reason uses exactly
  `{kind="cleanup-absent-unsynced",role,authorityEventId,authorityDigest,
  unlinkReturnedSuccess=true,parentSyncCompleted,absenceReadback,failureCode}`.
  `role` is `prepared-post|retained-preimage|displaced-post` and selects the
  matching reason/authorizing event. `parent-sync-failed` requires
  `parentSyncCompleted=false` and `absenceReadback=absent|unreadable`;
  `absence-readback-failed` requires parent true and readback `unreadable`.
  It cross-equals `reservedNameWitness.classification=event-bound-absent-
  unsynced`. Neither arm authorizes retry or cleanup.

The incident record's top-level `namespaceMutationLeaseEvidence` is the exact
still-live encompassing operation evidence, or on recovery the fresh
`incident-classification` evidence used for its protected observation, or
JSON null only when acquisition never succeeded or enforcer loss made a protected
result unprovable. A recovery classifier never reuses the dead holder's receipt;
even when the missing causal event makes the mutation ambiguous, any non-null
evidence describes only the fresh current observation. It is the record's only
complete lease-evidence object. Any exchange/namespace-failure phase witness
carries only its digest, non-null exactly when it refers to that object and then
byte-equal to `D(namespaceMutationLeaseEvidence)`. A non-null top-level value
must verify completely and match the predecessor, operation class, target scope,
and classifier result; it documents the observation but never authorizes cleanup.

For a matrix predecessor before `apply.started`, `intentDigest` is exactly null;
for `apply.started` or later it is the exact event-bound intent digest. Expected
hashes still come from the plan. `quarantineTargets` is exactly
`[{rootIdentityDigest,artifactPath}]`. Any extra/missing witness key, wrong union
null, or mismatch between reason and classification fails. Its quarantine
document is exact
`{schemaVersion,kind="promotion-quarantine",rootIdentityDigest,transactionId,
incidentId,incidentRecordDigest,observedState,requiresOperatorAction=true}`.
The fixed latch is exact
`{schemaVersion,kind="promotion-latch",incidentId,transactionId,runId,
planDigest,candidateId,rootIdentityDigest,artifactPath,expectedPreHash,
expectedPostHash,observedState,intentDigest,incidentRecordDigest,
quarantineDisposition,blockingQuarantineDigest,requiresOperatorAction=true}`.
In both objects `observedState` equals the incident record's
`targetWitness.classification`; no independent state label is accepted.
First exact CAS wins; none of
these documents is repaired, overwritten, or cleared by Task 8.

Publication is directionally acyclic: publish/adopt the one fixed incident record
CAS first; attempt
the fixed per-root quarantine CAS second; attempt the fixed global latch CAS
third; only then append the event. A quarantine CAS result is exactly
`quarantineDisposition=created|preexisting` plus
`blockingQuarantineDigest`. Created means the quarantine document above binds
the local incident; preexisting means the exact strict existing document blocks
the root and must not be claimed as local. If this transaction creates the
latch, that latch binds its local incident plus the quarantine disposition and
blocking digest. If another transaction
already won, strictly read the immutable existing latch and do not claim it
belongs to the local incident. In addition to the unchanged normative common
payload fields, the Task 8 `incident.latched` arm has exactly the transaction
fields `{transactionId,incidentDigest,quarantineRef,quarantineDisposition,
blockingQuarantineDigest,latchRef,latchDisposition,blockingLatchDigest}`, where
both dispositions are `created` or `preexisting`, `incidentDigest` is the local
referenced record, and `blocking*Digest` is the exact created or preexisting
object digest. Created objects must bind the local predecessors; preexisting
objects must be valid but must not be asserted to match them. The incident
terminal `transaction-decision` binds the same local refs, both dispositions,
and both blocking digests. Thus concurrent same-root or different-root incidents can
both close quarantined while only the CAS winner claims latch creation. No
document may self-bind or name a future digest, and an impossible cycle or
reordered/partial publication grants no close authority.

The Task 8 incident arm has this total closed predecessor/reason matrix;
causation and `lastDurableEventId` name the same predecessor:

| Predecessor | Closed reason codes |
|---|---|
| `run.started`, `promotion.gated`, `staging.completed`, or `validation.completed` | `preapply-provider-terminal`, `preapply-provider-unknown`, `namespace-lease-unavailable`, `namespace-enforcer-lost`, `preexisting-latch` |
| `promotion.planned` or `snapshot.created` | `preapply-provider-terminal`, `preapply-provider-unknown`, `partial-apply-authority`, `namespace-lease-unavailable`, `namespace-enforcer-lost`, `preexisting-latch` |
| `apply.started` | `prepared-temp-unknown`, `prepared-temp-sync-failed`, `pre-state-drift`, `pre-state-unreadable`, `provider-terminal-after-apply-start`, `provider-state-unknown`, `namespace-lease-unavailable`, `namespace-enforcer-lost`, `preexisting-latch`, `forward-exchange-ambiguous`, `emergency-reverse`, `emergency-reverse-ambiguous`, `post-state-drift`, `post-state-unreadable`, `retained-preimage-drift`, `ancestry-lost` |
| `apply.completed(outcome=applied)` | `post-state-drift`, `post-state-unreadable`, `retained-preimage-drift`, `provider-terminal-before-verification`, `provider-state-unknown`, `verifier-state-unknown`, `namespace-lease-unavailable`, `namespace-enforcer-lost`, `preexisting-latch`, `ancestry-lost` |
| `apply.completed(outcome=not-applied)` | `prepared-temp-drift`, `prepared-temp-cleanup-failed`, `prepared-temp-cleanup-absent-unsynced`, `pre-state-drift`, `pre-state-unreadable`, `provider-resolved-before-close`, `provider-state-unknown`, `namespace-lease-unavailable`, `namespace-enforcer-lost`, `preexisting-latch`, `ancestry-lost` |
| `verification.completed(outcome=affirmed)` | `post-state-drift`, `post-state-unreadable`, `retained-preimage-drift`, `resolve-authority-expired`, `resolve-authority-drift`, `competing-resolution`, `provider-state-unknown`, `verifier-receipt-invalid`, `namespace-lease-unavailable`, `namespace-enforcer-lost`, `preexisting-latch`, `ancestry-lost` |
| `verification.completed(outcome=rollback-armed)` | `post-state-drift`, `post-state-unreadable`, `retained-preimage-drift`, `displaced-post-drift`, `rollback-authority-blocked`, `provider-state-unknown`, `rollback-capability-lost`, `rollback-exchange-ambiguous`, `verifier-receipt-invalid`, `namespace-lease-unavailable`, `namespace-enforcer-lost`, `preexisting-latch`, `ancestry-lost` |
| `resolution.recorded` | `resolved-target-not-post`, `post-state-unreadable`, `retained-preimage-drift`, `retained-preimage-cleanup-failed`, `retained-preimage-cleanup-absent-unsynced`, `resolved-provider-mismatch`, `provider-state-unknown`, `namespace-lease-unavailable`, `namespace-enforcer-lost`, `preexisting-latch`, `ancestry-lost` |
| `apply.reverted` | `displaced-post-drift`, `displaced-post-cleanup-failed`, `displaced-post-cleanup-absent-unsynced`, `rollback-pre-state-drift`, `pre-state-unreadable`, `provider-resolved-before-close`, `provider-state-unknown`, `namespace-lease-unavailable`, `namespace-enforcer-lost`, `preexisting-latch`, `ancestry-lost` |

Reason/witness agreement is total: every `*-unreadable` requires unreadable
target; target drift ordinarily requires `other`, except `post-state-drift`
after an applied/affirmed predecessor permits `exact-pre|other`,
`resolved-target-not-post` permits `exact-pre|other`, and
`rollback-pre-state-drift` permits `exact-post|other`; every provider-
terminal/resolved/competing/blocked reason requires terminal provider; every
provider-unknown reason requires unknown provider; `verifier-state-unknown` and
`verifier-receipt-invalid` require unknown verifier; `preexisting-latch` requires
the strictly validated existing latch; `prepared-temp-unknown` requires
`unbound-present|unknown`; ancestry reasons require lost/unknown ancestry; and
exchange/emergency reasons require the non-null exchange witness. All other
exchange witnesses are null. Namespace-lease reasons require the exact lease-
failure phase arm and an `unreadable` target sentinel because a stable protected
classification was unavailable; they are selected before target classification,
so the sentinel cannot relabel the lease failure as ordinary target drift.
Enforcer loss is always possible-mutation and
must not be downgraded by a later-looking exact hash. `retained-preimage-drift` requires a non-event-
bound/unknown retained-preimage witness or absence while cleanup is not yet
authorized; `displaced-post-drift` requires the corresponding non-event-bound/
unknown post witness or absence before its cleanup authority. Once `resolution.recorded` or
`apply.reverted` is durable, absence is authorized-cleanup recovery, not drift.
Cleanup-failed reasons require the exact event-bound inode still present after an
authorized unlink/sync/readback failure; `prepared-temp-unknown` requires no
authority event. `prepared-temp-drift` requires a causal not-applied retained arm
but current `reservedNameWitness.classification=event-bound-drift|event-bound-
unknown`; it preserves the replaced/unknown name and is quarantined. At rollback-
armed, `displaced-post-drift` is legal only after
reverse is proven with target exact pre. Known
exact-pre/post reasons require that exact target classification.
`prepared-temp-sync-failed` requires the exact live-FD phase arm, a
`live-fd-bound` reserved-name witness, exact pre target, and an authenticated
still-live forward lease. Each `*-cleanup-absent-unsynced` reason requires the
matching cleanup phase arm and `event-bound-absent-unsynced` reserved-name
witness; it wins over generic target/readback or cleanup failure and never claims
durable absence. Ordinary `*-cleanup-failed` continues to mean the exact
event-bound inode is still present after failed authorized cleanup.

Classification has one closed first-match order: after a rollback-armed event,
the post-crash exact-pre/displaced-post shape without `apply.reverted` is
`rollback-exchange-ambiguous`; after `apply.started`, the post-crash exact-post/
swap-pre shape without `apply.completed` is `forward-exchange-ambiguous`; then an
unbound/unknown reserved name with no authenticated transition is
`prepared-temp-unknown`; then authenticated namespace lease/enforcer or
rollback-capability failure;
then preexisting latch; live-FD prepared sync failure; authorized unlink with
unproved sync/readback; ancestry loss; provider unknown; phase-terminal/provider
mismatch; verifier invalid/unknown; expected swap identity drift; target
unreadable; readable target drift; then exchange/cleanup failure.
Normal exact continuation from an already durable transition event is never an
incident. In particular, target exact-pre plus an unbound-present/unknown
reserved name after `apply.started` selects `prepared-temp-unknown` regardless of
its bytes, but target exact-post plus the exact expected displaced preimage
selects `forward-exchange-ambiguous`; neither arm upgrades the missing event.

No other Task 8 incident predecessor/reason pair is accepted. Crash at incident
record, quarantine CAS, latch CAS, event, decision, or close resumes the exact
create-once chain from durable objects; it never rewrites a winner or skips a
predecessor. A fixed blocking latch remains effective even when its event is
missing, while an unselected/alternate record name grants no authority. Recovery
derives and opens only the one fixed transaction record path, validates its exact
name, bytes, digest, transaction and deterministic event binding, and resumes that
immutable winner even if live observations later differ. It performs no directory
content scan and never chooses among reason-derived files. An invalid fixed
record or any alternate incident record for that transaction is corrupt and
leaves the fixed latch/implicit transaction latch blocking. A no-replace race
loser rereads and resumes the one winner rather than deriving a second incident.

`providerIdentity` is exactly `{providerContractDigest,providerVersionDigest,
providerRuntimeIdentityDigest,providerExecutionIdentityDigest}`.
`target`/`targetPre`/`beforeTarget`/`afterTarget` are the complete exact
`TargetWitnessV1` mappings defined below, including their schema/domain/UID.
`retainedPreimage` is either null or exactly
`{name,device,inode,mode,uid,nlink,size,sha256}`. Every non-null prepared-post,
retained-preimage or displaced-post named witness has that same exact shape.
For such a witness `w`, define the sole projection
`objectFromNamed(w)={device:w.device,inode:w.inode,type:"regular",mode:w.mode,
uid:w.uid,nlink:w.nlink,size:w.size,sha256:w.sha256}`. Projection is fieldwise;
the differently shaped objects are never claimed byte-equal. `cleanup` is exactly
the nine-key mapping
`{disposition,name,device,inode,nlinkBefore,removed,absentAfter,directorySynced,
namespaceMutationLeaseEvidenceDigest}`. It is a closed three-arm union.
`pending-event-bound` records the exact still-present inode before cleanup with
`removed=false,absentAfter=false,directorySynced=true` and
`namespaceMutationLeaseEvidenceDigest=null`; the causal top-level apply/revert
lease evidence separately proves that parent sync. `removed-now` records the
same causal identity with `removed=true,absentAfter=true,directorySynced=true`
and a non-null digest equal to `D` of the containing sidecar's sole top-level
cleanup-lease evidence. `already-absent-authorized` retains the exact identity
from the causal event but truthfully records
`removed=false,absentAfter=true,directorySynced=true` and the fresh matching
cleanup-evidence digest whose top-level object proves protected absence and
parent sync. No other boolean/null/digest combination is legal. Every
`directorySynced=true` in apply, rollback, incident, cleanup, or decision
evidence means the one exact retained artifact-parent dirfd was synced after the
claimed same-parent name transition; it never denotes the canonical root or a
second directory. All file
witnesses require current UID, regular type, `nlink=1`, safe mode, exact named
inode, and the admitted raw/manifest digest; numeric fields are non-negative
bounded integers. Every final cleanup arm's sidecar carries exactly one non-null
top-level authenticated lease-evidence object whose receipt operation class is
exactly `prepared-post-cleanup`,
`retained-preimage-cleanup`, or `displaced-post-cleanup` for that name; an absent-
without-unlink recovery proof still reacquires the corresponding lease across the
final name check/readback and records its digest only in `cleanup`. Null, reused,
wrong-name, live-expired, timestamp-invalid, incomplete-result, or wrong-operation
lease evidence cannot authorize cleanup. A historically read event-bound
evidence object does not become invalid merely because current wall-clock time is
later than its receipt expiry; its signatures, causal binding, and original
`issuedAt<=completedAt<expiresAt` relation remain mandatory, and it never
authorizes a new mutation without a fresh live lease.

The one swap/preimage name is deterministic, not caller-selected:

```text
transactionHex = transactionId after the exact "tx_" prefix (64 lowercase hex)
retainedPreimageName = ".rsi-promotion-swap-" + transactionHex
retainedPreimageRelativePath = POSIX-parent(plan.artifact.relativePath)
                               + "/" + retainedPreimageName
```

For a root-level artifact the parent component is omitted. The resulting UTF-8
relative path is normalized once, has no empty/`.`/`..` component, slash,
backslash, NUL, alternate normalization, or platform alias in its filename, and
must remain inside the attested root through the retained ancestry FDs. It is a
reserved Task 8 name and must be absent before `apply.started`; every other
reserved-name match is a preexisting-latch incident, never adopted. At creation,
the service uses the already retained exact artifact-parent dirfd; it never
creates a swap/preimage in the canonical root when the artifact is nested.
Forward, emergency-reverse, and rollback exchanges pass the target basename and
this swap basename relative to that same dirfd. A cross-directory exchange is
unsupported and fails before `apply.started`, so there is exactly one parent
directory sync and no reachable crash state between two directory syncs.
At creation,
the new inode must differ from the target, every ancestor/control/provider/
EventStore/snapshot inode, and every other active transaction inode; the service
retains the original `O_EXCL|O_NOFOLLOW` FD and continually proves name↔FD,
`nlink=1`, mode, UID, device, and bytes. Only that live FD capability can bind the
prepared inode to a not-applied receipt or present it to exchange. A matching
pathname/hash without the original live FD is not ownership evidence.

`apply.completed` is a closed union matching the specification's “actual
post-hash or typed failure”:

- `outcome=applied`: `reasonCode=null`; event payload includes
  `transactionId`, `outcome`, `actualPostHash`, `actualManifestPostHash`, and
  `readbackDigest`; the sidecar proves exact post plus the exact retained
  preimage, uses `preparedPostDisposition=exchanged`, binds `preparedPost` to the
  exact post inode now at the target name, has `cleanup=null`, and contains the
  exact committed verifier request/nonce arm defined below. Its non-null
  top-level `directorySynced` is exactly true and cross-equals the performed
  forward-exchange backend result. Its non-null
  `namespaceMutationLeaseEvidence` embeds the authenticated `forward-apply`
  receipt plus the signed backend results used for the mutation and protected
  classification.
- `outcome=not-applied`: event payload includes `transactionId`, `outcome`,
  `actualPreHash`, `actualManifestPreHash`, `reasonCode`, and `readbackDigest`;
  the sidecar has `retainedPreimage=null` and proves exact pre. Its
  `preparedPostDisposition` is either `never-created` with
  `preparedPost=cleanup=null`, or `retained` with the exact transaction-owned
  prepared-post `(name,device,inode,mode,uid,nlink,size,sha256)` witness for its
  current complete or partial bytes and `cleanup=null`. Both not-applied arms use
  non-null authenticated classification lease evidence and the exact
  `verifierCommitment.state=not-reached` null arm. The `retained` arm may be
  published only by the uninterrupted process that still holds and revalidates
  the original exclusive-create FD; pathname/bytes alone never select it. The readback/event must
  be durable before any retained temp is deleted; it authorizes cleanup of only
  that exact inode. The later `transaction-decision(outcome=not-applied)` proves
  either truthful final cleanup arm: `removed-now` has
  `removed=true,absentAfter=true,directorySynced=true`; crash recovery after an
  already completed unlink has `already-absent-authorized`,
  `removed=false,absentAfter=true,directorySynced=true`. The closed reason codes
  are `authority-expired`, `candidate-drift`, `control-disabled`,
  `policy-drift`, `kill-switch-active`, `allowlist-drift`, `root-drift`,
  `control-plane-drift`, `target-drift`, `temp-create-failed`,
  `temp-write-failed`, `temp-sync-failed`,
  `pre-exchange-check-failed`, and `capability-lost`. An unknown, partial,
  mismatched, or unremovable temp is `other` and latches; exact pre alone cannot
  hide it. Here `capability-lost` means only the requested atomic mutation
  sub-capability was denied before any possible mutation while an authenticated
  `forward-apply` live-attempt lease or `unresolved-terminal` no-create restart
  lease continued to enforce exact pre through the event callback.
  Failure to acquire/retain that lease, unknown lease liveness, or enforcer loss
  uses the incident matrix and cannot emit clean not-applied. This terminalizes a durable `apply.started` after a pre-exchange
  failure and permits only a failed/deferred close after authorized cleanup. A
  crash after the event resumes that exact cleanup; no pre-event `removed` arm is
  valid. If the process dies before that event, only an absent reserved name may
  discharge as `never-created`; any present unbound reserved object is
  `prepared-temp-unknown`, is preserved, and incidents. It can never be relabelled
  as an apply or rollback.
  The retained arm's evidence is exactly `forward-apply`. A never-created arm
  produced by the uninterrupted live create attempt also uses `forward-apply`
  with the truthful create-not-performed sequence. A post-crash exact-pre/absent
  restart instead uses a fresh `unresolved-terminal` protected-readback-only
  evidence arm and never fabricates a create attempt. `directorySynced` is JSON
  null for `never-created`; for `retained` it is
  exactly true and cross-equals the
  `prepared-post-create-write/performed` backend result. A `temp-write-failed`
  or `temp-sync-failed` arm is clean only when the uninterrupted original-FD
  holder subsequently syncs the exact current partial-or-complete prepared
  inode and its artifact parent successfully under the same still-live lease.
  Persistent sync failure with the live original FD selects the exact
  `prepared-temp-sync-failed` ambiguous incident arm and
  `prepared-post-create-write/performed-unsynced` result; loss of that FD uses
  `prepared-temp-unknown`. This field never
  claims a target-name transition.

### Durable live-verifier authority

The constructor admits one acyclic `VerifierExecutionBaseIdentity` object. Its
exact canonical-final-LF mapping is
`{schemaVersion=1,domain="rsi-live-verifier-execution-base-v1",verifierName,
verifierVersion,implementationDigest,configurationDigest,runtimeIdentityDigest,
receiptParserDigest,receiptSignerKeyId,receiptSignerPublicKeyDigest,
receiptSignerCapabilityDigest,receiptSignatureAlgorithm}`. Strings are nonempty
bounded UTF-8: name/version/key ID are 1--128 ASCII characters matching
`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`; every named digest is an exact prefixed
Task 8 digest; integer/domain fields are exact; and `receiptSignatureAlgorithm` is literally
`platform-attestation-v1`. Its digest is
`verifierExecutionBaseIdentityDigest = "sha256:" +
lowerhex(SHA256(exactCanonicalFinalLfBytes))`. This base object contains no
`controlPlaneDigest`, promotion authority, plan digest, or object that contains
one of them; therefore `controlPlaneDigest -> PromotionAuthorityV2 ->
verifierExecutionBaseIdentityDigest` is directional and acyclic. The base digest
is pinned in Task 7 V2 authority. Source/runtime/configuration, verification-key,
and strict receipt-parser path/bytes/mode/link/identity drift rejects before
verifier execution or receipt admission. A constructor-approved immutable
registry resolves the digest to exact opened execution/parser/key objects; a
caller path, claimed digest, or late file cannot select them.

`receiptSignerCapabilityDigest` binds the exact canonical-final-LF object
`{schemaVersion=1,domain="rsi-verifier-receipt-signer-capability-v1",
signerKeyId,signerPublicKeyDigest,
capability="event-bound-verifier-receipt-signing",nonExportableKey=true,
coordinatorOnlyInvocation=true,durableApplyCompletedRequired=true,
terminalNonIssuanceSigning=true,singleTerminalPerRequest=true,
receiptPathAbsenceAttestation=true,byteIdenticalReplay=true}`. Its prefixed SHA-256 digest and key fields equal the
base identity and are independently attested by the constructor registry. The
schema version is integer 1, the domain/capability strings are literal, the key
ID obeys the exact base-ID grammar, the public-key digest is prefixed, all seven
flags are JSON booleans exactly true, and no key is nullable or extra. The
signer refuses a request unless it descriptor-verifies the exact durable applied
event/readback named below; repeated signing of the same request returns
one byte-identical terminal body—receipt or signed non-issuance—and can never
issue the other arm for that request. A caller-visible key, generic signing callback, or
self-reported capability cannot construct this identity.

During trusted intent construction and before `apply.started`, the parent draws
exactly 32 bytes from its constructor-attested CSPRNG and renders them as the 64
lowercase-hex `verifierInvocationNonce`; it is never caller supplied or reused by
another transaction. The immutable intent sidecar carries that nonce plus the
base and final control-plane digests, and `apply.started` binds the intent digest,
so a crash can never choose a second nonce. For an exact applied target define
`verifiedPostReadbackDigest` as the prefixed digest of the exact canonical-final-LF mapping
`{schemaVersion=1,domain="rsi-applied-target-readback-v1",transactionId,
planDigest,target,retainedPreimage,artifactHash,manifestHash,directorySynced}`;
this preimage contains no verifier request, event, or sidecar digest. Define
`VerifierRequestCore` as the exact canonical-final-LF mapping
`{schemaVersion=1,domain="rsi-live-verifier-request-core-v1",transactionId,runId,
planDigest,verifiedPostReadbackDigest,validationAttestationDigest,
verifierExecutionBaseIdentityDigest,controlPlaneDigest,
verifierInvocationNonce,expiresAt}` and define `verifierRequestCoreDigest` as its
prefixed SHA-256. The applied `apply-readback` commits
`verifierCommitment` exactly as `{state="committed",verifierInvocationNonce,
verifierRequestCoreDigest,verifierExecutionBaseIdentityDigest,
controlPlaneDigest}`; the sidecar independently reconstructs the complete core.
Its separate `verifiedPostReadbackDigest` field equals the core preimage. A
not-applied readback has `verifiedPostReadbackDigest=null` and instead uses the exact five-key
`{state="not-reached",verifierInvocationNonce=null,verifierRequestCoreDigest=null,
verifierExecutionBaseIdentityDigest=null,controlPlaneDigest=null}`. Mixed or
late-created commitments fail.

Only after the applied sidecar and `apply.completed` event are durably fsynced and
strictly read back does the service construct the final canonical-final-LF
`VerifierRequest` exactly as
`{schemaVersion=1,domain="rsi-live-verifier-request-v1",core,
verifierRequestCoreDigest,applyCompletedEventId,applyCompletedEventDigest,
applyReadbackRef,applyReadbackDigest}`. `core` is byte-equal to the committed core;
the readback ref/digest are the event's exact sidecar binding; and
`applyCompletedEventDigest` is the prefixed SHA-256 of the exact persisted
canonical event JSONL line including its one LF. `verifierRequestDigest` is the
prefixed SHA-256 of this final request. This DAG is acyclic:
base/authority/plan -> intent nonce -> post-readback/core -> applied sidecar ->
applied event -> final request -> receipt -> verification. The signer capability
itself verifies the durable event/readback before issuing, so no valid receipt can
predate `apply.completed`. Recovery deterministically reconstructs this one final
request and nonce; it never generates a second nonce or scans for another request.

The trusted verifier receives only that admitted request and exact post readback,
and has no EventStore path or write descriptor. Its authenticated
canonical-final-LF `verifier-receipt` is at most 64 KiB and has exactly
`{schemaVersion=1,domain="rsi-live-verifier-receipt-v1",
kind="verifier-receipt",verifierRequestDigest,receiptSignerKeyId,
signatureAlgorithm,issuedAt,liveReadback,tests,attestationMatch,result,signature}`.
Transaction/run/plan/control/nonce/base identity are reconstructed from the
strict signed final request rather than redundantly copied into the receipt.
`liveReadback` is exactly
`{artifactHash,manifestHash,targetWitnessDigest,ancestryWitnessDigest}`; `tests`
is exactly `{skillValidationPassed,contractValidationPassed,targetTestsPassed}`;
`attestationMatch` is boolean; `result=passed|failed` equals the conjunction of
the three tests and attestation match. `issuedAt` is a strict trusted UTC value
not earlier than `apply.completed.createdAt` and not later than the request TTL.
`receiptSignerKeyId` equals
`VerifierExecutionBaseIdentity.receiptSignerKeyId`;
`signatureAlgorithm` is literally `platform-attestation-v1`. Let
`receiptSignedMapping` be the exact receipt mapping minus only `signature`, and
let `receiptBodyDigest` be its prefixed SHA-256 over exact canonical-final-LF
bytes. The signer signs only the domain-separated prefixed digest of exact
canonical-final-LF `{schemaVersion=1,
domain="rsi-verifier-receipt-signature-v1",receiptBodyDigest,
verifierRequestDigest,receiptSignerCapabilityDigest}`. `signature` is
exactly `"base64:"` plus canonical RFC 4648 standard-alphabet padded base64,
decodes to 1..2,048 bytes, and must verify that domain-separated digest with the exact
constructor-pinned signer key ID/public-key digest. Byte equality without this
verification is never provenance.

The parent publishes the verified receipt only at
`objects/transactions/<tx>-verifier-<verifierRequestDigest hex>.json`, mode
`0600`, current UID, regular type and `nlink=1`; it complete-writes create-once,
syncs the file and that exact directory, then nofollow-readbacks identical bytes,
name, inode and mode. On `EEXIST`, replay is accepted only after the pinned parser
recomputes the event-bound request/nonce/base/control-plane fields, exact receipt
digest and signature. Invalid, unauthenticated, conflicting, unsafe, or
request-mismatched residue is unknown, never overwritten, repaired, or adopted.
The digest-pinned parser uses existing-only nofollow reads capped at 64 KiB,
rejects duplicate/additional keys and noncanonical framing, double-checks
named/opened identity, and performs no creation, repair, chmod, temp recovery, or
normalization. The fresh nonce makes the selector unpredictable before the
intent commitment; afterward it is readable and is not a secret. Pinned-key
signature verification plus the coordinator-only signer capability—not nonce
secrecy—prevents a late same-UID actor from fabricating authority.

`VerifierNonIssuanceEvidenceV1` is the exact CFL object
`{schemaVersion=1,domain="rsi-verifier-non-issuance-evidence-v1",
verifierRequestDigest,receiptSignerKeyId,receiptSignerPublicKeyDigest,
receiptSignerCapabilityDigest,receiptRef,receiptPathAbsent=true,
result="not-issued",code,completedAt,
signatureAlgorithm="platform-attestation-v1",signature}`. `code` is exactly
`timeout|capacity|temporarily-unavailable`; every request/key/capability field
equals the final request and admitted `VerifierExecutionBaseIdentity`, and
`apply.completed.createdAt<=completedAt<=VerifierRequest.core.expiresAt` under
the trusted clock. Let `nonIssuanceSignedMapping` be this exact object minus only
`signature` and `nonIssuanceBodyDigest=D(nonIssuanceSignedMapping)`. The pinned
signer signs only `D({schemaVersion=1,
domain="rsi-verifier-non-issuance-signature-v1",nonIssuanceBodyDigest,
verifierRequestDigest,receiptSignerCapabilityDigest})`; signature encoding and
key verification are exactly the receipt rules. The constructor-attested signer
capability enforces one terminal result per request digest: either one signed
receipt or one signed non-issuance body, never both, and exact replay returns
byte-identical bytes. A non-issuance object is embedded only in the event-bound
verification sidecar; it is never published at a separate path/selector or as an
external auxiliary object.
`receiptRef` is the one deterministic verifier-receipt path selected by the
request digest. The signer capability descriptor-checks it absent before signing,
and the coordinator independently nofollow-rechecks the same absence immediately
before the verification sidecar/event callback; `receiptPathAbsent` is never a
caller assertion.

The live-verification sidecar's `verifierReceipt` is a closed five-key union:

- `present`: exactly `{availability="present",ref,digest,errorCode=null,
  nonIssuanceEvidence=null}`; ref is
  `transactions/<tx>-verifier-<verifierRequestDigest hex>.json` and the strict
  signed receipt must match
  all inline `liveReadback`, `tests`, `attestationMatch`, request and execution
  identity fields;
- `unavailable`: exactly `{availability="unavailable",ref=null,digest=null,
  errorCode,nonIssuanceEvidence}` where `errorCode` is one of `timeout`,
  `capacity`, `temporarily-unavailable` and the non-null value is the complete
  exact signed evidence above with the same code/request; inline `liveReadback`
  remains exact, `tests` is exactly
  `{skillValidationPassed=null,contractValidationPassed=null,
  targetTestsPassed=null}`, and `attestationMatch=null`; it authorizes only
  rollback-armed/deferred recovery;
- there is no durable `unknown` verification arm. Malformed, partial, conflicting,
  transport-unknown, missing-after-claimed-present, or unprovable verifier state
  incidents from `apply.completed(applied)` as `verifier-state-unknown` and emits
  no verification event.

The unavailable arm creates no verifier object and is legal only when the exact
embedded signature authenticates terminal non-issuance for this final request
and a protected nofollow lookup proves the deterministic receipt path absent
through the verification event callback. Replay must reproduce the byte-identical
non-issuance body and re-prove path absence; a changed body, later receipt, or
receipt/non-issuance pair is a conflict/unknown. `timeout|capacity|temporarily-
unavailable` is admissible only when the capability proves no issuance; process
timeout, termination, transport failure, partial output, or any possible-issued
state is unknown even if the path currently looks absent. An authenticated receipt left after a crash remains inert until an
event-bound live-verification sidecar names it, but recovery may adopt it only
because its signature and nonce match the already event-bound applied request. A
syntactically exact, same-digest, preplanted, or late object without that
cryptographic provenance cannot replace the create-once publication witness. A crash at
receipt file write, file sync, parent sync, readback, verification sidecar, or
event is recovered by strict existing-object admission and the last durable
event—never by rewriting bytes or treating unknown as unavailable.

Task 8 `verification.completed` is a closed union. `outcome=affirmed` requires
exact post, `verifierReceipt.availability=present`, receipt result passed, all
three tests true, attestation match true, unchanged planned new-apply authority,
and `reasonCode=null`. `outcome=rollback-armed` requires exact post/readback and
provider resolution null under rollback guard semantics. Its reason is exactly
`attestation-mismatch` when a present failed receipt has
`attestationMatch=false`, regardless of test booleans; otherwise, with
`attestationMatch=true` and any test false, it is exactly
`verification-failed`. No input selects both or reverses this precedence.
Its reason may instead be
`verifier-unavailable` with the unavailable arm, or `authority-invalidated` when
a present passed receipt loses current new-apply authority before append. Unknown
verifier state or non-exact post incidents instead. Mixed arms fail.
In both arms the event payload itself, in addition to unchanged common fields, is
exactly `{transactionId,outcome,reasonCode,verificationDigest,liveReadback,tests,
attestationMatch}` and must equal the sidecar/receipt fields. Fold therefore enforces
`resolution.recorded <- verification.completed(outcome=affirmed)` and
`apply.reverted <- verification.completed(outcome=rollback-armed)` without
trusting an unbound sidecar; a missing, mixed, or mismatched inline outcome fails.

`apply.reverted` is legal only after an actual exchanged `apply.completed` and
its causation must be the durable `verification.completed(outcome=rollback-armed)`
for the same transaction. The rollback sidecar's `verificationRef` and
`verificationDigest` are mandatory and must name that exact event/evidence. The
event requires payload `{transactionId,restoredPreHash,restoredManifestPreHash,
displacedPostHash,rollbackVerified,rollbackDigest}`. It proves the exact reverse
exchange and exact pre readback. Its rollback sidecar requires
`retainedPreimage=null`: after reverse exchange the original preimage is the
target, not a retained-name object. `displacedPost` is the sole exact current
swap-name inode. Its pre-cleanup witness is exactly that name/identity with
`disposition=pending-event-bound`, `removed=false`, `absentAfter=false`, and
`directorySynced=true`; here the sync
proves the reverse-exchanged exact-pre target plus still-present displaced name
durable and never claims an unlink. The durable event authorizes removal of only
that displaced inode. The later rollback decision sidecar replaces the cleanup
witness with either truthful final cleanup disposition, always
`absentAfter=true,directorySynced=true`, after the unlink-or-authorized-absence
proof and parent sync, and again proves exact pre. A no-apply branch is not a
revert. The rollback sidecar has a non-null authenticated
`rollback-apply` lease evidence; each later cleanup witness has its own non-null
operation-matching `displaced-post-cleanup` evidence rather than reusing the
reverse receipt or results.

`snapshot.created`, `apply.started`, `verification.completed`,
`apply.reverted`, and promote-safe `run.closed` each add `transactionId` plus
their phase digest (`snapshotDigest`, `intentDigest`, `verificationDigest`,
`rollbackDigest`, or `decisionDigest`) to the existing normative payload.
`run.closed.linkedIds` is the exact ordered list
`[transactionId,terminalEventId]`; its Task 8 payload also includes the exact
`outcome`, `terminalReasonCode`, and `closeStatus`, all equal to the referenced
decision arm and with `status=closeStatus`.

The Task 8 `incident.latched` arm uses the exact final binding above; its
`incidentId`, reason code, quarantine targets, payload ref, and local record must
agree. The quarantine must agree with the local record only for
`quarantineDisposition=created`; a preexisting arm binds only the validated
blocking quarantine. The fixed latch must agree with them only for
`latchDisposition=created`; a `preexisting` arm instead proves the separately
validated `blockingLatchDigest` without counterfeiting local ownership.

`resolution.recorded.payloadRef` is the exact content-addressed
`resolution-readback` ref above. Its Task 8 payload is the exact bounded shape
`{logicalOperationId,targetSkill,transactionId,providerOperationId,resolutionId,
providerResolutionRequestDigest,candidateFullRecordBeforeDigest,
providerAuthorityBindingBeforeDigest,task7CandidateBindingDigest,
candidateCaptureLineageBindingDigest,candidateStateBindingBeforeDigest,
candidateFullRecordAfterDigest,providerAuthorityBindingAfterDigest,
candidateStateBindingAfterDigest,providerResolutionRecordDigest,
resolutionDigest}`. No target view, provider record, receipt, lease evidence or
other unbounded mapping is inline. Every field byte-equals the exact sidecar and
provider ledger, and `resolutionDigest` and `payloadRef` select that sidecar.
The sidecar's embedded evidence has operation class exactly
`promoted-terminal` and binds the protected exact-post readback plus provider-
result/event linearization. It requires affirmative
`verification.completed` causation; that event's verified sidecar contains the
exact retained-preimage witness for the same transaction. Only the conjunction
of this durable resolution event, its exact resolution-readback sidecar, its
exact promoted provider record, and that causally bound witness authorizes
unlink of the named retained inode. A changed inode, orphan/oversized sidecar,
or cross-transaction witness latches and is preserved.

For a pre-apply terminal, `terminalEventId` is the last durable
`run.started`, `promotion.planned`, or `snapshot.created` event. A `run.started`
terminal is legal only with no gate, plan, snapshot, intent, `apply.started`, or
Task 8 reserved name,
provider resolution null under the terminal guard, and
`targetDisposition=stale-external`; it is the ordinary external-drift non-
attribution arm, never an incident masquerading as Task 8 mutation. For plan/
snapshot terminals the closed `targetDisposition`
is either `exact-pre` with the ordinary exact target witness, or
`stale-external` with only the bounded target witness
`{expectedRootIdentityDigest,relativePath,observedKind,taskMutationProof}`. The
latter's `observedKind` is exactly one of
`manifest-drift`, `named-object-drift`, `missing`, `unreadable`, or
`reserved-name-present`; `taskMutationProof` is exactly
`{applyStartedAbsent=true,eventTailComplete=true,
taskOwnedCleanupAuthorized=false}`. It stores no unknown bytes, inode, mode, or
hash and is legal only while the same-transaction lock excludes a Task 8 writer,
there is no durable/partial/corrupt `apply.started`, no event-authorized Task 8
temp/preimage, and provider resolution is null. `stale-external` closes only
with `terminalReasonCode=target-stale-external`/`failed`; exact-pre uses the total
reason map below. This covers an external
pre-apply edit/delete/chmod/symlink/unreadable/reserved-name without claiming or
overwriting it. A partial/corrupt apply-started record forbids not-started and
remains open/incident diagnostic. A post-gate capability loss, TTL, authority,
or intent-publication failure before `apply.started` uses the applicable arm;
initial capability-probe failure occurs before any continuation/gate. An
orphan intent is not terminal evidence. Promoted, not-applied, rolled-back, and exact-pre
not-started closes reread the exact named post/pre manifest and every authorized
cleanup absence. A stale-external not-started close intentionally cannot make
that proof; it relies only on its closed non-attribution proof and preserves any
reserved name. A resolution event without exact cleanup evidence cannot close
promoted.

The decision sidecar is a closed union, not an optional-field superset. Let the
six common keys be
`C={schemaVersion,kind,transactionId,runId,planDigest,eventBinding}`. Clean arms
`promoted|not-started|not-applied|rolled-back` have exactly `C` plus
`{outcome,terminalReasonCode,closeStatus,terminalEventId,terminalEvidenceRef,
terminalEvidenceDigest,targetDisposition,target,providerStateDigest,cleanup,
latchAbsent,promotionDecision,namespaceMutationLeaseEvidence}`. Incident arms `ambiguous|quarantined` instead
have exactly `C` plus
`{outcome,terminalReasonCode,closeStatus,terminalEventId,terminalEvidenceRef,
terminalEvidenceDigest,targetDisposition,targetWitness,providerStateDigest,
cleanup,latchAbsent,promotionDecision,incidentClosure}`. `target` and
`targetWitness` are opposite-arm absent keys, never null placeholders.
Each clean or incident arm therefore has exactly 19 top-level keys; the two
closed 13-key additions are mutually exclusive rather than an optional superset.

| Field | promoted | not-started | not-applied | rolled-back | ambiguous/quarantined |
|---|---|---|---|---|---|
| `outcome` | `promoted` | `not-started` | `not-applied` | `rolled-back` | exactly `ambiguous` or `quarantined` |
| `terminalReasonCode` | `verified-promotion` | one mapped not-started reason | exact not-applied reason | causal rollback-armed verification reason | exact incident-record reason |
| `closeStatus` | `completed` | mapped blocked/failed/deferred | mapped failed/deferred | mapped failed/deferred | exactly equals outcome |
| `terminalEventId` | exact resolution event ID | exact run-start, plan or snapshot event ID | exact apply-completed event ID | exact apply-reverted event ID | exact incident-latched event ID |
| `terminalEvidenceRef` | exact resolution-readback ref | null for run-start/plan, snapshot ref for snapshot | apply-readback ref | rollback-readback ref | fixed incident-record ref |
| `terminalEvidenceDigest` | resolution-readback digest | matching exact persisted run-start event-line digest, plan digest or snapshot digest | readback digest | rollback digest | incident-record digest |
| `targetDisposition` | `exact-post` | `exact-pre|stale-external` | `exact-pre` | `exact-pre` | `incident` |
| target evidence | `target` exact post | `target` corresponding non-null witness | `target` exact pre | `target` exact pre | `targetWitness` exactly from incident record |
| `providerStateDigest` | exact promoted full-record digest | exact final guarded unresolved full-record digest | same | same | null iff provider witness is unknown, otherwise its exact full-record digest |
| `cleanup` | exact retained-preimage final `removed-now|already-absent-authorized` arm | null | null iff never-created, otherwise exact prepared-post final cleanup arm | exact displaced-post final cleanup arm | null |
| `latchAbsent` | true | true | true | true | false |
| `promotionDecision` | exact section-12.11 decision | null | null | null | null |
| `namespaceMutationLeaseEvidence` | exact `retained-preimage-cleanup` final evidence | exact `unresolved-terminal` evidence | exact `unresolved-terminal` if never-created, otherwise `prepared-post-cleanup` | exact `displaced-post-cleanup` evidence | key absent |
| `incidentClosure` | key absent | key absent | key absent | key absent | exact non-null closure |

When `cleanup` is non-null, its nested
`namespaceMutationLeaseEvidenceDigest` is non-null and equals `D` of the
decision's sole top-level `namespaceMutationLeaseEvidence`; the complete object
appears nowhere else in the decision. A pending cleanup uses a null nested
digest as defined above. The clean arm's one top-level object proves the lease
protected the final target/provider callback. A never-created not-applied arm
performs no unlink and therefore uses a fresh `unresolved-terminal` protected
readback, not a fabricated cleanup result.

The exact `incidentClosure` is
`{incidentRecordRef,incidentRecordDigest,quarantineRef,
quarantineDisposition,blockingQuarantineDigest,latchRef,latchDisposition,
blockingLatchDigest}` and matches the causal event. The rolled-back reason is
copied from its causal `verification.completed(outcome=rollback-armed)`; neither
`apply.reverted` nor the closer invents a new terminal reason.

`terminalReasonCode` is closed and maps total evidence to one status:

| Outcome | Exact reason → `closeStatus` |
|---|---|
| promoted | `verified-promotion` → `completed` |
| not-started | `eligibility-blocked`, `control-disabled`, `capability-lost` → `blocked`; `target-stale-external`, `snapshot-failed`, `intent-publication-failed` → `failed`; `authority-expired`, `candidate-drift`, `provider-authority-drift` → `deferred` |
| not-applied | `authority-expired`, `candidate-drift` → `deferred`; every other closed `apply.completed(not-applied).reasonCode` → `failed` |
| rolled-back | `verifier-unavailable`, `authority-invalidated` → `deferred`; `verification-failed`, `attestation-mismatch` → `failed` |
| ambiguous/quarantined | `preapply-provider-unknown`, `partial-apply-authority`, `prepared-temp-unknown`, `prepared-temp-sync-failed`, `prepared-temp-cleanup-absent-unsynced`, `retained-preimage-cleanup-absent-unsynced`, `displaced-post-cleanup-absent-unsynced`, `pre-state-unreadable`, `post-state-unreadable`, `provider-state-unknown`, `verifier-state-unknown`, `namespace-lease-unavailable`, `namespace-enforcer-lost`, `forward-exchange-ambiguous`, `emergency-reverse-ambiguous`, `rollback-exchange-ambiguous`, `ancestry-lost` → `ambiguous`; every other matrix reason → `quarantined`; `outcome == closeStatus` |

The `run.closed` status/payload must equal this unique `closeStatus`/reason/outcome
and may not choose another allowed-looking status. Replays and concurrent closers
recompute the mapping and converge on identical decision/event bytes.
`providerStateDigest` is never opaque: the final guard or incident witness
recomputes it. Incident cleanup is always null so unknown/emergency objects stay
preserved.

## Trusted plan resolution and Task 7 integration

Do not accept an arbitrary caller filesystem path as promotion authority. Use
the closed `PromotionPlanRef` defined above. In particular it binds the
experiment operation ID, distinct outer reservation and inner experiment
request digests, candidate ID/capture/full-record/state-binding digests, plan
ID/digest, validation attestation digest, Task 7 artifact-store identity, and the
two exact deployment-attestation refs/digests bound by Task 7's issuance-time
result marker.

Add a strictly read-only Task 7 seam that reconstructs and re-admits the
persisted reservation/bundle plus the two exact marker-bound raw deployment
attestations from the operation above, verifies canonical sidecars and post-image,
revalidates signatures/chains/current semantic authority, and returns exact
typed `ExperimentRequest`, `ExperimentBundle`, and `PromotionPlan`. It must not
create directories, acquire creating locks, bind a replay ledger, run a sandbox,
invoke an issuer, reserve, publish, repair, chmod, fsync, or mutate provider
state.

Before `apply.started`, run the complete existing `verify_promotion_plan()` gate with a freshly sampled trusted context/clock and require the plan TTL to remain valid. After `apply.started`, crash recovery uses the durable transaction intent plus persisted Task 7 authority; it must not rerun the pending-only/new-apply admission in a way that makes an already committed provider resolution unrecoverable. Expired authority never permits a new apply; after an exact post-state it permits only deterministic recovery to verified rollback, exact resolve replay, or quarantine.

Task 7 current-state admission must be extended from fresh `pending` to the
strict unresolved authority described below: `pending` or first/second
`deferred`, while binding the complete folded provider record digest in the
control-plane identity. Task 8 separately reads authoritative provider
escalation state and requires `needsEscalation=false`. Any status/review/
escalation drift requires a newly validated Task 7 plan; it cannot reuse old
authority, and a third deferral blocks.

## Public Task 8 interfaces

Create deeply immutable, closed models and services:

```python
PromotionService(...).promote_candidate(plan_ref: PromotionPlanRef) -> PromotionDecision

PromotionRecovery.open_existing(...).inspect(
    transaction_id: str | None = None,
) -> RecoveryReport
```

Expose the specification's public CLI without widening that service boundary:

```text
rsi.py promote-candidate \
  --candidate-id <closed candidate ID> \
  --promotion-plan <sha256 plan digest selector> \
  --validation-attestation <sha256 attestation digest selector> \
  --expected-target-hash <sha256 whole-manifest pre-hash> \
  --run-id <deterministic continuation run ID> \
  --idempotency-key <deterministic promotion command key> [--json]
```

The two selector arguments are digests resolved only inside the
constructor-configured, attested Task 7 store; they are never filesystem paths,
raw JSON, caller attestations, or alternate stores. `--candidate-id`, both
selectors, and `--expected-target-hash` must equal the fully recomputed
`PromotionPlanRef` candidate, plan digest, validation attestation digest, and
`PromotionPlan.target.manifestPreHash`. `--run-id` must equal the deterministic
continuation `runId` above. The command key is exactly
`"promote_" + sha256(canonical({"domain":"rsi-promote-cli-v1",
"planDigest":planDigest}))[7:]`; callers cannot choose a second operation for
the same plan. Reconciliation happens through zero-write existing-only readers
before constructing any writable service. Missing/malformed/swapped/substituted
arguments return a stable typed nonzero error and leave target, provider,
EventStore, Task 7 store, transaction, latch, and caches unchanged. Exact restart
replay returns the previously bound stable result envelope without a new event or
provider call; same key/different selector is a typed conflict. With `--json`,
stdout is the existing stable machine-readable envelope, diagnostics are
sanitized on stderr, and failure always has a typed error code and nonzero exit.

`PromotionService` receives trusted dependencies at construction: strict event
writer/reader, read-only Task 7 loader, promotion journal, provider adapter,
trusted current-state/clock source, trusted
live verifier, a constructor-approved non-target atomic-exchange probe, the
constructor-owned `TrustedNamespaceMutationLease` registry/identity, and explicit
allowlisted homes/roots. The registry-resolved lease backend alone performs or
gates every production exchange/reverse/unlink; the service never receives a
caller-supplied mutation backend, lease instance, token, receipt, or capability
boolean. The
method takes only the immutable plan ref; it does not take replacement or
deployment-attestation bytes, target/provider/store paths, decision text,
provider reason text, operation IDs, or a caller-selected snapshot.

`PromotionDecision` follows spec section 12.11 and is accepted only after exact post readback, affirmative live verification, provider resolution replay/readback, exact retained-preimage cleanup, lifecycle close, a bound decision sidecar, and no active latch. Its reason is the fixed schema-v1 constant:

```text
Verified additive knowledge with passing validation
```

Recovery is diagnostic/read-only in Task 8. It may recommend resume, rollback, quarantine, operator restore, or event reconciliation, but it must not clear a latch, restore a provider snapshot, rewrite a target, invoke provider snapshot/resolve/defer, append an event, create/repair a store, chmod, unlink, fsync, or acquire a creating lock.

## Provider authority and dependency hardening

Task 8 requires a separately reviewed provider dependency slice before target mutation is implemented.

### Candidate authority

Add a strict adapter method over the already declared read capability:

```python
get_candidate(candidate_id, expected_skill) -> CandidateAuthority
```

Use the existing declared list capability as bounded
`list --status all --skill <skill> --candidate-id <id> --json` and require
exactly one matching ID. The provider reads at most 64 MiB/100,000 ledger events,
at most 64 KiB per line, and emits at most 64 KiB. Do not add a capability merely
to expose the existing manual `show` command.

A list/get response followed by lock release is not mutation authority. Formally
version the provider contract with the separately reviewed
`skill-learning.guard` capability and add:

```python
with adapter.guard_candidate(
    candidate_id, expected_skill, mode, expected_authority
) as guarded_authority:
    ...  # final bounded recheck, apply.started, atomic exchange only
```

Read and guard authority is parent-local and executes no provider child. The
adapter descriptor-walks the constructor-attested canonical learning home and
nofollow-opens the exact existing `events.lock`, `events.jsonl`, and current
`skill-contract.json`; current list/get/validate/new-apply/rollback additionally pin the
reviewed provider source/helper bytes needed to map the current contract/version
to an immutable RSI `ProviderHistoricalFoldProfile`; terminal-readback and
historical revalidation pin them as well. Every opened component is
current-UID, regular/directory as required, single-link, private-mode, and
named/opened device/inode/bytes/mode identical. Historical revalidation verifies
the current source/helper/contract against a current adapter-approved
`ProviderCompatibilityEntry` with the unchanged ledger protocol, but deliberately
does not compare those current bytes to the gate-time source/version bytes; it
folds the receipt prefix with the receipt-bound RSI profile.

List/get/validate use `LOCK_SH` when the declared provider protocol admits shared
readers; current/historical guards use `LOCK_EX`. Acquisition is
`LOCK_NB` with a constructor-fixed monotonic deadline of 5 seconds and a maximum
10 ms retry interval; timeout is a typed no-authority result. The parent folds the
exact already-open ledger FD directly with the selected pure bounded profile. No
Python/provider source is executed, no stdout protocol exists, and process death
naturally releases the flock and FDs. `validate()` combines this fold with
descriptor-only snapshot verification. The versioned `skill-learning.guard`
contract promises that every ledger read-modify-append or repair path uses this
same exact named exclusive lock and protocol: capture, review/defer, resolution,
snapshot prepare/result/abort, operation-result records, and any explicit
initializer repair. No writer may publish a prepare or auxiliary operation event
outside it.

Every nonterminal current-candidate guard phase uses `locked precheck → bounded action/
callback → locked post identity+refold → classification`. Both checks cover
all applicable named/opened root/source/helper/contract/lock/ledger/fold-profile
identities and the exact candidate. Guard A may append its event in the action
callback because a postcheck failure can still terminalize not-applied or
incident before target mutation. Historical gate creation is narrower: it
performs its final locked identity/fixed-prefix check immediately before the
bounded EventStore gate callback; once that callback succeeds, exit is release-
only and makes no fallible current-state claim. A later append after the sealed
prefix cannot retroactively invalidate it, while any rewrite/truncation of the
prefix fails the next historical validation. Guard B performs the
exchange as its action, then post-classifies both target operands/ancestry and
post-refolds provider authority before release. It performs no EventStore append
and builds no historical batch. A direct lock-bypassing ledger write during the
exchange is therefore detected. A mismatch before exchange yields no exchange
and a closed classification; one after exchange yields an incident
classification. After Guard B releases, a separate append-capable unresolved or
incident guard reacquires the provider lock, validates the all-origin historical
batch, rechecks the classified target/provider state, and publishes the phase-
correct event/terminal evidence while the encompassing namespace lease remains
held. Every new-apply/Guard-B precheck and postcheck
also requires a valid ledger with no open provider snapshot prepare, abort,
operation-result, or initializer-repair transaction; a prepare that wins before
the guard blocks it and one attempted during the guard blocks on the same lock.
If that follow-up cannot prove/publish failure
evidence, durable `apply.started` remains the implicit latch.

Terminal finalization is stricter: while locked, perform precheck, bounded
authorized cleanup/evidence/decision-sidecar work, then postcheck/refold; only
after both succeed may a final bounded EventStore callback append `run.closed`.
After that callback `__exit__` is release-only and makes no fallible check or
later authority claim, because events after close are illegal. Whether any prior
step succeeds or raises, one unconditional `finally` explicitly `LOCK_UN`s and
closes every root/source/helper/contract/ledger/lock FD so the provider is never
wedged.
Production does not attempt a post-unlock reacquire: a legitimate queued writer
may win that race. Controlled tests may prove release with an independent writer,
but authority depends on the held named lock plus mandatory locked finalization.
A contract/capability/source/profile swap, missing/replaced lock/ledger name,
changed inode, unexpected mode/link, direct unlocked ledger write, or
post-action candidate drift fails closed; after
exchange it latches. The guard performs no ledger write or storage repair.

New apply uses two short guarded linearizations over the same expected
provider-full/provider-authority/Task-7-binding/capture-lineage/combined-state
digests. Guard A
covers final candidate/control witnesses and
durable `apply.started`, then releases. The bounded post-image temp write/fsync/
readback occurs without a provider lock. Guard B reacquires and revalidates both
provider-native digests, then the adapter revalidates the Task 7, capture-lineage,
and combined digests immediately before the final target/tree metadata witness and forward
exchange, remains through exact post-classification, then releases on the normal
exact-post path. Authority drift between A and B causes a no-exchange
classification followed by exact-pre `apply.completed(outcome=not-applied)`
under a separate append-capable guard; it first retains and binds the prepared
temp, and only that event authorizes cleanup. No tree hash, temp I/O,
snapshot, verification, or other long operation occurs inside either guard. A
concurrent defer/resolve either commits before a guard and invalidates its digest,
or blocks until that guard releases; it cannot cross the exchange linearization.
The candidate guard has a closed mode union. `new-apply` requires the exact
planned full-record, provider-authority, Task 7 binding, capture-lineage, and
combined-state digests plus unexpired/current control authority. It is used for
Guard A and affirmative verification publication. `rollback` instead requires the exact recomputed
`candidateCaptureLineageBindingDigest` and `resolution=null`; pending,
deferred, or escalated review drift does not prevent restoration of an already
applied target. It is also the append guard for `apply.completed(applied)`,
rollback-armed verification and their unresolved safety terminals. Any terminal or unknown resolution blocks reverse exchange and
latches/quarantines. Thus a defer during verification can still roll back safely,
while a competing resolution can never be overwritten by rollback. The guard is
released before provider resolve; any
competing terminal that wins afterward is observed and quarantined rather than
treated as success. `terminal-readback` requires the exact planned promoted
resolution operation/request/record plus recomputed terminal provider full,
provider-authority, Task 7, capture-lineage, and combined-state digests; it is the only mode that may bind
`resolution.recorded`, promoted cleanup/decision, and successful close. Neither
new-apply nor rollback admits terminal provider state. Historical-prefix admission uses the separate read-only
`guard_historical_prefix` context above, never either candidate-guard mode.

No whole-tree hash is computed in any provider guard. A full readback is prepared
while holding only the mandatory managed-tree namespace lease and no transaction/
global/target/provider/EventStore lock, as an immutable
`TargetReadbackView`. Its acyclic digest body is exactly
`{schemaVersion=1,domain="rsi-target-readback-view-body-v1",classification,
target,retainedNameWitness,ancestryWitnessDigest,memberMetadataWitnesses}` and
`scanDigest` is the prefixed SHA-256 of that body's exact canonical-final-LF
bytes. The full view is exactly
`{schemaVersion=1,domain="rsi-target-readback-view-v1",classification,target,
retainedNameWitness,ancestryWitnessDigest,memberMetadataWitnesses,scanDigest}`;
the full-view domain/digest never enters its own `scanDigest` preimage. It
has `classification=exact-pre|exact-post|other`; `target` is the exact
`TargetWitnessV1`, `retainedNameWitness` the exact `RetainedNameWitnessV1`, and
`memberMetadataWitnesses` the exact ordered `MemberMetadataWitnessV1` array.
Exact-pre/post require the corresponding plan artifact and whole-manifest hashes;
`other` still requires a fully readable, schema-valid target/member view but at
least one recomputed value differs. Proven missing, special, or unsafe-link
drift uses the separate closed `other` known-drift arm of the containing
protected-readback state; only an observation whose kind or metadata cannot be
proved uses `unreadable`. Neither arm may be smuggled into a partial full view.
The ancestry digest equals the exact scope `AncestryWitnessV1`. Target and
artifact-member observations cross-equal only their common live fields
`{relativePath,device,inode,type,mode,uid,nlink,size}`. Member `mtimeNs` and
`ctimeNs` have no target counterpart; target root/artifact/manifest hashes have
no member counterpart. Plan/manifest values equal the observations only for
`exact-pre|exact-post`; `other` deliberately records bounded readable drift.
The reserved-name witness cross-equals the same protected observation through
the role-specific projection defined below.
For each protected operation, the causal phase determines whether the comparison
arm is pre or post and whether the reserved name is expected absent or present
in its exact role. The scanner walks the strict UTF-8-byte-sorted union of every
policy path plus the reserved relative path and deterministically selects the
first path that cannot enter a full view. Expected reserved-name absence is a
normal observation, not `missing`. A policy/reserved path expected present but
proved absent selects known drift `missing` with `metadata=null`. A symlink or
regular file with `nlink>=2` selects `unsafe-link`. A proved
`dir|fifo|socket|block|char|other-special` selects
`special`. Both latter arms carry the exact bounded nofollow metadata below. A
safe readable regular file with `nlink=1` enters the full view—even when its
bytes, size, mode, or expected-absence status make that view `other`. A lookup,
kind, metadata, canonicalization, or numeric bound that cannot be proved selects
`unreadable`; it is never coerced into known drift. This partition is disjoint
and total for the bounded scan.
The service double-scans the complete admitted managed set and exact reserved
name. After acquiring locks in normal order, the
append-capable guard performs only bounded name↔opened/metadata/ancestry checks
against the view, appends the sidecar/event callback with the all-origin batch,
then repeats those checks and provider refold. Only after callback/postcheck does
the encompassing lease release. Drift before callback selects the
prior event's incident arm; drift after callback incidents from the newly durable
event. The view is never durable authority by itself.

Every clean terminal that asserts provider `resolution=null` is serialized, not
self-asserted after guard or lease release. Not-applied publication stays within
its forward lease through the event callback; a fresh cleanup lease then encloses
an exact-pre lease-only full view, then one continuously held unresolved guard
across bounded authorized temp unlink-or-absence, parent sync, bounded protected
recheck, decision and close. A not-started
close uses a terminal target/readback lease even though it performs no target
mutation. Rollback performs reverse, unlocked-from-provider but lease-held exact-
pre hashing, and `apply.reverted` callback under one rollback lease; a second
cleanup lease first builds the heavy exact-pre view with no provider guard, then
holds one unresolved guard continuously across displaced-post cleanup and final
decision/close. Promoted service restart uses a promoted-terminal lease through exact-post
readback, resolve and `resolution.recorded`, then a cleanup lease through retained-
preimage removal and final terminal guard/close by the same split: heavy view
first, then one continuous terminal guard across bounded unlink/absence and
callback. A provider/target/lease race detected before that guard selects the
matrix incident and never cleanup; a direct lock-bypassing drift detected by the
guard postcheck after an authorized cleanup incidents from the causal event and
cannot claim a clean close. A crash releases the
holder lease; service restart must reacquire the exact operation class before readback,
event, cleanup or close. Bounded EventStore evidence/callback and backend-gated
unlink/sync may occur inside the applicable lease/terminal guard; hashing,
snapshot, verifier execution, and temp writes never occur inside a provider guard.

The returned authority deeply binds candidate status, skill/root/owner,
class/destination, capture operation/request, review count/escalation/last
review, exact nested resolution metadata, and a canonical record digest. The
record digest covers the entire strict folded provider object, including exact
`status`, integer `review_count`, boolean `needs_escalation`, and the complete
`last_review` or `resolution` object (including its operation/request binding),
not a selected-field projection. `pending` requires review count zero and no last
review. `deferred` requires review count one or two, one exact last review,
`needs_escalation=false`, and no resolution. Review count three or greater,
`needs_escalation=true`, an inconsistent derived field, or any drift blocks new
apply and must be surfaced rather than silently deferred again. Unknown/missing/
extra fields, mutable nested values, changed skill/path/owner, legacy candidates
without provider-v2 operation binding, or malformed resolution fail closed. New
apply permits only unresolved, non-escalated authority that exactly matches the
captured candidate and Task 7 plan.

An opaque full-record digest alone is not recomputable by Task 7 current-state
models, and the provider cannot derive Task 7 `CandidateBinding.digest`. Task 8
first normalizes the exact eligible routed-capture ledger fold into
`ProviderCandidateFullRecordV1`, a canonical-final-LF object with exactly
`{schemaVersion=1,domain="rsi-provider-candidate-full-record-v1",candidateEvent,
reviews,resolution,derived}`. `candidateEvent` is the exact provider mapping
`{schema_version,event,id,created_at,skill,kind,change_class,title,finding,
evidence,target_hint,confidence,sourceSkill,ownerSkill,ownerReason,
destinationClass,relatedSkills,dedupeKey,scope,operationType,operationId,
requestDigest}`: `event="candidate"`, `operationType="capture"`, `skill` is
exactly `{name,path}`, `target_hint` is explicitly null or the admitted string,
and `requestDigest` is native bare 64-hex. Its field types and bounds are closed:
`schema_version` is integer 1 (never boolean); `id` is the provider-generated
`YYYYMMDDTHHMMSSZ-<12 lowercase hex>` ID; `created_at` is its exact canonical
20-byte UTC-second `YYYY-MM-DDTHH:MM:SSZ` timestamp; `skill.name`, `sourceSkill`,
`ownerSkill`, and every `relatedSkills` item are 1--64-character lowercase
hyphen-case UTF-8 strings; `skill.path` is the 1--4096-byte provider-normalized
canonical skill path and resolves to the constructor-admitted target skill;
`kind` is exactly one of `procedure|gotcha|fact|reference|script-opportunity`;
`change_class` is exactly `knowledge|behavior`; `title`, `finding`, and
`ownerReason` are nonempty normalized secret/PII-free UTF-8 strings of at most
120, 2,000, and 500 characters respectively; `evidence` is an array of 1--5
such strings, each at most 1,200 characters; `target_hint` is JSON null or one
normalized relative artifact string of at most 500 characters; `confidence` is
a finite JSON number (not boolean) in `[0,1]`; `destinationClass` is exactly
`skill|reference|script|profile|agents`; `relatedSkills` is a sorted, duplicate-
free array of at most 64 skill names; `dedupeKey` and `scope` are nonempty,
at-most-200-character values matching
`^[a-z0-9]+(?:[.:-][a-z0-9]+)*$`; `operationId` is 1--200 ASCII characters
matching `^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`. All strings reject NUL/control
characters and non-normalized alternatives; all candidate keys shown above are
mandatory for a Task 8-eligible routed capture and no extra key is admitted.

`reviews` is the ordered ledger array of zero through 4,096 exact mappings
`{schema_version,event="review",id,created_at,candidate_id,outcome,reason,
next_trigger,operationType="defer",operationId,requestDigest}`. `resolution` is
either JSON null or a closed exact two-arm mapping. The current/manual arm is
`{schema_version,event="resolution",id,created_at,candidate_id,decision,reason,
artifacts,operationType="resolve",operationId,requestDigest}`. The guarded-v2 arm
has those exact 11 keys plus exactly
`{authoritySchemaVersion=2,expectedCandidateFullRecordDigest,
expectedProviderAuthorityBindingDigest,task7CandidateBindingDigest,
candidateCaptureLineageBindingDigest,expectedCandidateStateBindingDigest,
authorityExpiresAt}`. No optional/mixed arm is accepted. `derived` is
exactly `{status,reviewCount,needsEscalation,lastReview}`; `lastReview` is JSON
null iff `reviews=[]`, otherwise byte-equal to the last review. Status, count,
escalation and resolution must be recomputed from the ordered prefix. No provider
pretty-print/output-only field enters this document.

Every review/resolution has integer `schema_version=1`, the same exact ID/time
formats above, `candidate_id` byte-equal to `candidateEvent.id`, an operation ID
with the same 1--200-character grammar, and a native bare lowercase 64-hex
`requestDigest`. A review has only `outcome="deferred"`, a nonempty normalized
secret/PII-free `reason` of at most 1,000 characters, and a similarly normalized
`next_trigger` of at most 500 characters. A resolution has `decision` exactly
`promoted|rejected|superseded`, a nonempty normalized secret/PII-free `reason`
of at most 1,000 characters, and `artifacts` as a duplicate-free ordered array
of at most 64 normalized relative artifact strings, each at most 500 characters.
In a guarded-v2 resolution, all five named authority values are exact prefixed
digests equal to the committed request, `authoritySchemaVersion` is integer 2,
and `authorityExpiresAt` is the exact canonical UTC-second plan expiry; every one
of the seven fields is absent in the manual arm.
No review/resolution key is optional and no extra key is accepted. In `derived`,
`status` is exactly `pending|deferred|promoted|rejected|superseded`,
`reviewCount` is a nonnegative integer (never boolean) equal to `len(reviews)`,
`needsEscalation` is boolean and equals `reviewCount>=3 && resolution is null`,
and `lastReview` obeys the exact null/equality union above. A Task 8 admission
requires zero through two reviews and an unresolved `pending|deferred` derived
state; the full historical fold can represent a later terminal resolution but
never an inconsistent or unbounded projection. Let

```text
providerCandidateEventDigest = lowerhex(SHA256(canonical-no-LF(candidateEvent)))
candidateFullRecordDigest = "sha256:" +
  lowerhex(SHA256(canonical-final-LF(ProviderCandidateFullRecordV1)))
```

The first value deliberately retains native bare provider representation; the
second is a Task 8 document digest. The provider fold profile and adapter build
the same normalized object and compare every nested event, not a caller digest.

The provider-native semantic `ProviderCandidateAuthorityBinding` is the exact
canonical-final-LF object:

```text
schemaVersion=1, domain="rsi-provider-candidate-authority-v1", candidateId,
providerCandidateEventDigest, skillName, skillPath, ownerSkill, changeClass,
destinationClass, captureOperationId, providerCaptureRequestDigest, status, reviewCount,
needsEscalation, lastReview, resolution, providerContractDigest,
providerVersionDigest
```

The capture request digest uses the native bare provider representation.
`lastReview` is null or the normalized complete 11-key object
`{schemaVersion=1,domain="rsi-provider-review-authority-v1",reviewEventId,
createdAt,candidateId,outcome="deferred",reason,nextTrigger,
operationType="defer",operationId,providerReviewRequestDigest}`. `resolution`
is null for unresolved authority or the normalized complete 12-key object
`{schemaVersion=1,domain="rsi-provider-resolution-authority-v1",
resolutionEventId,createdAt,candidateId,decision,reason,artifacts,
operationType="resolve",operationId,providerResolutionRequestDigest,
guardedAuthority}`. `guardedAuthority` is JSON null for the current/manual raw
arm or the exact seven-key object
`{authoritySchemaVersion=2,expectedCandidateFullRecordDigest,
expectedProviderAuthorityBindingDigest,task7CandidateBindingDigest,
candidateCaptureLineageBindingDigest,expectedCandidateStateBindingDigest,
authorityExpiresAt}` for guarded v2. Every
value is copied from and cross-checked against the corresponding exact raw
provider record above; only the closed Task 8 key/domain spelling changes, and
both named request digests remain native bare 64-hex. Provider live/historical
parsers independently build it and recompute
`providerAuthorityBindingDigest = "sha256:" +
lowerhex(SHA256(exactCanonicalFinalLfBytes))`; they also retain the separately
recomputed full-record digest above. `lastReview` and `resolution` use the exact
closed null/event unions above, so absence cannot be represented by a missing key.
In this binding, `schemaVersion` is integer 1; `candidateId`, skill/owner/class/
destination/operation fields have the exact types, enums, grammars, bounds, and
cross-equalities of the normalized event above; each named provider event/request
digest is bare lowercase 64-hex; status is the exact five-value derived enum;
`reviewCount` is a nonnegative integer equal to the full record; and
`needsEscalation` is a JSON boolean equal to the fold. `lastReview` is JSON null
or the exact normalized 11-key review mapping just above, and `resolution` is
JSON null or the exact normalized 12-key resolution mapping—there is no
abbreviated nested form.
`providerContractDigest` and `providerVersionDigest` are prefixed Task 8 digests.
No field is optional, no numeric field accepts boolean, and no extra key is legal.

The trusted Task 7 loader separately re-admits the complete immutable
`CandidateBinding` mapping. Its exact canonical-no-LF six-key object is
`{schemaVersion=1,domain="rsi-captured-candidate-binding-v1",lineage,
changeClass,destinationClass,evidenceRefs}`; `lineage` is exactly
`{schemaVersion=1,domain="rsi-captured-candidate-lineage-v1",candidateId,
providerRequestDigest,captureOperationId,captureBindingDigest,evaluationId,
targetSkill,targetSkillVersionHash,taskClass,ownerSkill}`. Its
`providerRequestDigest` and every other Task 7 digest are prefixed, and
`providerRequestDigest == "sha256:"+candidateEvent.requestDigest`.
Every Task 7 lineage ID is a 1--128-character ASCII value matching
`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`; `targetSkill`/`ownerSkill` additionally
equal the admitted provider skill/owner; all three lineage digest fields are
prefixed lowercase SHA-256 strings. `changeClass` and `destinationClass` equal
the provider enums selected by the plan. `evidenceRefs` is a sorted,
duplicate-free array of 1--5 strings matching
`^event:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`. Integers/domains are exact, every
key is mandatory, and no extra/null field is accepted.
`task7CandidateBindingDigest = "sha256:" +
lowerhex(SHA256(canonical-no-LF(exactCandidateBinding)))`.

The shared `CandidateStateBinding` is the exact canonical-final-LF object
`{schemaVersion=1,domain="rsi-candidate-state-v1",task7CandidateBinding,
task7CandidateBindingDigest,providerAuthority,
providerAuthorityBindingDigest}`. Its constructor recomputes both nested digests
and cross-checks candidate ID, provider request/capture operation, target/owner,
change class, and destination class before producing
`candidateStateBindingDigest = "sha256:" +
lowerhex(SHA256(exactCanonicalFinalLfBytes))`. Get/guard/snapshot/resolve compare provider-native
fields under the provider lock; the trusted adapter then combines that result
with the independently admitted Task 7 binding. Provider requests bind the Task
7 digest plus expected provider/full/capture-lineage/combined digests but never
claim the provider itself derived Task 7 authority. Cross-candidate substitution
or any self-asserted nested digest fails. Plans, origin receipts, current state,
snapshot/intent/verification evidence, and provider guards bind the five closed
authority digests: full provider record, provider-authority binding, Task 7
candidate binding, capture-lineage binding, and combined state binding.
`CandidateStateBinding` intentionally does not contain the complete provider
record or `candidateFullRecordDigest`: it binds the independently recomputable
provider semantic state plus Task 7 authority, while the sibling
`PromotionAuthorityV2.candidateFullRecordDigest` separately and mandatorily binds
the complete record. Omitting either sibling, substituting one for the other, or
claiming that the state-binding digest transitively covers the full record fails.

Rollback's stable authority is a separate literal
`CandidateCaptureLineageBinding`:

```text
schemaVersion=1, domain="rsi-candidate-capture-lineage-v1", candidateId,
providerCandidateEventDigest, skillName, skillPath, ownerSkill, changeClass,
destinationClass, captureOperationId, providerCaptureRequestDigest,
task7CandidateBindingDigest, providerContractDigest, providerVersionDigest
```

The lineage request digest is native bare provider hex. The adapter independently
re-admits the complete Task 7 binding before hashing
this exact canonical-final-LF object as
`candidateCaptureLineageBindingDigest = "sha256:" +
lowerhex(SHA256(exactCanonicalFinalLfBytes))`. Rollback mode folds
the current provider record under lock, recomputes this stable digest, and
requires `resolution=null`. It deliberately ignores only mutable review/status/
escalation state; a changed capture event, ID, skill/path/owner, class,
destination, operation/request, Task 7 binding, contract, or provider version
blocks rollback even if the candidate ID was reused.
All lineage scalar fields reuse the exact provider/Task 7 types, bounds, enums,
and cross-equalities above: the provider event/request digests are bare 64-hex,
the Task 7/contract/version digests are prefixed, and every other value is the
exact admitted candidate value. `schemaVersion` is integer 1, every listed key is
required, and null/extra/abbreviated nested data is forbidden.

The five promotion-authority digest preimages are therefore closed and
noninterchangeable:

| Digest | Exact framing / representation | Mandatory equality source |
|---|---|---|
| `candidateFullRecordDigest` | full record above, canonical-final-LF, prefixed | current/historical provider fold and `CurrentTrustedState.providerCandidateRecordDigest` |
| `providerAuthorityBindingDigest` | provider authority above, canonical-final-LF, prefixed | same provider fold/profile under the named ledger lock |
| `task7CandidateBindingDigest` | Task 7 CandidateBinding above, canonical-no-LF, prefixed | issuance-bound Task 7 request/plan artifacts |
| `candidateCaptureLineageBindingDigest` | capture-lineage object above, canonical-final-LF, prefixed | provider capture event plus re-admitted Task 7 binding |
| `candidateStateBindingDigest` | combined state object above, canonical-final-LF, prefixed | independently recomputed provider and Task 7 nested mappings/digests |

`providerCandidateEventDigest` and every `provider*RequestDigest` remain bare
native 64-hex only inside the explicitly named fields. Missing versus null,
reordered reviews, a derived-value mismatch, provider pretty JSON, provider JSONL
LF inclusion, Task 7 final-LF insertion, or bare/prefixed substitution changes or
invalidates the corresponding digest.

### Snapshot authority

Expand `SnapshotRef` to bind the full strict provider result: path, manifest
digest, operation/request/prepare/snapshot IDs, skill/source, `phase=pre`, source
manifest digest, files and executable modes. The V2 `manifest.json` is exact
compact sorted-key UTF-8 JSON plus one final LF and has only these top-level keys
and types:

```text
snapshotManifestVersion=2, domain="rsi-provider-snapshot-manifest-v2",
operationId=<string>, requestDigest=<native 64-hex>, prepareId=<string>,
snapshotId=<string>, skillName=<string>, sourcePath=<canonical absolute string>,
phase="pre", sourceManifestDigest=<native 64-hex>, files=<ordered array>
```

`files` is the exact ordered array of
`{path=<UTF-8 relative string>,byteSize=<bounded int>,sha256=<native 64-hex>,
executable=<bool>}` already defined. `manifestDigest` is SHA-256 of the exact
canonical bytes including LF. Let `bindingHex` be the raw lowercase hex encoding
of `SHA256(UTF8("snapshot\\0" + operationId + "\\0" + requestDigest))` (the
input `requestDigest` is the exact provider-native bare 64-hex and `bindingHex`
also has no prefix).
Exact IDs/path are `prepareId="snapshot-prepare-"+bindingHex[:24]`,
`snapshotId="snapshot-"+bindingHex[24:48]`, and
`snapshots/<skillName>/op-<bindingHex[:32]>`; no caller path/name is accepted.
`SnapshotRef.sourceManifestDigest` must equal
`PromotionPlan.target.manifestPreHash` by the single declared conversion
`"sha256:"+nativeSourceManifestDigest`, and its ordered file array must equal the
independently rebuilt Task 7 pre-manifest under Task 8's stricter no-link/no-
secret admission. Same skill/path with changed managed bytes or executable bit is
a conflict. Snapshot sidecar and intent bind this equality, not just a provider
path.

Provider V2 `requestDigest`, `sourceManifestDigest`, per-file `sha256`, and
ledger `manifest_sha256` retain provider-native bare hex for mixed-ledger/manual
compatibility. `SnapshotRef.manifestDigest` and transaction-sidecar digests are
the explicitly wrapped `sha256:<hex>` forms. Deterministic snapshot identity uses
the native bare `requestDigest` bytes exactly. Supplying a prefixed provider
field, a bare Task 8 ref, or replaying one representation as the other is a typed
conflict, not an alternate spelling.

The adapter rejects duplicate keys, extra/missing manifest keys or tree members,
symlink/hardlink/special objects, wrong mode, wrong deterministic path/ID,
request-digest mismatch, source/skill/phase mismatch, or a provider validate
result with an open snapshot prepare.

Provider list/get/guard and `validate()` reads must open existing storage without
mkdir, chmod/fchmod, temp-copy, bytecode/cache creation, incomplete-tail repair,
fsync, creating locks, or any other write. `validate()` uses the same bounded
existing-only FD-backed ledger fold, including strict detection of an open
snapshot prepare; it may not reach the provider's current creating/repairing
storage path. Keep a separate explicit initializer for writable provider commands
and fresh temporary learning homes, never called by lookup, validation, guard, or
recovery. The adapter opens the pinned provider script and helper as nofollow,
single-link, read-only descriptors only to attest current provider version and
select the matching immutable RSI fold profile; it does not compile or execute
them for list/get/validate/guard. The old temporary-copy/pathname/PID-only
`_execute_verified` path is retired for every Task 8/zero-write read. Recovery
uses only the direct locked descriptor/profile path. Write-syscall traps
and full before/after byte/mode/link/inode manifests cover `validate()` as well as
list/get/guard.

Provider snapshot scanning must match the normative Task 7 managed-set and exact
bounds:

- exact `SKILL.md`, `skill-contract.json`, and managed directories;
- deterministic exclusion of all approved generated caches/runtime artifacts;
- sensitive material is rejected rather than silently snapshotted;
- at most 4,096 enumerated records/manifest entries, 4 MiB cumulative UTF-8 path
  bytes, depth 32, 16 MiB per file, 64 MiB total managed bytes, and exactly three
  stabilization scans;
- raw byte hash and executable bit for each regular file;
- no symlink, hardlink or special file in a Task 8 snapshot;
- copied snapshot files preserve and verify the executable bit (`0600` for
  non-executable, `0700` for executable snapshot copies; snapshot directories
  `0700`, manifest `0600`).

The exact exclusions are directories `__pycache__`, `.pytest_cache`,
`.mypy_cache`, `.ruff_cache`, `.hypothesis`, `.git` and files `.DS_Store`,
`*.pyc`, `*.pyo`. `.env`, `.env.*`, `credentials`, `credentials.json`,
`.credentials`, `secrets.json`, or any detected secret are rejection conditions,
not exclusions. Every admitted snapshot manifest uses
`snapshotManifestVersion=2` and an ordered `files` array of exact
`{path,byteSize,sha256,executable}` objects plus exact operation/request/prepare/
snapshot/skill/source/phase identity. The provider stages and rescans this exact
manifest, then the adapter independently rescans the installed tree and rejects
extra/missing files or mode drift.

Legacy snapshots remain readable for manual preview, but only the new exact schema may authorize Task 8. Provider `restore --confirm` stays disabled; automatic promotion recovery never calls restore.

### Provider identity and writes

Replace the ambiguous single-script provider digest with a typed identity:

```text
providerContractDigest = "sha256:" + lowerhex(SHA256(raw skill-contract.json bytes))
providerVersionDigest  = "sha256:" + lowerhex(SHA256(exact ProviderVersionDocument bytes))
```

`ProviderVersionDocument` is compact sorted-key UTF-8 JSON followed by exactly
one LF, with the closed shape
`{schemaVersion=1,domain="rsi-skill-evolver-provider-version-v1",files}`.
`files` is the exact ordered array (UTF-8 relative-path order) containing only
`scripts/learning_log.py` and `scripts/skill_contract.py`; each entry is exactly
`{relativePath,type="regular",nlink=1,mode,executable,byteSize,rawSha256}`.
`mode` is the admitted permission-mode integer, `executable` must equal its
execute bits, and `rawSha256` is the prefixed Task 8 digest over exact source
bytes. Paths are relative to
the constructor-attested canonical provider root; every ancestor/name and final
file is nofollow-opened and named/opened identity is rechecked. Missing/extra/
reordered paths, same bytes through a symlink or alternate provider root, mode/
executable drift, a non-regular or multi-link file, a noncanonical document, or
missing final LF changes/invalidates the version.

Runtime is bound separately rather than pretending it is portable provider
source. `ProviderRuntimeIdentity` is the exact canonical object
`{schemaVersion=1,domain="rsi-provider-runtime-v1",canonicalPath,type="regular",
nlink=1,mode,byteSize,rawSha256,implementation,version,cacheTag,
writerBootstrapRawSha256}`. The constructor pins and rechecks its nofollow
named/opened executable identity; `writerBootstrapRawSha256` binds the exact
contained provider-write bootstrap. Direct read/guard folding executes neither
runtime nor bootstrap. Its bytes are canonical-final-LF and
`providerRuntimeIdentityDigest = "sha256:" +
lowerhex(SHA256(exactBytes))`; `rawSha256` and
`writerBootstrapRawSha256` are prefixed Task 8 digests over their exact raw bytes.
`ProviderExecutionIdentity` is the exact canonical-final-LF object
`{schemaVersion=1,domain="rsi-provider-execution-v1",canonicalProviderRoot,
providerContractDigest,providerVersionDigest,providerRuntimeIdentityDigest}`;
`providerExecutionIdentityDigest = "sha256:" +
lowerhex(SHA256(exactBytes))`. The canonical provider root and all three nested
digests must equal independently opened/recomputed constructor-approved sources,
never plan fields. The execution digest is included in
`providerHistoricalAuthority`, the promotion control-plane, and
every guard receipt. Runtime/
bootstrap/path/symlink/mode drift therefore invalidates execution authority even
when provider source bytes match.

Together with the earlier store formula, the portable identity framing is exact:
provider contract hashes raw bytes; provider version/runtime/execution Task 8
documents use canonical-final-LF; `artifactStoreIdentityDigest` uses Task 7
canonical-no-LF and freezes the literal no-LF marker bytes. All results are
prefixed Task 8 digests. These identity preimages are re-opened and recomputed at
construction/guard boundaries; a same textual mapping with the wrong framing,
path, topology, mode, link state, or raw source/marker bytes is not equal.

The reviewed provider contract `provides`, RSI contract `requires` provider
array, and adapter `REQUIRED_CAPABILITIES` must all include exactly the same new
`skill-learning.guard` capability in addition to their current set. A missing,
duplicate, misspelled, or self-asserted capability fails before provider read or
target mutation.

Task 8 `PromotionService` invokes only provider snapshot/resolve writes, but the
adapter/provider still supports Task 6 capture plus defer/manual writes. Every
mutating command intentionally enters the explicit creating initializer and uses
the pinned runtime/source/helper/contract writer runner with a new contained process
group, stdin EOF, fixed non-writing cwd, minimal environment, user-site/bytecode
off, `close_fds=True` with only explicit read/lock descriptors, and one 64 KiB
combined stdout/stderr cap. Timeout/protocol failure performs bounded
TERM→deadline→KILL→wait/reap and proves group disappearance; a pathname/runtime
swap, forked descendant, excess output, or unprovable containment is a transport
failure, never proof that no append occurred. After every timeout/protocol/
output/exit failure, the parent uses the direct locked fold to look up the exact
operation/request and classifies only `committed-exact`, `provably-uncommitted`,
`conflict`, or `unknown`. Exact commit is verified/replayed; uncommitted may fail
safely; conflict fails closed. Snapshot unknown remains pre-apply and blocks all
target mutation. Resolve unknown with exact post latches/quarantines. The child
enters the provider's exact named lock for lookup/append, while the parent
independently verifies pre/post ledger and result agreement. List/get/validate/
guard never use this runner, and Task 6 route/capture regressions remain
mandatory.

Every live provider change is performed as an isolated dependency task: make a recoverable pre-edit snapshot under a fresh Task 8 learning home, establish provider RED first, edit only the reviewed skill files, run the entire provider suite and validators against temporary homes, obtain independent review, then refresh repository pins and rerun all adapter/Task 6/Task 7 regressions. Never write the real provider ledger, create a real candidate/resolution, or use a real target during this implementation.

The current provider-v1 snapshot copies every file as `0600` and does not bind
executable bits, so it cannot by itself be called an exact rollback artifact.
Before the first live provider edit, pair the required fresh-Task8-home legacy
snapshot with a separately captured read-only manifest of the exact reviewed
non-cache provider surface `{relativePath,rawSha256,mode,executable,size}` and a
private recoverable byte copy preserving those modes. Record both identities and
prove restore preview/diff without touching live source. After hardening, the v2
snapshot must itself be byte/mode exact. A legacy snapshot never authorizes a
Task 8 target apply.

Preserve existing manual provider callers with closed schema unions rather than
globally making Task 8 fields optional. Snapshot and resolve each retain their
exact legacy command/request/result arm. Their guarded-v2 arm has mandatory
`authoritySchemaVersion=2`; snapshot additionally requires candidate ID, all
five authority digests under the exact field names
`expectedCandidateFullRecordDigest,expectedProviderAuthorityBindingDigest,
task7CandidateBindingDigest,candidateCaptureLineageBindingDigest,
expectedCandidateStateBindingDigest`, and `authorityExpiresAt`, while resolve requires those
same fields plus its existing decision/reason/artifacts. All guarded-v2 fields
are present together or none are; a partial/mixed arm is invalid. Legacy/manual
writes and mixed valid v1+v2 ledgers remain readable by strict list/validate/
preview and preserve their prior CLI behavior, but a legacy event, result, or
manifest can never authorize Task 8. Historical v1 records are parsed under
their original exact schemas and are never reinterpreted as v2 authority.
Writable commands and Task 6 capture explicitly enter the separate creating
initializer before validation/write; default list/get/validate/guard remain
existing-only and zero-write.

Snapshot is called exactly once with the plan's deterministic operation ID,
exact target skill/root, `phase="pre"`, `git_sha=None`, candidate ID, and the
expected candidate full-record, provider-authority-binding, Task 7 binding,
capture-lineage-binding, and combined-state-binding digests plus the plan
`authorityExpiresAt`. Candidate ID, all five digests, and expiry are part of the immutable
provider snapshot request digest and result. Lookup is first: under `events.lock`
an exact same-operation/same-request snapshot result replays before current-state
or TTL admission and before a new source scan, even if the candidate later
deferred/resolved. Same operation with a different request conflicts. Only a new
operation performs heavy bounded source scans, staging, copying, and fsync
outside `events.lock`. Immediately before its authoritative snapshot-result
append, provider code reacquires `events.lock` and first performs a second exact
operation/request lookup so a concurrent winner replays instead of conflicting
or duplicating. Only if still new does it fold the candidate from the locked
ledger, recompute the provider full-record and provider-authority-binding
digests, require them to equal the request, and require its authoritative UTC to
be strictly before `authorityExpiresAt`. The adapter independently
recomputes the Task 7, capture-lineage, and combined digests before accepting the result. Drift
records/cleans only an exact aborted staging operation and returns a typed
conflict; it cannot publish an authoritative snapshot result. Resolve uses
exactly:

```python
decision = "promoted"
reason = "Verified additive knowledge with passing validation"
artifacts = (plan.artifact.relative_path,)
operation_id = plan.provider_operation_ids.resolve
candidate_id = plan.candidate_id
expected_full_record_digest = verified_authority.full_record_digest
expected_provider_authority_binding_digest = verified_authority.provider_binding_digest
task7_candidate_binding_digest = plan.candidate_digest
candidate_capture_lineage_binding_digest = plan.candidate_capture_lineage_binding_digest
expected_state_binding_digest = verified_authority.combined_state_binding_digest
authority_expires_at = plan.expires_at
```

Candidate ID and all five authority digests are part of the immutable resolve
request digest, as is the exact plan/attestation `expiresAt`. Under the same
`events.lock` transaction, provider resolve performs exact operation/request
lookup first and returns an already-recorded result even after expiry or later
candidate state drift. Changed request still conflicts. For a new result,
immediately before append it folds/recomputes the current provider candidate,
compares the expected provider full-record and provider-authority-binding
digests, samples its authoritative current UTC/append timestamp, and requires it
to be strictly before `expiresAt`, then appends at most one resolution. The
adapter independently verifies the echoed Task 7 and combined binding digests.
The capture-lineage digest is independently recomputed and verified as well.
Expiry or candidate drift after
affirmative verification cannot produce `promoted`; with exact post it latches/
quarantines rather than inventing a rollback arm. A concurrent defer/resolve
cannot cross either provider commit. After each provider call, fetch authoritative
operation/result state and verify the exact committed request, record and
snapshot manifest or resolution. In particular, snapshot replay checks its
committed operation/request/result/manifest binding and does not re-require the
later mutable current candidate to equal the old snapshot-time state; current
authority is rechecked separately by each later guard. Same operation/same
request replays one result; changed request is a typed conflict. A competing
resolution is never treated as idempotent success.

## Write-ahead promotion journal inside EventStore

`EventStore` events remain the sole lifecycle source of truth. Do not create a second mutable FSM/log. Extend the existing closed home with `objects/transactions/`, target/transaction lock directories, and strict incident files. A typed `PromotionJournal` publishes immutable, event-bound sidecars through EventStore.

Add `EventStore.open_existing(home)`. It bypasses the creating constructor and
performs a descriptor-relative, nofollow, read-only inspection of only existing
components. Neither open nor any read reached from that object may call
`mkdir`, `open(...O_CREAT...)`, `chmod`/`fchmod`, unlink/rename/link, truncate,
fsync, lock acquisition, temporary recovery, SQLite rebuild, or topology repair.
Existing modes/UID/type/link/name/inode are verified exactly and unsafe or missing
authority is reported, not tightened. `read_events()` and `read_sidecar()` on
this object use bounded read-only descriptors and double-check named/opened
identity. Every mutation method on it raises before a syscall. Tests monkeypatch
all write-capable syscalls, include a non-writable store, and compare complete
before/after inode/mode/link/byte manifests; no temporary copy adapter is an
acceptable substitute.

Topology admission is a closed legacy/Task-8 union. An existing valid Task 6/7
home with none of the Task 8 additions remains fully readable/replayable through
`open_existing()`, creates nothing, and is simply promotion-ineligible. Before a
first writable promotion, an explicit `initialize_promotion_topology()` under the
normal store lock validates every legacy component without chmod/repair, then
durably creates exactly `objects/transactions`, `incidents/records`,
`incidents/quarantine`, `locks/promotion`, `locks/promotion/transactions`,
`locks/promotion/targets`, and `locks/promotion/gate.lock` with the prescribed
private modes and publishes the exact marker
`.rsi-promotion-store-v1 = {"domain":"rsi-promotion-store-v1",
"schemaVersion":1}\n` last. It readbacks/syncs each created object and parent.
The initializer is the only upgrade path; read-only open never invokes it.

Once the marker or any Task 8 event/evidence exists, the entire exact Task 8
topology and marker are mandatory. Any subset, extra alias/link/special entry,
unsafe existing mode/owner, marker-before-directory state, or Task 8 object in a
legacy arm is a partial upgrade and fails closed; no reader or ordinary
constructor completes, deletes, or tightens it. Thus old-home zero-write replay,
explicit marker-last upgrade, and injected/crashed partial upgrade are distinct
tested states.

Minimum sidecars:

```text
objects/transactions/<tx>-origin-<digest>.json
objects/transactions/<tx>-intent-<digest>.json
objects/transactions/<tx>-snapshot-<digest>.json
objects/transactions/<tx>-readback-<digest>.json
objects/transactions/<tx>-verification-<digest>.json
objects/transactions/<tx>-verifier-<verifierRequestDigest hex>.json
objects/transactions/<tx>-resolution-<digest>.json
objects/transactions/<tx>-decision-<digest>.json
incidents/records/<incidentId>.json
incidents/quarantine/<root-digest>.json
incidents/latch.json
```

There is no `lease-evidence` object, selector, or sidecar beyond this closed
list. Applicable sidecars/incident records embed their one top-level evidence
object; nested witnesses carry only its digest. Before `apply.started`, the
service admits the worst-case size vector for every reachable kind in this list,
and publication/replay applies the exact-length/cap relation defined above.

- Transaction identity is deterministically derived from the domain-separated plan digest.
- The intent binds the complete admitted plan/request/candidate/root/contract/control-plane/attestation/post-image/provider/event lineage, exact pre/post artifact and whole-manifest hashes, target locator, original file mode/inode witness, retained-preimage swap name, snapshot/resolve operation IDs, and TTL.
- Transaction sidecars are canonical, immutable, content-addressed, create-once
  and strict. The incident record is canonical, immutable and create-once at its
  fixed transaction-derived selector path, with its exact content digest carried
  by the event/decision. Exact bytes replay; conflicting bytes fail closed.
- Publish with bounded complete-write loop, file sync, no-replace CAS, directory sync, nofollow readback and exact bytes/inode/mode/link verification.
- Directories/files are owned by the current UID, `0700`/`0600`, no symlink/hardlink/special entry, and closed bounded membership. Never repair unsafe existing topology.
- Transaction publication uses a dedicated strict create-once implementation.
  On replay it opens the exact final name read-only and requires mode `0600`,
  current UID, regular type, `nlink=1`, unchanged named/opened inode, bounded exact
  bytes, and no RSI temporary aliases. It never calls the legacy
  `_recover_owned_temp_links`, never chmods existing evidence, and never accepts
  an unexpected hardlink. New publication may use a private create-once temp plus
  no-replace link CAS, but cleans only the exact temp inode it created. The
  current `_write_once_locked()` and `_read_regular()` are not reused for
  transaction/latch replay or diagnostic reads until they satisfy this contract.
- An unreferenced transaction/verifier sidecar is an inert orphan and can never
  authorize target mutation. A fixed incident record without its event remains a
  mandatory incident-publication recovery selector but likewise grants no target
  mutation or cleanup. `apply.started` is the commit marker that proves its exact
  intent is durable; an unresolved `apply.started` is an implicit latch even if
  explicit latch publication failed.
- Provider snapshot is the one authoritative full pre-snapshot; transaction sidecars record only its binding and the retained swap-file witness, not a second skill snapshot.

Required ordering around the live boundary:

1. Provider snapshot commits and `snapshot.created` plus its exact receipt sidecar commits.
2. Publish the deterministic transaction intent sidecar.
3. Append and fsync `apply.started` referencing that exact intent with the strict
   transaction evidence append path (not the legacy repair-capable
   `append_with_sidecar()` implementation).
4. Only after the durable event returns may temp creation or target mutation begin.
5. Exact readback/verification/decision sidecars are each authoritative only through their matching durable event.

## Capability-gated atomic apply

Plain `os.replace()` is forbidden for a live target because a concurrent name replacement can be silently destroyed. Before provider snapshot, run a bounded capability probe for same-filesystem atomic exchange and directory durability:

- macOS: pinned `renameatx_np(..., RENAME_SWAP|RENAME_NOFOLLOW_ANY|RENAME_RESOLVE_BENEATH)` (`0x02|0x10|0x20 == 0x32`) with same-volume capability and reverse-swap canary;
- Linux: pinned `renameat2(..., RENAME_EXCHANGE)`;
- any unsupported filesystem/kernel, ambiguous EINTR behavior, unsafe alias handling, or unsupported directory sync blocks before snapshot.

The probe never uses the target artifact or any existing managed name. Under an
already verified private probe directory in the exact target parent filesystem,
create two fresh, disjoint, single-link regular canaries whose `(dev,ino,bytes,
mode)` differ from each other and from every transaction/target name. Prove the
probe directory has the same `st_dev` as both target parent and artifact, exchange
once, classify exact exchanged state, reverse-exchange once, prove exact original
state, sync the directory, then remove only the proven canaries. A probe in a
different temporary volume, an alias of either target/swap operand, or a probe
that cannot prove reverse state is not capability evidence.

Because `promotion.gated.requiredChecks` claims `atomic-exchange`, this probe
must finish successfully before creating the writable continuation run or
appending an allow gate. Probe failure returns a typed pre-gate block with no
continuation event, no not-started decision, no provider call, and no target
mutation; its private canaries are exact-cleaned or the preflight fails unsafe.

An exchange syscall returning `EINTR` is never blindly retried. Reopen both exact
names nofollow and classify them from their admitted inode/bytes/mode witnesses:

- exact pre-order means the exchange did not linearize; fail pre-safe (or, for a
  capability canary only, start a fresh probe with fresh names);
- exact exchanged order means it did linearize; continue from post-classification
  without a second syscall;
- any missing, duplicated, mixed, replaced, unreadable, or unprovable order is
  ambiguous and latches/quarantines.

The same rule applies to forward and reverse exchange. No production operand is
ever retried merely because the kernel reported `EINTR`.

The portable `rootIdentityDigest` is not a live inode-CAS. At final admission,
open nofollow descriptors for the canonical root's parent anchor, every root and
relative-path ancestor, and the target parent, and retain that complete bounded
chain through forward/reverse exchange, cleanup, and terminal readback. A live
`AncestryWitness` records for every edge the exact component bytes plus
parent/child device, inode, type, mode, UID and link count. Immediately before
and after each exchange syscall, and again before any temp/preimage/displaced-
post cleanup, compare every parent-name to its already-opened child using
descriptor-relative nofollow metadata and compare the configured root name from
its anchor. Also recheck the retained FDs themselves. A root/ancestor rename,
replacement, symlink/alias, detached-tree binding, mount/device change, or
unprovable edge is `other`: latch/quarantine and do not exchange, reverse, or
unlink through either the stale pathname or detached dirfd. No final-component
hash or durable path-only identity can waive this ancestry proof.

The ancestry and protected-readback primitives are literal CFL objects, not
opaque digests:

- `AncestryEdgeV1` has exactly
  `{schemaVersion=1,domain="rsi-ancestry-edge-v1",componentName,
  childRelativePath,parentDevice,parentInode,parentType,parentMode,parentUid,
  parentNlink,childDevice,childInode,childType,childMode,childUid,childNlink}`.
  `componentName` is an NFC basename of 1--255 UTF-8 bytes and is neither `.`
  nor `..` and contains no slash, backslash or NUL. `childRelativePath` is the
  empty string only for the canonical-root child in edge zero; otherwise it is
  an NFC canonical POSIX directory path of at most 8,191 bytes with no empty,
  `.` or `..` component. Both types are literally `directory`. Device/inode are
  integers in `0..2^64-1`, UID in `0..2^32-1`, link count in `1..2^31-1`, and
  mode is `stat.S_IMODE` in `0..0o7777`; booleans are never integers. Each tuple
  comes from retained FDs plus descriptor-relative nofollow lookup in one
  protected observation.
- `AncestryWitnessV1` has exactly
  `{schemaVersion=1,domain="rsi-ancestry-witness-v1",rootIdentityDigest,
  parentRelativePath,edges}`. The root digest equals the plan/intent/scope/request;
  `parentRelativePath` is the exact POSIX parent of the planned artifact, empty
  for a root-level artifact. `edges` contains 1--32 root-to-leaf entries. Edge
  zero describes anchor-to-root, has empty `childRelativePath`, and names the
  root basename. Each later parent metadata tuple equals the preceding child
  tuple and appends exactly its component to the accumulated path; child paths
  are unique and the final path equals `parentRelativePath`.
  `ancestryWitnessDigest=D(AncestryWitnessV1)`.
- `ArtifactParentWitnessV1` has exactly
  `{schemaVersion=1,domain="rsi-artifact-parent-witness-v1",
  rootIdentityDigest,parentRelativePath,device,inode,type="directory",mode,
  uid,nlink,ancestryWitnessDigest}`. The cross-equalities are fieldwise and
  exhaustive: its `rootIdentityDigest == ancestry.rootIdentityDigest ==
  request.rootIdentityDigest`; its `parentRelativePath ==
  ancestry.parentRelativePath == POSIX-dirname(policy.artifactRelativePath) ==
  POSIX-dirname(policy.reservedRelativePath)` and is not a request field; its
  `ancestryWitnessDigest == D(ancestry) == request.ancestryWitnessDigest`; and
  `D(ArtifactParentWitnessV1) == request.artifactParentWitnessDigest`. Its
  `{device,inode,type,mode,uid,nlink}` tuple equals the final ancestry edge's
  child tuple. The named nofollow parent, retained artifact-parent dirfd and
  final ancestry node must equal that tuple before and after every protected
  operation.
- `ManagedTreePolicyV1` has exactly
  `{schemaVersion=1,domain="rsi-managed-tree-policy-v1",rootIdentityDigest,
  allowlistEntryDigest,artifactRelativePath,reservedRelativePath,
  manifestPreHash,manifestPostHash,
  scopeMode="complete-managed-set-ancestry-names-inodes-and-aliases",members}`.
  `members` is the duplicate-free strict UTF-8-byte-sorted union of the exact
  Task 7 pre/post manifest paths, with each entry exactly
  `{relativePath,pre,post}`. Each `pre`/`post` is JSON null for absence or
  exactly `{type="regular-file",byteSize,digest,executable}` using the exact
  Task 7 manifest-entry vocabulary. For every union path `p`, the policy
  member's `relativePath=p`; its `pre`/`post` is null iff that side has no Task 7
  entry whose `path=p`, otherwise its four values fieldwise equal exactly that
  entry's `{type,byteSize,digest,executable}`. The differently shaped policy
  projection is never claimed byte-equal to the Task 7 entry containing
  `path`. There are no extra paths or fields. `rootIdentityDigest`,
  `manifestPreHash`, and
  `manifestPostHash` equal their request and plan fields;
  `allowlistEntryDigest` equals the plan allowlist digest.
  `artifactRelativePath` equals the planned artifact path and its POSIX basename
  equals `request.targetName`; `reservedRelativePath` is the deterministic
  sibling path and its basename equals `request.reservedName`. Both relative
  paths have POSIX dirname equal to
  `ArtifactParentWitnessV1.parentRelativePath`. The request carries only the
  policy/root/manifest digests and the two basenames, not the full policy,
  allowlist, or relative paths. The scope literal covers every implied
  ancestor, name, inode and alias.
  `managedTreePolicyDigest=D(ManagedTreePolicyV1)`.
- `TargetWitnessV1` has exactly
  `{schemaVersion=1,domain="rsi-target-witness-v1",rootIdentityDigest,
  relativePath,device,inode,type="regular-file",mode,uid,nlink,size,
  artifactHash,manifestHash}` and no null. Its path is the exact NFC canonical
  Task 7/plan artifact path of 1--1,024 UTF-8 bytes; numeric bounds reuse the
  ancestry rules, `nlink=1`, and size is `0..16 MiB` (the admitted post image is
  additionally at most 4 MiB). The artifact hash covers exact named/opened raw
  bytes and the manifest hash is the Task 7 whole-managed-manifest digest from
  the same protected scan. This mapping is a bounded live observation, not a
  restatement of planned values. Its `rootIdentityDigest` always equals the
  policy/request/plan root identity and its `relativePath` always equals
  `policy.artifactRelativePath`. Only when its enclosing readback is
  `exact-pre|exact-post` do `size` and `artifactHash` equal the selected Task 7
  entry's `byteSize` and `digest`, the execute bits of `mode` equal that entry's
  boolean `executable`, and `manifestHash` equal the selected complete Task 7
  manifest digest. There is no `executable` field in `TargetWitnessV1` and no
  plan equality is asserted for its device, inode, UID, or full mode. Those live
  metadata fields equal another named witness only when both causally describe
  the same opened object. An `other` full view records differing readable
  values. `targetWitnessDigest=D(TargetWitnessV1)`.
- `RetainedNameWitnessV1` has exactly
  `{schemaVersion=1,domain="rsi-retained-name-witness-v1",name,role,
  classification,object}`. `role` is exactly `unallocated|prepared-post|
  retained-preimage|displaced-post`; `classification` is `absent|present`.
  The absent arm has `object=null`; the present arm has exactly
  `{device,inode,type="regular",mode,uid,nlink=1,size,sha256}`. `name` equals
  the request's deterministic reserved basename, and role/classification/object
  equal the causal apply, rollback or cleanup arm through the exact projection:
  for its causal named witness `w`, `name==w.name` and
  `object==objectFromNamed(w)`. This leaf contains no event,
  sidecar, evidence or scan digest.
- `MemberMetadataWitnessV1` has exactly
  `{schemaVersion=1,domain="rsi-member-metadata-witness-v1",relativePath,
  device,inode,type="regular-file",mode,uid,nlink=1,size,mtimeNs,ctimeNs}` and
  no null. Paths are nonempty NFC canonical POSIX member paths; integer bounds
  reuse the ancestry rules, nanosecond times are signed int64, and size is at
  most 16 MiB. These are bounded observations of safe readable regular files
  only. The readback array is duplicate-free and strictly UTF-8-path sorted. It
  has exactly one entry for each policy path observed present as a safe regular
  file and no entry for an observed-absent path; the known-drift classifier
  below handles any expected-present missing, unsafe-link, or special object.
  For an `exact-pre|exact-post` view, membership matches the selected Task 7
  manifest exactly and each entry's size and execute bits equal that selected
  entry. For an `other` full view a safe regular file may be unexpectedly
  present or have different readable values. The artifact member and
  `TargetWitnessV1` cross-equal only the common live fields
  `{relativePath,device,inode,type,mode,uid,nlink,size}` when they describe the
  same opened artifact; member `mtimeNs`/`ctimeNs` and target root/hash fields
  remain one-sided. The reserved name is excluded and appears only in
  `RetainedNameWitnessV1`. A per-member digest is derivable for tests but is
  never nested as authority.

The digest DAG is strictly ancestry/policy/target/member leaves → ancestry and
parent digests → scope/request → signed results/evidence. No leaf contains a
scope, request, receipt, result, evidence, event, sidecar or scan digest.

Those descriptor checks still leave an uncloseable check-to-syscall gap against
a noncooperative same-UID actor that detaches an ancestor or rebinds a cleanup
name after the last check. Task 8 therefore requires a constructor-attested
`TrustedNamespaceMutationLease`; an advisory file lock, cooperative target lock,
dirfd, postcheck, inode hash, or self-reported `held=true` is not this capability.

Its backend identity is the exact canonical-final-LF object
`{schemaVersion=1,domain="rsi-namespace-mutation-lease-backend-v1",backendName,
backendVersion,implementationDigest,runtimeIdentityDigest,configurationDigest,
leaseSignerKeyId,leaseSignerPublicKeyDigest,signatureAlgorithm}` with
`signatureAlgorithm="platform-attestation-v1"`. Its capability is the exact
canonical-final-LF object
`{schemaVersion=1,domain="rsi-namespace-mutation-lease-capability-v1",
backendIdentityDigest,capability="noncooperative-same-uid-namespace-exclusion",
scope="canonical-managed-tree-ancestry-names-and-operand-inodes",atomicAcquire=true,
holderDeathReleases=true,enforcerDeathFailClosed=true,
liveHolderNeverOutlivesProtection=true,signedCausalResults=true,
exchangeCovered=true,reverseCovered=true,unlinkCovered=true,
preparedPostCreationAndWriteCovered=true,
operandLinkMutationCovered=true,operandContentMutationCovered=true,
operandMetadataMutationCovered=true,managedTreeMutationCovered=true,
mountAndAliasMutationCovered=true,preopenedHandleMutationCovered=true,
writableMmapMutationCovered=true,dirtyWritebackCovered=true,
fullManifestReadbackCovered=true,
fullVerifierWindowCovered=true,eventCallbackCovered=true,
noSilentExpiry=true,backendPerformsMutation=true}`.
Their digests are respectively
`namespaceMutationLeaseBackendIdentityDigest` and
`namespaceMutationLeaseCapabilityDigest`, each `"sha256:"+lowerhex(SHA256(`
exact canonical-final-LF bytes `))`. A constructor-owned immutable registry—not a
public caller subclass or request object—resolves those exact digests to pinned
implementation/runtime/configuration/signing-key objects and an independently
attested OS/host capability report. The report must prove mandatory exclusion of
noncooperative same-UID namespace mutations for the stated scope; copying these
booleans into an object is not proof.
Backend name/version/key ID are 1--128 ASCII characters matching the Task 7 ID
grammar; every implementation/runtime/configuration/public-key/identity/
capability digest is an exact prefixed Task 8 digest; and every capability flag
is a JSON boolean exactly true. Both mappings reject null, extra keys, booleans
in integer slots, alternate domains, and noncanonical framing.

For each mutation, the service constructs the exact canonical-final-LF
`NamespaceMutationLeaseRequest`
`{schemaVersion=1,domain="rsi-namespace-mutation-lease-request-v1",transactionId,
planDigest,rootIdentityDigest,ancestryWitnessDigest,artifactParentWitnessDigest,
managedTreePolicyDigest,expectedManifestPreHash,expectedManifestPostHash,
targetName,reservedName,operationClass,acquisitionNonce,deadline}`. Names are the
two admitted basenames in their one retained artifact parent; the managed-tree
policy fixes the complete bounded manifest membership/metadata scope and all
aliases/paths that could create an incoming hard link or change either operand's
link count. `operationClass` is exactly `forward-apply|rollback-apply|
verifier-readback|promoted-terminal|unresolved-terminal|incident-classification|prepared-post-cleanup|
retained-preimage-cleanup|displaced-post-cleanup`;
`acquisitionNonce` is fresh 32-byte lowercase hex from the trusted CSPRNG. The
request digest is exactly `requestDigest=D(NamespaceMutationLeaseRequestV1)`.
The matching `NamespaceMutationScopeV1` is the exact CFL object
`{schemaVersion=1,domain="rsi-namespace-mutation-scope-v1",ancestryWitness,
ancestryWitnessDigest,artifactParentWitness,artifactParentWitnessDigest,
managedTreePolicy,managedTreePolicyDigest}`. Each nested object is the complete
exact object defined above; each adjacent digest is `D` of that object and is
byte-equal to the request's corresponding digest field. Its own digest is
`scopeDigest=D(NamespaceMutationScopeV1)`. Specifically, root identity equals
the ancestry, parent, policy, request, plan and intent root fields;
`parent.parentRelativePath == ancestry.parentRelativePath ==
POSIX-dirname(policy.artifactRelativePath) ==
POSIX-dirname(policy.reservedRelativePath)` and is not a request field;
`parent.ancestryWitnessDigest == D(ancestry) ==
request.ancestryWitnessDigest`; and `D(parent) ==
request.artifactParentWitnessDigest`. Parent metadata equals the last ancestry
child tuple. Policy and pre/post manifest digests equal the request/plan/intent
fields. The policy allowlist digest equals the plan; its full artifact and
reserved relative paths equal the plan/deterministic sibling, while only their
basenames equal `request.targetName`/`request.reservedName`. The request binds
the policy digest but does not contain or purport to equal the full policy
object, allowlist, parent-relative path, or full relative paths.

The backend atomically acquires that exact mandatory scope and returns a private, invocation-
bound handle plus a signed canonical-final-LF receipt exactly
`{schemaVersion=1,domain="rsi-namespace-mutation-lease-receipt-v1",leaseId,
leaseRequestDigest,backendIdentityDigest,capabilityDigest,transactionId,
operationClass,acquisitionNonce,issuedAt,expiresAt,signatureAlgorithm,signature}`.
`leaseId` is
`"lease_"` plus its first 32 digest hex; transaction/class/nonce equal the
request, while identity/capability equal the constructor-admitted promotion
authority; time is trusted and covers the complete guarded operation. The signed
mapping is the exact receipt minus only `signature` and uses
the pinned key plus the same canonical platform-attestation signature encoding
defined for verifier receipts. Specifically, `leaseReceiptBodyDigest` is the
prefixed SHA-256 of that signed mapping's canonical-final-LF bytes and the signer
signs only the prefixed SHA-256 of exact canonical-final-LF
`{schemaVersion=1,domain="rsi-namespace-mutation-lease-receipt-signature-v1",
leaseReceiptBodyDigest}`.
The request's schema version is integer 1; transaction/plan/root/ancestry/parent/
policy/manifest fields are exact admitted IDs or prefixed digests; target and
reserved names are 1--255-byte normalized UTF-8 basenames with no slash,
backslash, NUL, dot component, or alternate normalization; and `deadline` is a
canonical UTC-second string strictly after acquisition. The receipt's IDs/digests
and class/nonce are byte-equal to that request, `issuedAt<=expiresAt==deadline`,
and its signature is the same 1--2,048-byte canonical padded `base64:` form.

Every event-bound use embeds, rather than merely echoing a digest of, one exact
`NamespaceMutationLeaseEvidenceV1` CFL object with exactly the twelve keys
`{schemaVersion=1,domain="rsi-namespace-mutation-lease-evidence-v1",request,
requestDigest,scope,scopeDigest,receipt,receiptDigest,backendResults,
backendResultsDigest,stepWitnesses,stepWitnessesDigest}`. `request` and `scope`
are the complete objects above and both adjacent digests are recomputed with
`D`; a digest-only or reconstructed subset is invalid. `receipt` is the complete
signed receipt above; `receiptDigest` is the prefixed SHA-256 of its exact
canonical-final-LF bytes. `backendResults` is an ordered array of one through
five exact signed result objects and `backendResultsDigest` is the prefixed
SHA-256 of the array's canonical-final-LF bytes. `stepWitnesses` is the
same-length, same-order array of the exact step-witness objects below and
`stepWitnessesDigest` is the prefixed SHA-256 of that array's
canonical-final-LF bytes. Each result is exactly
`{schemaVersion=1,domain="rsi-namespace-mutation-backend-result-v1",leaseId,
leaseRequestDigest,backendIdentityDigest,capabilityDigest,transactionId,
operationClass,step,outcome,possibleMutation,beforeWitnessDigest,
afterWitnessDigest,directorySynced,completedAt,signatureAlgorithm,signature}`.
Its signed mapping is the exact object minus only `signature`; receipt and every
result `leaseRequestDigest` equal the embedded `requestDigest`; embedded request,
receipt and every result have byte-equal transaction ID and operation class;
request and receipt alone have byte-equal `acquisitionNonce`; request
`deadline == receipt.expiresAt`; and the deterministic
`leaseId` is derived from that embedded request digest. Receipt/result backend
identity and capability equal each other and the admitted `PromotionAuthorityV2`.
The request plan/root/manifest/names equal the causal plan, intent and operation
arm, and its three scope digests equal the embedded exact scope preimages. All
identity, request, transaction, class, and algorithm fields otherwise cross-equal, while
canonical trusted `issuedAt<=completedAt<expiresAt` is mandatory.
That inequality is evaluated from the signed historical timestamps. Once the
complete evidence is causally bound by its durable event, later wall-clock
passage beyond `expiresAt` does not invalidate replay or fold. Current trusted
`now<expiresAt` is required only while a live handle is about to perform a step
or event callback; an old receipt/result can never authorize a fresh mutation.
`backendResultBodyDigest` is the prefixed SHA-256 of that signed mapping and the
same lease key signs only the prefixed SHA-256 of exact canonical-final-LF
`{schemaVersion=1,domain="rsi-namespace-mutation-backend-result-signature-v1",
backendResultBodyDigest,leaseRequestDigest}`.
`step` is exactly `prepared-post-create-write|forward-exchange|emergency-reverse|
rollback-exchange|protected-readback|prepared-post-cleanup|
retained-preimage-cleanup|displaced-post-cleanup`.

Each `stepWitnesses` entry is exactly
`{schemaVersion=1,domain="rsi-namespace-mutation-step-witness-v1",step,before,
after}` and has the same `step` and array index as its signed result. `before`
and non-null `after` are exactly one of these canonical-final-LF closed mappings:

- prepared state:
  `{schemaVersion=1,domain="rsi-namespace-prepared-post-state-v1",name,
  artifactParentWitnessDigest,classification,preparedPost}`;
  `classification=absent` has `preparedPost=null`, while `present` has the exact
  complete prepared-post file witness used by the apply sidecar or live-FD
  incident phase arm. For the matching present `RetainedNameWitnessV1`,
  `preparedState.name==preparedPost.name==retained.name` and
  `retained.object==objectFromNamed(preparedPost)`; no differently shaped
  mapping is byte-equal;
- exchange state:
  `{schemaVersion=1,domain="rsi-namespace-exchange-state-v1",direction,
  ancestryWitnessDigest,artifactParentWitnessDigest,target,swap,
  operandClassification}`; direction is exactly
  `forward|emergency-reverse|rollback`; `target` is the complete exact
  `TargetWitnessV1`, `swap` is the complete present `RetainedNameWitnessV1`
  with the direction-appropriate role, and `operandClassification` is exactly
  `pre-order|exchanged-order|other|unreadable`. This step records only the two
  operands/ancestry known at the syscall boundary; the following distinct
  protected-readback step carries whole-manifest classification;
- cleanup state:
  `{schemaVersion=1,domain="rsi-namespace-cleanup-state-v1",name,
  authorizedObject,classification,artifactParentWitnessDigest}`; the exact
  `authorizedObject` is the causal present `RetainedNameWitnessV1` and remains
  non-null in both
  `classification=present|absent` arms;
- protected-readback state:
  the exact five-key mapping
  `{schemaVersion=1,domain="rsi-namespace-protected-readback-state-v1",
  classification,targetReadbackView,errorWitness}`. It is a closed union:
  `exact-pre|exact-post` has the matching complete `TargetReadbackView` and
  `errorWitness=null`; readable `other` has a complete `TargetReadbackView` and
  `errorWitness=null`; proven missing/special/unsafe-link drift has
  `classification=other`, `targetReadbackView=null`, and exact
  five-key `{kind="known-drift",observedKind,rootIdentityDigest,relativePath,
  metadata}`.
  `observedKind` is exactly `missing|special|unsafe-link`; `missing` requires
  `metadata=null` and a causal expected-present predicate, while the other arms
  require exact bounded nofollow metadata
  `{type,device,inode,mode,uid,nlink,size}` with `type` exactly
  `regular-file|symlink|dir|fifo|socket|block|char|other-special`.
  `unsafe-link` permits only `type=symlink` or
  `type=regular-file,nlink>=2`; `special` permits only
  `dir|fifo|socket|block|char|other-special`.
  Missing, special, and unsafe-link map respectively to the
  incident target-witness kinds `missing`, `named-object-drift`, and
  `link-drift`, with equal root/path and null incident `errorCode`. Only a
  failure to prove the named object's kind or metadata has
  `classification=unreadable`, `targetReadbackView=null`, and exact
  four-key `{kind="unreadable",errorCode,rootIdentityDigest,relativePath}` whose fields
  equal the unreadable incident target witness. Known drift
  is never mislabeled unreadable, and no null-view arm can authorize a clean
  exact-pre/exact-post terminal.

For each non-null nested state, the corresponding result witness digest is the
prefixed SHA-256 of that exact mapping's canonical-final-LF bytes. An ambiguous
mutation result alone has `after=null` and `afterWitnessDigest=null`. The only
other null-after result is `*-cleanup/performed-unsynced` after an authorized
unlink returned success but the protected absence readback itself failed; its
matching cleanup phase witness is mandatory. Every other result has both
mappings and digests. A protected-readback has byte-identical
before/after state. A performed create is absent→present, a not-performed create
is absent→absent, a performed exchange has the exact direction-appropriate
operand permutation, a not-performed exchange has equal states, a performed
cleanup is present→absent, and an already-absent not-performed cleanup is
absent→absent. The witness preimages are authority, not opaque signer claims:
prepared state cross-equals the intent/readback prepared-post fields; exchange
state cross-equals the intent plus apply/rollback/incident operand and ancestry
witnesses; cleanup state cross-equals the causal event-bound identity and exact
cleanup disposition; and every protected-readback view has its `scanDigest`,
classification, target/hash/retained-name/ancestry fields independently
recomputed and byte-equal to the containing readback, verification, decision, or
incident fields. A null-view protected-readback instead independently recomputes
the complete exact known-drift or unreadable witness and cross-equals the
incident target witness and reason mapping above; it cannot satisfy a clean
readback. A digest whose complete preimage is absent, mismatched, or not
recomputable fails.

The outcome/null arms are literal and step-specific:

| step/outcome | `possibleMutation` | witness digests | `directorySynced` |
|---|---:|---|---|
| `prepared-post-create-write/performed` | true | exact absence → exact still-live partial-or-complete prepared inode | true, only after the exact current inode and artifact parent are successfully synced |
| `prepared-post-create-write/performed-unsynced` | true | exact absence → exact still-live prepared inode | false; file or artifact-parent durability failed, incident only |
| `forward-exchange`, `emergency-reverse`, or `rollback-exchange` / `performed` | true | exact before → exact exchanged/reversed operands | true, only after artifact-parent sync |
| any `*-cleanup/performed` | true | exact bound inode → exact absence | true, only after artifact-parent sync |
| any `*-cleanup/performed-unsynced` | true | exact bound inode → exact absence, or null after only when absence readback failed | false; authorized unlink returned success but durable absence is unproved, incident only |
| any mutation step / `not-performed` | false | equal exact before/after | null, except an already-absent cleanup proof is true after parent sync |
| `protected-readback/exact-pre`, `/exact-post`, or `/other` | false | equal exact complete protected state; `other` is either full readable view/null error or null view/exact known-drift | null |
| `protected-readback/unreadable` | false | equal exact complete unreadable state with null view and exact `kind=unreadable` witness | null |
| any mutation step / `ambiguous` | true | exact before / null after | null |

No other step/outcome pairing is legal. A partial prepared inode is cleanly
recordable as `performed` only by the uninterrupted original-FD holder after a
successful subsequent sync of its exact current bytes and parent while target
remains protected exact-pre. Persistent file/parent sync failure with the
original FD and exact inode still live is `performed-unsynced` plus the exact
prepared-sync incident phase witness. Unknown inode/bytes/name or loss of that
handle is ambiguous and incident-only.
Digests
are Task 8 prefixed digests; booleans are JSON booleans; timestamps are canonical
UTC-second strings. Missing, extra, reordered, unsigned, cross-lease, or
semantically impossible results fail; a duplicate step fails except for the two
positionally distinct protected readbacks in the exact emergency and rollback
sequences below.
For `step=protected-readback`, result `outcome` equals the complete state's
`classification` byte-for-byte. Its `beforeWitnessDigest` and
`afterWitnessDigest` both digest that complete exact state, including either the
full view or the closed error witness; a digest of only the nested view/error is
invalid.
The containing sidecar/event digest
binds the complete evidence object. An evidence object without its mapped durable
event is an inert orphan and never authorizes replay, mutation, cleanup, or close.
The ordered result sequence is also closed by operation:

- uninterrupted forward create failure is exactly
  `[prepared-post-create-write/not-performed, protected-readback(exact-pre)]`;
- post-crash never-created recovery performs no fictional create step and is
  exactly `[protected-readback(exact-pre)]` under `unresolved-terminal`;
- a retained pre-exchange failure is exactly
  `[prepared-post-create-write/performed, protected-readback(exact-pre)]`;
- a live-FD persistent prepared sync failure is exactly
  `[prepared-post-create-write/performed-unsynced,
  protected-readback(exact-pre)]` and is incident-only;
- commit-check drift is exactly `[prepared-post-create-write/performed,
  forward-exchange/not-performed, protected-readback(exact-pre)]`;
- applied is exactly `[prepared-post-create-write/performed,
  forward-exchange/performed, protected-readback(exact-post)]`;
- emergency reverse is exactly `[prepared-post-create-write/performed,
  forward-exchange/performed, protected-readback(other),
  emergency-reverse/performed, protected-readback(exact-pre)]`;
- forward incident arms are the applicable exact sequence above with the final
  protected readback changed to `other|unreadable`; when an emergency reverse is
  unsafe or refused, the sequence ends after the `other` readback or with
  `emergency-reverse/not-performed|ambiguous`; when reverse performed but final
  classification is not exact pre, its fifth result is
  `protected-readback(other|unreadable)`. A create-not-performed or
  forward-not-performed incident likewise carries its truthful result followed
  by the `other|unreadable` readback;
- verifier, promoted-terminal, unresolved-terminal, and incident-classification
  each have exactly one `protected-readback(exact-pre|exact-post|other|
  unreadable)` as its causal arm permits;
- rollback is exactly `[protected-readback(exact-post),
  rollback-exchange/performed, protected-readback(exact-pre)]`;
- rollback incident arms use the same exact prefix with
  `rollback-exchange/not-performed|ambiguous`, or a performed exchange followed
  by `protected-readback(other|unreadable)`;
- clean cleanup is exactly `[matching-cleanup/performed,
  protected-readback(expected-terminal-state)]` for `removed-now`, or
  `[matching-cleanup/not-performed,protected-readback(expected-terminal-state)]`
  only when both cleanup states are already absent and parent sync succeeded;
  cleanup incident arms use a present→present not-performed result, an ambiguous
  result, a `performed-unsynced` result followed by the expected protected
  readback when protected absence was readable, a sole `performed-unsynced`
  result when absence readback failed, or a performed/not-performed result
  followed by `protected-readback(other|unreadable)`.

For a cleanup sequence, the heavy whole-tree `TargetReadbackView` is built
lease-only before entering the continuously held provider guard. The final
`protected-readback` result performs no file-content hash under that guard: while
the same lease excludes managed-tree mutation, it bounded-rechecks the cached
member/name/ancestry metadata, substitutes only the newly proven reserved-name
absence, and recomputes the canonical view/scan digests. Any mismatch or
unreadable bounded recheck selects the incident sequence rather than clean close.

An ambiguous failure may be a strict applicable prefix ending in the exact
ambiguous step and is incident-only. Any reordered, repeated (except the two
positionally distinct readbacks in the exact emergency and rollback sequences),
skipped-after-performed, sixth, or cross-operation result is invalid.

The private handle exposes only backend-gated prepared-post create/write,
`exchange`, `unlink`, and protected readback methods; the backend itself performs
or gates each scoped mutation inside its
enforced critical section and refuses a different request/name/dirfd/token. No
raw rename/unlink is returned to the caller for later execution. For the complete
lease duration the backend excludes noncooperative same-UID rename/link/unlink/
mount/alias operations over the root/ancestry/tree/name scope, incoming hard-link
creation or any other `nlink` change for either operand, and write/truncate/chmod/
xattr or other content/metadata mutation of the managed tree and operand inodes.
That exclusion includes aliases, file descriptors opened before acquisition,
writable memory mappings, delayed/dirty-page writeback, and mutation issued from
another mount namespace or process; blocking only newly opened paths is
insufficient.
The lease is held continuously from atomic acquisition through final ancestry/
name/operand recheck, forward or reverse exchange (or exact-name unlink), parent
sync, exact full-manifest readback, postclassification, and the event callback
that durably records that classification. The forward class includes at most one
conditional emergency reverse without releasing the scope. Verifier and promoted-
terminal classes cover their full readback plus verifier/resolve terminal
linearization; cleanup classes cover exact-name check, optional unlink, parent
sync and absence readback. The backend emits the signed causal result immediately
after each gated step; the coordinator cross-checks it against the live post-
witness and embeds the complete receipt/results evidence in the pending sidecar
before the EventStore callback. The signed acquisition receipt proves only
authenticated acquisition—not mutation, continued liveness, or final state—and
can never invoke a mutation by itself. Only the exact signed backend result plus
post-witness and the causally mapped durable event proves a completed step.
Release occurs only afterward;
process death releases the mandatory host scope. PromotionService restart never
assumes a prior
lease survives: it reopens all descriptors, rebuilds witnesses, and obtains a new
operation-specific lease before any reverse or unlink. Failure to acquire,
authenticate, retain, or prove the lease is a pre-mutation typed failure when the
target is still exact pre; after any possible forward mutation it is incident-
only and never falls back to an advisory path.

Holder and enforcer death are distinct. Holder death atomically releases the
scope, invalidates the old private handle, and allows a fresh recovery acquisition;
the old token can never resume. Enforcer/backend death while the holder remains
must either leave kernel-enforced protection intact or be atomically detectable by
the backend before any mutation/callback. It must not silently release protection.
An external enforcer is privileged and protected from the same-UID threat actor;
loss that cannot be proven pre-mutation is a possible-mutation incident, with no
success claim or fallback. A lease never silently expires while a live holder can
continue. The holder must explicitly release before `expiresAt`; if the bounded
deadline is reached, the privileged backend first atomically fences and terminates
the holder (or retains kernel protection) and only then releases. It never returns
unprotected control to that holder. Long full-readback/verifier/callback work must
fit the admitted bound; expiry, watchdog uncertainty, or enforcer uncertainty can
never affirm or clean-close. Tests kill holder and enforcer separately.

The built-in local-host registry permanently advertises unavailable on ordinary
macOS/Linux: advisory flocks, `RENAME_SECLUDE`, dirfds, nofollow flags and inode
postchecks do not block noncooperative same-UID ancestor/name/link/content/
metadata mutation. Production availability therefore requires an integration-
tagged privileged kernel/filesystem/host mediation backend whose report proves
the whole contract. Positive unit tests
may install only an explicit test-authority registry fixture that actually
serializes the adversarial namespace actors; they may not pass an arbitrary
backend instance, callback, boolean, capability report, receipt, or token.

Guarded apply sequence:

1. Strictly load/re-admit the validation bridge, Task 7 request/bundle/attestation/plan/post-image, provider identity, candidate authority, current allowlist/root/contract/control-plane/deployment state, policy/kill switches, TTL, latch/quarantine state, and exact artifact/whole-manifest pre-state.
2. Prove the specification's single-artifact promotion-scope V1 compatibility
   using the strict Task 7 V2 authority, and prove that target, provider, event,
   experiment and control-plane roots are canonical and pairwise disjoint. Reject
   unsafe permissions, ownership, links, special files, dangerous mode bits, and
   metadata the implementation cannot preserve exactly. Re-admit the exact
   namespace-lease backend/capability and complete both its non-mutating scoped
   acquisition probe and the atomic-exchange self-probe before any continuation
   write.
3. Only after the successful probe, create/re-admit and journal the continuation's `run.started`, `promotion.gated`, `staging.completed`, `validation.completed`, and `promotion.planned` events.
4. Under deterministic lock order, recheck all volatile authority and filesystem witnesses; call the one exact provider snapshot and durably bind its receipt to `snapshot.created`.
5. Draw and bind the one verifier nonce in the exact intent sidecar, including
   the planned namespace-lease identity/capability digests; publish it, then enter
   provider Guard A for the five bound
   candidate authority digests, then acquire the brief EventStore journal lock. Recheck
   candidate, latch, TTL/control state plus bounded root/parent/artifact/
   previously-hashed-tree metadata witnesses, append/fsync `apply.started`
   before any temp or target write, release the journal lock, then release Guard
   A and every transaction/global/target lock. No EventStore-held path may attempt
   to enter a provider guard.
6. With no RSI/provider/EventStore lock held, preliminarily descriptor-admit the
   exact scope and acquire an authenticated `forward-apply` namespace lease.
   Only after acquisition, take transaction/global/target locks in forward order,
   reread the complete durable tail, and require the same `apply.started` intent.
   Through the lease backend create the transaction-owned hidden swap file
   descriptor-relative in the exact artifact parent (never another directory),
   `O_CREAT|O_EXCL|O_NOFOLLOW`, `nlink=1`; write only the exact content-addressed
   post-image, preserve admitted mode/metadata, fsync/full-sync, sync that parent,
   and read back exact bytes/identity. A concurrent caller waits on the lease
   without any RSI lock, then rereads/replays instead of racing a live temp.
7. Still holding that outer `forward-apply` lease plus inner target locks for the
   exact retained ancestry, complete managed tree, parent, two basenames and
   operand inodes, enter provider Guard B with
   the same expected provider-full/provider-
   authority/Task-7-binding/capture-lineage/combined-state digests. Immediately before exchange,
   freshly sample the trusted clock and require `now < expiresAt`, then recheck
   every volatile new-apply authority: provider candidate, policy and kill
   switches, allowlist/root/contract/control-plane/deployment witnesses, absence
   of latch/quarantine, the entire retained ancestry chain, named target inode,
   prepared temp, and bounded metadata witness for the already-hashed exact
   pre-manifest. These are commit checks, not results cached from Guard A. Then
   invoke the lease handle's backend-gated atomic exchange of the swap basename
   with the target basename through the same retained artifact-parent dirfd.
   Cross-directory operands are forbidden.
   Platform flags are not topology validation or inode-
   CAS: temp and target are independently nofollow/nonblocking-opened and proven
   regular, single-link and exact before and after the syscall. On an exactly
   exchanged arm, sync/read back that one artifact parent before claiming
   `directorySynced=true`. Keep Guard B through exact post-classification and
   ancestry recheck on the successful arm. Guard B then releases and the complete
   inner transaction/global/target suffix releases, but the outer namespace lease
   remains held. Any pre-exchange drift with
   still-exact named ancestry/pre-state returns a closed no-exchange
   classification. Still under that same lease and with no inner lock,
   full-readback exact pre, then reacquire transaction/global/target and a separate
   append-capable unresolved guard in forward order, validate the all-origin batch, and
   durably record `apply.completed(outcome=not-applied)` with the exact prepared
   temp retained and the original exclusive-create FD still held; if that live
   capability was lost, the reserved object is unknown and incidents. The
   matching closed reason (`authority-expired`, `candidate-drift`,
   `policy-drift`, `kill-switch-active`, `allowlist-drift`, `root-drift`,
   `control-plane-drift`, or `target-drift`); no exchange occurs. A preexisting
   immutable latch instead takes the matrix `preexisting-latch` incident arm and
   closes quarantined with `latchDisposition=preexisting`.
   After that event, release the complete inner suffix in reverse order and then
   the forward lease; only a fresh
   `prepared-post-cleanup` lease may first build the heavy exact-pre full view
   with no inner lock. It then acquires transaction/global/target and one
   unresolved terminal guard in forward order, bounded-rechecks that view and
   exact event-bound temp, keeps the guard continuously held while the backend
   removes-or-proves-absent that inode, syncs its parent, performs the bounded
   protected postcheck, and appends the not-applied decision/close. It then
   releases the complete inner suffix in reverse order and finally the cleanup
   lease. If
   exact event binding, cleanup, lease, ancestry, or pre-state
   cannot be proven, latch without unlinking or exchanging.
8. On an exact exchange, Guard B still post-classifies only operands/ancestry/
   current provider and then releases with the entire inner lock suffix; it
   performs no whole-tree hash. Keep only the forward lease and double-scan
   the complete managed tree into `TargetReadbackView`. If exact post, reacquire
   transaction/global/target then the rollback-mode append guard (capture lineage
   + resolution null) in forward order, validate the
   all-origin batch and bounded view identity, and publish
   `apply.completed(outcome=applied)` plus readback sidecar with the complete
   forward-lease evidence and intent-bound verifier core commitment. Only this
   uninterrupted holder, whose backend result and live handle were just
   revalidated, may publish that factual event. Complete the guard
   postcheck/EventStore fsync, then release the complete inner suffix in reverse
   order and finally the lease. A defer may still
   permit this factual event; terminal/unknown resolution incidents. If the full
   tree is `other` while the artifact operands remain exact, the same still-held
   forward lease backend performs at most one emergency reverse, syncs and full-
   readbacks exact pre, then an incident append guard publishes incident directly
   from `apply.started` before lease release. This is neither not-applied nor
   apply-reverted and preserves the displaced post. Unknown operands/tree/
   ancestry/provider, lease/enforcer loss, or reverse ambiguity incidents under
   the same lease when possible and otherwise leaves the unresolved apply as an
   implicit latch. After a crash, target-pre plus an unbound swap-post remains
   `prepared-temp-unknown` and is preserved.
9. From durable applied state, acquire a `verifier-readback` lease over the whole
   managed tree, construct a fresh exact-post readback, reconstruct the final
   applied-event-bound verifier request, and run the bounded trusted verifier
   while the lease—not a provider/EventStore/global lock—remains held. Verify the
   pinned-key signature before publishing any receipt at its deterministic request
   path. For passed/failed/authenticated-unavailable results, reacquire
   transaction/global/target and then enter the appropriate new-apply or rollback
   append guard in forward order under the same lease, validate current
   authority and the all-origin batch, and append respectively
   `verification.completed(affirmed|rollback-armed)` before releasing the
   complete inner suffix in reverse order and finally the lease. Resolve/defer
   races select the exact allowed arm or incident; unknown
   verifier state incidents from applied. No verification event is appended from
   a readback whose lease was released.
10. Affirmed flow acquires a `promoted-terminal` lease with no inner lock and
    full-readbacks exact post. It then calls the exact provider resolve while the
    lease remains held but no transaction/global/target/EventStore lock is held.
    It reacquires transaction/global/target then enters terminal-readback guard in
    forward order, rechecks the result and bounded target metadata, publishes or
    strictly replays the bounded `resolution-readback` sidecar, and appends
    missing `resolution.recorded` referencing it; then releases the inner suffix
    and lease. A
    fresh `retained-preimage-cleanup` lease first builds the heavy exact-post view
    with no inner lock, then acquires transaction/global/target and one terminal
    guard. After bounded provider/target/name recheck it keeps that guard held
    while the backend removes-or-proves-absent only the bound retained inode,
    syncs the parent, performs the bounded protected postcheck, and publishes
    decision/close; it then releases the complete inner suffix before the cleanup
    lease. Crash after
    resolve repairs only under these fresh leases; drift incidents without cleanup.
11. Rollback-armed flow acquires a `rollback-apply` lease with no inner lock,
    then transaction/global/target and a short rollback guard in forward order.
    It reverse-exchanges through the backend, releases the entire inner suffix
    while retaining the lease, full-readbacks exact pre lease-only, then
    reacquires transaction/global/target and the rollback terminal guard in
    forward order to append `apply.reverted` with the complete signed rollback
    lease evidence before releasing the complete inner suffix in reverse order
    and finally the lease. Only the uninterrupted
    holder that received that backend result may append the revert. A
    separate `displaced-post-cleanup` lease builds the heavy exact-pre view with
    no inner lock, then acquires transaction/global/target and one unresolved
    terminal guard and keeps it continuously across bounded exact displaced-post
    cleanup-or-absence, parent sync, protected postcheck, decision and close. It
    then releases the inner suffix before the cleanup lease. Every gap/race/crash is classified
    from the last durable event; no heavy hash runs under provider authority and
    no target classification becomes stale before its event callback.

No transaction, global, target, provider, or EventStore lock may be held while hashing a
large tree or running live verification. The namespace-lease-only double-scan
produces the exact hash result; retained descriptors and bounded name/metadata/ancestry
precheck/postcheck witnesses couple that immutable view to the guarded callback.

## Rollback, recovery, and incident latch

Classify live target state as exactly one of:

- `exact-pre`: canonical root/path/metadata, artifact pre-hash and whole manifest-pre hash match;
- `exact-post`: canonical root/path/metadata, artifact post-hash and whole manifest-post hash match;
- `other`: mixed state, changed member, missing entry, alias/link/special/mode/root/parent drift, or unknown temp;
- `unreadable`: bounded safe proof is impossible.

Automatic rollback is permitted only when target is exact post, provider resolution is proven uncommitted, authoritative snapshot/preimage proves exact pre, retained swap operands remain exact, and `rollback-armed` is already durable. Roll back with a second atomic exchange, prove exact pre artifact and whole manifest, then remove only the exact displaced post inode. Never rollback from artifact hash alone, after committed/unknown provider resolution, or over any concurrent/unknown state.

The following are `PromotionService.promote_candidate()` restart/resumption
rules after an explicit exact-plan replay. They do not grant mutation authority
to `PromotionRecovery.inspect()`: that public recovery object only observes the
same last durable state and reports the recommended branch.

- a durable plan/snapshot, with or without an orphan intent but with no complete
  durable `apply.started`, may close only through the exact not-started arm; it
  can never append `apply.completed`;
- a complete durable `apply.started` with exact pre and an absent reserved name
  may be resumed by the service only while all new-apply authority/TTL remains
  valid; otherwise service replay appends exact
  `apply.completed(outcome=not-applied,
  preparedPostDisposition=never-created)` and closes without target mutation;
- after process loss, any present reserved name without an already durable event-
  bound inode witness is `prepared-temp-unknown`: preserve it and incident even
  if its bytes exactly equal the post-image. The observational state target-pre +
  swap-post is also indistinguishable from an emergency reverse and never resumes,
  cleans, or emits not-applied;
- `apply.started` with exact post and no durable `apply.completed` never upgrades
  from observed hashes: a forward backend call may have happened but its
  event-bound result did not. Exact expected swap-pre selects
  `forward-exchange-ambiguous`; a missing/wrong/unknown swap selects the matching
  closed reserved-name/post-state incident. Recovery preserves target and swap
  and never synthesizes applied authority;
- apply-completed without verification continues only from exact post;
- exact post plus committed planned provider resolution lets service replay
  repair local events/terminal without another target write or pending-only
  verification;
- committed provider resolution plus non-post target, unknown provider state, `other`, unreadable, malformed chain, or corrupt journal produces durable quarantine and never rollback/overwrite;
- service replay repairs event/sidecar/close loss only after full exact readback
  of every prerequisite;
- a verified exact rollback may close failed/deferred without claiming promotion.

PromotionService restart crash classification is phase-exact:

- after intent but before `apply.started`: the sidecar is an orphan and permits no
  target/temp/provider action; a permanent failure closes from the last durable
  plan/snapshot through `transaction-decision(outcome=not-started)`;
- after `apply.started` but before temp creation, during temp write/fsync, or
  before exchange: the uninterrupted process may publish not-applied/`retained`
  only while it still holds the original FD, then clean from that event. After a
  crash, exact pre plus an absent name becomes not-applied/`never-created`; any
  present reserved object is unbound, preserved, and incidents. Recovery never
  infers ownership from expected bytes/inode shape and never deletes before an
  event;
- after an exchange syscall or `EINTR`, only the uninterrupted holder may
  classify the two names with its live backend handle, signed result, and exact
  inode witnesses and then publish the mapped event; it never retries blindly.
  After process loss, path hashes/inodes alone cannot attribute the mutation;
- after forward exchange with exact operands but whole-tree `other`: immediately
  reverse only the exact owned artifact when safe, retain the displaced post, and
  incident directly from `apply.started`; crash or reverse `EINTR` uses exact
  operand classification and never emits not-applied/apply-reverted or cleans it;
- after a forward exchange but before durable `apply.completed`, any recovery
  state compatible with a mutation is `forward-exchange-ambiguous` from
  `apply.started`, even when target/swap exactly resemble the expected exchange;
  an orphan sidecar, acquisition receipt, or backend-result object grants no
  authority;
- after negative verification and before reverse exchange: rollback only under a
  reacquired provider guard proving unresolved authority;
- after reverse exchange but before durable `apply.reverted`, recovery selects
  `rollback-exchange-ambiguous` from the rollback-armed verification and
  preserves both names; exact pre plus exact displaced post, an orphan rollback
  sidecar, or an acquisition receipt cannot reconstruct the missing event. Only
  the uninterrupted holder that performed the reverse may publish
  `apply.reverted`, after which its exact event authorizes cleanup;
- after provider resolve but before `resolution.recorded`: exact promoted provider
  authority plus exact verification repairs the local resolution event without a
  target write;
- after `resolution.recorded` but before retained-preimage unlink: that bounded
  event, its exact event-bound resolution-readback sidecar and provider record,
  and its causally bound affirmative verification sidecar are the sole cleanup
  authorization. Reopen the recorded
  name and require exact device/inode/mode/link/bytes before unlink; a mismatch
  latches and preserves it;
- after unlink but before directory sync/decision/close: prove the recorded name
  absent, sync/read back the parent, prove exact post and provider resolution,
  then publish decision and close. A reappearing or different name is never
  removed.

Incident publication order is transaction stop → local incident record → local
quarantine record → immutable latch CAS → `incident.latched` event → ambiguous/
quarantined close. First latch wins; conflicting content never overwrites it. The
winner records `created`; a loser records `preexisting` plus the exact blocking
latch digest and never claims the latch describes its local incident. A created
latch binds transaction/plan/candidate/run/root/artifact, closed reason code,
expected pre/post digests, observed state, lifecycle/intent digests, quarantine
targets, and `requiresOperatorAction=true`, with no raw diagnostics or secrets.
Explicit unlatch/restore is outside Task 8 and requires a separate trusted
operator workflow.

Read-only recovery double-scans immutable store/event/provider-read/target witnesses. If they drift, it returns `state-changing`. Monkeypatching every write syscall to fail must not prevent diagnosis; before/after filesystem manifests and inode/mode/link witnesses must be identical.

## Lock order and concurrency

Protected target phases use one outermost order:

```text
trusted namespace-mutation lease
  → transaction lock
    → global promotion gate
      → canonical-root target lock
        → short provider-authority guard or provider operation lock
          → brief EventStore lock
```

The lease is acquired only while no transaction/global/target/provider/EventStore
lock is held. Its scope is identified by preliminary descriptor admission and is
fully revalidated after acquisition. A protected phase may release inner locks for
bounded full-tree hashing or verifier execution and reacquire them only in the
same forward order while retaining the lease. No path ever acquires a lease while
holding an inner lock, and the backend never calls back into RSI locks. Pre-apply
phases that need no lease retain the suffix
`transaction→global→target→provider→EventStore`, but must release that entire
suffix before entering a protected phase. This prevents a lease holder waiting on
transaction/global locks from deadlocking with a caller that holds those locks
while waiting for the lease.

Snapshot and resolve provider operation/ledger locks are never nested with an
EventStore lock: the provider call returns, then its exact result is event-bound.
Snapshot occurs before any target lease; resolve may run inside a promoted-
terminal lease but still without EventStore, then the terminal guard/event
callback follows in the declared order. A namespace lease may span a bounded full
tree readback or trusted verifier because it is the mandatory non-bypassable
mutation exclusion boundary, but no provider/EventStore/global lock spans that
heavy work.
The complete allowed provider→EventStore nesting set is closed: historical gate/
all-origin batch callbacks; Guard A `apply.started`; rollback-mode
`apply.completed(outcome=applied)`; new-apply
`verification.completed(outcome=affirmed)`; rollback-mode
`verification.completed(outcome=rollback-armed)`; not-started/not-applied
event/terminal callbacks; rollback `apply.reverted`/terminal callbacks;
terminal-readback `resolution.recorded`/promoted close; and locked incident
publication/close. Each callback consumes the all-origin batch folded from that
same held provider FD. Current-candidate callbacks complete their locked
postcheck before release; historical gate callbacks use the final fixed-prefix
precheck rule above and then release without a mutable-current-state claim.
EventStore releases first. Guard A then releases before temp I/O. Guard B
later reacquires provider authority, performs final volatile/ancestry checks and
exchange/post-classification, and never appends or builds a historical batch. Its
encompassing namespace lease remains held through full readback and the later
append/incident callback. A classified failure releases Guard B, then enters the
separately listed not-applied/incident guard/callback without releasing that
lease. No path may
acquire EventStore→provider or obtain a second historical flock inside a current
guard. These guarded linearizations are the barrier against
concurrent defer/resolve. No EventStore/provider/target/transaction/global lock
may be held while acquiring the outer lease or
an earlier promotion lock. Same-plan
concurrent callers converge on one transaction, snapshot, apply, resolution and
terminal. A second incompatible plan for the same root sees stale authority and
conflicts before its snapshot/apply. External edits at every boundary must be
preserved, rejected, reverse-exchanged if safely possible, or quarantined; they
are never silently clobbered.

## Authoritative TDD slices

Write tests before each production slice and record exact RED/GREEN commands.

Before any Task 8 GREEN, the architecture RED set must demonstrate all of these
missing behaviors against the Task 7 baseline:

- the baseline registry rejects `apply.reverted`; the exact addendum admits only
  that one new type in promote-safe/local runs, only once per transaction, only
  after the same-transaction inline
  `verification.completed(outcome=rollback-armed)`, and with its exact sidecar/
  payload/formula. Affirmed/direct/cross-run/cross-transaction/duplicate/orphan
  variants fail. Every Task 8 event, including run start/close, uses the exact
  deterministic event-ID formula while legacy IDs remain unchanged. Tampering
  the normative Markdown while leaving JSON unchanged, either addendum digest,
  or the control-plane version makes a V2 plan ineligible;
- external gate acceptance requires the exact recomputed Task 6 origin seal and
  every finding/observation/evaluation/provider binding/route/report/freshness/
  close source. Missing, orphaned, wrong-kind, substituted, changed request/path/
  owner, generic external predecessor, fabricated expiry/tombstone, or missing
  pinned origin object fails. Full lineage admission/double-scan happens outside
  provider/EventStore locks; callbacks use only immutable views and bounded
  metadata checks. Many max-size terminal origins cause zero source-body reads
  while either lock is held, but tampered seal/prefix/profile still fails;
- historical authority remains valid after the exact candidate is promoted later
  and binds byte length, event count, final event ID, latest authority event,
  protocol/profile, candidate/root and all five authority digests. Truncation,
  substitution, unsupported/tampered profile, arbitrary current source/helper/
  contract drift, or protocol change fails. An approved compatible provider
  upgrade with the same protocol validates old prefixes through the retained RSI
  profile while making a fresh old-version plan stale;
- historical batches cover every origin from one provider lock/FD, group by at
  most eight exact profiles, stream each profile once at sorted boundaries, and
  reject more than 4,096 origins, 200,000 decoded applications, or ledger bounds
  before EventStore append. Gate/Guard A, applied readback, both verification
  arms, not-started/not-applied, rollback/terminal, and incident callbacks consume
  the same-lock batch and never recursively flock;
  Guard B builds no historical batch. Counters prove bounded rather than
  origin×ledger work;
- a hashed-active-skill `promote-safe` continuation closes under promotion
  invariants while unchanged observe/propose Task 4 close guards still reject
  missing observations/evaluations;
- Task 7 V2 persists and recomputes outer `reservationDigest`, inner
  `experimentRequestDigest`, all five candidate authority digests, both exact
  issuance-bound deployment-attestation refs/raw bytes, artifact-store identity,
  control-plane digest/version, and both addendum digests throughout current
  state/reservation/result/attestation/plan/provider operation IDs. REDs lock the
  literal 21/34/21/9/19/22/6/12/5/4/23-key schemas, exact domains and no-null
  rules; validation signed-body versus raw digest; plan-core/plan-ID/operation-ID
  preimages; byte-equal nested authority; exact seven-member marker-last bundle;
  and full runtime/execution/verifier/policy cross-equalities. Swaps,
  omissions, copied stores, late same-digest injection, changed managed bytes/
  executable bits, bare/prefixed confusion, or final-newline substitution fails.
  V2 publication-to-Task 8 load is zero-write; strict V1 remains readable/
  replayable but promotion-ineligible;
- public `promote-candidate` requires all six selectors/IDs, reconciles each to
  the trusted plan and deterministic run/command IDs before writable open, and
  has stable JSON/replay/typed-nonzero behavior. Malformed, path-like, swapped,
  conflicting, or substituted CLI values are zero-write;
- every transaction event admits only its exact closed payload arm, sidecar kind/
  path/transaction/filename digest/event binding, and predecessor. The
  applied/not-applied union rejects mixed hashes. A prepared post is either never
  created or retained and event-bound before cleanup; only the uninterrupted
  original FD may publish the retained arm. After process loss any present
  unbound reserved name—including exact expected bytes and target-pre/swap-post—
  is preserved and incidents. Crash resumes only already event-bound cleanup,
  while exact-pre/absent no-create recovery uses only a fresh
  `unresolved-terminal` protected readback and never fabricates a create result,
  while cleanup-before-event, hidden/unknown temp, or mislabeled rollback fails/
  latches. Rollback readback requires `retainedPreimage=null`, exact pre target,
  sole displaced-post witness, and the precise before/after cleanup states.
  Exact-post/swap-pre after `apply.started` but before applied event is
  forward-exchange-ambiguous; exact-pre/displaced-post after rollback-armed but
  before revert event is rollback-exchange-ambiguous. Orphan sidecar/receipt/
  backend-result bytes cannot reconstruct either missing event. The direct
  `resolution-readback` sidecar is marker-last/content-addressed, capped at the
  exact admitted bound below, while its event remains below 64 KiB. Before
  `apply.started`, REDs require only the per-kind worst-case vector for every
  reachable sidecar/incident/receipt kind; claiming an exact future CFL length
  fails. Once a complete document exists, publication and replay require
  `exactLength<=preflightBound(kind)<=cap(kind)` with identical allocation,
  write, `fstat`, read, parse, replay and downstream counters. Tests lock the
  200-MiB general arithmetic (120 MiB escaped paths + 48 MiB metadata + 16 MiB
  evidence/framing + 16 MiB outer, `R<=2`), the specialized 144-MiB resolution
  cap, the 64-KiB verifier-receipt cap, and six-byte escaping of every valid
  Task 7 path;
  missing, oversized, alternate-name, orphan, cross-verification, changed
  provider-record or mismatched resolution digest/ref fails without cleanup;
- verifier authority REDs bind the exact constructor-approved acyclic base/
  parser/signer capability, intent-bound 32-byte nonce, request-core digest,
  durable apply-event-bound final request, domain-separated platform signature,
  canonical 64-KiB receipt schema and sole
  transaction-object ref/path, create-once file+parent sync/readback, and the
  `present|unavailable` sidecar union. The unavailable arm embeds the literal
  signed non-issuance object; receipt/non-issuance double terminal, wrong
  request/key/capability/code/time/signature, changed replay bytes, or non-absent
  receipt path is unknown rather than unavailable. Parser/source/runtime/path drift, extra or
  mixed keys, preplant/orphan/late/conflicting receipts, signer-capability drift,
  request/readback/event cycles, crash at every publication cut, and transport/
  possible-issued unknown emit no verification event and incident only. A valid
  signed exact-request EEXIST replay succeeds; unavailable requires authenticated
  terminal non-issuance, never mere path absence. With a present failed receipt,
  `attestationMatch=false` deterministically selects `attestation-mismatch` even
  when tests also fail; only attestation true plus any false test selects
  `verification-failed`;
- `EventStore.open_existing`, Task 7 open/load, and provider list/get/validate/
  guard perform zero writes with write syscalls trapped and preserve full inode/
  mode/link/byte manifests. A legacy EventStore home remains readable and creates
  nothing; only explicit marker-last promotion initialization upgrades it, while
  every partial/unsafe upgrade fails without repair. Writable provider flows use
  only their explicit initializer;
- candidate full/provider/Task7/capture-lineage/state digests change on their
  complete strict preimages. REDs lock every candidate/review/resolution/derived
  key, scalar type, enum, bound, null arm, ordered array, provider-native versus
  prefixed digest, framing rule, and the deliberate sibling full-record/state-
  binding split. Deferral one/two is admissible only if fully bound
  and non-escalated; the third blocks. Changed capture/path/owner/class/request,
  cross-candidate/nested digest, partial guarded-v2 fields, or missing
  `skill-learning.guard` fails. Mixed valid provider v1/v2 ledgers and legacy
  manual commands remain compatible but v1 cannot authorize Task 8;
- parent-local list/get/validate/guards nofollow-open the exact existing root,
  contract/source/helper/lock/ledger FDs and pure RSI fold profile; no child,
  stdout, runtime, temp copy, repair, or bytecode path exists. Contention timeout,
  lock/root/name/inode/mode/capability/profile drift, direct lock-bypassing ledger
  write, and pre/action/post sync-point substitution fail before exchange or
  latch afterward. Property/differential corpora match provider folds for valid
  mixed ledgers; parent SIGKILL releases the flock naturally; a controlled writer
  proves post-release liveness. Terminal pre/post checks finish before close and
  no fallible authority check runs after `run.closed`. Sync-point REDs race
  defer/resolve and direct lock-bypassing writes against
  `apply.completed(applied)`, affirmed verification, rollback-armed verification,
  resolution, apply-reverted, and every terminal callback;
- the provider ledger protocol forces every capture, review/defer, resolution,
  snapshot prepare/result/abort, operation-result, and explicit repair mutation
  through the named exclusive lock. Snapshot-prepare versus Guard B and direct
  bypass-write races are detected; no released list/get result authorizes apply;
- Guard A, provider-unlocked lease-protected bounded temp I/O, and Guard B form
  two linearizations. Races
  and fresh Guard-B drift in candidate, TTL, policy/kill switch, allowlist/root/
  control/deployment, latch/quarantine, target metadata, or ancestry cause zero
  exchange and durable retained-temp not-applied cleanup. Defer during live
  verification still permits capture-lineage-bound rollback; competing resolution
  blocks rollback and quarantines;
- provider snapshot V2 has the literal closed canonical-final-LF manifest,
  deterministic native-bare request formula/path, exact Task 7 pre-manifest
  equality, bounded stable managed set and mode preservation. Over-bound,
  excluded-sensitive, link/special, extra/missing, changed byte/executable, native/
  prefixed, request/ID/path/schema/framing, or open-prepare variants fail;
- guarded-v2 snapshot/resolve bind candidate ID, all five authority digests, and
  TTL. Lookup-first exact replay survives later drift/expiry; changed requests
  conflict. Snapshot's second lookup and new snapshot/resolve commit recompute
  authority atomically under the ledger lock. Expiry/drift before a new resolve
  latches exact post, but an exact prior result replays. Writer-child timeout,
  output, exit, runtime/path swap, or descendant failure is contained and then
  classified by direct locked exact-operation lookup as committed, uncommitted,
  conflict, or unknown—never assumed uncommitted;
- initial atomic-exchange capability probing succeeds before continuation/gate
  creation; failure emits no allow gate, provider call, not-started record, or
  target mutation. A later pre-apply capability loss may use the guarded terminal
  arm. Not-started exact-pre/stale-external tests cover edit/delete/chmod/symlink/
  unreadable/reserved-name drift, non-attribution, and partial/corrupt
  `apply.started` refusal;
- exchange probes use disjoint same-volume operands. Forward/reverse `EINTR` is
  post-classified without blind retry. Root/ancestor rename/rebind at exchange or
  cleanup fails the full retained named/opened ancestry chain and never mutates a
  stale path/detached tree. Emergency exact-artifact reverse with whole-tree
  `other` preserves displaced post and incidents directly from `apply.started`;
- namespace protection REDs prove the lease is acquired with no RSI/provider/
  EventStore lock held and the sole order is `lease→transaction→global→target→
  provider→EventStore`; a contender/deadlock harness covers release/reacquire of
  the inner suffix during full scan and verifier. The built-in macOS/Linux
  backend is unavailable and emits no allow gate; only the constructor-owned
  test-authority registry enables positive unit cases, while caller subclasses,
  booleans, receipts and tokens fail. Final-boundary adversaries attempt ancestor/
  name replacement, incoming hard link, write/truncate/chmod/xattr, pre-opened-FD
  write, writable mmap/dirty writeback, mount/alias mutation, and an unrelated
  managed-file mutation during exchange/reverse/readback/unlink. Every attempt is
  excluded or incidents; none is detected only after exposure. Holder death
  releases, enforcer death stays fail-closed, and watchdog expiry never returns
  an unprotected live holder. Exact capability-schema REDs require the distinct
  holder-death, enforcer-death, live-holder-protection, signed-results,
  pre-opened-handle, writable-mmap, and dirty-writeback booleans rather than a
  generic crash claim. Every applicable mapped sidecar has exactly one
  top-level evidence object embedding a strict signed receipt plus ordered
  signed backend results and their complete closed before/after witness
  preimages; nested cleanup/exchange/namespace-failure witnesses carry only its
  recomputed digest with the exact null rules. A second complete object or a
  lease-evidence auxiliary sidecar fails. REDs lock the exact CFL/D schemas and acyclic
  cross-equalities for provider-ledger identity, ancestry edges/witness,
  artifact parent, managed-tree policy/members, target, retained name and member
  metadata. Cross-equality REDs require root/ancestry/request and parent-digest
  relations fieldwise, forbid a request `parentRelativePath`, project each
  policy pre/post arm from its Task 7 entry by path, and never compare
  differently shaped objects. Target witnesses have no `executable` field:
  exact arms compare size/hash/manifest and mode execute bits to Task 7, while
  live device/inode/UID/full-mode equality requires the same causal opened
  object. Full member views contain only safe regular `nlink=1` observations.
  The protected-readback result outcome must equal the complete state
  classification; readable `other` uses a full view, proven first-path
  missing/symlink-or-multilink/special drift uses the closed null-view known arm,
  and only unconstructable or out-of-bound observation is unreadable. Strict
  UTF-8 path order includes the reserved name, whose expected absence is normal.
  Lease evidence must embed the complete request and exact scope plus
  their recomputed digests; digest-only, cross-request, cross-scope and
  plan/authority substitution fails. Arbitrary signer digests or a mismatch to the
  apply/rollback/cleanup/readback fields fail. The `TargetReadbackView` body/
  scan/full-view domains are tested as an acyclic digest DAG (the scan preimage
  excludes `scanDigest`). Evidence rejects digest-only, cross-operation,
  missing, extra, live-expired, timestamp-invalid or orphan evidence,
  while proving that correctly timed causally bound historical evidence remains
  replay-valid after wall-clock expiry and never authorizes a new step. The tests lock every
  operation's literal result sequence, including the exact five-result emergency
  arm and the exact three-result rollback arm; those are the only sequences with
  two positionally distinct `protected-readback` results. Any reorder, other
  duplicate, skipped result, sixth result, or retained temp without successful
  exact inode+parent sync fails. Incident REDs cover a still-live exact prepared
  inode whose file/parent sync persistently fails, and an authorized unlink that
  succeeds while parent sync or protected absence readback fails; neither may
  clean-close or be reclassified by a later-looking target hash. Cleanup REDs require both truthful
  `removed-now` and `already-absent-authorized` arms and keep the applicable
  provider guard continuous across bounded unlink/absence, sync, protected
  postcheck, decision and close. Crash after backend
  forward/reverse mutation but before its event is conservative ambiguous
  incident, never hash-inferred completion; crash after an authorizing cleanup
  event may prove absence under a fresh operation-specific lease;
- a nested target creates the deterministic swap name only in its exact retained
  artifact parent and every forward/reverse exchange uses that single parent
  dirfd. Root-level swap placement for a nested artifact, cross-directory
  operands, a claimed second-parent witness, or two-directory sync/crash state is
  unreachable/rejected; one artifact-parent sync proves both names;
- rollback requires the same-transaction durable inline rollback-armed
  verification and sidecar. Defer/review drift permits lineage-bound unresolved
  rollback, but competing/unknown resolution blocks it. Reverse-exchange/readback/
  `apply.reverted`/cleanup crash cuts converge; false retained-preimage, direct
  apply edge, affirmative predecessor, cleanup-before-event, or orphan evidence
  grants no authority;
- retained-preimage cleanup requires the conjunction of bounded
  `resolution.recorded`, its exact event-bound resolution-readback sidecar and
  provider record, and its causally bound affirmative verification witness.
  Cross-transaction/changed inode and crashes
  before unlink, after unlink, after parent sync, decision, or close preserve or
  converge only from exact post/provider/absence proof;
- incident publication is acyclic record → quarantine CAS → latch CAS → event →
  decision → close, with created/preexisting dispositions and blocking digests.
  The tx-only incident ID selects one fixed create-once record; concurrent
  classifiers adopt its valid winner without directory scans or a second reason-
  derived record. Every predecessor/reason pair, first-match classifier branch,
  exact decision null/key arm and crash cut is closed; concurrent roots may bind
  an existing global latch without claiming it is their incident. Cycles, future
  digests, alternate/poisoned selectors, reordered/partial evidence, preexisting
  latch injection, or cleanup/ancestry ambiguity cannot clean-close.

1. **Lifecycle/plan bridge RED** — closed proposal import, validation reconciliation, plan transaction import, missing/unclosed/cross-candidate/substituted/tampered refs, replay/conflict, and no target/provider mutation.
2. **Provider authority RED** — strict bounded list/nested resolution, zero-write provider reads, exact provider identity, snapshot managed-set/bounds/modes/schema/tree/replay, pending/deferred/escalated gates, resolve replay/conflict and commit-before-caller-crash; all real-provider cases use temp homes.
3. **Promotion-journal RED** — closed transaction-sidecar topology, event/sidecar binding, permissions/ownership, nofollow, lock/home replacement, orphan/conflict/fault points, exact replay, concurrency and zero-mutation read-only open.
4. **Eligibility/preflight RED** — every V1 forbidden class/destination/path/root/self/control/multi-file/stale/latch/secret/metadata/capability condition fails before snapshot and leaves every non-promotion command byte-identical.
5. **Atomic apply RED** — exact CRLF/newline/4 MiB bytes and executable bit, root/ancestor/file swaps, symlink/FIFO/socket/hardlink, temp preplant/rebind, short write/EINTR/fsync/dir-sync/exchange/readback faults, and no `os.replace` target call.
6. **Verification/resolve/rollback RED** — happy decision, verifier drift/failure/crash, exact rollback, mixed-tree rollback refusal, provider commit/output/journal loss, competing resolution, terminal repair and no promoted partial state.
7. **Recovery/latch RED** — kill after every durable phase; exact pre/post/other/unreadable classification; latch-before-event repair; malformed/tampered/extra transaction or latch; read-only diagnostics with all writes forbidden.
8. **Concurrency/adversarial RED** — same plan/process convergence, incompatible plans, external replacement at every syncpoint, provider/candidate/control drift, lock-name/home replacement, and deterministic preserved attacker data.

Use fault injection only in tests and keep production error taxonomy closed/sanitized. Every fault node must assert target, transaction, provider, lifecycle, latch and decision together rather than checking only an exception.

## Primary files and permitted supporting edits

- Create `recursive-self-improvement/scripts/rsi_core/promotion.py`.
- Create `recursive-self-improvement/scripts/rsi_core/recovery.py`.
- Create `recursive-self-improvement/tests/test_promotion.py`.
- Create `recursive-self-improvement/tests/test_recovery.py`.
- Create `recursive-self-improvement/tests/test_concurrency.py`.
- Create `recursive-self-improvement/tests/test_adversarial.py`.
- Modify `rsi.py`, `events.py`, `storage.py`, `experiment.py`,
  `evolver_adapter.py`, package exports, schemas/references, and existing tests
  only for the exact CLI, lifecycle, read-only loader, provider authority and
  storage seams above.
- Provider dependency edits are limited to the reviewed `skill-evolver`
  docs/scripts/tests required for zero-write strict reads, the formally versioned
  parent-FD authority guard proven necessary above, and exact bounded mode-
  preserving snapshots; add no lookup-only capability and make no unrelated
  skill guidance or ledger content change.
- Do not add monitoring, rollback-proposal execution, operator unlatch, confirmed restore, defragmentation, deployment hooks, or generic multi-file mutation in Task 8.

## Verification and handoff

- Obtain independent reviews for provider dependency, lifecycle/cross-run storage, transaction/exchange/recovery, and final end-to-end safety before commit.
- Run focused tests after every RED/GREEN slice, all Task 6/7 regressions, provider suite/validators on temporary homes, then the complete RSI suite twice from clean temporary homes.
- Run skill validator, strict contract validator, provider `validate` on a fresh temp home, approved-spec SHA/diff check, `git diff --check`, compile checks and cache cleanup.
- Record exact before/after target, provider source, real provider ledger, event home and spec digests. The real ledger must remain byte-identical during Task 8 implementation/verification.
- Demonstrate rollback of repository changes and the separate provider dependency snapshot/restore preview before final staging.
- Commit only intended changes with `feat: guard RSI knowledge promotion`; leave the worktree clean.
