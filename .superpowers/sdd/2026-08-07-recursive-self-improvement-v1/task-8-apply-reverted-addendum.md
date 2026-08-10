# Task 8 Normative Implementation Addendum — `apply.reverted`

## Status and scope

- Addendum version: 1.
- Approved specification remains byte-identical at SHA-256
  `4d691659fc3f2a97c863fc8153e49227fc152ebe6dcf0c7a6aa8829842dd0b37`.
- The approved registry has no truthful explicit rollback terminal. Task 8 adds
  exactly one normative event type, `apply.reverted`; it adds no other event
  type. Existing types may use only the closed Task 8 payload arms in the Task 8
  brief.
- The canonical registry artifact `task-8-registry-addendum-v1.json` defines
  `TASK8_CONTROL_PLANE_VERSION=1.1.0`. That canonical JSON includes the exact raw
  SHA-256 of this Markdown file as `normativeMarkdownRawSha256`; this Markdown
  deliberately embeds no JSON digest, so the binding is directional and
  cycle-free. Task 7 V2 current state, reservation, result, attestation, plan,
  operation IDs, Task 8 control-plane identity, and every promotion continuation
  bind both `task8AddendumDigest` (the exact canonical-final-LF JSON digest) and
  `task8AddendumMarkdownDigest` (this exact raw Markdown digest). A missing,
  tampered, mismatched, or pre-addendum plan is ineligible and must be
  revalidated.

## Closed event and predecessor

`apply.reverted` is legal only in a `mode=promote-safe`, `runKind=local`
continuation and exactly once per transaction. Its direct cause is the same-run,
same-transaction `verification.completed(outcome="rollback-armed")` event. An
affirmed verification, direct `apply.completed` cause, external/cross-run cause,
cross-transaction cause, duplicate event, legacy/non-promotion run, or missing
cause fails fold and append.

The causal verification event carries its lifecycle-critical
`outcome="rollback-armed"` and exact non-null `reasonCode` inline, matching its
event-bound sidecar. An orphan or mismatched sidecar cannot supply that outcome.

In addition to the unchanged normative common payload fields, its exact Task 8
payload fields are:

```text
transactionId, restoredPreHash, restoredManifestPreHash,
displacedPostHash, rollbackVerified=true, rollbackDigest
```

All three hashes and `rollbackDigest` use the Task 8 `sha256:<lowercase hex>`
form. No additional or missing field is allowed. The event has:

```text
logicalOperationId = "promote:" + transactionId + ":rollback"
eventId = "evt_" + sha256(canonical-no-LF({
  "domain":"rsi-promotion-event-v1",
  "transactionId":transactionId,
  "eventType":"apply.reverted"
}))[7:]
idempotencyKey = existing normative digest of
  (producerVersion,eventType,runId,logicalOperationId,targetSkill)
correlationId = exact planDigest
payloadRef = "transactions/<tx>-readback-<rollbackDigest hex>.json"
```

The referenced canonical-final-LF `rollback-readback` sidecar has the Task 8
common transaction fields plus exactly:

```text
intentRef, intentDigest, readbackRef, readbackDigest,
verificationRef, verificationDigest,
providerFullRecordDigest, providerAuthorityBindingDigest,
task7CandidateBindingDigest, candidateCaptureLineageBindingDigest,
candidateStateBindingDigest,
beforeTarget, afterTarget, retainedPreimage, displacedPost, cleanup,
namespaceMutationLeaseEvidence
```

`verificationRef`/`verificationDigest` must bind the causal rollback-armed event
and sidecar. `beforeTarget` is exact post; `afterTarget` is exact pre.
`retainedPreimage` is exactly null because the original preimage has been
restored to the target name. `displacedPost` is the sole exact transaction-owned
post inode now under the deterministic swap basename in the exact artifact
parent. The forward and reverse exchanges both use the target basename and swap
basename through the same retained artifact-parent dirfd; cross-directory
exchange or canonical-root placement for a nested artifact is forbidden. Its
pre-cleanup witness has
`disposition="pending-event-bound"`, `removed=false`, `absentAfter=false`, and
`directorySynced=true`; that sync proves
the reverse-exchanged target and still-present displaced name durable in that
one parent and does not claim unlink. There is no second-directory sync or crash
state between two directory syncs. Wrong kind, directory, transaction, filename digest, event
binding, mode, link count, content, a false retained-preimage claim, or orphan
sidecar is non-authoritative.

`namespaceMutationLeaseEvidence` is the exact inline signed receipt plus ordered
signed backend-result object defined by the Task 8 brief, with operation class
`rollback-apply`; its digest-only, unsigned, cross-operation, or orphan form is
invalid. The receipt proves acquisition only. The causal signed reverse result,
exact readback, and durable mapped event together prove the transition.

## Ordering and cleanup authority

Append `apply.reverted` only after a guarded reverse atomic exchange and exact
artifact plus whole-manifest pre-state readback. Append and fsync the sidecar and
event before deleting the displaced post. This event alone authorizes cleanup of
that exact recorded inode. Cleanup then proves either exact identity and removal
now (`disposition="removed-now"`, `removed=true`) or, after a crash following an
already completed authorized unlink, exact causal identity plus protected
absence (`disposition="already-absent-authorized"`, `removed=false`). Both final
arms require `absentAfter=true`, the same artifact-parent directory sync with
`directorySynced=true`, and fresh operation-matching signed cleanup-lease
evidence; the guarded `transaction-decision(outcome="rolled-
back")` plus failed/deferred `run.closed` bind that proof. Cleanup failure or
provider-resolution drift produces an incident causally following
`apply.reverted`; it never rewrites the target or reports rollback/promotion.

Only the uninterrupted lease holder that received the signed reverse result may
append `apply.reverted`. If the process loses that holder after reverse exchange
but before the durable event, recovery treats even exact-pre target plus exact
displaced-post swap as `rollback-exchange-ambiguous`, preserves both names, and
never reconstructs the event from hashes, an acquisition receipt, backend-result
bytes, or an orphan sidecar.

Replay accepts only exact bytes and converges on the same event. Fold/replay
rejects an affirmative predecessor, direct apply edge, duplicate, cross-
transaction event, orphan/mismatched sidecar, cleanup-before-event claim, or use
outside the promote-safe continuation.
