# RSI event schemas (V1)

`rsi_core.events.EventRegistry` is the executable, closed registry for the V1
event envelope. Every event has exactly these top-level fields:

```text
schemaVersion, eventType, eventId, runId, correlationId, causationId,
createdAt, idempotencyKey, producerVersion, payload, payloadRef
```

Unknown schema versions, event types, top-level fields, missing required
payload keys, invalid causation, malformed JSONL, and terminal conflicts fail
closed. V1 event payloads use `additionalProperties: false`; a future additive
field requires a schema-versioned registry update. Every payload also contains
`logicalOperationId` and `targetSkill`, both non-empty strings of at most 1024
characters. `idempotencyKey` is exactly the SHA-256 digest of the canonical
five-item tuple `(producerVersion, eventType, runId, logicalOperationId,
targetSkill)`.

| Event type | Required payload keys |
|---|---|
| `run.started` | `mode`, `hookMode`, `activeSkills`, `policyVersion`, `controlPlaneVersion` |
| `finding.drafted` | `draftId`, `proposedScope`, `summary` |
| `task.observed` | `taskOutcome`, `verificationStatus`, `targetSkillHashes` |
| `evaluation.completed` | `targetSkill`, `baseline`, `metricDeltas`, `evidenceStatus` |
| `candidate.admission_decided` | `decision`, `hardReasons` |
| `candidate.captured` | `providerCandidateId`, `captureOperationId`, `owner` |
| `promotion.gated` | `decision`, `requiredChecks` |
| `staging.completed` | `diffDigest`, `targetPreHash`, `stagingRef` |
| `validation.completed` | `attestationRef`, `attestationDigest` |
| `promotion.planned` | `planRef`, `planDigest`, `candidateHash`, `diffDigest`, `targetHash`, `contractHash`, `providerOperationIds` |
| `snapshot.created` | `snapshotOperationId`, `snapshotPath`, `manifestDigest` |
| `apply.started` | `transactionId`, `expectedPreHash`, `expectedPostHash` |
| `apply.completed` | `actualPostHash` |
| `verification.completed` | `liveReadback`, `tests`, `attestationMatch` |
| `resolution.recorded` | `providerOperationId`, `resolutionId` |
| `monitoring.recorded` | `promotionRef`, `evaluationId`, `causalAttribution`, `outcome` |
| `report.generated` | `reportKind`, `pathDigest`, `inputRefs`, `mutationPerformed` |
| `global.report.generated` | `sourceEvaluationRefs`, `thresholds`, `reportDigest`, `mutationPerformed` |
| `defrag.audit.completed` | `registrationDigest`, `inventoryDigest`, `findings`, `mutationPerformed` |
| `defrag.plan.built` | `ruleInventoryDigest`, `ledgerDigest`, `umbrellaPlanDigest` |
| `defrag.plan.validated` | `coverage`, `goldenValidation`, `rollbackValidation`, `mutationPerformed` |
| `payload.expired` | `sourceEventId`, `payloadRef`, `originalDigest`, `tombstoneAt` |
| `incident.latched` | `incidentId`, `reason`, `quarantineTargets` |
| `run.closed` | `status`, `linkedIds` |

All ordinary strings are non-empty and at most 1024 characters. Arrays and
objects have at most 64 entries; every array entry is a bounded non-empty
string. `*Digest`, `*Hash`, and `targetSkillHashes` fields use the exact form
`sha256:<64 lowercase hexadecimal characters>`. `metricDeltas` and
`thresholds` are objects; `liveReadback`, `attestationMatch`, and
`mutationPerformed` are booleans. The latter is exactly `false` for the four
read-only report/defrag event types. `candidate.admission_decided.decision` is
`allow|reject`; `promotion.gated.decision` is
`allow|defer|reject|supersede`; `run.closed.status` is one of the typed
terminal statuses. `run.started.mode` is
`off|observe|propose|promote-safe`; optional `runKind` is
`local|global|defrag|retention`.

`promotionRef` and `evaluationId` in `monitoring.recorded` are immutable
`event:<eventId>` references. The storage validator proves that a monitoring
event belongs to a different run whose `run.started` follows the referenced,
positively verified promotion resolution. `providerOperationId` is unique
across the full ledger, including different runs. Only a `promote-safe` local run may begin an
apply transaction. Any unresolved or failed verification requires an incident
and an `ambiguous|quarantined` close; no other terminal status can hide it.

The source ledger is append-only JSONL. SQLite is a rebuildable query cache;
`doctor --salvage-report` is read-only and never repairs the JSONL source.

## Task 9 monitoring reports

Content-addressed Task 9 objects live under `reports/`. A monitoring JSON object
is referenced by `monitoring.recorded`; a global JSON object is referenced by
`global.report.generated` and has a deterministic Markdown derivative. The
event is appended only after its JSON bytes are durable. Replay validates the
same path and exact bytes. Global runs accept exactly one report terminal plus
an optional incident and close; local lifecycle and mutation events are
forbidden. See `metrics.md` for the closed metric record and aggregation rules.

## Task 6 durable proposal objects

Canonical proposal mode reconstructs candidates only from write-once objects
bound to the journal. Paths below are relative to `$CODEX_RSI_HOME`:

| Object | Required binding |
|---|---|
| `objects/findings/<finding-event-id>.json` | Complete sanitized candidate seed; `finding.drafted.payloadRef`, event correlation digest, declared target/version, and observation causal chain must agree. Publication, target+dedupe-key merging/conflict detection, and the global three-draft cap share the journal lock, so concurrent duplicate/conflicting writers cannot publish a second event or orphan object. |
| `objects/observations/<observation-event-id>.json` | Strict observation schema, verified authority result, request digest, declared targets, and `task.observed` payload must agree. A canonical-capture authority also binds each name/version to its canonical real root, bounded whole-target manifest, contract digest, and trusted contract-root graph. |
| `objects/evaluations/<evaluation-event-id>.json` | Closed per-target evaluation with finite bounded metrics, observation/finding refs, request digest, target/version, copied verification-root proof, and `evaluation.completed` payload must agree. |
| `objects/proposals/<run-id>.json` | Canonical provider root, provider learning-home identity, validated provider digest, contract roots, and target roots. They must exactly match the authority-bound verification roots; replay recomputes target and contract manifests before a provider write. |
| `objects/proposals/<capture-operation-id>-<raw-sha256>.json` | Candidate correlation, provider-binding digest, exact sanitized route decision, atomic route binding, and admission decision/reasons. The digest-bearing `candidate.admission_decided.payloadRef` binds every receipt byte. |
| `objects/proposals/<run-id>-freshness-<raw-sha256>.json` | Closed bounded metadata witness, its semantic digest, and the stable verification-binding digest. `run.closed.payloadRef` and correlation bind the exact historical bytes. Replay validates this receipt but recomputes current byte/mode manifests separately; current inode/ctime/mtime are not required to reproduce historical identity. |
| `reports/local-review-<run-id>.json` | Exact evaluation IDs, provider candidate IDs, rejection count, terminal status, and `mutationPerformed=false`; raw-byte SHA-256 and semantic digest must match `report.generated`. |

All object readers reject duplicate keys, non-finite numbers, malformed framing,
symlink aliases, missing files, changed bytes, extra fields, or inconsistent
event/causation references. `run.closed` revalidates the complete object graph;
a previously closed replay does not trust event counts alone. Target identity
scans are finite (entry, byte, root, contract, and stabilization-attempt caps)
and the heavy byte/directory scan runs before journal append. It is sandwiched
by a no-follow metadata snapshot rather than rebased if the tree changes. The
under-lock close performs only a bounded descriptor-relative metadata recheck:
it reads no file bytes and enumerates no directory, and it rebinds every opened
ancestry/internal directory to its parent name on unwind. In-place writes,
atomic replacements, member changes, and symlink/rename aliases therefore
cannot cross the scan-to-append boundary. The exact checked witness is written
only after that final check and atomically referenced by `run.closed`; rejected
freshness branches publish no new object. Finding sidecar admission and the
maximum-three check share one journal transaction, so concurrent rejected
writers leave no orphan object.

## Bound provider-v2 protocol

The Task 6 adapter pins the provider script, helper, and capability contract by
SHA-256 and runs private verified bytes under an isolated, no-site Python
boundary with closed stdin, bounded stdout/stderr, timeout, controlled
environment, and a temporary or explicitly selected learning home. It supports
exactly `list`, `route`, routed `capture`, `snapshot`, `defer`, `resolve`,
restore preview, and `validate`.

Resolved routing uses `route --include-binding` and accepts exactly:

```text
status, owner_skill, owner_path, matched_scope, reason, route_binding
```

`route_binding` is 64 lowercase hexadecimal characters and binds the canonical
contract roots, graph bytes, resolved decision, and owner target identity.
`route-capture` must receive the same value through
`--expected-route-binding`; provider-side revalidation rejects graph, owner,
path, or target drift before candidate append. Unresolved route stderr retains
the exact five-field `needs-owner|ownership-conflict` decision and is a durable
reject branch. Unexpected exit codes, success stderr, extra output, unknown
fields, malformed nested review/resolution state, inconsistent folded status,
or operation-ID/request conflicts are typed failures.

The Stage 2 terminal sequence is:

```text
evaluation.completed
  -> candidate.admission_decided(reject)
  -> report.generated -> run.closed(rejected)

evaluation.completed
  -> candidate.admission_decided(allow)
  -> candidate.captured
  -> report.generated -> run.closed(completed)
```

Every globally selected draft has exactly one admission and every allowed
admission exactly one capture terminal. No eligible drafts produce a read-only
`no-op` without a provider call. Task 6 never fabricates `promotion.gated` and
never mutates the target tree.
