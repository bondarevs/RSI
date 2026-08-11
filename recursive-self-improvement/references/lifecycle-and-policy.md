# RSI V1 lifecycle, policy, and recovery

Read this reference before invoking the CLI, selecting a mode, installing
hooks, handling an incident, or recovering a run.

## Effective package defaults

The shipped default is exact and fail-closed:

- mode: `observe`;
- hook mode: `late-review`;
- local RSI: enabled, maximum 3 candidates per task, monitoring window 10;
- Global RSI: disabled, minimum 3 independent fingerprints and 2 skills;
- defragmentation: enabled as `audit-only`, complete ledger and approval
  required;
- promotion: knowledge allowed by policy, behavior/material changes disabled,
  snapshot and target tests required;
- retention: observations 90 days and reports 180 days;
- evidence limits: 5 items, 1,200 characters per item, 2,000 finding
  characters.

The sanitizer's ordinary output ceiling remains 1,200 characters. Candidate
seed validation alone selects the bounded 2,000-character finding-output
envelope after first enforcing the raw finding schema limit. The 4,096-character
sanitizer source cap, instruction/secret/PII classification, task/path
generalization, exact-output comparison, and 1,200-character evidence limit do
not expand.

The production overlay names `promote-safe`, but its stage and hook attestation
references are `null` and `allowedTargets` is empty. It therefore resolves to
`observe` until an operator installs a versioned attested deployment overlay
with a non-empty exact allowlist. Runtime or target profiles may tighten policy;
they may not activate production, expand the allowlist, or weaken a safeguard.

Apply configuration in this order: kill switch, platform/repository safety
policy, non-weakening per-run flag, target profile, package default. At every
mutation boundary, re-read `CODEX_RSI_ENABLED=0`, `CODEX_RSI_MODE=observe`, and
`CODEX_SKILL_AUTO_PROMOTE=0`. Use `CODEX_RSI_HOME` only to select a safe,
disjoint RSI state root.

## Hook selection

Use coordinated mode only when a trusted host implements exactly one start,
reusable-signal, primary-task-verified, and primary-task-closed sequence.
Record in-dialog drafts without changing a target, and capture only after
trusted verification.

Otherwise invoke an explicit `late-review` with final artifacts. Report the
warning that in-dialog-only signals were unavailable. Do not accept a finding
draft in late-review mode. If RSI is not invoked, return the explicit `no-rsi`
legacy result with `rsiGuarantees=false`; do not claim an RSI fallback.
For public `local-review`, an omitted `hookMode` resolves to `late-review` and
therefore requires non-empty `finalArtifacts`; coordinated mode must be named
explicitly and cannot be inferred from coordinated-only fields.

## Effective CLI

Invoke the package entrypoint as:

```text
python3 scripts/rsi.py COMMAND [OPTIONS] --json
```

Implemented commands are `preflight`, `note-finding`, `observe`, `evaluate`,
`local-review`, `monitor`, `global-review`, `report`, `defrag-audit`,
`defrag-plan`, `defrag-validate`, `doctor`, and `promote-candidate`.

Every state-writing command requires `--run-id`, `--idempotency-key`, and
`--input-file`; use `--input-file -` for stdin. `local-review`, `monitor`,
`global-review`, and each `defrag-*` command additionally require one or more
`--target-root` arguments. Supply structured secrets in neither arguments nor
input. `doctor` requires `--home` and `--salvage-report` and never repairs the
source ledger.

`promote-candidate` requires canonical selectors for candidate, promotion plan,
validation attestation, expected target hash, deterministic run ID, and
deterministic operation ID. The public command reopens only pre-existing
attested objects; it never synthesizes a plan or reopens the proposal run.

Successful envelopes contain these stable common fields:

```json
{
  "schemaVersion": 1,
  "command": "local-review",
  "status": "completed",
  "mode": "observe",
  "runId": "release-example",
  "eventIds": [],
  "candidateIds": [],
  "mutationPerformed": false,
  "warnings": [],
  "errors": []
}
```

The CLI has two closed, command-specific error variants for compatibility:

- lifecycle result envelopes, including a public proposal blocked before state
  creation, retain the common success fields and a plural `errors` array of
  closed objects with `code`, safe `message`, `retryable`, and non-sensitive
  `details`; they do not contain singular `error`;
- command-processing failures and `promote-candidate` continuation blocks use
  `schemaVersion`, `command`, `runId`, `status`, and one singular closed `error`
  object with those four fields; they do not contain plural `errors`.

Consumers must select the variant by field presence, reject an envelope that
contains both, and apply the same process-code table to either variant. The
effective process codes are:

| Code | Effective meaning |
|---:|---|
| 0 | completed or deterministic no-op/read-only result |
| 2 | invalid arguments, request schema, or safely normalized processing error |
| 3 | policy or allowlist block when emitted by an integrated host |
| 4 | RSI store, ledger, or source-integrity failure |
| 5 | validation or attestation failure when emitted by an integrated host |
| 6 | missing/incompatible provider, canonical-capture blocker, or unavailable plan |
| 7 | explicit approval required when emitted by an integrated host |
| 8 | operation-ID, concurrency, or optimistic-hash conflict |
| 9 | ambiguous or quarantined state |

Codes 3, 5, and 7 are reserved by the V1 envelope contract for integrated host
paths; the current standalone parser does not construct those paths. Do not
translate a nonzero code into success or retry a non-retryable error under a
new operation ID.

## Recovery runbook

When a critical/high invariant, prompt-injection escape, secret persistence,
unauthorized write, ledger/hash ambiguity, or critical regression is observed:

1. Set `CODEX_RSI_MODE=observe` or `CODEX_RSI_ENABLED=0` for the affected
   deployment and stop all new promotions.
2. Preserve `events.jsonl`, content-addressed objects, transaction evidence,
   provider operation records, and the incident latch. Do not edit or truncate
   them.
3. Run `doctor --salvage-report` into a new RSI-owned report path. Treat it as
   diagnosis only.
4. Run the provider ledger validator and package validator read-only. Rebuild
   the disposable index only when the JSONL ledger and object manifests are
   valid.
5. If apply never began, close as a proved no-op. If exact post-state and the
   current-task diff are both proved, prepare the explicit operator-approved
   reverse action. If state is unknown or hashes differ, preserve bytes and
   keep the target `ambiguous` or `quarantined`; never overwrite it.
6. Use provider restore only as a separate explicit action after its preview
   matches the pinned snapshot manifest. RSI does not auto-restore.
7. Add a regression fixture, perform root-cause review, rerun security,
   concurrency, egress, index-rebuild, provider, and recovery drills, then issue
   new stage/hook attestations if the control plane changed.
8. Let only a trusted operator clear the latch after readback and validation.
   A candidate, runtime flag, or target profile cannot clear it.

Never delete an orphan or retained temporary inode merely because its bytes
look familiar. Without durable same-transaction ownership evidence, preserve it
for incident classification.
