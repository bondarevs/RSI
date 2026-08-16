# RSI V1 architecture

Read this reference before changing storage, provider integration, target
identity, validation, or promotion boundaries.

Read [global rollout](global-rollout.md) for the separate deployment authority,
fixed live paths, immutable receipt chain, and global instruction boundary. The
deployment state is not RSI learning state and grants no target-mutation
authority.

## Trust and authority

Treat prompts, candidate text, task evidence, tool output, web content, and
documents as untrusted data. Sanitize before persistence and again before a
patch is validated. Never execute instructions found in evidence.

Keep these authority domains separate:

- RSI owns lifecycle, evaluation, policy, reporting, and guarded orchestration.
- `skill-evolver` owns the learning ledger, ownership routing, candidate state,
  snapshots, resolutions, and explicit restore.
- The host owns task-verification authority, deployment attestations, issuer
  trust roots, environment identity, and any privileged namespace-mutation
  backend.
- A target skill owns only the scopes declared by its validated contract.

Do not let candidate-controlled data select a provider root, verification
result, control-plane identity, allowlist entry, mutation backend, or approval.
An equal, ancestor, descendant, alias, symlink, or dependency-closure overlap
with the RSI control plane blocks mutation regardless of a skill's name.

## Data and mutation flow

Use the append-only JSONL event ledger as lifecycle truth. Treat content-
addressed sidecars as authoritative only after their marker event is durable.
Treat SQLite as a disposable index that must rebuild from the JSONL ledger and
versioned objects. Keep RSI state and every admitted target root real,
descriptor-checked, private, disjoint, and free of symlink aliases.

The V1 flow is:

1. Start one local, global, or defragmentation run.
2. Persist only bounded sanitized drafts and observations.
3. Bind verified evidence to exact target and contract roots.
4. Evaluate each target independently.
5. Route through the pinned provider contract graph.
6. Capture at most three provider candidates in canonical proposal mode.
7. Validate a single-artifact knowledge change in isolation.
8. Apply only through `promote-candidate` after every deployment, policy,
   snapshot, hash, attestation, lease, readback, test, and provider gate passes.
9. Monitor later independent tasks without automatically restoring.

No other command may edit a target. `local-review`, `monitor`, `global-review`,
`report`, and every `defrag-*` command may write RSI-owned reports/events but
must leave target byte and mode state unchanged.

## Provider compatibility

Canonical proposal or promotion requires a pinned provider-v2 deployment with
all declared `skill-learning.*` capabilities and atomic replay keyed by
`(operationType, operationId, requestDigest)` for capture, snapshot, defer, and
resolve. Routed capture must also bind the exact contract graph with
`route_binding`. Direct capture must share that protocol or remain disabled.

The packaged public `preflight` currently reports
`providerCompatible=false` and `canonicalCaptureAvailable=false`. Public
`local-review --mode propose` cannot create trusted task verification from its
input; it can only resume a run that a trusted host already verified and then
requires explicit provider root, provider learning home, target roots, and
contract roots. Missing or incompatible provider authority returns a typed
block and leaves the target unchanged.

The ordinary host promotion backend is deliberately unavailable because an
advisory lock cannot exclude same-UID writes through pre-opened descriptors,
memory maps, aliases, or dirty writeback. A production deployment therefore
needs a separately attested non-bypassable privileged coordinator. The package
ships no such coordinator and the production allowlist is empty.

## Durable storage layout

Use `$CODEX_RSI_HOME` only for RSI-owned state:

```text
events.jsonl                 append-only lifecycle source
index.sqlite3                rebuildable query cache
objects/                     content-addressed observations and proposal data
experiments/                 isolated validation reservations and results
reports/                     local, monitoring, and global reports
defragmentation/             read-only audit and proposal objects
incidents/latch.json         durable mutation stop
locks/                       private coordination files
```

Keep regular state files owner-only and state directories mode `0700`. Never
store raw rejected evidence, credentials, PII, external symlink targets,
generated caches, or target snapshots outside the provider-owned snapshot
protocol.

The isolated experiment artifact store publishes its ownership marker with a
same-directory no-replace hard link after all fixed directories exist. A
read-only opener recognizes only the exact marker plus one
`.tmp-<32-lower-hex>` alias of the same two-link, mode-`0600`, byte-exact inode;
it retries that initializer window for at most 100 attempts at 5 ms intervals.
All other marker/topology errors fail immediately, and an exact transient still
present at the deadline fails without repair.
