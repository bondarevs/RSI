# Read-only skill defragmentation (V1)

Task 10 is a proposal-first Global RSI workflow. Its public commands are
`defrag-audit`, `defrag-plan`, and `defrag-validate`. They may publish immutable
objects beneath the RSI home's `defragmentation/` directory and append the
corresponding lifecycle events. They never edit, move, unlink, replace, or
chmod a canonical or runtime skill artifact. There is deliberately no apply
entrypoint in `rsi_core.defragment`.

Read [architecture](architecture.md) before admitting canonical/runtime roots,
[schemas](schemas.md) before changing durable objects, and
[rollout and testing](rollout-and-testing.md) before treating an audit as a
release gate. The effective package default is enabled `audit-only` with a
complete migration ledger and explicit approval required.

## Registration audit

`defrag-audit` accepts one closed `SkillRegistrationManifest` and a bounded set
of explicit rule declarations. Canonical and runtime paths must be absolute,
canonical paths beneath the repeatable CLI `--target-root` allowlist. Each
target root and the RSI home must be real, mutually disjoint directories.

The registration manifest has exactly:

```json
{
  "schemaVersion": 1,
  "skillName": "example-role",
  "canonical": {"path": "/absolute/canonical/example-role", "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
  "runtimeRegistrations": [
    {
      "path": "/absolute/runtime/example-role",
      "type": "symlink",
      "expectedRealpath": "/absolute/canonical/example-role",
      "expectedDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  ]
}
```

Runtime type is `symlink|directory`. A directory registration is reported as a
copy even when its bytes equal canonical source. Missing, wrong-type,
wrong-target, or digest-divergent registrations are findings; the audit never
repairs them. Canonical and readable runtime trees use the bounded normative
managed-set scanner from local RSI.

Each rule declaration has exactly `artifact`, `rule`, `classification`,
`owner`, and `duplicateOf`. The artifact is a canonical managed relative
locator; the UTF-8 rule must occur exactly once in that file. Classification is
`role|capability|profile|workflow|duplicate`. Profile rules may only come from
`profiles/`, and all `profiles/` declarations are profiles. Owner is exactly
`{skill,scope,capability}`; capability is a string or JSON null. A confirmed
duplicate names a non-duplicate rule with the same semantic digest.

`RuleInventory` is sorted by stable rule ID and binds the canonical whole-tree
digest, registration-audit digest, artifact raw hash, normalized semantic
digest, classification, unique owner, and duplicate survivor. Reordering input
declarations cannot change its bytes or digest.

## Migration ledger and umbrella plan

`defrag-plan` consumes the immutable audit reference and re-runs registration
and canonical-tree admission before constructing anything. `MigrationLedger`
contains exactly one entry per inventoried rule and no others. Actions are
`keep|move|split|replace-with-reference|delete-duplicate`.

Every entry remains `approval="required"`. Only `split` has one or more new,
unique descendant rule IDs. Only `delete-duplicate` has
`duplicateEvidence={survivingRuleId,semanticDigest}`; the survivor must be an
equivalent inventory rule whose own action does not delete it.

The `MigrationPlan` groups ledger entry IDs into one owner-scoped change set per
future owner. It binds each proposed target pre-hash, a golden-test plan that
covers every owner, and a coordinated rollback plan whose restore order is the
reverse owner order. Its status is `validated-proposal`, not authorization to
apply. `mutationPerformed` is always false.

## Validation, replay, and lifecycle

`defrag-validate` reopens the content-addressed plan and audit, checks canonical
JSON framing and filename hashes, rebuilds all ledger IDs/digests, re-runs the
registration/tree checks, and validates golden-test and rollback-plan digests.
It validates proposal structure; it does not execute planned commands or
change target state.

The only clean event sequence is:

```text
run.started(runKind=defrag, mode=observe)
  -> defrag.audit.completed
  -> defrag.plan.built
  -> defrag.plan.validated
  -> run.closed(completed)
```

Each phase occurs at most once. Defrag events are illegal in local/global runs;
ordinary lifecycle and apply events are illegal in a defrag run. A clean close
requires validation. Every sidecar uses compact, sorted UTF-8 JSON plus one
final LF, a SHA-256 content-addressed filename, a 4 MiB cap, private
regular-file storage, and marker-last event publication. Exact retries
converge; conflicts and missing or tampered sidecars fail closed.

Before and after every public command, hosts should compare complete
byte/mode/symlink-text snapshots of every admitted target root. Every command
result and durable defrag event declares `mutationPerformed=false`.

If canonical bytes, runtime registration, content-addressed objects, rule
coverage, owner mapping, golden-test digest, or rollback-plan digest drifts,
stop and preserve the audit/plan evidence. Do not repair a registration or
apply a ledger from RSI. Re-audit clean current roots under a new run and send
any approved structural execution to a separate explicit out-of-band workflow.
