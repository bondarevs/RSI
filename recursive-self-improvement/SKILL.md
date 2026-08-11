---
name: recursive-self-improvement
description: Track and evaluate Codex role-skill tasks, preserve evidence-backed reusable findings, validate safe local improvements, and aggregate global learning without changing role goals or weakening safeguards. Use during or after skill-driven tasks when important findings must not be lost, when reviewing a role's recurring failures or successes, when validating a proposed skill improvement, when auditing skill ownership or defragmentation, or when producing a cross-skill RSI report.
---

# Recursive Self-Improvement

Operate as the control plane for evidence-backed role-skill improvement. Preserve the target role's goals, ownership boundaries, safeguards, and user-task authority.

## Preflight

1. Read the target skill contract, effective profile, task evidence, and relevant references before evaluating a completed task.
2. Verify the provider supports the required `skill-evolver` operation and provider-v2 semantics before canonical capture or any Stage 2 work.
3. Select local RSI only for a target skill's own reusable finding; select global RSI only for cross-skill reporting or structural audit. Keep global work read-only or proposal-only.
4. Apply kill switches and the most restrictive effective mode before every mutation boundary. Treat missing prerequisites, attestations, or allowlist entries as `observe`.

## Review and validation workflow

1. Sanitize and record evidence within configured limits.
2. Evaluate the completed task, form a bounded finding draft, and route ownership through `skill-evolver`.
3. Validate a proposed improvement in an isolated environment. Do not create a production snapshot or patch until all promotion gates pass.
4. Permit v1 promotion only for one allowlisted regular file containing declarative knowledge, with exact hashes, valid attestations, target tests, and an approved immutable plan.
5. Defer or reject findings when evidence, ownership, provider prerequisites, or validation are insufficient; leave the production target unchanged.

## References and commands

Read `references/metrics.md` before post-promotion monitoring or Global RSI;
it defines exact baseline, missing-data, denominator, causation, independence,
confidence, and read-only report rules. Read `references/defragmentation.md`
before any structural audit; use it for migration-ledger details rather than
duplicating them here. Read the applicable policy, deployment, validation, and
recovery references before their respective operations when those references
are present in the package.

Use `observe`, `evaluate`, `validate-candidate`, `promote-candidate`, `monitor`,
`global-review`, `report`, `defrag-audit`, `defrag-plan`, and
`defrag-validate` only through the declared CLI and provider
capability. `monitor` may emit an exact approval-required rollback proposal but
never restores. `global-review`, `report`, and every `defrag-*` command are
read-only and have no target mutation path. Canonical Stage 2 proposal mode is available only when the
pinned provider-v2 identity validates and returns a bound route receipt. Resume
it with explicit provider root, temporary or approved provider learning home,
repeatable target roots, and repeatable contract roots; never accept a public
input field as trusted task verification. A new public `propose` request blocks
before creating RSI state because only the host verification authority may
establish that boundary. If identity, route binding, durable evidence,
topology, or provider configuration differs on replay, fail closed without
capture. Stage 3 production mutation remains out of scope.

For a verified `propose` run, the host verification result must bind every declared target name/version to a canonical real root, bounded byte manifest, contract digest, and trusted contract-root graph. Those proofs persist through observation and evaluation; resume recomputes them before any provider call and before close, so a caller cannot first-pin a same-name substitute. The heavy byte/tree scan runs outside the journal lock and yields a descriptor-relative metadata witness; immediately before terminal append, the lock protects a bounded no-follow metadata recheck that rebinds every ancestry and internal directory on unwind. A content-addressed historical witness is published atomically with `run.closed`; replay validates that immutable receipt and separately recomputes current semantic manifests, so harmless inode/timestamp churn is not historical identity. The only legal Task 6 sequence is per-target evaluation, deterministic globally capped draft construction, bound route preview, durable allow/reject admission, atomic bound provider capture when allowed, read-only report, and close. The journal lock atomically enforces both provider-identity deduplication and the maximum of three durable findings, including concurrent writers; rejected races publish no orphan sidecar. A zero-draft run closes `no-op` without contacting the provider. Proposal mode writes provider learning state only; it never changes a target skill.

## Recovery and reporting

Fail closed to `observe` on an invalid contract, profile, attestation, allowlist, hash, test, or provider result. Stop mutation after any incident, preserve evidence for recovery, and require explicit recovery before reuse of an ambiguous target.

At end of task, report the effective mode, evidence status, candidate outcome, validation results, deferred or rejected reasons, and whether any production state changed.
