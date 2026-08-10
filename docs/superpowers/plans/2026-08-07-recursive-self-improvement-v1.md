# Recursive Self-Improvement v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-hardened Codex role-skill `recursive-self-improvement` that observes completed skill-driven tasks, captures verified reusable findings, safely promotes only allowlisted single-file declarative knowledge, and provides read-only global RSI and defragmentation reports.

**Architecture:** The package is a Python CLI-backed Codex role-skill with an append-only RSI event store, strict schemas/FSM, isolated validation, signed attestations, an immutable `PromotionPlan`, and one guarded mutation command. `skill-evolver` remains the owner of the learning ledger, routing, candidate status, snapshots, and explicit restore; its provider-v2 upgrade is a separate reviewed change and is required before canonical Stage 2 capture.

**Tech Stack:** Python 3.11+, standard library (`argparse`, `dataclasses`, `hashlib`, `json`, `sqlite3`, `subprocess`, `tempfile`), `pytest`, `hypothesis`, Codex `SKILL.md`, JSON/YAML metadata.

## Global Constraints

- Authoritative design input: `/Users/macbook/Documents/Codex/2026-08-07/referenced-chatgpt-conversation-this-is-an/outputs/recursive-self-improvement-spec.md`.
- Package default is `observe`; installing the skill must not enable mutation.
- Current `skill-evolver` supports only observe/noncanonical offline reporting for RSI; canonical Stage 2 and all Stage 3 work require provider v2.
- Provider writes use `(operationType, operationId, requestDigest)` replay semantics for routed/direct capture, snapshot, defer, and resolve.
- V1 auto-apply is limited to one allowlisted regular file containing declarative knowledge; behavior, material, global, defrag, tests, profiles, scripts, contracts, agents metadata, evaluator, and metrics remain manual/out-of-band.
- `local-review`, `global-review`, and every `defrag-*` command leave target skills byte-identical.
- Validation occurs before the single fresh production snapshot; only `promote-candidate` may mutate a target.
- Self-target denial uses canonical identity/path overlap and control-plane dependency closure, not skill names.
- Unknown schema, corrupt ledger, stale hash, invalid attestation, ownership conflict, or ambiguous transaction fails closed for learning while preserving the completed user task.
- Use TDD, small commits, and a clean verification checkpoint after every task.

## Usage-Aware Execution Protocol

- Do not start implementation on 2026-08-07 with only 10% usage remaining; this plan is the final artifact for the current cycle.
- At the start of each reset, select exactly one task below as the required checkpoint.
- Stop starting new implementation work when approximately 70% of the daily allowance is consumed.
- Reserve the final approximately 30% for tests, diff review, documentation, commit, and a restart note.
- If less than 15% remains, make no new code changes; run verification and record the next exact failing test instead.
- Never stop between production snapshot and transaction resolution; Task 8 must be executed only with enough allowance to complete its full fault-test checkpoint.

## Calendar and Checkpoints

| Usage cycle | Target checkpoint | Exit artifact |
|---|---|---|
| 2026-08-07, current 10% | Planning only | This saved plan; no implementation files |
| Reset 1 | Task 1 | Valid skill scaffold and test runner |
| Reset 2 | Task 2 | Strict schemas, FSM, and append-only storage |
| Reset 3 | Task 3 | Fail-closed configuration, policy, and sanitizer |
| Reset 4 | Task 4 | Observe-only coordinated/late-review lifecycle |
| Resets 5–6 | Task 5 | Tested `skill-evolver` provider v2 |
| Reset 7 | Task 6 | Canonical proposal mode and real adapter |
| Reset 8 | Task 7 | Isolated validation, hashes, attestations, plan |
| Resets 9–10 | Task 8 | Guarded single-file promotion and recovery |
| Reset 11 | Task 9 | Monitoring and read-only Global RSI |
| Reset 12 | Task 10 | Read-only defragmentation plan |
| Resets 13–14 | Task 11 | Full hardening, forward tests, and release docs |

After implementation, rollout time is evidence-driven rather than usage-driven: Stage 1 requires at least 100 episodes and 14 days; Stage 2 requires 50 reviewed proposals; Stage 3 requires 10 mature knowledge promotions. A claim of a one-sided 95% false-promotion upper bound below 2% requires at least 149 independently monitored zero-failure promotions.

## File Map

```text
docs/
├── specs/
│   └── recursive-self-improvement-spec.md
└── superpowers/plans/
    └── 2026-08-07-recursive-self-improvement-v1.md
pyproject.toml
recursive-self-improvement/
├── SKILL.md
├── skill-contract.json
├── agents/openai.yaml
├── profiles/default.json
├── profiles/production.json
├── references/
│   ├── architecture.md
│   ├── lifecycle-and-policy.md
│   ├── schemas.md
│   ├── metrics.md
│   ├── defragmentation.md
│   └── rollout-and-testing.md
├── scripts/rsi.py
├── scripts/rsi_core/
│   ├── __init__.py
│   ├── config.py
│   ├── events.py
│   ├── storage.py
│   ├── hooks.py
│   ├── sanitize.py
│   ├── observe.py
│   ├── evaluate.py
│   ├── candidates.py
│   ├── policy.py
│   ├── evolver_adapter.py
│   ├── hashing.py
│   ├── attestations.py
│   ├── experiment.py
│   ├── promotion.py
│   ├── recovery.py
│   ├── defragment.py
│   ├── metrics.py
│   └── report.py
└── tests/
    ├── fixtures/
    └── test_*.py
```

External provider-v2 files:

```text
/Users/macbook/.codex/skills/skill-evolver/
├── skill-contract.json
├── references/candidate-schema.md
├── references/skill-contracts.md
├── scripts/learning_log.py
├── tests/test_learning_routing.py
├── tests/test_snapshots.py
└── tests/test_skill_contract.py
```

---

### Task 1: Repository Baseline and Skill Scaffold

**Scheduled:** Reset 1

**Files:**
- Create: `docs/specs/recursive-self-improvement-spec.md`
- Create: `pyproject.toml`
- Create: `recursive-self-improvement/SKILL.md`
- Create: `recursive-self-improvement/skill-contract.json`
- Create: `recursive-self-improvement/agents/openai.yaml`
- Create: `recursive-self-improvement/profiles/default.json`
- Create: `recursive-self-improvement/profiles/production.json`
- Create: `recursive-self-improvement/tests/test_package_contract.py`

**Interfaces:**
- Consumes: approved specification path from Global Constraints.
- Produces: importable package root, pytest configuration, v2 contract dependency, fail-closed profiles.

- [ ] Copy the approved specification verbatim into `docs/specs/recursive-self-improvement-spec.md` and verify both files have the same SHA-256 digest.
- [ ] Run the skill creator with:

```bash
python3 /Users/macbook/.codex/skills/.system/skill-creator/scripts/init_skill.py \
  recursive-self-improvement --path . --resources scripts,references \
  --interface display_name='Recursive Self-Improvement' \
  --interface short_description='Safely improve role-skills from evidence' \
  --interface default_prompt='Use $recursive-self-improvement to review the completed skill-driven task and validate a safe, evidence-backed improvement.'
```

- [ ] Create `pyproject.toml` with the exact test environment:

```toml
[project]
name = "recursive-self-improvement"
version = "0.1.0"
requires-python = ">=3.11"

[project.optional-dependencies]
dev = [
  "pytest>=8,<9",
  "hypothesis>=6,<7",
]

[tool.pytest.ini_options]
testpaths = ["recursive-self-improvement/tests"]
pythonpath = ["recursive-self-improvement/scripts"]
addopts = "-ra"
```

- [ ] Write `test_package_contract.py` to assert package default mode is `observe`, production allowlist is empty, implicit invocation is false, and contract kind is `role`.
- [ ] Run `pytest recursive-self-improvement/tests/test_package_contract.py -v` and confirm the assertions fail against the generated placeholders.
- [ ] Replace generated placeholders with the exact metadata and profile values from specification sections 9–10.
- [ ] Run the skill validator and package test; expect both to pass.
- [ ] Commit with `git commit -m "chore: scaffold recursive self improvement skill"`.

### Task 2: Strict Events, FSM, and Storage

**Scheduled:** Reset 2

**Files:**
- Create: `recursive-self-improvement/scripts/rsi_core/events.py`
- Create: `recursive-self-improvement/scripts/rsi_core/storage.py`
- Create: `recursive-self-improvement/tests/test_events.py`
- Create: `recursive-self-improvement/tests/test_storage.py`
- Create: `recursive-self-improvement/tests/test_permissions.py`
- Modify: `recursive-self-improvement/references/schemas.md`

**Interfaces:**
- Produces: `EventEnvelope`, `EventRegistry`, `fold_run(events)`, `EventStore.append(event)`, `EventStore.rebuild_index()`.

- [ ] Write failing tests for every normative event type, legal/illegal predecessor, duplicate terminal event, unresolved-apply close, malformed JSONL tail, idempotent replay, and `payload.expired` tombstone.
- [ ] Write failing permission tests asserting directories are `0700` and regular/lock/SQLite/report files are no wider than `0600`.
- [ ] Run `pytest recursive-self-improvement/tests/test_events.py recursive-self-improvement/tests/test_storage.py recursive-self-improvement/tests/test_permissions.py -v`; expect failures for missing modules.
- [ ] Implement immutable event envelopes, strict schema/version checks, deterministic folding, bounded `O_APPEND` writes under lock, fsync, and SQLite cache rebuild.
- [ ] Implement read-only `doctor --salvage-report`; it may report malformed lines but may not rewrite source ledgers.
- [ ] Run the three test files plus 1,000 replay permutations; expect all pass.
- [ ] Commit with `git commit -m "feat: add strict RSI event store"`.

### Task 3: Configuration, Policy, and Sanitization

**Scheduled:** Reset 3

**Files:**
- Create: `recursive-self-improvement/scripts/rsi_core/config.py`
- Create: `recursive-self-improvement/scripts/rsi_core/policy.py`
- Create: `recursive-self-improvement/scripts/rsi_core/sanitize.py`
- Create: `recursive-self-improvement/tests/test_config.py`
- Create: `recursive-self-improvement/tests/test_policy.py`
- Create: `recursive-self-improvement/tests/test_sanitize.py`

**Interfaces:**
- Produces: `load_effective_config() -> EffectiveConfig`, `evaluate_admission(candidate, config) -> GateDecision`, `sanitize_evidence(items) -> SanitizationResult`.

- [ ] Write failing tests for most-restrictive precedence, empty/invalid production activation, exact target entry digests, V1 destination matrix, and canonical control-plane identity overlap.
- [ ] Add adversarial fixtures for API keys, private keys, passwords, low-entropy identifiers, instruction payloads, absolute paths, `..`, Unicode path collisions, and symlink escape.
- [ ] Run the three test files and confirm failures.
- [ ] Implement fail-closed config merging, allowlist/root identity verification, `ControlPlaneIdentitySet`, capture admission, promotion gates, and bounded sanitization.
- [ ] Run tests and verify rejected sensitive payloads do not appear in events, diagnostics, hashes, or reports.
- [ ] Commit with `git commit -m "feat: enforce RSI policy and sanitization"`.

### Task 4: Observe-Only Lifecycle

**Scheduled:** Reset 4

**Files:**
- Create: `recursive-self-improvement/scripts/rsi_core/hooks.py`
- Create: `recursive-self-improvement/scripts/rsi_core/observe.py`
- Create: `recursive-self-improvement/scripts/rsi_core/evaluate.py`
- Create: `recursive-self-improvement/scripts/rsi.py`
- Create: `recursive-self-improvement/tests/test_hooks.py`
- Create: `recursive-self-improvement/tests/test_observe.py`
- Create: `recursive-self-improvement/tests/test_evaluate.py`

**Interfaces:**
- Produces: `RunCoordinator.start()`, `note_finding()`, `verify_primary_task()`, `close()`, `Evaluator.evaluate_per_target()` and CLI commands `preflight`, `note-finding`, `observe`, `evaluate`, `local-review`.

- [ ] Write failing tests for coordinated exactly-once hooks, explicit `late-review`, no-RSI legacy separation, verified success/failure, unverified capture block, and separate evaluations/baselines for two target skills.
- [ ] Run the hook/observe/evaluate tests and confirm failures.
- [ ] Implement the lifecycle through `evaluation.completed` and read-only offline reports; do not add canonical candidate capture.
- [ ] Run an end-to-end observe fixture twice with the same run/idempotency keys and verify identical envelopes and byte-identical target trees.
- [ ] Commit with `git commit -m "feat: implement observe only RSI lifecycle"`.

### Task 5: `skill-evolver` Provider v2

**Scheduled:** Resets 5–6

**Files:**
- Modify: `/Users/macbook/.codex/skills/skill-evolver/scripts/learning_log.py`
- Modify: `/Users/macbook/.codex/skills/skill-evolver/skill-contract.json`
- Modify: `/Users/macbook/.codex/skills/skill-evolver/references/candidate-schema.md`
- Modify: `/Users/macbook/.codex/skills/skill-evolver/references/skill-contracts.md`
- Modify: `/Users/macbook/.codex/skills/skill-evolver/tests/test_learning_routing.py`
- Modify: `/Users/macbook/.codex/skills/skill-evolver/tests/test_snapshots.py`
- Modify: `/Users/macbook/.codex/skills/skill-evolver/tests/test_skill_contract.py`

**Interfaces:**
- Produces: request-bound replay for routed/direct capture, snapshot, defer, resolve; declared `skill-learning.defer` and `skill-learning.validate`.

- [ ] Snapshot the user-owned skill using its own snapshot command before editing.
- [ ] Write failing real-process tests for two concurrent same-request captures, same operation ID with different request digest, replay after each status, direct-capture bypass, snapshot replay, defer review-count replay, resolve replay, and provider-commit/caller-crash retry.
- [ ] Run the provider tests and confirm the current non-atomic behavior fails.
- [ ] Add canonical request digests and one ledger transaction implementing `lookup → append-or-return-recorded-result` for every write operation.
- [ ] Reject `(operationType, operationId)` reuse with a different digest using typed `operation-id-conflict`.
- [ ] Disable direct capture unless it uses the same operation namespace and transaction.
- [ ] Declare and validate defer/validate capabilities in `skill-contract.json`.
- [ ] Run all provider tests, strict ledger validation, and the real concurrency race 100 times.
- [ ] Commit the provider source change in its owning repository or record the exact snapshot/diff if the source is not Git-managed.

### Task 6: Adapter, Candidate Builder, and Canonical Proposal Mode

**Scheduled:** Reset 7

**Files:**
- Create: `recursive-self-improvement/scripts/rsi_core/evolver_adapter.py`
- Create: `recursive-self-improvement/scripts/rsi_core/candidates.py`
- Create: `recursive-self-improvement/tests/test_evolver_adapter.py`
- Create: `recursive-self-improvement/tests/test_candidates.py`
- Create: `recursive-self-improvement/tests/test_local_lifecycle.py`

**Interfaces:**
- Produces: typed adapter methods from specification section 11.3 and `CandidateBuilder.build(evaluation) -> list[ImprovementCandidateDraft]`.

- [ ] Write failing exact stdout/stderr tests for list, route, route-capture, snapshot, defer, resolve, validate, restore preview, malformed output, and version mismatch.
- [ ] Write failing admission tests proving unverified/unsafe/conflicted findings never reach the canonical provider.
- [ ] Implement the adapter without direct JSONL writes and implement a maximum of three stable, owner-routed candidates per task.
- [ ] Run Stage 2 E2E in a temporary learning home and verify `local-review` leaves the target byte-identical.
- [ ] Commit with `git commit -m "feat: add canonical RSI proposal mode"`.

### Task 7: Isolated Validation and Immutable Plans

**Scheduled:** Reset 8

**Files:**
- Create: `recursive-self-improvement/scripts/rsi_core/hashing.py`
- Create: `recursive-self-improvement/scripts/rsi_core/attestations.py`
- Create: `recursive-self-improvement/scripts/rsi_core/experiment.py`
- Create: `recursive-self-improvement/tests/test_hashing.py`
- Create: `recursive-self-improvement/tests/test_attestations.py`
- Create: `recursive-self-improvement/tests/test_experiment.py`

**Interfaces:**
- Produces: `build_skill_manifest(root)`, `verify_deployment_attestation()`, `run_experiment()`, immutable `ValidationAttestation` and `PromotionPlan`.

- [ ] Write failing tests for raw-byte hashes, line endings, executable bit, NFC/case collision, symlink entries, allowlist/root reassignment, stage/hook/provider digest changes, signature/TTL/replay, and exact post-image binding.
- [ ] Write sandbox tests denying environment credentials, host home, network, DNS, subprocess egress, and MCP/tool access while allowing mocks and temporary outputs.
- [ ] Implement canonical manifests, content-addressed post-images, trusted verifier interfaces, isolated staging, resource limits, and plan generation with zero production snapshots.
- [ ] Run all validation tests and prove failed experiments leave the production target and snapshot count unchanged.
- [ ] Commit with `git commit -m "feat: add isolated RSI validation plans"`.

### Task 8: Guarded Promotion, Recovery, and Incident Latch

**Scheduled:** Resets 9–10

**Files:**
- Create: `recursive-self-improvement/scripts/rsi_core/promotion.py`
- Create: `recursive-self-improvement/scripts/rsi_core/recovery.py`
- Create: `recursive-self-improvement/tests/test_promotion.py`
- Create: `recursive-self-improvement/tests/test_recovery.py`
- Create: `recursive-self-improvement/tests/test_concurrency.py`
- Create: `recursive-self-improvement/tests/test_adversarial.py`

**Interfaces:**
- Produces: the only target-mutating path `promote_candidate(plan_ref) -> PromotionDecision` and read-only recovery diagnostics.

- [ ] Write failing tests proving all non-promotion commands are byte-identical and V1 blocks behavior, tests, profiles, agents, contracts, multi-file changes, self/control-plane targets, and stale plans.
- [ ] Add fault injection at event append, snapshot commit, caller journal append, temp write, fsync, atomic replace, readback, verification, and resolve.
- [ ] Implement final identity/policy/hash rechecks, one request-bound fresh snapshot, exact post-image atomic replace, readback, live verification, idempotent resolve, and durable incident latch.
- [ ] Prove every injected failure yields verified pre-state, verified post-state, or durable `ambiguous/quarantined`; no path may report promoted partial state.
- [ ] Run the full suite twice from clean temporary homes and commit with `git commit -m "feat: guard RSI knowledge promotion"`.

### Task 9: Monitoring and Read-Only Global RSI

**Scheduled:** Reset 11

**Files:**
- Create: `recursive-self-improvement/scripts/rsi_core/metrics.py`
- Create: `recursive-self-improvement/scripts/rsi_core/report.py`
- Create: `recursive-self-improvement/tests/test_metrics.py`
- Create: `recursive-self-improvement/tests/test_global_lifecycle.py`
- Modify: `recursive-self-improvement/references/metrics.md`

**Interfaces:**
- Produces: `monitor`, `report`, `global-review`; outcomes `stable`, `rollback-proposed`, `quarantined`.

- [ ] Write failing tests for per-target baselines, missing-as-unknown, exact denominators, duplicate task fingerprints, independence thresholds, confidence intervals, and control-plane version quarantine.
- [ ] Implement lexicographic safety/quality/efficiency evaluation, monitoring linkage across runs, rollback proposals, and global reports with `mutationPerformed=false`.
- [ ] Run Global RSI against arbitrary target trees and assert byte-for-byte equality before and after.
- [ ] Commit with `git commit -m "feat: add RSI monitoring and global reports"`.

### Task 10: Read-Only Defragmentation

**Scheduled:** Reset 12

**Files:**
- Create: `recursive-self-improvement/scripts/rsi_core/defragment.py`
- Create: `recursive-self-improvement/tests/test_defragmentation.py`
- Modify: `recursive-self-improvement/references/defragmentation.md`

**Interfaces:**
- Produces: `defrag-audit`, `defrag-plan`, `defrag-validate`, `RuleInventory`, `MigrationLedger`, umbrella `MigrationPlan`.

- [ ] Write failing tests for canonical/runtime drift, stable rule IDs, role/capability/profile/workflow classification, one disposition per rule, split descendants, surviving duplicate, owner-scoped change sets, golden-test plan, and rollback plan.
- [ ] Implement audit/plan/validation without any filesystem apply function.
- [ ] Run property tests over generated skill trees and prove every command leaves canonical and runtime trees byte-identical.
- [ ] Commit with `git commit -m "feat: add read only skill defragmentation"`.

### Task 11: Hardening, Forward Tests, and Release Documentation

**Scheduled:** Resets 13–14

**Files:**
- Modify: `recursive-self-improvement/SKILL.md`
- Modify: all `recursive-self-improvement/references/*.md`
- Modify: `recursive-self-improvement/agents/openai.yaml`
- Modify: `recursive-self-improvement/tests/test_adversarial.py`
- Create: `recursive-self-improvement/tests/test_forward.py`

**Interfaces:**
- Produces: complete v1 package ready for staged rollout.

- [ ] Run the minimum security corpus: 250 injection fixtures, 100 secret/PII canaries, 10,000 path/FSM property cases, and fault injection at every write boundary.
- [ ] Run independent forward fixtures for safe knowledge, unsafe finding, two-target task, explicit late-review, no-RSI legacy case, recurring global pattern, and defrag drift without revealing expected outputs.
- [ ] Verify all JSON/YAML examples, links, contract graph, file permissions, index rebuild, provider ledger, package validator, and full pytest suite.
- [ ] Update references with exact effective defaults, CLI envelopes/exit codes, provider compatibility, recovery runbook, rollout manifest schema, and known limitations.
- [ ] Confirm no critical/high defects, no placeholders, no target mutation outside `promote-candidate`, and no unreviewed skill-learning candidates.
- [ ] Commit with `git commit -m "docs: complete RSI v1 release package"`.

## Final Verification Command Set

```bash
pytest recursive-self-improvement/tests -q
python3 /Users/macbook/.codex/skills/skill-evolver/scripts/learning_log.py validate
python3 /Users/macbook/.codex/skills/.system/skill-creator/scripts/quick_validate.py recursive-self-improvement
git status --short
```

Expected final state: all tests and validators pass, `git status --short` contains no unintended files, package default remains `observe`, production allowlist remains empty until attested deployment, and the approved specification maps to at least one passing test for every invariant.
