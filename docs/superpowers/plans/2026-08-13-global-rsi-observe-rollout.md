# Global RSI Observe Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install a pinned, verified copy of RSI globally and add a bounded post-task `observe + late-review` trigger without enabling production mutation.

**Architecture:** The repository gains strict deployment schemas, a descriptor-safe package scanner, a managed global-instruction renderer, and a transactional deploy/verify/rollback service. The live deployment copies one clean Git commit into `~/.codex/skills/recursive-self-improvement`, binds it with immutable manifests and marker-last receipts, and updates one exact block in `~/.codex/AGENTS.md`; read-only health checks and temporary-home drills prove trigger behavior before live activation.

**Tech Stack:** Python 3.11+, pytest, Hypothesis, POSIX file descriptors and `flock`, macOS `renameatx_np(RENAME_SWAP)` for atomic installed-directory updates, canonical JSON, existing RSI validators and CLI.

## Global Constraints

- The normative design is `docs/superpowers/specs/2026-08-13-global-rsi-observe-rollout-design.md`; implementation must not weaken it.
- Live defaults remain exactly `mode=observe` and `hookMode=late-review`.
- The production allowlist remains exactly empty; deployment must never call `promote-candidate` or write a production target.
- The repository is the only release source; live deployment requires a clean exact commit and rejects untracked members inside `recursive-self-improvement`.
- Live paths are constructor-fixed under `~/.codex`; caller and ambient environment cannot redirect them.
- Tests use explicit temporary Codex, RSI, provider, repository, and target homes; tests never mutate live provider or RSI state.
- Package and instruction publication are marker-last, fsynced, read back, idempotent, and fail closed on identity drift.
- Read-only commands perform no mkdir, chmod, repair, cache, bytecode, temporary-file, or ledger write.
- Installed members are current-user-owned directories or regular files; regular files require `nlink=1`, while directories use retained nofollow FD identity. Symlinks, special files, unsafe modes, and hard-linked files are rejected.
- The installed manifest excludes itself from package entries/tree digests; the receipt separately binds its exact bytes.
- Immutable deployment authority uses exactly `receipts/<operation-id>.manifest.json` followed marker-last by `receipts/<operation-id>.json`.
- Global instruction text outside the exact managed block remains byte-identical.
- Recursion guard is exactly `CODEX_RSI_TRIGGER_ACTIVE=1`; other values skip nested review fail closed.
- Ordinary conversation, status questions, one-off facts, and tasks without reusable evidence never trigger RSI state.
- No P0, P1, or P2 may remain after independent review.

---

### Task 1: Strict deployment schemas and package identity

**Files:**
- Create: `recursive-self-improvement/scripts/rsi_core/deployment_schema.py`
- Create: `recursive-self-improvement/scripts/rsi_core/deployment_fs.py`
- Create: `recursive-self-improvement/tests/test_deployment_schema.py`
- Create: `recursive-self-improvement/tests/test_deployment_fs.py`

**Interfaces:**
- Produces: `canonical_json_bytes(value: Mapping[str, object]) -> bytes`
- Produces: `FileEntry.from_mapping(value)`, `DeploymentManifest.from_mapping(value)`, and `DeploymentReceipt.from_mapping(value)` strict closed parsers.
- Produces: `scan_package(root: Path, *, exclude_manifest: bool) -> PackageSnapshot` where `PackageSnapshot.entries`, `.tree_digest`, and `.root_identity` are immutable.
- Produces: `verify_package_snapshot(root: Path, expected: PackageSnapshot) -> None`.

- [ ] **Step 1: Write schema golden-byte RED tests**

```python
def test_manifest_is_closed_canonical_and_acyclic() -> None:
    manifest = manifest_fixture()
    encoded = canonical_json_bytes(manifest)
    assert encoded.endswith(b"\n")
    assert b'.rsi-deployment-manifest.json' not in encoded_file_paths(encoded)
    assert DeploymentManifest.from_bytes(encoded).to_bytes() == encoded

@pytest.mark.parametrize("mutation", [drop_key, add_key, duplicate_key, bad_digest, bad_mode, self_member])
def test_manifest_rejects_every_malformed_arm(mutation) -> None:
    with pytest.raises(DeploymentSchemaError):
        DeploymentManifest.from_bytes(mutation(valid_manifest_bytes()))
```

- [ ] **Step 2: Run the focused schema tests and record authoritative RED**

Run: `PYTHONDONTWRITEBYTECODE=1 pytest -q recursive-self-improvement/tests/test_deployment_schema.py`

Expected: collection or import failure because `rsi_core.deployment_schema` does not exist.

- [ ] **Step 3: Implement exact schema types and digest domains**

Use exact domains `rsi-global-observe-deployment-v1`, `rsi-global-observe-receipt-v1`, and `rsi-global-package-tree-v1`. Reject duplicate JSON keys, BOM, CRLF, floats, booleans in integer fields, non-NFC paths, missing/additional keys, non-prefixed digests, invalid operation IDs, and bytes after the final LF. `fileEntries` are strictly UTF-8-byte sorted and contain exactly `relativePath`, `byteLength`, `executable`, and `digest`.

- [ ] **Step 4: Write filesystem identity RED tests**

```python
@pytest.mark.parametrize("unsafe", ["symlink", "fifo", "hardlink", "world-write", "group-write"])
def test_scan_package_rejects_unsafe_topology(tmp_path: Path, unsafe: str) -> None:
    root = safe_package(tmp_path)
    install_unsafe_member(root, unsafe)
    with pytest.raises(DeploymentIntegrityError):
        scan_package(root, exclude_manifest=True)

def test_scan_package_excludes_only_the_exact_manifest_name(tmp_path: Path) -> None:
    root = safe_package(tmp_path)
    (root / ".rsi-deployment-manifest.json").write_bytes(b"ignored")
    snapshot = scan_package(root, exclude_manifest=True)
    assert ".rsi-deployment-manifest.json" not in snapshot.relative_paths
    assert set(snapshot.relative_paths) == expected_repository_members(root)
```

- [ ] **Step 5: Run filesystem tests and record RED**

Run: `PYTHONDONTWRITEBYTECODE=1 pytest -q recursive-self-improvement/tests/test_deployment_fs.py`

Expected: import failure for the missing scanner.

- [ ] **Step 6: Implement bounded descriptor-relative scanning**

Open the root with `O_DIRECTORY|O_NOFOLLOW`, walk with retained directory FDs, reject more than 4,096 entries, depth over 32, path bytes over 4 MiB aggregate, individual files over 16 MiB, and aggregate bytes over 64 MiB. Hash file bytes from `O_NOFOLLOW` FDs, recheck `fstat` before/after, and double-scan named/opened identities. Do not write or repair.

- [ ] **Step 7: Run focused schema/filesystem GREEN tests**

Run: `PYTHONDONTWRITEBYTECODE=1 pytest -q recursive-self-improvement/tests/test_deployment_schema.py recursive-self-improvement/tests/test_deployment_fs.py`

Expected: all pass.

- [ ] **Step 8: Commit Task 1**

```bash
git add recursive-self-improvement/scripts/rsi_core/deployment_schema.py \
  recursive-self-improvement/scripts/rsi_core/deployment_fs.py \
  recursive-self-improvement/tests/test_deployment_schema.py \
  recursive-self-improvement/tests/test_deployment_fs.py
git commit -m "feat: add strict RSI deployment identity"
```

---

### Task 2: Managed global instruction block

**Files:**
- Create: `recursive-self-improvement/scripts/rsi_core/global_instructions.py`
- Create: `recursive-self-improvement/tests/test_global_instructions.py`

**Interfaces:**
- Consumes: `canonical_json_bytes` from Task 1.
- Produces: `MANAGED_BLOCK: bytes`, `BEGIN_MARKER`, and `END_MARKER` matching the design byte-for-byte.
- Produces: `plan_agents_update(existing: bytes | None) -> AgentsUpdate`.
- Produces: `verify_agents_bytes(actual: bytes, expected_block_digest: str) -> None`.

- [ ] **Step 1: Write exact preservation and trigger RED tests**

```python
def test_agents_update_preserves_every_unmanaged_byte() -> None:
    before = b"prefix\n\xff-owned\n"
    plan = plan_agents_update(before)
    assert plan.after.startswith(before)
    assert plan.after.count(BEGIN_MARKER) == 1
    assert plan.after.count(END_MARKER) == 1

@pytest.mark.parametrize("task,trigger", [
    (qualifying_skill_task(), True),
    (verified_reusable_finding(), True),
    (ordinary_conversation(), False),
    (rsi_maintenance_task(), False),
    (recursion_guarded_task(), False),
])
def test_managed_block_declares_closed_trigger_matrix(task, trigger) -> None:
    assert independent_trigger_oracle(MANAGED_BLOCK, task) is trigger
```

- [ ] **Step 2: Run tests and record RED**

Run: `PYTHONDONTWRITEBYTECODE=1 pytest -q recursive-self-improvement/tests/test_global_instructions.py`

Expected: import failure for the missing module.

- [ ] **Step 3: Implement the exact managed block and parser**

Embed the block from the design as a constant. Accept zero or one complete block. Reject duplicate markers, unmatched markers, non-UTF-8 managed content, NUL, unsafe line framing, or any existing block whose bytes differ from a previously manifest-bound block unless the caller is executing a verified update. Preserve unmanaged prefix/suffix bytes exactly, including an absent final LF. Preserve the exact safe mode of an existing file; use `0600` only when creating it.

- [ ] **Step 4: Add recursion and privacy tests**

Assert the block contains exactly one `CODEX_RSI_TRIGGER_ACTIVE=1`, explicitly excludes RSI/skill-learning maintenance, forbids raw dialogue/rejected evidence/secrets/PII, forbids promotion/allowlist/target changes, and reports failure without changing the main task result.

- [ ] **Step 5: Run Task 2 GREEN tests**

Run: `PYTHONDONTWRITEBYTECODE=1 pytest -q recursive-self-improvement/tests/test_global_instructions.py`

Expected: all pass.

- [ ] **Step 6: Commit Task 2**

```bash
git add recursive-self-improvement/scripts/rsi_core/global_instructions.py \
  recursive-self-improvement/tests/test_global_instructions.py
git commit -m "feat: define global RSI observe trigger"
```

---

### Task 3: Transactional deploy, update, verify, and rollback

**Files:**
- Create: `recursive-self-improvement/scripts/rsi_core/deployment.py`
- Create: `recursive-self-improvement/tests/test_global_deployment.py`
- Modify: `recursive-self-improvement/scripts/rsi_core/__init__.py`

**Interfaces:**
- Consumes: Task 1 schemas/scanner and Task 2 instruction planner.
- Produces: `DeploymentPaths.live() -> DeploymentPaths` with fixed `~/.codex` paths.
- Produces: `DeploymentPaths.for_testing(codex_home: Path) -> DeploymentPaths` for direct test injection only.
- Produces: `GlobalRsiDeployer.plan(source_repo: Path) -> DeploymentPlan`.
- Produces: `GlobalRsiDeployer.deploy(source_repo: Path, operation_id: str) -> DeploymentReceipt`.
- Produces: `GlobalRsiDeployer.verify() -> DeploymentStatus` and `.status() -> DeploymentStatus`, both read-only.
- Produces: `GlobalRsiDeployer.rollback(receipt_id: str, operation_id: str) -> DeploymentReceipt`.

- [ ] **Step 1: Write plan/verify zero-write RED tests**

Snapshot every path, inode, mode, and byte under a temporary Codex home before and after `plan`, `verify`, and `status`. Trap `mkdir`, `chmod`, rename, link, unlink, and writable opens; require zero calls for read-only operations. Missing installation returns a typed `not-installed` status without creating a home.

- [ ] **Step 2: Run read-only tests and record RED**

Run: `PYTHONDONTWRITEBYTECODE=1 pytest -q recursive-self-improvement/tests/test_global_deployment.py -k 'plan or verify or status'`

Expected: import failure for `GlobalRsiDeployer`.

- [ ] **Step 3: Implement source admission and read-only status**

Require a clean Git worktree, exact `HEAD`, tracked package membership equality, package validator success, strict JSON/YAML parsing, `observe`, `late-review`, empty allowlist, and no package symlink/unsafe mode. `verify` opens existing deployment state only and cross-checks both manifests, receipt, installed tree, and managed block.

- [ ] **Step 4: Write initial deploy and idempotent replay RED tests**

```python
def test_initial_deploy_is_marker_last_and_exact(tmp_path: Path) -> None:
    deployer = test_deployer(tmp_path)
    receipt = deployer.deploy(clean_repo(tmp_path), "deploy-v1")
    assert deployer.verify().receipt_digest == receipt.digest
    assert installed_tree(deployer.paths) == admitted_source_tree(tmp_path)

def test_exact_replay_returns_same_receipt_and_conflicting_operation_fails(tmp_path: Path) -> None:
    deployer = test_deployer(tmp_path)
    first = deployer.deploy(repo_v1(tmp_path), "same-op")
    assert deployer.deploy(repo_v1(tmp_path), "same-op") == first
    with pytest.raises(DeploymentOperationConflict):
        deployer.deploy(repo_v2(tmp_path), "same-op")
```

- [ ] **Step 5: Implement private staging and marker-last initial install**

Use a current-user `flock` with nonblocking monotonic retry. Create staging under the destination parent using `0700`; copy through complete-write loops handling EINTR/short write; fsync files and every created directory; install manifest last inside staging; scan/read back; rename staging to the absent destination; fsync parent; publish instruction bytes; verify; then publish `<operation>.manifest.json` and `<operation>.json` receipt last.

- [ ] **Step 6: Write update/exchange and rollback RED tests**

Test byte-identical no-op, v1→v2 update, v2→v1 rollback, absent prior `AGENTS.md`, exact non-UTF-8 unmanaged bytes, drift before exchange, drift before instruction replace, and unsupported exchange capability. On macOS, test the real `renameatx_np(RENAME_SWAP)` backend in a temporary same-filesystem directory; on other platforms, require typed unsupported status and no write.

- [ ] **Step 7: Implement atomic update backend and exact rollback**

For an existing installation, validate the old tree, create and validate the content-addressed backup, and use `renameatx_np(RENAME_SWAP)` with retained parent FD and pre/post inode verification. Do not use delete-then-rename. If instruction publication fails after exchange, reverse-exchange the exact operands, restore exact prior instruction bytes/absence, fsync/read back, and preserve ambiguous evidence if any identity differs.

- [ ] **Step 8: Add fault-injection tests at every boundary**

Parameterize failures at staging create, every file write, short write, EINTR, file fsync, directory fsync, manifest write, staging readback, package rename/exchange, parent fsync, instruction temp write/fsync/replace/parent fsync/readback, receipt manifest write/fsync, and marker write/fsync. Every cut must yield one of: unchanged old deployment, exact verified new deployment, exact verified rollback, or typed ambiguous state with no guessed cleanup.

- [ ] **Step 9: Add concurrency tests**

Run concurrent identical deploys, conflicting deploys, verify during staging, verify during exchange, rollback versus deploy, and killed lock holder. Prove one serialized winner, exact replay, bounded wait, automatic lock release on process death, and no partial authority.

- [ ] **Step 10: Run Task 3 GREEN tests**

Run: `PYTHONDONTWRITEBYTECODE=1 pytest -q recursive-self-improvement/tests/test_global_deployment.py`

Expected: all pass.

- [ ] **Step 11: Commit Task 3**

```bash
git add recursive-self-improvement/scripts/rsi_core/deployment.py \
  recursive-self-improvement/scripts/rsi_core/__init__.py \
  recursive-self-improvement/tests/test_global_deployment.py
git commit -m "feat: add transactional global RSI deployment"
```

---

### Task 4: Deployment CLI, health check, and trigger dry run

**Files:**
- Create: `recursive-self-improvement/scripts/rsi_deploy.py`
- Create: `recursive-self-improvement/scripts/rsi_core/global_rollout.py`
- Create: `recursive-self-improvement/tests/test_global_rollout.py`

**Interfaces:**
- Consumes: `GlobalRsiDeployer` and installed `rsi.py` local-review command.
- Produces CLI commands: `plan --source-repo`, `deploy --source-repo --operation-id`, `verify`, `status`, and `rollback --receipt-id --operation-id`.
- Produces: `classify_global_trigger(TaskSummary) -> TriggerDecision` with closed reasons.
- Produces: `run_observe_dry_run(installed_root: Path, temp_root: Path) -> DryRunReport`.

- [ ] **Step 1: Write CLI grammar and live-path RED tests**

Assert mutation commands require operation IDs, live CLI exposes no `--codex-home`, environment variables cannot redirect live paths, unknown/duplicate options fail, JSON output is canonical, and exit codes distinguish complete, not-installed, conflict, integrity, unsupported, and ambiguous results.

- [ ] **Step 2: Run CLI tests and record RED**

Run: `PYTHONDONTWRITEBYTECODE=1 pytest -q recursive-self-improvement/tests/test_global_rollout.py -k cli`

Expected: missing `rsi_deploy.py` or missing symbols.

- [ ] **Step 3: Implement the strict CLI**

Keep test path injection in Python constructors only. CLI `verify` and `status` set `PYTHONDONTWRITEBYTECODE=1`, never import modules from the mutable source after opening the installed package, and return one bounded canonical result envelope.

- [ ] **Step 4: Write independent trigger-matrix RED tests**

Use at least these fixtures: skill with reusable safe finding, skill without finding, verified reusable finding without skill, ordinary chat, status question, one-off fact, RSI deployment, skill-evolver service operation, recursion guard `1`, recursion guard invalid value, secret, PII, prompt-instruction evidence, two-skill task, and failed main task. The test oracle is a literal truth table, not copied from production predicates.

- [ ] **Step 5: Implement trigger classification**

Return only `triggered-safe`, `triggered-no-finding`, or `skipped` plus a closed reason. Never include raw evidence in a decision. Qualifying safe runs invoke installed `rsi.py local-review` with `mode=observe`, `hookMode=late-review`, final sanitized artifacts, temporary RSI home, and `CODEX_RSI_TRIGGER_ACTIVE=1`.

- [ ] **Step 6: Add temporary-home dry-run and privacy tests**

For each design scenario, compare live repository, installed package, global instructions, live provider ledger, and synthetic target trees before/after. Only qualifying safe cases may write the temporary RSI home. Rejected bytes and their hashes must be absent from every temporary object/event/report.

- [ ] **Step 7: Run Task 4 GREEN tests**

Run: `PYTHONDONTWRITEBYTECODE=1 pytest -q recursive-self-improvement/tests/test_global_rollout.py`

Expected: all pass.

- [ ] **Step 8: Commit Task 4**

```bash
git add recursive-self-improvement/scripts/rsi_deploy.py \
  recursive-self-improvement/scripts/rsi_core/global_rollout.py \
  recursive-self-improvement/tests/test_global_rollout.py
git commit -m "feat: add global RSI rollout controls"
```

---

### Task 5: Package documentation and release verification

**Files:**
- Create: `recursive-self-improvement/references/global-rollout.md`
- Modify: `recursive-self-improvement/SKILL.md`
- Modify: `recursive-self-improvement/references/architecture.md`
- Modify: `recursive-self-improvement/references/lifecycle-and-policy.md`
- Modify: `recursive-self-improvement/references/rollout-and-testing.md`
- Modify: `recursive-self-improvement/tests/test_forward.py`
- Modify: `recursive-self-improvement/tests/test_package_contract.py`

**Interfaces:**
- Documents exact CLI grammar, manifest/receipt paths, trigger/no-trigger rules, health checks, update, rollback, limitations, and recovery.
- Routes global installation questions from `SKILL.md` to `references/global-rollout.md`.

- [ ] **Step 1: Write package/documentation RED tests**

Require the new reference and links, parse every JSON example, verify exact managed block equality with production constant, verify command examples against the parser, assert `allow_implicit_invocation: false` remains unchanged, assert default `observe + late-review`, assert empty allowlist, and reject claims that promotion or privileged coordination is enabled.

- [ ] **Step 2: Run documentation tests and record RED**

Run: `PYTHONDONTWRITEBYTECODE=1 pytest -q recursive-self-improvement/tests/test_package_contract.py recursive-self-improvement/tests/test_forward.py -k 'global_rollout or package_links'`

Expected: failure because the rollout reference and routing are absent.

- [ ] **Step 3: Write the rollout and recovery documentation**

Document `plan`, `deploy`, `verify`, `status`, and `rollback`; exact live paths; Stage 0/1 limits; operator steps for invalid source, installed drift, instruction drift, failed reverse exchange, and ambiguous state; and the rule that a new Codex task is needed to observe a newly installed skill.

- [ ] **Step 4: Add forward release fixtures**

Exercise a complete temporary-home install, qualifying dry run, no-trigger dry run, exact update, rollback, source drift, installed drift, instruction conflict, and recursion suppression. Assert target/provider/live-state snapshots remain unchanged.

- [ ] **Step 5: Run focused and full package tests**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q \
  recursive-self-improvement/tests/test_deployment_schema.py \
  recursive-self-improvement/tests/test_deployment_fs.py \
  recursive-self-improvement/tests/test_global_instructions.py \
  recursive-self-improvement/tests/test_global_deployment.py \
  recursive-self-improvement/tests/test_global_rollout.py \
  recursive-self-improvement/tests/test_package_contract.py \
  recursive-self-improvement/tests/test_forward.py
```

Expected: all pass.

- [ ] **Step 6: Run package validators and full suite twice**

Run:

```bash
python3 ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py recursive-self-improvement
python3 ~/.codex/skills/skill-evolver/scripts/learning_log.py validate
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest -q --tb=short
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest -q --tb=short
```

Expected: both validators and both full suites pass.

- [ ] **Step 7: Commit Task 5**

```bash
git add recursive-self-improvement
git commit -m "docs: complete global RSI observe rollout"
```

---

### Task 6: Independent review, integration, and live rollout

**Files:**
- Create during execution report: `.superpowers/sdd/2026-08-13-global-rsi-observe-rollout/report.md`
- Modify live only after review: `~/.codex/skills/recursive-self-improvement/**`
- Modify live only after review: `~/.codex/AGENTS.md`
- Create live deployment state only after review: `~/.codex/rsi-deployments-v1/**`

**Interfaces:**
- Consumes the reviewed implementation commits and `rsi_deploy.py`.
- Produces a verified global installation and marker-last live deployment receipt.

- [ ] **Step 1: Generate a review package and request independent review**

Give a fresh reviewer the design, this plan, implementation report, base/head SHAs, and actual diff. Require explicit spec and code-quality verdicts and no P0/P1/P2. Reviewer must use temporary homes and must not invoke the live provider or modify global files.

- [ ] **Step 2: Fix every review finding with RED/GREEN evidence**

Return findings to the task implementer, commit fixes separately, rerun focused tests, and request a fresh re-review. Do not proceed on a partial or provisional approval.

- [ ] **Step 3: Fast-forward implementation to local `master`**

Require clean root and worktree, fetch `origin/master`, prove it is the expected ancestor, use `git merge --ff-only`, and rerun the full suite on `master`.

- [ ] **Step 4: Capture live pre-state witnesses**

Record hashes and metadata for `~/.codex/AGENTS.md`, any prior installed RSI path, `~/.codex/rsi-deployments-v1`, the live provider source tree, and live provider ledger. Do not record contents containing user data in the report.

- [ ] **Step 5: Run live plan and deploy**

```bash
python3 recursive-self-improvement/scripts/rsi_deploy.py plan \
  --source-repo "$PWD"
python3 recursive-self-improvement/scripts/rsi_deploy.py deploy \
  --source-repo "$PWD" \
  --operation-id "global-observe-$(git rev-parse HEAD)"
```

Expected: plan reports eligible with zero writes; deploy reports completed, `observe`, `late-review`, empty allowlist, and one verified receipt.

- [ ] **Step 6: Verify from a fresh process and run bounded dry run**

```bash
PYTHONDONTWRITEBYTECODE=1 python3 \
  ~/.codex/skills/recursive-self-improvement/scripts/rsi_deploy.py verify
```

Run the installed dry-run API in a fresh temporary RSI/provider home and verify trigger/no-trigger cases. Then start a fresh, read-only Codex process whose only task is to report whether the skill catalog contains `recursive-self-improvement`; it must not invoke provider or mutation commands.

- [ ] **Step 7: Recheck live invariants**

Require the provider source and ledger hashes and all production target witnesses to equal pre-state, global instructions to differ only by the exact managed block, the installed tree to match the manifest, and `git status` to be clean.

- [ ] **Step 8: Push and clean up**

Push `master` only after post-install verification is green. Remove the merged worktree and local feature branch without force. Preserve immutable receipts/backups and report their paths without exposing user data.

- [ ] **Step 9: Stop before enabling promotion**

Report that global RSI observe rollout is active, but production promotion, allowlist population, and privileged coordination remain separate future stages.
