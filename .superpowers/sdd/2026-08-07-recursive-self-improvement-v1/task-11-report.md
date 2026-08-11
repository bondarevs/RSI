# Task 11 implementation report

## Result

Task 11 is complete as a Stage 0/1, observe-by-default release package. The
security corpus, independent forward fixtures, durable-boundary fault drills,
package/readiness checks, provider checks, validators, and complete test suite
pass. No critical or high defect remains open. The production target allowlist
is still empty, and no Task 11 test or command mutated a live provider ledger or
a production target.

The implementation commit is
`5c9dddd1f273877d36f958121b838a3388c253fd`, with the required subject
`docs: complete RSI v1 release package`.

## Baseline

Before adding Task 11 tests:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest -q --tb=short
1418 passed in 56.11s
```

The worktree already contained an untracked root `uv.lock`. It was treated as a
user-owned baseline artifact, was not edited, and is not included in either
Task 11 commit.

## Changed files

- `recursive-self-improvement/SKILL.md`: exact defaults, preflight, lifecycle,
  mutation boundaries, reference routing, recovery, and final reporting.
- `recursive-self-improvement/agents/openai.yaml`: explicit observe-only,
  late-review default prompt; implicit invocation remains disabled.
- `recursive-self-improvement/references/architecture.md`: trust domains,
  storage, mutation flow, provider-v2 compatibility, and ordinary-host limits.
- `recursive-self-improvement/references/lifecycle-and-policy.md`: exact
  defaults, hook modes, CLI envelope, process codes, and recovery runbook.
- `recursive-self-improvement/references/rollout-and-testing.md`: closed rollout
  manifest example/schema, stages, release corpus, forward tests, commands, and
  limitations.
- `recursive-self-improvement/references/schemas.md`: durable-object routing,
  strict JSON/rebuild rules, and release compatibility limits.
- `recursive-self-improvement/references/metrics.md`: exact monitoring/global
  defaults and fail-closed operational limits.
- `recursive-self-improvement/references/defragmentation.md`: exact audit-only
  defaults, valid digest example, routing, and no-repair recovery guidance.
- `recursive-self-improvement/tests/test_adversarial.py`: 250 injections, 100
  canaries, 10,000 real path/FSM cases, and real provider fault/replay drills.
- `recursive-self-improvement/tests/test_forward.py`: seven independent forward
  scenarios plus examples, links, metadata, permissions, defaults, CLI codes,
  index, contract graph, provider ledger, and package-validator checks.
- `recursive-self-improvement/scripts/rsi_core/sanitize.py`: bounded NFKC/control
  normalization and repeated URL, HTML-entity, Unicode-escape, and Base64 views,
  plus the multilingual instruction set required by the RED corpus.
- `recursive-self-improvement/scripts/rsi.py`: typed result-envelope-to-process
  status mapping for normative V1 exit codes.
- This report records the evidence and implementation commit.

The last two production files were outside the brief's documentation/test list.
Each was changed only after a focused RED demonstrated a release blocker.

## Strict TDD evidence

An initial construction-only execution detected duplicate generated fixtures
and was corrected before the behavioral RED; it is deliberately not counted as
the authoritative RED.

### Authoritative RED 1: injection behavior

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'release_injection_corpus'
1 failed, 106 deselected in 0.47s
```

The independent 250-case set was valid and unique, but the existing sanitizer
admitted 208 encoded, Unicode-control, compatibility-form, and multilingual
instruction cases. The expected assertion was `misses == 0`, so this was a RED
caused by missing release behavior, not a broken fixture.

### Authoritative RED 2: forward package behavior

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_forward.py -q --tb=short
2 failed, 7 passed in 0.95s
```

The Japanese unsafe-finding fixture was durably admitted instead of raising,
and the release package lacked the required architecture, lifecycle/policy,
and rollout/testing references. Both failures were direct Task 11 gaps.

### Authoritative RED 3: CLI process status

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_forward.py -q --tb=short -k 'normative_exit_codes'
6 failed, 3 passed, 9 deselected in 0.49s
```

Policy, validation/attestation, approval, conflict, ambiguous, and quarantined
result envelopes returned process success or the generic provider code instead
of the V1 code table. This justified the small `rsi.py` production change.

## Focused GREEN evidence

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py recursive-self-improvement/tests/test_forward.py -q --tb=short -k 'release_injection_corpus or forward_unsafe_finding'
2 passed, 114 deselected in 0.45s

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'release_secret_pii_corpus or release_path_and_fsm_property_corpus'
2 passed, 105 deselected in 0.89s

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_forward.py -q --tb=short -k 'normative_exit_codes'
9 passed, 9 deselected in 0.46s

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_sanitize.py recursive-self-improvement/tests/test_candidates.py recursive-self-improvement/tests/test_policy.py recursive-self-improvement/tests/test_local_lifecycle.py -q --tb=short
183 passed in 8.87s

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'release_provider'
14 passed, 107 deselected in 3.37s

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py recursive-self-improvement/tests/test_forward.py -q --tb=short
139 passed in 4.53s
```

The final one-test validator portability recheck, after replacing a fixed
interpreter path with the running interpreter's base executable, was:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_forward.py -q --tb=short -k 'release_package_links'
1 passed, 17 deselected in 0.44s
```

## Corpus and fault case counts

- Injection fixtures: exactly 250 unique cases: 10 instruction-bearing phrases
  in English, Spanish, French, German, Portuguese, Russian, Ukrainian, Chinese,
  Japanese, and Arabic, each under 25 independent plain/nested/encoded/control
  transformations.
- Secret/PII canaries: exactly 100 unique values: 20 each of Stripe-like,
  GitHub-like, AWS-like, email, and telephone forms. All 100 were rejected and
  byte scans of the real temporary `EventStore` found zero persisted canaries.
- Property cases: exactly 10,000 real calls: 5,000 path-admission cases through
  `_path_reason` and 5,000 valid/terminal-order cases through `fold_run`.
- Release provider fault cases: 14 pytest cases and 15 injected cuts. Six
  capture cases cover lookup, pre-append, partial write, file fsync, parent
  fsync, and post-commit/pre-return; seven snapshot cases cover prepare append,
  prepare fsync, post-prepare, post-install/pre-result, result append, result
  fsync, and post-commit/pre-return; one case separately loses defer and resolve
  results after their commits. Every exact retry converged to one operation and
  the real provider validator passed in the controlled temporary home.
- The pre-existing durable-store/recovery drill was rerun explicitly:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest -q --tb=short recursive-self-improvement/tests/test_storage.py::test_append_with_sidecar_is_marker_last_and_retry_converges_after_event_fault recursive-self-improvement/tests/test_storage.py::test_rebuild_index_holds_store_lock_and_atomically_replaces_existing_cache recursive-self-improvement/tests/test_experiment.py::test_equal_existing_post_image_retry_fsyncs_and_reads_back recursive-self-improvement/tests/test_experiment.py::test_complete_bundle_retry_repairs_result_directory_fsync recursive-self-improvement/tests/test_experiment.py::test_store_fsyncs_created_home_directories_and_lock recursive-self-improvement/tests/test_experiment.py::test_post_image_publish_faults_never_return_unverified_authority recursive-self-improvement/tests/test_experiment.py::test_store_faults_never_make_partial_bundle_authoritative recursive-self-improvement/tests/test_evolver_adapter.py::test_task8_adapter_recovers_exact_committed_snapshot_and_resolve_after_writer_transport_loss recursive-self-improvement/tests/test_evolver_adapter.py::test_guarded_v2_snapshot_lookup_first_replays_commit_after_unknown_writer_outcome recursive-self-improvement/tests/test_evolver_adapter.py::test_guarded_v2_resolve_lookup_first_converges_race_and_commit_before_return_loss recursive-self-improvement/tests/test_recovery.py::test_recovery_crash_cut_classifier_is_phase_exact_and_conservative recursive-self-improvement/tests/test_recovery.py::test_unlink_crash_cut_requires_absence_parent_sync_and_terminal_readback
28 passed in 1.24s
```

- Sidecar short-write/EINTR and verifier receipt/non-issuance were rerun:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest -q --tb=short recursive-self-improvement/tests/test_storage.py::test_transaction_sidecar_prepublication_failure_leaves_no_named_temp_and_retries recursive-self-improvement/tests/test_storage.py::test_transaction_sidecar_complete_write_loop_handles_short_write_and_eintr recursive-self-improvement/tests/test_promotion.py::test_verifier_receipt_result_is_the_exact_conjunction recursive-self-improvement/tests/test_promotion.py::test_signed_nonissuance_and_receipt_are_mutually_exclusive_terminal_results recursive-self-improvement/tests/test_experiment.py::test_failed_timed_out_crashed_and_unknown_experiments_never_publish_plan_or_post_image recursive-self-improvement/tests/test_experiment.py::test_eligible_experiment_publishes_immutable_plan_without_production_or_provider_mutation
10 passed in 1.33s
```

Together these exercise every reachable V1 durable boundary: event/sidecar
write and marker, short/partial write, file and directory fsync, create-once
publication, atomic index replace, readback, validation reservation/result and
post-image, verifier receipt/non-issuance, provider capture/snapshot/defer/
resolve commit/replay, and conservative recovery. The live target exchange is
not reachable on an ordinary host by design: the production backend fails
before mutation without an attested non-bypassable coordinator.

## Independent forward fixtures

All seven required fixtures use real lifecycle/report/defragmentation code and
fresh temporary roots rather than matching source text or mirroring a production
helper:

1. verified safe knowledge creates one bounded candidate and leaves the target
   byte/mode tree unchanged;
2. an instruction-bearing Japanese unsafe finding is refused before finding
   sidecar or target write;
3. two targets receive separate evaluations and candidate lineage;
4. explicit late-review reports in-dialog signal loss and remains read-only;
5. the legacy no-RSI path creates no state and claims no RSI guarantees;
6. three fingerprints across two skills support a global pattern without target
   mutation;
7. defragmentation detects copy and digest drift without repair.

The final `test_forward.py` result is included in the 139-test combined run
above; its 18 tests all pass.

## Full suite and release validators

Authoritative full-suite GREEN after all production and release-test changes:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest -q --tb=short
1453 passed in 61.55s (0:01:01)
```

The brief's final path-scoped form was then run unchanged apart from the
required project environment wrapper:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests -q
1453 passed in 62.91s (0:01:02)
```

The release validators and static package checks produced:

```text
python3 /Users/macbook/.codex/skills/skill-evolver/scripts/learning_log.py validate
OK: 1293 events

python3 /Users/macbook/.codex/skills/.system/skill-creator/scripts/quick_validate.py recursive-self-improvement
Skill is valid!

git diff --check
<no output; exit 0>

find recursive-self-improvement -type l -print
<no output>

find recursive-self-improvement -type f -perm -0022 -print
<no output>

rg -n -i '\b(TODO|TBD|FIXME|PLACEHOLDER)\b' recursive-self-improvement/SKILL.md recursive-self-improvement/references recursive-self-improvement/agents/openai.yaml
<no output>

python3 /Users/macbook/.codex/skills/skill-evolver/scripts/learning_log.py list --status pending --skill recursive-self-improvement --json
[]
```

The package test parses every fenced JSON example, parses the closed
`agents/openai.yaml` metadata shape, resolves every local Markdown link, rejects
symlinks and group/world-writable files, proves the default mode is `observe`,
proves the production allowlist is empty, rebuilds the index byte-identically,
routes `rsi.lifecycle` through the real provider contract graph, validates a
fresh provider ledger, and proves the provider source tree is unchanged. The
live provider validator was read-only; all provider mutation drills set
`CODEX_SKILL_LEARNING_HOME` to fresh temporary directories.

## Self-review

- No Task 11 code introduces a target-writing call. The only new production
  behavior is bounded evidence classification and result exit selection. Target
  mutation remains confined to the already-gated `promote-candidate` path.
- Normalization is bounded to at most 12 decoded views, two Base64 tokens per
  view, and the existing source-length cap. Rejected raw data is neither hashed
  nor persisted.
- The injection fixtures generate their phrases/transforms independently; the
  forward cases assert durable events, objects, reports, process status, and
  byte/mode trees rather than source strings.
- Error-code precedence is fail-closed: conflict, approval, provider,
  validation, integrity, and policy types are distinguished; an otherwise
  blocked result remains provider/unavailable code 6, and failed unknowns are
  code 2.
- Documentation does not overclaim deployment readiness. It identifies this as
  a Stage 0/1 package, not an attested Stage 6 installation.
- The pending queues inspected for the active TDD, verification, validator, and
  RSI skills contained no causally related unresolved candidate. No generic or
  environment-specific finding was promoted into a skill.
- Review found no critical/high issue and no weakened fail-closed boundary.

## Known limitations

- The effective shipped mode remains `observe`; the production overlay's
  allowlist is empty and its attestation references are null.
- Public preflight cannot establish trusted host verification or canonical
  provider capture. Proposal resume needs a compatible pinned provider-v2 and
  explicit trusted roots.
- Isolated validation/plan APIs exist, but the standalone CLI has no
  `validate-candidate` command.
- Ordinary macOS/Linux hosts have no attested non-bypassable namespace lease.
  Live target exchange remains unavailable until a privileged coordinator is
  separately implemented and attested.
- Late-review cannot recover in-dialog signals; no RSI invocation gives no RSI
  lifecycle guarantees.
- Global RSI and defragmentation remain report/proposal-only; monitoring never
  restores automatically.
- Index rebuild and `doctor --salvage-report` do not repair corrupt authority.
- The root `uv.lock` remains an intentional pre-existing untracked artifact.

These limitations are fail-closed rollout constraints, not hidden release
defects.
