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
`docs: complete RSI v1 release package`. Later independent-review correction
commits contain the additional evidence and fixes documented below.

## Baseline

Before adding Task 11 tests:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest -q --tb=short
1418 passed in 56.11s
```

The worktree already contained an untracked root `uv.lock`. It was treated as a
user-owned baseline artifact, was not edited, and is not included in any Task
11 implementation change.

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
  canaries, three held-out encoded-decoy injections, three short-Base64 and four
  combining/default-ignorable durable regressions, four shorter canonical
  Base64 and four letter/reserved/control durable regressions, benign
  encoding/Unicode controls, 10,000 generated real path/FSM cases, and real
  provider fault/replay drills.
- `recursive-self-improvement/tests/test_experiment.py`: exact held-marker,
  unsafe/deadline, bounded-membership, and real concurrent initializer/read-only
  open regressions.
- `recursive-self-improvement/tests/test_forward.py`: seven independent forward
  scenarios plus examples, links, metadata, permissions, defaults, CLI codes,
  omitted-hook and real envelope variants, index, contract graph, provider
  ledger, and package-validator checks.
- `recursive-self-improvement/scripts/rsi_core/sanitize.py`: bounded ordinary
  NFKC and classifier-only mark-stripped views plus repeated URL, HTML-entity,
  Unicode-escape, versioned Unicode 16.0.0 default-ignorable/control handling,
  and canonical seven-character-or-longer standard/URL-safe Base64 views, and
  the multilingual instruction set required by the RED corpus.
- `recursive-self-improvement/scripts/rsi_core/experiment.py`: bounded,
  read-only recognition/retry for the exact no-replace ownership-marker
  publication transient; every other topology remains fail-closed.
- `recursive-self-improvement/scripts/rsi_core/validation.py`: public omitted
  `hookMode` now resolves to the shipped `late-review` default.
- `recursive-self-improvement/scripts/rsi.py`: typed result-envelope-to-process
  status mapping for normative V1 exit codes.
- This report records the evidence and implementation commit.

The production files were outside the brief's documentation/test list. Each
behavior change was made only after a focused RED demonstrated a release
blocker.

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

## Independent-review TDD follow-up

### RED 4: decoy-prefix encoded injection

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'decoy_prefix'
3 failed, 121 deselected in 0.46s
```

Padded standard, unpadded standard, and unpadded Base64url instruction payloads
were each admitted when placed after two valid Base64 decoys. The root cause was
the production `[:2]` token slice plus a standard/padded-only token grammar.
The fix scans every token up to eight per decoded view, supports standard and
URL-safe alphabets with canonical padding repair, and rejects the evidence with
`encoded-content-budget` if the eight-token or twelve-view bound is exceeded.
Each held-out case now also drives the real coordinator/store boundary and
proves the raw/encoded payload is absent from durable state.

### RED 5: omitted public hook mode

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_forward.py -q --tb=short -k 'omitted_hook_mode'
1 failed, 19 deselected in 0.55s
```

The real CLI returned exit 2 and `coordinated local-review does not accept
finalArtifacts`; `validate_local_review` defaulted to coordinated despite the
shipped/default documentation. It now defaults omitted `hookMode` to
`late-review`. The end-to-end test proves the response warning, persisted
`run.started.payload.hookMode`, and unchanged target byte/mode tree.

### Characterization before test-quality/documentation corrections

The diverse property corpus required no production fix. Its first construction
run exposed a missing test-helper import (`NameError`) and is not a behavioral
RED. After that test-only correction, the generated independent-oracle corpus
passed against production:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'path_and_fsm_property_corpus'
1 passed, 123 deselected in 1.30s
```

The envelope mismatch was documentation, not dispatch behavior. A real CLI
characterization (no monkeypatched result dictionaries) confirmed the existing
closed variants before the reference was corrected:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_forward.py -q --tb=short -k 'real_cli_blocked_envelopes'
1 passed, 19 deselected in 0.67s
```

Public proposal lifecycle results use plural `errors`; command-processing and
promotion-continuation blocks use singular `error`. The reference now documents
field-presence selection, mutual exclusion, and one shared exit-code table.

### Follow-up GREEN

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py recursive-self-improvement/tests/test_forward.py -q --tb=short -k 'decoy_prefix or omitted_hook_mode or path_and_fsm_property_corpus or real_cli_blocked_envelopes'
6 passed, 138 deselected in 1.81s

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_sanitize.py recursive-self-improvement/tests/test_candidates.py recursive-self-improvement/tests/test_observe.py recursive-self-improvement/tests/test_local_lifecycle.py recursive-self-improvement/tests/test_adversarial.py recursive-self-improvement/tests/test_forward.py -q --tb=short
278 passed in 14.48s
```

## Second independent-review TDD follow-up

### RED 6: short Base64 instruction payloads

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'short_base64_instruction'
3 failed, 136 deselected in 0.53s
```

The existing 24-character token floor admitted the held-out padded standard,
unpadded standard, and unpadded Base64url instructions. Each fixture first
drove the real coordinator/store path, so the baseline accepted and durably
persisted the bypass before the assertion failed. The minimum is now 12
characters. Only successfully decoded UTF-8 tokens consume the existing
eight-token budget, which avoids treating long Base64-alphabet English words as
encoded content while still failing closed on a ninth decoded token.

### RED 7: default-ignorable combining marks

The first construction used an independent `edit AGENTS.md` trigger and passed
four cases; it was corrected before the authoritative behavioral RED and is not
counted as evidence. With that unrelated trigger removed:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'default_ignorable_combining_mark_instruction'
4 failed, 135 deselected in 0.53s
```

U+034F, U+180B, U+FE00, and U+E0100 split `ignore`, bypassed classification,
and were persisted through the real coordinator/store path. The sanitizer now
retains its ordinary NFKC view and adds a classifier-only NFD view with format
and combining marks removed. Both participate in the unchanged twelve-view
limit; accepted output continues to derive from the original evidence.

Benign controls passed before production changed:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'short_base64_lookalike_and_benign or benign_accented_multilingual'
8 passed, 131 deselected in 0.41s
```

They cover long Base64-alphabet English words, exactly eight benign decoded
tokens, benign short standard/Base64url payloads, composed and decomposed
accents, Greek, Arabic, Japanese, Hindi, and benign variation selectors. The
accepted summaries remain exactly equal to their original strings.

### Second follow-up GREEN

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'short_base64_instruction or default_ignorable_combining_mark_instruction or short_base64_lookalike_and_benign or benign_accented_multilingual'
15 passed, 124 deselected in 0.48s

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py recursive-self-improvement/tests/test_sanitize.py -q --tb=short
161 passed in 4.61s

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_sanitize.py recursive-self-improvement/tests/test_candidates.py recursive-self-improvement/tests/test_observe.py recursive-self-improvement/tests/test_local_lifecycle.py recursive-self-improvement/tests/test_adversarial.py recursive-self-improvement/tests/test_forward.py -q --tb=short
293 passed in 14.70s
```

## Third independent-review TDD follow-up

### RED 8: seven-to-eleven-character canonical Base64

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'shorter_canonical_base64_instruction'
4 failed, 150 deselected in 0.52s
```

The 12-character candidate floor admitted and durably persisted padded and
unpadded `run x`, unpadded `edit x`, and Base64url `run ¾`. The production
decoder now scans candidates with at least seven alphabet characters and
admits only an exact canonical padded or unpadded re-encoding. Successfully
decoded UTF-8 tokens still share the existing eight-token/twelve-view limits.

### RED 9: Unicode 16 default-ignorables and controls

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'default_ignorable_letter_reserved_and_control_instruction'
4 failed, 150 deselected in 0.56s
```

U+115F (`Lo`), U+FFA0 (`Lo`, normalized to U+1160), U+FFF0 (`Cn`), and NUL
(`Cc`) split `ignore`, bypassed classification, and persisted through the real
coordinator/store path. The deterministic predicate now uses the complete
Unicode 16.0.0 `Default_Ignorable_Code_Point` ranges. The classifier-only view
removes those code points, combining marks, and `Cc` controls while the ordinary
view and accepted evidence remain unchanged.

Seven benign controls passed before either sanitizer change:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'shorter_base64_lookalike_and_benign or benign_default_ignorable_and_control'
7 passed, 147 deselected in 0.41s
```

They cover ordinary seven/eight-character alphabetic words, canonical benign
standard and URL-safe encodings, exactly eight short decoded tokens, Hangul
fillers, a reserved default-ignorable, and benign NUL-bearing evidence. Every
accepted summary remains exactly equal to its input.

### RED 10: read-only experiment-store initializer race

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_experiment.py -q --tb=short -k 'exact_held_marker_publication_link or retries_only_exact_marker_publication_transient or concurrent_read_only_open_converges'
3 failed, 172 deselected in 2.66s
```

`open_existing()` made one marker read and treated the initializer's real
no-replace hard-link window (`st_nlink == 2`) as permanent unsafe topology. The
new read-only path retries only when root membership is exact and the marker
and one `.tmp-<32-lower-hex>` name are the same byte-exact, mode-`0600`,
two-link regular inode. It makes at most 100 attempts separated by 5 ms. Other
hard-link names fail immediately, a stuck exact topology fails at the deadline,
and the reader never repairs state.

Self-review then exposed an unbounded root-membership materialization in that
recognizer. Its focused test failed before the bounded scan was implemented:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_experiment.py -q --tb=short -k 'marker_publication_transient_membership_scan_is_bounded'
1 failed, 175 deselected in 0.68s
```

The recognizer now consumes at most six entries: the five exact transient
members are admissible for retry, and a sixth proves non-exact membership and
fails closed without scanning further.

### Third follow-up GREEN

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'shorter_canonical_base64_instruction or shorter_base64_lookalike_and_benign'
7 passed, 147 deselected in 0.43s

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_adversarial.py -q --tb=short -k 'default_ignorable_letter_reserved_and_control_instruction or benign_default_ignorable_and_control'
8 passed, 146 deselected in 0.45s

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_experiment.py -q --tb=short -k 'exact_held_marker_publication_link or retries_only_exact_marker_publication_transient or marker_publication_transient_membership_scan_is_bounded or concurrent_read_only_open_converges'
4 passed, 172 deselected in 0.52s

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_sanitize.py recursive-self-improvement/tests/test_adversarial.py -q --tb=short
176 passed in 4.69s

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_experiment.py -q --tb=short
176 passed in 26.47s
```

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
  transformations. Three additional held-out decoy-prefix cases cover padded,
  unpadded, and Base64url third-token bypasses; three short-Base64 cases cover
  padded, unpadded, and URL-safe forms below 24 characters; and four durable
  cases cover U+034F, U+180B, U+FE00, and U+E0100 keyword splitting. Four more
  canonical Base64 cases cover seven-to-eleven-character padded, unpadded, and
  URL-safe forms; four more durable cases cover U+115F, U+FFA0, U+FFF0, and NUL.
  These 18 held-out cases do not inflate the 250 count. Fifteen benign encoding
  and Unicode/control cases constrain false positives and output preservation.
- Secret/PII canaries: exactly 100 unique values: 20 each of Stripe-like,
  GitHub-like, AWS-like, email, and telephone forms. All 100 were rejected and
  byte scans of the real temporary `EventStore` found zero persisted canaries.
- Property cases: exactly 10,000 real calls with independent literal oracles:
  5,000 generated path-admission cases through `_path_reason` across 22
  filesystem/path classes, and 5,000 generated histories through `fold_run`
  across 33 run-kind, predecessor, terminal, incident, apply, verification, and
  resolution graph classes. Paths include multilingual/decomposed Unicode,
  normalization and casefold collisions, internal and escaping symlinks,
  FIFO/special entries,
  missing/directory/symlink/FIFO markers, broad roots, marker targets, reserved
  roots, absolute paths, and traversal.
- Release provider fault cases: 14 pytest cases and 15 injected cuts. Six
  capture cases cover lookup, pre-append, partial write, file fsync, parent
  fsync, and post-commit/pre-return; seven snapshot cases cover prepare append,
  prepare fsync, post-prepare, post-install/pre-result, result append, result
  fsync, and post-commit/pre-return; one case separately loses defer and resolve
  results after their commits. Every exact retry converged to one operation and
  the real provider validator passed in the controlled temporary home.
- Experiment initializer/read-only concurrency: four pytest cases cover a held
  exact two-link window, an immediate noninitializer hard-link rejection, an
  exact stuck-window deadline, a six-entry membership-consumption ceiling, and
  a real concurrent `_write_once` marker publication/read-only open.
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

The initial `test_forward.py` result is included in the 139-test combined run
above; the follow-up real-dispatch/default tests are included in the fresh full
suite below.

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

Fresh authoritative GREEN after every independent-review correction:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest -q --tb=short
1458 passed in 62.45s (0:01:02)
```

Fresh authoritative GREEN after the short-Base64 and Unicode-obfuscation
corrections:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest -q --tb=short
1473 passed in 62.75s (0:01:02)
```

Two sequential authoritative GREEN runs after the canonical-short-Base64,
Unicode 16.0.0, and experiment-store initializer-race corrections:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest -q --tb=short
1492 passed in 71.50s (0:01:11)

PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest -q --tb=short
1492 passed in 70.70s (0:01:10)
```

The release validators and static package checks produced:

```text
python3 /Users/macbook/.codex/skills/skill-evolver/scripts/learning_log.py validate
OK: 1295 events

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

The package/link validator test was rerun after the second follow-up report and
release-matrix changes:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_forward.py -q --tb=short -k 'release_package_links'
1 passed, 19 deselected in 0.43s
```

It was rerun again after the third follow-up report, architecture, and release
matrix changes:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest recursive-self-improvement/tests/test_forward.py -q --tb=short -k 'release_package_links'
1 passed, 19 deselected in 0.45s
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
- Normalization is bounded to at most 12 decoded views, eight successfully
  decoded UTF-8 Base64 tokens per view, and the existing source-length cap. All
  seven-character-or-longer token candidates in the bounded source are checked
  for canonical padded/unpadded standard or URL-safe encoding until the ninth
  decoded token fails closed. An ordinary normalized view preserves accented,
  control-bearing, and multilingual evidence, while a separate classifier-only
  view removes Unicode 16.0.0 default-ignorables, combining marks, and `Cc`
  controls. Exceeding either bound rejects rather than silently skipping later
  tokens. Rejected raw data is neither hashed nor persisted.
- Read-only experiment-store open retries only the exact byte/mode/inode/root
  membership of the initializer's marker hard-link window, at most 100 times
  with 5 ms intervals. The membership probe reads at most six names. All other
  unsafe topologies fail immediately; deadline expiry fails without mutation.
- The injection fixtures generate their phrases/transforms independently; the
  forward cases assert durable events, objects, reports, process status, and
  byte/mode trees rather than source strings.
- Error-code precedence is fail-closed: conflict, approval, provider,
  validation, integrity, and policy types are distinguished; an otherwise
  blocked result remains provider/unavailable code 6, and failed unknowns are
  code 2.
- Real dispatch proves the two compatible blocked/error envelope variants and
  the documentation now names them instead of claiming one universal shape.
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
- The classifier's `Default_Ignorable_Code_Point` table is intentionally frozen
  to Unicode 16.0.0; a future Unicode upgrade requires an explicit reviewed
  table and corpus update rather than changing behavior with the interpreter.
- Index rebuild and `doctor --salvage-report` do not repair corrupt authority.
- The root `uv.lock` remains an intentional pre-existing untracked artifact.

These limitations are fail-closed rollout constraints, not hidden release
defects.
