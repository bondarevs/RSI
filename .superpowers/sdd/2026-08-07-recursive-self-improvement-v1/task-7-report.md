# Task 7 Report — Isolated RSI Validation Artifacts

## Scope and safety boundary

- Worktree: `/Users/macbook/Documents/ChatGPT/RSI/.worktrees/rsi-task-1`.
- Baseline: `e3427fc` (`feat: add canonical RSI proposal mode`).
- The approved specification remained byte-identical at SHA-256
  `4d691659fc3f2a97c863fc8153e49227fc152ebe6dcf0c7a6aa8829842dd0b37`.
- Task 7 is pure validation. It does not append lifecycle events, repair a
  journal, invoke provider snapshot/defer/resolve, write a provider ledger, or
  mutate a production target. Task 8 owns those cross-run FSM transitions.
- All integration targets, stores, control roots, harnesses, and candidate
  artifacts in tests are temporary. The real provider source and learning
  ledger are read-only witnesses.

## Implemented artifacts

### Exact managed-tree hashing

`hashing.py` provides bounded descriptor-relative managed-tree manifests,
canonical semantic JSON and raw-byte digests, exact one-artifact replacement
descriptors, and content-addressed post-image verification. It binds file
membership, canonical path spelling, type, raw bytes, executable bit, and safe
relative symlink text while rejecting alias, normalization/case collision,
hardlink, special-file, size/count/depth, and stat/open/read races. Generated
caches are excluded only after a whole-tree safety scan; sensitive runtime
files remain a hard rejection.

### Closed signed attestations

`attestations.py` provides deeply immutable closed rollout-stage,
orchestration-hook, and validation attestation models. Strict parsers reject
duplicate keys, non-finite values, noncanonical arrays/base64, malformed IDs,
issuers, timestamps, types, and unknown fields. Verification binds the exact
signed-body digest, trusted signature verifier, bounded chain, active
allowlist/root/registration/contract identity, TTL, and exact replay semantics.
Stage and hook domains remain distinct and share the required deployment
context.

### Isolated experiment, immutable store, and promotion plan

`experiment.py` provides:

- host-built `ArtifactProposal` and authoritative captured-candidate lineage;
- closed request, trusted-current-state, reservation, result, receipt, bundle,
  and promotion-plan models;
- a marker-last, descriptor-relative, no-follow, result-last artifact store
  with per-operation process locks, exact replay/convergence, bounded post-image
  CAS, fsync/readback, closed topology, and zero-mutation read paths;
- pinned source, harness, control-plane, baseline, variant, and scratch
  witnesses across S0/S1/S2/S3, with exact staged copies and no shared links;
- per-case and per-invariant comparison, deterministic full-core provider
  operation IDs, strict eligible/rejected bundle semantics, and pure
  `verify_promotion_plan`;
- full-artifact UTF-8 safety scanning and the V1 compatibility gate before
  store initialization: knowledge-only, exact admitted reference, or exact
  `SKILL.md` append with unchanged trusted frontmatter;
- one host-precreated private scratch-output inode, bounded post-executor
  admission/reseal, and successful staging cleanup before any post-image or
  result authority is published;
- canonical issuer-byte admission before verifier/replay binding;
- a real macOS Seatbelt diagnostic probe pinned to root-owned canonical
  launcher/interpreter bytes. The built-in backend is deliberately unavailable:
  this host cannot prove hard memory enforcement or denial of same-image exec,
  and Task 7 contains no downgraded subprocess path.

## TDD and adversarial review evidence

All pytest runs used `PYTHONDONTWRITEBYTECODE=1`.

### Hashing and attestation RED/GREEN

The combined hardening RED, after adversarial direct-constructor, race, path,
chain, replay, and canonicalization tests were added, was:

```text
19 failed, 45 passed in 6.99s
```

Subsequent focused review found and reproduced direct-manifest domain,
post-construction mutation, ancestry-open race, cross-context attestation,
mutable nested model, malformed replay, canonical base64, issuer, timestamp,
and forged-verification-provenance defects. The independently reviewed final
focused suites were:

```text
37 hashing tests passed, plus 9 independent probes
39 attestation tests passed, plus independent fuzz/probes
```

The stable combined command is:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q \
  recursive-self-improvement/tests/test_hashing.py \
  recursive-self-improvement/tests/test_attestations.py
```

Final result:

```text
76 passed in 0.70s
```

### Store, state, staging, and replay RED/GREEN

Layered RED rounds covered unsafe ownership initialization, path/fd races,
cross-operation bundle copies, noncanonical reservation bytes, result-last and
fsync faults, lock replacement, two-process convergence, read-path mutation,
trusted-state drift, candidate relabeling, topology overlap, TTL/clock changes,
scratch/stage cleanup rebinding, stale receipts, and completed-replay T0 races.

Independent approvals were recorded after:

```text
26/26 store tests passed
13/13 state/model tests passed
45-case independent reservation mutation matrix rejected every mutation
104/104 pre-macOS experiment tests passed
```

The marker-last initialization follow-up additionally proved that a concurrent
reader cannot observe a marker-only partially initialized store.

### macOS boundary RED/GREEN

The original host-oracle RED was exactly the three missing local-backend nodes.
After the real probe and typed unavailable boundary:

```text
3 passed in 0.90s
```

Final review then reproduced an ambient-`PATH` launcher execution and two
unbounded process-runner defects. The added RED evidence was:

```text
1 failed in 0.83s
2 failed in 1.00s
```

After pinning `/usr/bin/sandbox-exec`, binding launcher/interpreter/profile/
worker/OS identities, incrementally enforcing one shared output cap, and
killing/reaping the complete process group on deadline or overflow:

```text
6 passed in 1.89s
```

The real host capability result retains successful filesystem, network, DNS,
Unix-socket, fork/spawn/system/subprocess, environment, stdin/fd, and scratch
canaries, but reports:

```text
hard_memory_enforced = false
same_image_exec_denied = false
complete = false
```

No untrusted target marker is executed.

### Final persistence/safety RED/GREEN

The final review added nine cases before the production correction:

```text
9 failed in 3.36s
```

They reproduced post-publication scratch cleanup failure, an authoritative
result surviving unsafe scratch topology, raw/base64 secret, PII and instruction
payload persistence, non-additive reference and changed `SKILL.md` frontmatter,
and valid-signature pretty issuer JSON. After the bounded fixes:

```text
9 passed in 1.68s
```

The final content-gate review then reproduced credential assignments outside
the shared sanitizer's vocabulary. The local scanner test matrix covered all
five required key families, case and `_`/`-`/space spelling, raw/URL/Base64
forms, the beginning and an overlapping scan-window boundary, and the exact
4 MiB artifact end. Before the production edit:

```text
10 failed, 1 passed, 119 deselected in 6.15s
```

The one passing node was the required benign `token`/`API_TOKEN` label without
an assigned value. After adding bounded local decoding and assignment matching:

```text
11 passed, 119 deselected in 2.52s
20/20 combined artifact-safety, scratch, compatibility, and issuer tests passed
```

Adversarial replay of that correction found quoted JSON/TOML/environment-map
keys and an equality-comparison false positive. The exact follow-up RED was:

```text
7 failed, 11 passed, 119 deselected in 6.00s
```

The final closed expression admits only symmetrical optional key quotes, an
optional environment-map closing bracket, and one `:` or non-comparison `=`
separator followed by a nonempty value. Raw, URL, and Base64 quoted forms at
the start, window boundary, and exact maximum end reject; benign `==` and `!=`
comparisons remain eligible. Final focused results:

```text
19 passed, 119 deselected in 4.29s
28/28 combined artifact-safety, scratch, compatibility, and issuer tests passed
```

The final independent credential re-review approved the stable
`fe8035d9`/`5b345f9b` source/test snapshot. Its separate matrix exercised all
five credential labels across JSON, TOML, environment-map, raw, URL, and
Base64 forms with zero misses. It also confirmed no store/executor/issuer or
raw/hash persistence for the original canary, accepted `==`/`!=` comparisons
and mismatched quotes as non-assignments, and kept the scratch/issuer
regressions green. The independent macOS boundary re-review separately
approved the pinned-launcher, bounded-I/O, process-group-reaping, and permanent
`complete=false` behavior with no remaining finding.

### Final test commands

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q \
  recursive-self-improvement/tests/test_experiment.py
```

```text
138 passed in 29.98s
```

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q \
  recursive-self-improvement/tests
```

```text
870 passed in 116.94s
```

## Validation and immutability evidence

Read-only validators:

```text
Skill is valid!
OK: 2 contracts
OK: 1255 events
```

`python -m py_compile` and `git diff --check` exited 0. The approved
specification has no diff and retains the digest shown above.

The provider source digest, excluding its pre-existing generated cache, was
identical before and after the focused/full tests and validators:

```text
6688ad5a44a6b33911251adc26992f17623b58ac824167ae001bd0480f2a4e09
```

It was computed without touching the provider using:

```text
find /Users/macbook/.codex/skills/skill-evolver -type f \
  -not -path '*/__pycache__/*' -print0 | sort -z | \
  xargs -0 shasum -a 256 | shasum -a 256
```

The real provider ledger was also byte- and line-identical:

```text
201acccac622b379f9c031a095a951133b033d92678fefece63967a6f13b1a6c
1,255 lines
```

Production-target immutability is exercised directly for eligible, rejected,
failed, timed-out, crashed, drifted, concurrent, cleanup-tainted, and replayed
experiments. Provider snapshot/ledger spies remain at zero in every Task 7
path. Static tests also reject imports/calls to provider mutation and EventStore
append APIs from the experiment module.

Task 7 intentionally receives no live production-target path. Every executable
experiment target is a fresh pytest temporary directory. Its pre/post `_tree`
witness binds each relative locator, `lstat` kind, permission mode, and exact
file bytes or symlink text; eligible, rejection, failure, drift, concurrency,
and cleanup cases all assert exact equality. The repository itself has no
tracked Task 7 diff and the approved specification diff is empty.

Final reviewed source/test hashes are:

```text
hashing.py          9b697cfb796799e86136fad0b57fb3bac8b8cec7802d3470ab118293776a08bd
attestations.py     637820ec5e8232e2a89e71d7e41257f8cc286ae67481a9dc9febf9bd4709f889
experiment.py       fe8035d959e314ab42498c68e7a36ebba36de5e0e6bc62304918e0719f8b5fbf
test_hashing.py     867d87d89241c39e040195dffac67b92a1930861dd8ad4f4d732a0f5b509924c
test_attestations.py 65f123129bc67a75031935c27af1553564c9bd1ab7a5df5dc21ca6e057bd064b
test_experiment.py  5b345f9bf9c4cf3634bcb595a2d8c9eae6dc268c7c1034ff1c215d47721eb43f
```

Generated project `__pycache__` and `.pytest_cache` directories were moved to
the macOS Trash after the final runs; the pre-existing virtual-environment
caches were not touched. The final status contains only the six intended
untracked Task 7 source/test files; this ignored report is the seventh intended
artifact.

## Intended repository changes and rollback

Task 7 creates exactly these six implementation/test files plus this report:

```text
recursive-self-improvement/scripts/rsi_core/hashing.py
recursive-self-improvement/scripts/rsi_core/attestations.py
recursive-self-improvement/scripts/rsi_core/experiment.py
recursive-self-improvement/tests/test_hashing.py
recursive-self-improvement/tests/test_attestations.py
recursive-self-improvement/tests/test_experiment.py
.superpowers/sdd/2026-08-07-recursive-self-improvement-v1/task-7-report.md
```

No storage, package, permission, lifecycle, provider, or approved-spec file was
modified. Before commit, rollback is removal of only these new files. After the
reviewed commit, use a normal `git revert` of that commit; no live provider or
target restoration is required because Task 7 never mutates them.

## Explicit Task 8 debt

Task 8 must integrate these pure artifacts into the cross-run validation FSM:

- journal the validation request/result and repair append-after-authority
  crash windows;
- revalidate typed deployment and validation attestations at the lifecycle
  boundary;
- make provider snapshot/resolve and target promotion the single reviewed
  mutation transaction with exact operation IDs and postimage;
- implement restart/retry/rollback and monitoring transitions without aliasing
  provider contract and provider version digests;
- either install a separately reviewed capability-complete local sandbox
  backend or continue to require an injected trusted executor. The Task 7
  macOS backend remains intentionally unavailable.
