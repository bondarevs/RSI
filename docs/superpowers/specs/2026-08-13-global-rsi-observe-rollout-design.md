# Global RSI Observe Rollout Design

## Status and objective

This specification defines the first global deployment of the completed RSI v1
package. The deployment makes RSI available to Codex tasks on this computer and
adds a global post-task trigger, while retaining the Stage 0/1 safety boundary:
`observe` mode, `late-review`, an empty production allowlist, read-only global
analysis, and no automatic promotion.

The rollout is successful when a newly started Codex task can discover the
installed `recursive-self-improvement` skill, qualifying completed tasks invoke
the documented late-review flow, non-qualifying conversations produce no RSI
state, the production allowlist remains empty, and neither installation nor
runtime changes a production target.

## Scope

The rollout includes:

- a deterministic deploy, verify, and rollback tool maintained in this
  repository;
- an immutable installed copy at
  `~/.codex/skills/recursive-self-improvement`;
- a closed deployment manifest binding the repository commit, source tree,
  installed tree, profile, and global-instruction block;
- one idempotent managed block in `~/.codex/AGENTS.md`;
- read-only health checks and temporary-home integration tests;
- a bounded dry run of the global trigger in `observe + late-review`.

The rollout does not include:

- enabling `promote-candidate` against production;
- populating the production target allowlist;
- installing a privileged namespace-mutation coordinator;
- changing existing skills, targets, provider state, or the live learning
  ledger during tests;
- invoking RSI after ordinary conversation or one-off tasks that produced no
  reusable evidence.

## Alternatives considered

### Pinned verified copy — selected

Install a byte-for-byte verified copy and update it only through a deployment
transaction. This prevents unfinished repository edits from changing every
Codex task and gives rollback a precise previous version.

### Symlink to the repository — rejected

A symlink would make uncommitted or partially tested repository changes live
immediately. It also makes the installed identity depend on mutable path
resolution rather than a closed manifest.

### Global availability without a trigger — rejected

This is safer than a symlink but leaves RSI mostly unused and fails to collect
evidence from normal skill-driven work.

## Source and installed package identity

The repository is the only source of releases. Deployment accepts a clean Git
commit and the source directory `recursive-self-improvement`. It rejects a
dirty source tree, symlinks, special files, unsafe permissions, untracked files
inside the package, invalid JSON/YAML, an invalid skill package, a non-`observe`
default profile, or a non-empty production allowlist.

The installed release is a regular-file-only tree owned by the current user.
Directories use mode `0700`; files use `0600`, except repository-declared
executables, which retain `0700`. The installer never follows a destination
symlink and rejects hard-linked, group-writable, or world-writable installed
members.

The manifest is canonical UTF-8 JSON with sorted keys and one final LF. Its
closed schema contains:

- `schemaVersion = 1`;
- `domain = "rsi-global-observe-deployment-v1"`;
- source repository canonical path and exact commit;
- package relative path;
- deployment mode `observe` and hook mode `late-review`;
- production allowlist digest and assertion that its entry count is zero;
- ordered file entries containing relative path, byte length, executable bit,
  and SHA-256 digest;
- aggregate source-tree and installed-tree digests;
- managed global-instruction block digest;
- installation timestamp;
- deployment operation ID.

The manifest is stored inside the installed release and in the deployment
receipt directory. The installed copy is authoritative only when both copies
match and a fresh descriptor-relative scan reproduces every entry and digest.

Deployment state lives under `~/.codex/rsi-deployments-v1`: `lock` is the
single deployment lock; `receipts/<operation-id>.json` contains immutable
marker-last receipts; and `backups/<tree-digest>/` contains immutable package,
manifest, and exact global-instruction bytes. These paths are constructor-fixed
and cannot be supplied by a caller or environment variable in live mode. Tests
use an explicitly injected temporary Codex home and never redirect a live
deployment through ambient environment variables.

## Global trigger contract

The deployer manages one exactly delimited block in `~/.codex/AGENTS.md`. Text
outside the block belongs to the user and must remain byte-identical. A missing
file is created privately; an existing file must be a current-user-owned,
single-link regular file with safe permissions.

The exact managed block is:

```markdown
<!-- BEGIN RSI GLOBAL OBSERVE V1 — managed by RSI deployer -->
## Global RSI observe review

After the main task is complete and verified, use the installed
`recursive-self-improvement` skill in `observe` + `late-review` only when a
skill was used or the task produced a directly verified, sanitized, reusable
finding. Skip ordinary conversation, status questions, one-off facts, tasks
without reusable evidence, and RSI/skill-learning deployment or maintenance.
Pass only final sanitized artifacts; never pass raw dialogue, rejected
evidence, secrets, credentials, PII, or production target bytes. Global review
is read-only: do not enable promotion, change a target, expand an allowlist, or
weaken a safeguard. Set `CODEX_RSI_TRIGGER_ACTIVE=1` for the invocation and do
not invoke RSI again while that guard is present. If RSI is unavailable or
fails, report a bounded diagnostic without changing the completed task result.
<!-- END RSI GLOBAL OBSERVE V1 — managed by RSI deployer -->
```

The block instructs future Codex tasks to perform RSI late review only after
the main task is complete and verified, and only when at least one condition is
true:

1. a named or automatically selected skill was used; or
2. the task produced a directly verified, sanitized, reusable finding that
   would materially prevent future errors or save work.

The trigger skips:

- ordinary conversation and status questions;
- one-off facts or task-specific observations;
- tasks with no reusable evidence;
- RSI deployment, verification, rollback, health-check, and recovery tasks;
- skill-evolver routing, capture, review, and resolution operations performed
  solely to service that same RSI invocation;
- any nested invocation already carrying the deployment's recursion guard.

The recursion guard is exactly `CODEX_RSI_TRIGGER_ACTIVE=1`. It applies only to
the post-task RSI invocation and is removed from any child environment that is
not part of that invocation. Any other value is invalid and causes the nested
review to be skipped fail-closed.

The trigger passes only final sanitized artifacts and bounded identifiers. It
must not pass raw dialogue, rejected evidence, secrets, credentials, PII, or
production target bytes. Failure of RSI must be reported but must not retroactively
change the result of the completed main task.

The invoked package must use the installed `profiles/default.json`; environment
or project overlays may tighten it but cannot enable promotion, add allowlist
entries, change `late-review`, or weaken sanitization and storage safeguards.

## Deployment transaction

Deployment is serialized by a private current-user lock outside the installed
tree. The tool supports `plan`, `deploy`, `verify`, `rollback`, and `status`.

`plan` performs all source, destination, global-instruction, package, profile,
and manifest checks without writing.

`deploy` follows this order:

1. acquire the deployment lock with a bounded deadline;
2. repeat every source and destination identity check;
3. build a private staging tree on the same filesystem as the destination;
4. write and fsync every file and directory;
5. validate and rescan the staging tree;
6. create a content-addressed backup of the current valid installation and the
   exact pre-deployment global instruction file, if present;
7. publish the staged package with an atomic same-parent rename;
8. update the managed instruction block through a private temporary file,
   fsync, no-replace/replace publication, parent fsync, and readback;
9. verify both installed manifest copies, the installed tree, and the managed
   block;
10. publish the deployment receipt last.

If failure occurs before publication, staging is cleaned only when its inode
identity is still exact. If package publication succeeds but the managed block
cannot be published or verified, the tool restores the exact prior package and
instruction bytes before returning failure. If state becomes ambiguous, it
preserves evidence, reports recovery instructions, and performs no guessed
overwrite.

Updates are idempotent: the same operation and request return the existing
verified receipt; a reused operation ID with different input conflicts. A
byte-identical current deployment performs no replacement.

## Rollback

Rollback accepts an exact deployment receipt or the immediately preceding
verified receipt. It validates the selected backup manifest and every backup
byte before changing active state. It then uses the same staging, atomic
publication, fsync, and readback protocol as deploy.

Rollback restores both the package and the exact pre-deployment global
instruction file. It never reconstructs or normalizes user-owned text. Missing,
drifted, or ambiguous backups fail closed and leave the current active version
unchanged.

## Health check and runtime observation

`verify` and `status` are read-only. They open existing objects without mkdir,
chmod, repair, cache creation, bytecode generation, or tolerant parsing. They
check package identity, manifest equality, file hashes and modes, profile
defaults, empty allowlist, managed-block digest, package validation, and the
availability of the RSI entry point.

The rollout dry run uses fresh temporary `CODEX_RSI_HOME` and learning-provider
homes. It simulates:

- a qualifying skill-driven task with one sanitized reusable finding;
- a qualifying skill-driven task with no reusable finding;
- ordinary conversation;
- a deployment/RSI maintenance task;
- a finding containing a secret, PII, or instruction-bearing evidence.

Only the qualifying safe cases may create RSI evidence. No dry-run case may
write the live provider ledger, installed source, global instructions,
repository, or a production target.

## Failure behavior

All deployment and runtime checks fail closed. Specifically:

- invalid package or profile: no installation write;
- source drift during staging: discard exact staging and keep active version;
- destination or `AGENTS.md` identity drift: no overwrite;
- partial package or instruction publication: exact rollback or preserved
  ambiguous evidence;
- installed hash drift: health check fails and RSI trigger is treated as
  unavailable;
- invalid live learning ledger: report and skip RSI recording;
- rejected or sensitive evidence: no raw bytes, hashes, sidecars, or events are
  persisted;
- recursion-guard conflict: skip the nested invocation and report one bounded
  diagnostic.

## Testing and review

Implementation follows strict TDD in an isolated worktree. Required tests
include:

- canonical manifest golden bytes and strict parser rejection;
- source and installed tree identity, permissions, symlink, hard-link, and
  digest checks;
- idempotent deploy/update and exact operation conflict;
- rollback of package and byte-identical user instruction text;
- injected failure at every file write, fsync, rename, directory fsync,
  readback, and receipt boundary;
- concurrent deploy, update, verify, and rollback attempts;
- trigger and no-trigger cases, including recursion suppression;
- zero-write syscall/file-tree assertions for `plan`, `verify`, `status`, and
  dry-run non-qualifying cases;
- secret, PII, prompt-injection, path, encoding, and Unicode regression corpus;
- full RSI suite twice before deployment and once after installation;
- package validator, JSON/YAML/link/permission checks;
- independent spec and implementation review with no open P0, P1, or P2.

The live installation occurs only after the implementation commit, full tests,
and independent review are green. The deployment is then verified from a new
process, and a new Codex task must discover the skill before rollout is called
complete.

## Acceptance criteria

The rollout is complete only when:

1. `~/.codex/skills/recursive-self-improvement` is a verified pinned copy of an
   exact repository commit;
2. the deployment manifest and receipt reproduce the installed bytes;
3. the managed `AGENTS.md` block is present exactly once and preserves all
   surrounding bytes;
4. defaults remain `observe + late-review` and the production allowlist remains
   empty;
5. qualifying temporary-task drills create only expected sanitized RSI state;
6. non-qualifying and recursive drills create no RSI state;
7. production targets and the live provider ledger remain byte-identical;
8. rollback to the prior state is proven in an isolated home;
9. the full test and validator matrix is green;
10. an independent reviewer reports no P0, P1, or P2; and
11. the repository changes are merged to `master`, pushed, and the worktree is
    cleaned.
