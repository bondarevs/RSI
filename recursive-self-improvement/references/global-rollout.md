# Global RSI observe rollout

Read this reference before planning, installing, updating, checking, or rolling
back the global RSI package. This is a Stage 0/1 availability rollout. It makes
one pinned package discoverable by future Codex tasks and installs a bounded
post-task review instruction. It does not enable `promote-candidate`, populate
the production allowlist, install a privileged namespace-mutation coordinator,
or authorize a production target write.

## Fixed safety contract

The following machine-readable block summarizes the shipped contract. The
paths are fixed by the deployer from the current user's account; command-line
options and environment variables cannot redirect them.

```rsi-rollout-contract
{
  "schemaVersion": 1,
  "stage": "0/1",
  "defaults": {
    "mode": "observe",
    "hookMode": "late-review",
    "productionAllowlist": []
  },
  "capabilities": {
    "promotionEnabled": false,
    "privilegedCoordinatorInstalled": false
  },
  "paths": {
    "installedPackage": "~/.codex/skills/recursive-self-improvement",
    "globalInstructions": "~/.codex/AGENTS.md",
    "deploymentState": "~/.codex/rsi-deployments-v1",
    "lock": "~/.codex/rsi-deployments-v1/lock",
    "activeAuthority": "~/.codex/rsi-deployments-v1/active.json",
    "receiptManifest": "~/.codex/rsi-deployments-v1/receipts/<operation-id>.manifest.json",
    "receipt": "~/.codex/rsi-deployments-v1/receipts/<operation-id>.json",
    "backup": "~/.codex/rsi-deployments-v1/backups/<backup-digest>/"
  },
  "trigger": {
    "newCodexTaskRequiredAfterInstall": true,
    "recursionGuard": "CODEX_RSI_TRIGGER_ACTIVE=1",
    "qualifies": [
      "skill-used",
      "directly-verified-sanitized-reusable-finding"
    ],
    "skips": [
      "ordinary-conversation",
      "status-question",
      "one-off-fact",
      "no-reusable-evidence",
      "rsi-or-skill-learning-maintenance",
      "recursive-invocation"
    ]
  },
  "recovery": {
    "invalidSource": "repair-or-commit-source-then-rerun-plan",
    "installedDrift": "stop-trigger-and-preserve-bytes",
    "instructionDrift": "restore-exact-managed-block-or-use-verified-rollback",
    "failedReverseExchange": "preserve-evidence-and-escalate-ambiguous",
    "ambiguousState": "do-not-retry-or-overwrite;preserve-and-investigate"
  }
}
```

The installed tree also contains
`.rsi-deployment-manifest.json`. Its bytes must equal
`~/.codex/rsi-deployments-v1/receipts/<operation-id>.manifest.json`. The
marker-last receipt at
`~/.codex/rsi-deployments-v1/receipts/<operation-id>.json` binds the exact
manifest digest and byte length. The manifest excludes itself from file and
tree digests to keep the graph acyclic. Immutable request and authority objects
and the active pointer complete the authority chain. A backup digest binds both
the prior package state and the exact prior `AGENTS.md` state, bytes, length,
and mode; it is not merely a package-tree digest.

## Operator commands

Run mutation commands from the clean repository root. Use a stable lowercase
operation ID containing only letters, digits, `_`, and `-`. These are the exact
accepted command forms; `verify` and `status` accept no options, and there is no
live `--codex-home` override.

```console
python3 recursive-self-improvement/scripts/rsi_deploy.py plan --source-repo /absolute/repository
python3 recursive-self-improvement/scripts/rsi_deploy.py deploy --source-repo /absolute/repository --operation-id global-observe-v1
python3 recursive-self-improvement/scripts/rsi_deploy.py verify
python3 recursive-self-improvement/scripts/rsi_deploy.py status
python3 recursive-self-improvement/scripts/rsi_deploy.py rollback --receipt-id global-observe-v1 --operation-id rollback-global-observe-v1
```

`plan` revalidates the clean exact Git commit, tracked package membership,
package bytes and modes, JSON/YAML, skill validator, default profile, empty
production allowlist, destination, and managed instructions without writing.
Its action is `install`, `update`, or `no-op`.

`deploy` repeats admission after it acquires the private bounded lock. Initial
installation uses private same-filesystem staging and marker-last authority.
An update first verifies and backs up the active version, then uses Darwin's
atomic directory exchange. Replaying the same operation and request returns the
same receipt; reusing an operation ID for different input is a conflict. A
byte-identical new request returns the already active verified receipt without
replacing the package.

`verify` and `status` are read-only. Both validate the authority pointer,
receipt and manifest copies, installed tree bytes and modes, profile defaults,
empty allowlist, managed block, and installed entry point. `verify` is the
release gate; `status` provides the same integrity result for routine health
checks. Neither command creates a directory, repairs a file, changes a mode,
writes bytecode, or records RSI/provider state.

`rollback` accepts the active receipt or the immediately preceding verified
receipt. It validates every backup byte and semantic package constraint before
an atomic exchange. It restores the exact prior package and exact prior
`AGENTS.md` bytes/mode, including an originally absent package or instruction
file. It never reconstructs user-owned text.

The deployment CLI returns canonical JSON and uses process code `0` for a
complete result, `2` for invalid input/source, `3` for not installed, `4` for
operation or lock conflict, `5` for integrity failure, `6` for an unavailable
atomic backend, and `9` for ambiguous state. Do not translate a nonzero result
to success or retry under a new operation ID without resolving its cause.

## Managed trigger

The deployer owns exactly this block and preserves all surrounding
`~/.codex/AGENTS.md` bytes and the safe existing mode:

```rsi-managed-block
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

Only a successful completed task qualifies, and only when it used a skill or
produced a directly verified, sanitized, reusable finding. A qualifying skill
task with no reusable finding may run the bounded late review but must not
invent one. Ordinary conversation, status questions, one-off facts, failed
tasks, missing final artifacts, RSI/skill-learning maintenance, sensitive or
instruction-bearing evidence, and any nested invocation are skipped. The
invocation receives only final sanitized artifacts and the exact guard
`CODEX_RSI_TRIGGER_ACTIVE=1`; any other present guard value fails closed.

Installation does not alter the catalog of an already running Codex task.
After a successful install or update, start a new Codex task to verify that the
installed `recursive-self-improvement` skill is discoverable. A dry run must
use a fresh temporary RSI/provider home and must leave the repository,
installed package, global instructions, live provider ledger, and all target
roots byte-identical.

## Recovery

Never edit receipts, manifests, backups, authorities, or the active pointer to
make a check pass. Never delete an unexplained temporary inode.

- Invalid source: keep the active deployment unchanged. Repair or deliberately
  commit the source, make the worktree exactly clean, and rerun `plan` before
  `deploy`.
- Installed drift: stop treating the global trigger as available. Preserve the
  installed bytes and deployment state, inspect with `verify`, and choose only
  a clean verified redeploy or a verified rollback.
- Instruction drift: preserve the user-owned prefix and suffix. Restore the
  exact managed block only from a verified source, or use rollback when its
  backup validates; do not normalize or reconstruct the complete file.
- Failed reverse exchange: if an update failure cannot prove the old package
  and instruction bytes were restored, preserve both operands and all
  transaction evidence. Treat the state as ambiguous.
- Ambiguous state: stop mutation, record only bounded metadata, and investigate
  the retained identities. Do not retry, overwrite, repair, or guess which
  version is authoritative. Resume only after exact byte, inode, manifest,
  receipt, authority, and backup validation establishes one safe action.

An unsupported non-Darwin atomic backend fails before deployment-state writes.
Global observe review remains unavailable until `verify` reports a fully
verified installation. Promotion, a non-empty production allowlist, and a
privileged mutation coordinator are separate later stages with separate
attestation and review.
