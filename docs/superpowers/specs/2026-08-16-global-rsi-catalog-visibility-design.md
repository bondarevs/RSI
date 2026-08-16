# Global RSI Catalog Visibility Design Addendum

## Status

Draft for written review. The design direction was approved on 2026-08-16, but
implementation is not authorized until this exact document is reviewed and
approved. The live global RSI installation remains rolled back and inactive.

This addendum narrows and amends one requirement of the approved
`2026-08-13-global-rsi-observe-rollout-design.md`: the installed skill's
`agents/openai.yaml` must use `policy.allow_implicit_invocation: true` instead
of `false`. All other rollout safety boundaries remain normative.

## Problem statement

The rollout implementation, deployment transaction, protected-root witness,
and observe-only dry run all passed their release checks. A subsequent fresh
Codex catalog check showed that the installed `recursive-self-improvement`
skill was not model-visible when `policy.allow_implicit_invocation` was
`false`.

The result was reproduced in fresh isolated Codex CLI processes using versions
0.143 and 0.147. It also reproduced when the prompt explicitly named
`$recursive-self-improvement`: prompt-input diagnostics contained the managed
global instruction but no RSI skill metadata or full skill instructions.
Consequently, the global trigger could describe when RSI should run, but the
model could not load the installed skill that implements the review.

OpenAI's published `openai.yaml` reference describes
`allow_implicit_invocation: false` as disabling implicit invocation while
preserving explicit `$skill` invocation. The observed CLI behavior does not
match that contract. The mismatch is tracked publicly in Codex issue reports,
but the rollout cannot depend on an unfixed client behavior:

- <https://github.com/openai/codex/blob/main/codex-rs/skills/src/assets/samples/skill-creator/references/openai_yaml.md>
- <https://github.com/openai/codex/issues/23454>
- <https://github.com/openai/codex/issues/15136>

The failed activation was rolled back through the verified deployment receipt.
The exact pre-deployment global instructions were restored, the provider ledger
and production targets were unchanged, and the immutable deployment history was
retained for audit and recovery.

Independent review then established that `debug prompt-input` is not
filesystem-read-only with respect to its active `CODEX_HOME`: both the installed
client and a published client synchronize `skills/.system`. Therefore neither
client may run with the live Codex home during a visibility probe. The safe
probe projects only the two verified catalog inputs into per-client disposable
homes and witnesses every live authority before and after the clients run.
Those inputs are opened without following links during deployment attestation,
matched to the active manifest, and retained by descriptor; projection writes
only those attested bytes and never reopens an installed catalog pathname.
Resolver and client processes run in new process groups with bounded streaming
capture and TERM-to-KILL cleanup. Post-client deployment and live-witness
comparisons run independently even if either raises, including timeout, output,
resolver, and client failure paths; bounded failure evidence preserves
primary/status/witness order while observed drift has precedence. Disposable
homes fail closed on RSI/provider/deployment state, including exact
`skill-learning` provider-root aliases and state locks, outside the exact
catalog projection and client-owned `skills/.system` subtree. Their recursive
inventory and path classification are bounded.
Skills and target trees use the bounded nofollow protected-tree witness so
supported symlink and special-file topology is witnessed rather than rejected.

## Decision

Set the installed package policy to:

```yaml
policy:
  allow_implicit_invocation: true
```

This is a catalog-visibility change, not an RSI mutation-authority change. It
makes the skill metadata available to the model so that a qualifying completed
task can follow the managed global trigger. It does not authorize RSI to run on
every task and does not relax any runtime safeguard.

The following invariants remain exact:

- the effective mode is `observe`;
- the hook mode is `late-review`;
- the production target allowlist is empty;
- production promotion is disabled;
- no privileged namespace-mutation coordinator is installed or enabled;
- no production target may be changed;
- raw dialogue, rejected evidence, secrets, credentials, PII, and production
  target bytes are excluded from the review input;
- the recursion guard is exactly `CODEX_RSI_TRIGGER_ACTIVE=1`;
- RSI failure produces a bounded diagnostic and never changes the already
  completed main-task result.

`allow_implicit_invocation: true` permits Codex to consider the skill for model
selection. The closed managed `AGENTS.md` trigger remains the policy that
decides whether global late review is appropriate. The skill description and
runtime checks must agree with that trigger and must not imply that ordinary
conversation, status questions, one-off facts, tasks without reusable evidence,
or RSI/skill-learning maintenance qualify.

## Alternatives

### Enable catalog visibility — selected

Use the supported policy field to make RSI model-visible, then retain safety at
the trigger, profile, allowlist, runtime, storage, and deployment layers. This
is the smallest change that makes the intended automatic post-task review
functional on the observed Codex clients.

### Add a companion trigger skill — rejected

A second always-visible skill could explicitly load RSI, but it would create
another installed package, another release identity, and another policy surface.
It would duplicate the trigger contract and complicate rollback and verification.

### Keep implicit invocation disabled — rejected

This preserves the original metadata setting but leaves global RSI unavailable
on the current clients, including for explicit `$recursive-self-improvement`
requests. It therefore cannot satisfy the rollout objective.

## Authority and data flow

The expected post-change flow is:

1. A fresh Codex task loads the installed RSI metadata into its model-visible
   skill catalog.
2. The managed global instruction evaluates the closed trigger matrix only
   after the main task is complete and verified.
3. Non-qualifying tasks stop without invoking RSI or creating RSI state.
4. A qualifying task invokes the verified installed package with the recursion
   guard and final sanitized artifacts only.
5. RSI performs `observe + late-review` in its admitted local/provider evidence
   stores. It cannot promote, mutate a target, add an allowlist entry, or claim
   privileged coordination.
6. A successful review reports its bounded result. An unavailable or failed
   review reports a bounded diagnostic without altering the completed task.

Catalog visibility is not evidence of deployment authority. Before invocation,
the existing deployment verifier must still bind the installed manifest,
receipt, tree, active authority, source commit, profile, allowlist, and managed
instruction block. The installed entry point must continue to execute only from
the FD-pinned verified snapshot.

## Package and documentation changes

Implementation must update only the surfaces that encode or verify the catalog
policy:

- `recursive-self-improvement/agents/openai.yaml`;
- the FD-attested `scripts/rsi_catalog_probe.py` entry point and its isolated
  catalog-projection implementation;
- the package contract and release-forward tests that currently require
  `allow_implicit_invocation: false`;
- the global rollout reference and any architecture/lifecycle wording that
  describes discovery or invocation;
- an exact-byte packaged mirror of this addendum so installed references do not
  escape the deployed package;
- the release evidence/report and versioned implementation plan.

The implementation must not change the default profile, production allowlist,
promotion gates, target mutation paths, provider writer authority, or recursion
guard. Any diff outside the catalog-policy contract requires a new design
review.

## Verification contract

Implementation is acceptable only when all of the following are independently
verified:

1. Package parsing and validation require the exact boolean value
   `allow_implicit_invocation: true`; strings, integers, missing keys, duplicate
   keys, and extra policy keys fail closed.
2. A fresh installed-package fixture exposes `recursive-self-improvement` in
   the model-visible Codex skill catalog without invoking it.
3. The FD-attested installed probe verifies the live deployment, copies only
   its exact `SKILL.md` and `agents/openai.yaml` bytes into a distinct disposable
   `CODEX_HOME` per client, and runs both the installed local Codex and the exact
   version first resolved from `@openai/codex@latest`. Neither client receives
   the live `CODEX_HOME`. Each result records its client version, exactly one
   model-visible row, the projected locator, the verified live locator and
   catalog-surface digest that bind the projection, and absence of the skill
   body. Both inputs remain bound by nofollow descriptors to active manifest
   entries throughout projection; no installed pathname is reopened. Resolver
   and client output is bounded in flight, every process group is reaped after
   timeout, output excess, failure, or lingering-child detection, and the final
   deployment-status and live-witness comparisons each run independently even
   when the other raises. Bounded failure aggregation preserves all three
   primary/status/witness errors without masking observed drift. Latest-client
   resolution or execution failure keeps the gate closed with its exact
   stage/version error.
4. The qualifying safe and qualifying no-finding cases still invoke only the
   verified installed snapshot in `observe + late-review`.
5. Ordinary conversation, status questions, one-off facts, tasks without
   reusable evidence, sensitive/rejected inputs, deployment maintenance, and
   recursive invocation remain skipped and create no RSI state.
6. The production allowlist remains exactly empty and promotion/target mutation
   spies remain at zero calls.
7. The full package, deployment, rollout, forward, adversarial, and repository
   test suite passes; the local/latest real-client mutation regression proves
   `.system` synchronization is confined to disposable homes, no disposable
   RSI/provider state (including `skill-learning` roots/locks and aliases)
   remains, bounded recursive inventory does not overrun, and supported
   protected-tree symlink/special topology is stable but drift-sensitive; and
   the skill
   validator, learning-ledger validator, installed-layout link, permission,
   unfinished-marker, compile, and diff checks pass.
8. A fresh independent security/spec review approves the exact implementation
   commit before live activation.

The catalog probe must distinguish visibility from invocation. Seeing skill
metadata is required; creating provider events, RSI state, or target writes
during the visibility-only probe is a failure. Client synchronization inside a
disposable projection is expected and discarded, but any live skill,
deployment, global-instruction, provider, target, or source witness drift fails
the probe.

## Deployment and rollback

The live system remains rolled back until implementation and independent review
are complete. Activation then uses the existing transactional deployer from one
clean, exact repository commit with a new deterministic operation ID.

Before deployment, record read-only witnesses for the current global
instructions, provider source, provider ledger, deployment state, and protected
targets. After deployment:

1. verify the installed receipt, manifest, tree, active authority, managed
   instruction block, profile, and empty allowlist;
2. run the bounded observe-only dry-run matrix;
3. run the attested local/latest catalog-visibility probe with per-client
   disposable projected homes;
4. confirm the provider ledger and every production target witness are
   unchanged.

If installation, dry run, catalog visibility, or post-deployment witnesses fail,
rollback through the exact deployment receipt. Rollback must restore the prior
installed/absent package state and the exact prior global-instruction bytes. It
must preserve immutable receipts and evidence and must not attempt a guessed
repair. Unexpected RSI invocation, unexpected state creation, promotion access,
or target mutation is an immediate rollback condition.

## Completion criteria

This addendum is complete only when:

- its implementation plan is separately reviewed;
- the catalog-policy change is implemented test-first;
- all verification-contract checks pass on the exact commit;
- an independent final review approves it;
- the live transactional deployment and fresh catalog probe pass;
- global RSI is reported active only after those live checks;
- `master` and the remote branch contain the approved exact commit; and
- temporary rollout branches/worktrees are cleaned without deleting user-owned
  untracked data.
