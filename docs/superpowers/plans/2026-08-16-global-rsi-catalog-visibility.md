# Global RSI Catalog Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the verified global RSI skill model-visible in fresh Codex tasks while retaining the exact Stage 0/1 `observe + late-review`, empty-allowlist, no-promotion safety boundary.

**Architecture:** Tighten the existing deployment document admission so `agents/openai.yaml` is a closed, exact authority requiring `allow_implicit_invocation: true`, then prove visibility with a fresh read-only `codex debug prompt-input` fixture that distinguishes catalog metadata from skill invocation. Update the release contract and operator documentation, pass independent review, and activate only through the existing transactional deploy/verify/rollback chain.

**Tech Stack:** Python 3.12+, pytest, Hypothesis, canonical JSON, strict mapping-only YAML parser, Git, Codex CLI `debug prompt-input`, existing RSI transactional deployment and dry-run APIs.

## Global Constraints

- The normative addendum is `docs/superpowers/specs/2026-08-16-global-rsi-catalog-visibility-design.md`; the original `2026-08-13` rollout design remains normative except for its superseded `allow_implicit_invocation: false` requirement.
- The live RSI installation remains rolled back and inactive until every task, full-suite gate, and independent review is complete.
- The effective mode remains exactly `observe`; the hook mode remains exactly `late-review`.
- The production target allowlist remains exactly empty.
- Production promotion, privileged namespace mutation, provider CLI mutation, and production target writes remain forbidden.
- Catalog visibility is not invocation authority and is not deployment authority.
- The managed trigger continues to skip ordinary conversation, status questions, one-off facts, tasks without reusable evidence, sensitive or rejected evidence, RSI/skill-learning maintenance, and recursive invocation.
- The recursion guard remains exactly `CODEX_RSI_TRIGGER_ACTIVE=1`.
- Visibility probes are read-only: they may render model input but must not execute RSI, call a provider writer, or create RSI state.
- All code changes follow RED → GREEN → relevant regression → full-suite verification and are committed separately from review fixes.
- Stop after each task's tests, review, report, and commit are complete; do not begin the next task with a provisional failure or open finding.
- Preserve the existing untracked `uv.lock` and `__pycache__` directories; never stage or delete them as part of this plan.

---

### Task 1: Require the exact catalog-visible package policy

**Files:**
- Modify: `recursive-self-improvement/agents/openai.yaml:1-6`
- Modify: `recursive-self-improvement/scripts/rsi_core/deployment.py:3034-3160`
- Modify: `recursive-self-improvement/tests/test_global_deployment.py:55-90`
- Modify: `recursive-self-improvement/tests/test_global_deployment.py:2390-2470`
- Modify: `recursive-self-improvement/tests/test_package_contract.py:25-38`
- Modify: `recursive-self-improvement/tests/test_forward.py:700-725`

**Interfaces:**
- Consumes: `_strict_yaml(payload: bytes, *, label: str) -> object` and `_validate_package_documents(package: Path, snapshot: PackageSnapshot) -> str` from `rsi_core.deployment`.
- Produces: `_validate_agent_metadata(value: object) -> None`, called for source plan/deploy, installed verify, and rollback-backup admission through `_validate_package_documents`.
- Produces: an exact shipped metadata mapping with top-level keys `interface` and `policy`, exact three-key `interface`, and exact `policy={"allow_implicit_invocation": True}`.

- [ ] **Step 1: Add failing package and deployment tests before changing production**

Update the repository fixture in `test_global_deployment.py` so every otherwise-valid fixture writes the complete intended metadata:

```python
OPENAI_METADATA = (
    'interface:\n'
    '  display_name: "Recursive Self-Improvement"\n'
    '  short_description: "Safely improve role-skills from evidence"\n'
    '  default_prompt: "Use $recursive-self-improvement in the default observe-only late-review mode to evaluate this completed skill-driven task without changing its target."\n'
    'policy:\n'
    '  allow_implicit_invocation: true\n'
)
```

Add a parameterized test that commits each malformed arm to a temporary source repository and proves `GlobalRsiDeployer.plan()` raises `DeploymentSourceError` without creating the temporary Codex home:

```python
@pytest.mark.parametrize(
    "metadata",
    [
        OPENAI_METADATA.replace("true", "false"),
        OPENAI_METADATA.replace("true", '"true"'),
        OPENAI_METADATA.replace("true", "1"),
        OPENAI_METADATA.replace("  allow_implicit_invocation: true\n", ""),
        OPENAI_METADATA.replace(
            "  allow_implicit_invocation: true\n",
            "  allow_implicit_invocation: true\n  extra: false\n",
        ),
        OPENAI_METADATA + "extra: true\n",
        OPENAI_METADATA.replace("  display_name:", "  wrong_name:"),
    ],
)
def test_source_admission_requires_exact_catalog_visibility_policy(
    tmp_path: Path, metadata: str
) -> None:
    repo = _write_repository(tmp_path)
    package = repo / "recursive-self-improvement"
    (package / "agents/openai.yaml").write_text(metadata, encoding="utf-8")
    _git(repo, "add", "recursive-self-improvement/agents/openai.yaml")
    _git(repo, "commit", "-q", "-m", "catalog-policy")
    codex_home = tmp_path / "codex-home"

    with pytest.raises(deployment_module.DeploymentSourceError):
        GlobalRsiDeployer(DeploymentPaths.for_testing(codex_home)).plan(repo)

    assert not codex_home.exists()
```

Rename `test_implicit_invocation_is_disabled` to
`test_catalog_visibility_policy_is_exactly_enabled`, parse the tiny YAML mapping
instead of using a substring assertion, and require a real boolean `True`.
Change the forward release expectation to:

```python
assert metadata["policy"] == {"allow_implicit_invocation": True}
```

- [ ] **Step 2: Run the focused tests and record authoritative RED**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q --tb=short \
  recursive-self-improvement/tests/test_global_deployment.py \
  recursive-self-improvement/tests/test_package_contract.py \
  recursive-self-improvement/tests/test_forward.py \
  -k 'catalog_visibility_policy or implicit_invocation or release_package_links'
```

Expected: the false/string/integer/missing/extra metadata arms are admitted by
the current deployment validator, and the real package assertions fail because
the shipped value is still `false`. Existing unrelated controls remain green.

- [ ] **Step 3: Add exact semantic validation to deployment admission**

Retain parsed YAML mappings in `_validate_package_documents` and add this
closed validator adjacent to `_strict_yaml`:

```python
_EXPECTED_AGENT_INTERFACE = {
    "display_name": "Recursive Self-Improvement",
    "short_description": "Safely improve role-skills from evidence",
    "default_prompt": (
        "Use $recursive-self-improvement in the default observe-only "
        "late-review mode to evaluate this completed skill-driven task "
        "without changing its target."
    ),
}


def _validate_agent_metadata(value: object) -> None:
    if type(value) is not dict or set(value) != {"interface", "policy"}:
        raise DeploymentSourceError("agent metadata has an invalid top-level schema")
    interface = value["interface"]
    policy = value["policy"]
    if type(interface) is not dict or interface != _EXPECTED_AGENT_INTERFACE:
        raise DeploymentSourceError("agent metadata interface is not exact")
    if type(policy) is not dict or set(policy) != {"allow_implicit_invocation"}:
        raise DeploymentSourceError("agent metadata policy is not exact")
    if policy["allow_implicit_invocation"] is not True:
        raise DeploymentSourceError("agent metadata catalog visibility is not enabled")
```

Change the YAML branch in `_validate_package_documents` from discard-on-parse
to `parsed_yaml[entry.relative_path] = _strict_yaml(...)`, then require:

```python
_validate_agent_metadata(parsed_yaml.get("agents/openai.yaml"))
```

This existing call path must enforce the same metadata while planning,
deploying, verifying an installed package, admitting an update, and validating
a rollback backup. Do not add a caller override or environment-variable arm.

- [ ] **Step 4: Flip the shipped catalog policy**

Change only the final policy scalar in `agents/openai.yaml`:

```yaml
policy:
  allow_implicit_invocation: true
```

Do not change `default_prompt`, profiles, allowlists, promotion code, provider
authority, global instructions, or target mutation paths in this task.

- [ ] **Step 5: Run focused GREEN and semantic regression tests**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q --tb=short \
  recursive-self-improvement/tests/test_global_deployment.py \
  recursive-self-improvement/tests/test_package_contract.py \
  recursive-self-improvement/tests/test_forward.py \
  -k 'catalog_visibility_policy or source_admission or semantic_profile or release_package_links'
```

Expected: all selected tests pass. Confirm the malformed-policy matrix reports
bounded `DeploymentSourceError`, leaves the temporary Codex home absent, and
does not fall through to a later quick-validator failure.

- [ ] **Step 6: Run Task 1 regression gate**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q --tb=short \
  recursive-self-improvement/tests/test_deployment_schema.py \
  recursive-self-improvement/tests/test_deployment_fs.py \
  recursive-self-improvement/tests/test_global_deployment.py \
  recursive-self-improvement/tests/test_package_contract.py \
  recursive-self-improvement/tests/test_forward.py
python3 ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py \
  recursive-self-improvement
git diff --check
```

Expected: all tests and the package validator pass, and diff-check is silent.

- [ ] **Step 7: Commit Task 1 and stop at its review gate**

```bash
git add \
  recursive-self-improvement/agents/openai.yaml \
  recursive-self-improvement/scripts/rsi_core/deployment.py \
  recursive-self-improvement/tests/test_global_deployment.py \
  recursive-self-improvement/tests/test_package_contract.py \
  recursive-self-improvement/tests/test_forward.py
git commit -m "feat: require global RSI catalog visibility"
```

Record RED/GREEN commands, counts, exact commit, and untouched live-state
assertion in the versioned rollout report. Do not start Task 2 until Task 1 has
no open review finding.

---

### Task 2: Prove fresh Codex catalog visibility without invocation

**Files:**
- Create: `recursive-self-improvement/tests/test_catalog_visibility.py`
- Modify: `recursive-self-improvement/tests/test_package_contract.py:1-45`
- Modify: `recursive-self-improvement/tests/test_forward.py:700-725`

**Interfaces:**
- Consumes: the exact shipped `agents/openai.yaml`, `SKILL.md`, and the host `codex debug prompt-input [PROMPT]` read-only command.
- Produces: `_render_fresh_catalog(package_root: Path, tmp_path: Path) -> tuple[str, Path]`, a test-only bounded fresh-Codex fixture.
- Produces: a regression proving the model-visible catalog contains RSI metadata while the RSI skill body is not invoked or injected.

- [ ] **Step 1: Write the fresh-process catalog test**

Create `test_catalog_visibility.py` with a host-Codex availability guard and the
following bounded fixture shape:

```python
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CODEX = shutil.which("codex")


def _render_fresh_catalog(package_root: Path, tmp_path: Path) -> tuple[str, Path]:
    assert CODEX is not None
    codex_home = tmp_path / "codex-home"
    installed = codex_home / "skills" / "recursive-self-improvement"
    (installed / "agents").mkdir(parents=True)
    shutil.copy2(package_root / "SKILL.md", installed / "SKILL.md")
    shutil.copy2(
        package_root / "agents/openai.yaml", installed / "agents/openai.yaml"
    )
    isolated_home = tmp_path / "isolated-home"
    isolated_home.mkdir()
    environment = {
        "CODEX_HOME": os.fspath(codex_home),
        "HOME": os.fspath(isolated_home),
        "PATH": os.environ["PATH"],
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
    }
    completed = subprocess.run(
        [
            CODEX,
            "debug",
            "prompt-input",
            (
                "Report only whether the model-visible skill catalog contains "
                "recursive-self-improvement. Do not invoke any skill."
            ),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert type(payload) is list
    rendered = "\n".join(
        item["text"]
        for message in payload
        for item in message.get("content", [])
        if item.get("type") == "input_text" and type(item.get("text")) is str
    )
    return rendered, codex_home


@pytest.mark.skipif(CODEX is None, reason="Codex CLI is unavailable")
def test_fresh_codex_catalog_lists_rsi_without_invoking_it(tmp_path: Path) -> None:
    rendered, codex_home = _render_fresh_catalog(PACKAGE_ROOT, tmp_path)

    assert "### Available skills" in rendered
    assert "- recursive-self-improvement:" in rendered
    assert os.fspath(
        codex_home / "skills/recursive-self-improvement/SKILL.md"
    ) in rendered
    assert "Operate as the control plane for evidence-backed role-skill improvement." not in rendered
    assert not (codex_home / "skill-learning").exists()
    assert not (codex_home / "rsi-deployments-v1").exists()
```

Add a companion negative control that copies the package, changes only the
temporary copy's policy to `false`, reruns the same command, and asserts the RSI
catalog line and RSI `SKILL.md` path are absent. The negative copy is test-only;
never modify the tracked source to construct it.

```python
@pytest.mark.skipif(CODEX is None, reason="Codex CLI is unavailable")
def test_disabled_policy_is_not_model_visible(tmp_path: Path) -> None:
    disabled = tmp_path / "disabled-package"
    (disabled / "agents").mkdir(parents=True)
    shutil.copy2(PACKAGE_ROOT / "SKILL.md", disabled / "SKILL.md")
    metadata = (PACKAGE_ROOT / "agents/openai.yaml").read_text(encoding="utf-8")
    assert metadata.count("allow_implicit_invocation: true") == 1
    (disabled / "agents/openai.yaml").write_text(
        metadata.replace(
            "allow_implicit_invocation: true",
            "allow_implicit_invocation: false",
        ),
        encoding="utf-8",
    )

    rendered, codex_home = _render_fresh_catalog(disabled, tmp_path / "run")

    assert "- recursive-self-improvement:" not in rendered
    assert os.fspath(
        codex_home / "skills/recursive-self-improvement/SKILL.md"
    ) not in rendered
```

- [ ] **Step 2: Demonstrate that the new test distinguishes the old policy**

Before relying on Task 1's source, run the negative control and prove it passes.
Then use `git show HEAD^:recursive-self-improvement/agents/openai.yaml` to create
an old-policy temporary fixture and run the positive assertion against it.

Expected: the old-policy fixture fails only the positive visibility assertion;
the current package passes it. Preserve this result in the Task 2 report without
recording prompt contents outside the public skill catalog metadata.

- [ ] **Step 3: Add a no-invocation and no-write oracle**

Snapshot the package tree and create protected sentinel files before the probe.
After `debug prompt-input`, require:

```python
assert _tree_snapshot(PACKAGE_ROOT) == package_before
assert protected.read_bytes() == b"protected-before\n"
assert not list(tmp_path.rglob("events.jsonl"))
assert not list(tmp_path.rglob("observations.jsonl"))
assert not list(tmp_path.rglob("reports.jsonl"))
```

Implement `_tree_snapshot` as a test-only deterministic tuple of relative path,
`lstat` mode, byte length, and SHA-256 for regular files. Do not follow symlinks
or read files outside `PACKAGE_ROOT`.

- [ ] **Step 4: Run focused catalog GREEN**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q --tb=short \
  recursive-self-improvement/tests/test_catalog_visibility.py \
  recursive-self-improvement/tests/test_package_contract.py \
  recursive-self-improvement/tests/test_forward.py \
  -k 'catalog or implicit_invocation or release_package_links'
```

Expected: positive, negative, non-invocation, and no-write assertions pass. A
skip is acceptable only on a host without a Codex binary; this rollout host
must execute, not skip, the positive test.

- [ ] **Step 5: Run Task 2 regression and repeatability gate**

Run the catalog test twice in fresh pytest processes:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q --tb=short \
  recursive-self-improvement/tests/test_catalog_visibility.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q --tb=short \
  recursive-self-improvement/tests/test_catalog_visibility.py
git diff --check
```

Expected: both passes expose the same skill name and installed path class, with
no provider/RSI state and no source-tree drift.

- [ ] **Step 6: Commit Task 2 and stop at its review gate**

```bash
git add \
  recursive-self-improvement/tests/test_catalog_visibility.py \
  recursive-self-improvement/tests/test_package_contract.py \
  recursive-self-improvement/tests/test_forward.py
git commit -m "test: prove global RSI catalog visibility"
```

If Task 1 already contains the final two modified test files with no Task 2
delta, stage only `test_catalog_visibility.py`; never manufacture a meaningless
diff. Do not start Task 3 until the fresh-process test is green twice and its
review has no open finding.

---

### Task 3: Update the release contract and operator evidence

**Files:**
- Modify: `recursive-self-improvement/SKILL.md:1-6`
- Modify: `recursive-self-improvement/references/global-rollout.md:1-165`
- Modify: `recursive-self-improvement/references/rollout-and-testing.md:1-12`
- Modify: `recursive-self-improvement/tests/test_package_contract.py:40-115`
- Modify: `recursive-self-improvement/tests/test_forward.py:680-735`
- Modify: `.superpowers/sdd/2026-08-13-global-rsi-observe-rollout/report.md` (ignored execution evidence only)

**Interfaces:**
- Consumes: Task 1's exact metadata policy and Task 2's fresh catalog proof.
- Produces: a closed rollout contract with exact `catalog` mapping and operator instructions that separate visibility, trigger eligibility, invocation, and deployment authority.
- Produces: a skill description that allows consideration only for completed verified reusable-learning work and explicitly excludes ordinary/status/one-off/maintenance work.

- [ ] **Step 1: Write failing release-contract assertions**

Extend the expected `rsi-rollout-contract` mapping in
`test_package_contract.py` with this exact sibling of `defaults`:

```python
"catalog": {
    "allowImplicitInvocation": True,
    "visibilityIsInvocationAuthority": False,
    "freshTaskRequiredAfterInstall": True,
},
```

Add exact assertions that `global-rollout.md` states:

```python
assert "Catalog visibility is not invocation authority" in text
assert "codex debug prompt-input" in text
assert "rollback through the exact deployment receipt" in text
```

Parse the `SKILL.md` frontmatter description and require the phrases
`completed, verified`, `reusable`, and `Do not use for ordinary conversation,
status questions, one-off facts, or RSI/skill-learning maintenance.`

- [ ] **Step 2: Run documentation RED**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q --tb=short \
  recursive-self-improvement/tests/test_package_contract.py \
  recursive-self-improvement/tests/test_forward.py \
  -k 'global_rollout_reference or release_package_links'
```

Expected: failures identify the absent catalog contract and missing visibility,
probe, rollback, and description language. No production file changes occur in
this RED step.

- [ ] **Step 3: Tighten the skill catalog description**

Replace only the frontmatter description with a bounded statement of the
trigger boundary. Keep the name and body unchanged:

```yaml
description: Use only during or after a completed, verified skill-driven task to preserve and evaluate evidence-backed reusable findings without changing role goals or weakening safeguards. Use for recurring role-skill evidence, validated improvements, ownership audits, defragmentation, or cross-skill RSI reports. Do not use for ordinary conversation, status questions, one-off facts, tasks without reusable evidence, or RSI/skill-learning deployment and maintenance.
```

The description may make the skill selectable for qualifying work; it must not
claim automatic promotion, production target authority, or privileged mutation.

- [ ] **Step 4: Update the machine-readable and prose release contract**

Add the exact `catalog` object to the `rsi-rollout-contract` JSON in
`references/global-rollout.md`. Add a `Catalog visibility` subsection that
states:

- `allow_implicit_invocation: true` makes metadata model-visible;
- visibility alone does not invoke RSI or authorize any write;
- the managed trigger and runtime profile remain the eligibility and authority
  gates;
- a new Codex task is required after install/update;
- `codex debug prompt-input` is the read-only visibility probe;
- absence, unexpected invocation, or state creation requires rollback through
  the exact deployment receipt.

Update `rollout-and-testing.md` to route release operators to that subsection
and retain `observe + late-review`, empty allowlist, no-promotion wording. Add
the design addendum link to `global-rollout.md`; do not rewrite the historical
2026-08-13 design or plan.

- [ ] **Step 5: Run documentation GREEN and package validators**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q --tb=short \
  recursive-self-improvement/tests/test_package_contract.py \
  recursive-self-improvement/tests/test_forward.py \
  recursive-self-improvement/tests/test_catalog_visibility.py
python3 ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py \
  recursive-self-improvement
python3 ~/.codex/skills/skill-evolver/scripts/learning_log.py validate
rg -n "TB[D]|TO[D]O|FIXM[E]|PLACEHOLD[E]R" \
  recursive-self-improvement/SKILL.md \
  recursive-self-improvement/references/global-rollout.md \
  recursive-self-improvement/references/rollout-and-testing.md
git diff --check
```

Expected: tests and validators pass; red-flag search emits no matches; all
local Markdown links and JSON examples remain valid.

- [ ] **Step 6: Run the complete pre-review release matrix**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q --tb=short \
  recursive-self-improvement/tests/test_deployment_schema.py \
  recursive-self-improvement/tests/test_deployment_fs.py \
  recursive-self-improvement/tests/test_global_instructions.py \
  recursive-self-improvement/tests/test_global_deployment.py \
  recursive-self-improvement/tests/test_global_rollout.py \
  recursive-self-improvement/tests/test_catalog_visibility.py \
  recursive-self-improvement/tests/test_package_contract.py \
  recursive-self-improvement/tests/test_forward.py
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis \
  pytest -q --tb=short
```

Expected: the focused release matrix and one complete repository suite pass on
the exact candidate commit. The catalog test must execute rather than skip on
this rollout host.

- [ ] **Step 7: Commit Task 3 and stop at its review gate**

```bash
git add \
  recursive-self-improvement/SKILL.md \
  recursive-self-improvement/references/global-rollout.md \
  recursive-self-improvement/references/rollout-and-testing.md \
  recursive-self-improvement/tests/test_package_contract.py \
  recursive-self-improvement/tests/test_forward.py
git commit -m "docs: document global RSI catalog visibility"
```

Update the ignored execution report with exact RED/GREEN/full-suite evidence,
the Task 1–3 commits, and confirmation that live RSI remains absent. Do not
start Task 4 with any dirty tracked file or unresolved finding.

---

### Task 4: Independent review, integration, and transactional live activation

**Files:**
- Modify during execution only: `.superpowers/sdd/2026-08-13-global-rsi-observe-rollout/report.md`
- Modify live only after approval: `~/.codex/skills/recursive-self-improvement/**`
- Modify live only after approval: `~/.codex/AGENTS.md`
- Append immutable live authority only after approval: `~/.codex/rsi-deployments-v1/**`

**Interfaces:**
- Consumes: reviewed Task 1–3 commits, `rsi_deploy.py`, `DryRunAuthority.live()`, `run_observe_dry_run()`, and Codex `debug prompt-input`.
- Produces: a verified active global RSI observe installation, exact deployment receipt, fresh local/latest Codex catalog evidence, unchanged provider/target witnesses, merged/pushed `master`, and a recoverable rollback authority.

- [ ] **Step 1: Build the exact review package**

Record base SHA `39a421340b1105eaaef279ad1bfe5a8b26265bfc`, candidate
HEAD, commit list, design addendum, this plan, `git diff --stat`, and complete
Task 1–3 test evidence. Require an independent reviewer to inspect source
admission, installed/backup replay, catalog visibility versus invocation,
trigger exclusions, provider/target zero-write boundaries, live commands, and
rollback.

The reviewer must return separate `Spec APPROVED` and `Quality APPROVED`
verdicts with no open P0, P1, P2, or Important finding. Review probes use only
temporary homes and may not touch live provider or target state.

- [ ] **Step 2: Close every review finding with a separate RED/GREEN commit**

For every validated finding:

1. add the smallest independent regression and record its failing output;
2. implement the minimal fix without widening authority;
3. rerun focused and affected suites;
4. commit with a `fix:` subject;
5. request a fresh exact-HEAD re-review.

Do not proceed on provisional approval. If a fix changes scope beyond catalog
visibility or its verification, return to design review.

- [ ] **Step 3: Run final branch verification**

Run on the exact approved feature HEAD:

```bash
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis \
  pytest -q --tb=short
python3 ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py \
  recursive-self-improvement
python3 ~/.codex/skills/skill-evolver/scripts/learning_log.py validate
git diff --check
git status --short
```

Expected: full suite and validators pass; tracked status is clean; only the
preserved pre-existing caches and `uv.lock` may remain untracked.

- [ ] **Step 4: Fast-forward local master and verify the exact integrated tree**

From the root worktree:

```bash
git fetch origin master
git merge-base --is-ancestor origin/master codex/global-rsi-observe-rollout
git merge --ff-only codex/global-rsi-observe-rollout
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis \
  pytest -q --tb=short
```

Expected: ancestry proof and fast-forward succeed; the full suite passes again
on `master`. Any root or feature tracked dirt stops integration.

- [ ] **Step 5: Capture bounded live pre-state witnesses**

Before any live mutation, record only paths, modes, byte lengths, SHA-256
digests, and present/absent classifications for:

- `~/.codex/AGENTS.md`;
- `~/.codex/skills/recursive-self-improvement`;
- `~/.codex/rsi-deployments-v1/active.json` and its selected receipt chain;
- `~/.codex/skill-learning/events.jsonl`;
- constructor-admitted provider source files;
- every protected target root from `DryRunAuthority.live()`.

Do not put raw provider events, user instructions, target contents, secrets, or
PII in the report. Run `rsi_deploy.py status`; the expected pre-state is the
previously verified `not-installed` absent authority.

- [ ] **Step 6: Run zero-write plan, then transactional deploy**

From the clean `master` root:

```bash
candidate_sha=$(git rev-parse HEAD)
operation_id="global-observe-catalog-${candidate_sha}"
python3 recursive-self-improvement/scripts/rsi_deploy.py plan \
  --source-repo "$PWD"
python3 recursive-self-improvement/scripts/rsi_deploy.py deploy \
  --source-repo "$PWD" \
  --operation-id "$operation_id"
```

Expected: plan is eligible with `action=install` and zero writes. Deploy returns
canonical JSON with `status=complete`, the exact candidate commit,
`mode=observe`, `hookMode=late-review`, zero allowlist entries, and one immutable
marker-last receipt. Save only bounded receipt identifiers and digests.

- [ ] **Step 7: Verify installed authority and run bounded observe dry run**

Run the installed verifier in a fresh process:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 \
  ~/.codex/skills/recursive-self-improvement/scripts/rsi_deploy.py verify
```

Then invoke `run_observe_dry_run` from the verified installed package with a
fresh `mktemp -d` root and `DryRunAuthority.live()`. Require the exact case
matrix already frozen by `test_global_rollout.py`: safe finding and skill/no
finding invoke in `observe + late-review`; ordinary, maintenance, sensitive,
and recursive cases skip; report `complete=true`.

Any nonzero verifier result, incomplete report, unexpected case, provider
event, or target drift jumps directly to Step 10 rollback.

- [ ] **Step 8: Run fresh local and latest Codex visibility-only probes**

Render prompt input with the installed live Codex and with the latest published
Codex CLI. Store outputs in a private temporary directory, not the repository:

```bash
probe_root=$(mktemp -d /tmp/rsi-catalog-live.XXXXXX)
probe='Report only whether the model-visible skill catalog contains recursive-self-improvement. Do not invoke any skill.'
codex debug prompt-input "$probe" > "$probe_root/local.json"
npx --yes @openai/codex@latest debug prompt-input "$probe" \
  > "$probe_root/latest.json"
```

For both canonical JSON arrays, join all `input_text` fields and require:

- `### Available skills` is present;
- exactly one `- recursive-self-improvement:` catalog entry is present;
- its locator is the verified live `SKILL.md` path;
- the skill-body sentence `Operate as the control plane for evidence-backed
  role-skill improvement.` is absent, proving visibility without invocation;
- no RSI/provider event, report, observation, target, deployment receipt, or
  global-instruction write occurred during the probes.

If network access prevents the latest-CLI probe, do not weaken the gate or call
the rollout complete; preserve the successful local result and retry only when
the published package is reachable.

- [ ] **Step 9: Recheck all live invariants**

Recompute every Step 5 witness. Require:

- provider source and ledger digests equal pre-state;
- every protected target witness equals pre-state;
- `AGENTS.md` differs from pre-state only by one exact managed block;
- the installed manifest, receipt, tree, active authority, source commit,
  profile, and allowlist verify exactly;
- catalog probes created no RSI state;
- repository tracked status is clean.

Only after these checks may the rollout be called active.

- [ ] **Step 10: Roll back automatically on any activation failure**

If Steps 6–9 fail after a receipt exists, run:

```bash
python3 recursive-self-improvement/scripts/rsi_deploy.py rollback \
  --receipt-id "$operation_id" \
  --operation-id "rollback-catalog-${candidate_sha}"
```

Then require `status=not-installed`, the exact prior `AGENTS.md` bytes/mode,
unchanged provider/target witnesses, absent installed package, and retained
immutable receipts/backups. On an ambiguous rollback result, stop mutation,
preserve evidence, and report recovery authority; never retry under a guessed
operation ID.

- [ ] **Step 11: Push, clean up, and report the final boundary**

After successful Step 9:

```bash
git push origin master
git worktree remove .worktrees/global-rsi-observe-rollout
git branch -d codex/global-rsi-observe-rollout
```

Before worktree removal, move or preserve any user-owned untracked files rather
than deleting them. Confirm `origin/master`, local `master`, installed manifest
source commit, and live receipt all bind the same exact SHA.

The final report must say that global RSI catalog visibility and observe-only
late review are active. It must also say that production promotion, allowlist
population, privileged coordination, and target mutation remain disabled and
are not part of this rollout.
