import json
from pathlib import Path
import re
import shlex

import rsi_deploy
from rsi_core.global_instructions import MANAGED_BLOCK


SKILL_ROOT = Path(__file__).resolve().parents[1]


def load_json(relative_path: str) -> dict:
    path = SKILL_ROOT / relative_path
    assert path.is_file(), f"Missing required package file: {relative_path}"
    return json.loads(path.read_text(encoding="utf-8"))


def test_package_default_mode_is_observe() -> None:
    default_profile = load_json("profiles/default.json")

    assert default_profile["mode"] == "observe"


def test_production_allowlist_is_empty() -> None:
    production_profile = load_json("profiles/production.json")

    assert production_profile["activation"]["allowedTargets"] == []


def _parse_openai_metadata() -> dict[str, object]:
    metadata: dict[str, object] = {}
    current: dict[str, object] | None = None
    path = SKILL_ROOT / "agents/openai.yaml"
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        key, separator, raw_value = raw_line.strip().partition(":")
        assert separator and key
        if indent == 0:
            assert not raw_value.strip()
            current = {}
            metadata[key] = current
            continue
        assert indent == 2 and current is not None
        value = raw_value.strip()
        current[key] = (
            value == "true" if value in {"true", "false"} else json.loads(value)
        )
    return metadata


def test_catalog_visibility_policy_is_exactly_enabled() -> None:
    metadata = _parse_openai_metadata()

    assert set(metadata) == {"interface", "policy"}
    assert metadata["policy"] == {"allow_implicit_invocation": True}


def test_contract_kind_is_role() -> None:
    contract = load_json("skill-contract.json")

    assert contract["kind"] == "role"


def _one_fence(text: str, language: str) -> str:
    matches = re.findall(rf"```{re.escape(language)}\n(.*?)\n```", text, re.S)
    assert len(matches) == 1, f"expected one {language} contract fence"
    return matches[0]


def test_global_rollout_reference_is_a_closed_release_contract() -> None:
    reference = SKILL_ROOT / "references" / "global-rollout.md"
    assert reference.is_file()
    text = reference.read_text(encoding="utf-8")
    contract = json.loads(_one_fence(text, "rsi-rollout-contract"))

    assert contract == {
        "schemaVersion": 1,
        "stage": "0/1",
        "defaults": {
            "mode": "observe",
            "hookMode": "late-review",
            "productionAllowlist": [],
        },
        "catalog": {
            "allowImplicitInvocation": True,
            "visibilityIsInvocationAuthority": False,
            "freshTaskRequiredAfterInstall": True,
        },
        "capabilities": {
            "promotionEnabled": False,
            "privilegedCoordinatorInstalled": False,
        },
        "paths": {
            "installedPackage": "~/.codex/skills/recursive-self-improvement",
            "globalInstructions": "~/.codex/AGENTS.md",
            "deploymentState": "~/.codex/rsi-deployments-v1",
            "lock": "~/.codex/rsi-deployments-v1/lock",
            "activeAuthority": "~/.codex/rsi-deployments-v1/active.json",
            "receiptManifest": "~/.codex/rsi-deployments-v1/receipts/<operation-id>.manifest.json",
            "receipt": "~/.codex/rsi-deployments-v1/receipts/<operation-id>.json",
            "backup": "~/.codex/rsi-deployments-v1/backups/<backup-digest>/",
        },
        "trigger": {
            "newCodexTaskRequiredAfterInstall": True,
            "recursionGuard": "CODEX_RSI_TRIGGER_ACTIVE=1",
            "qualifies": [
                "skill-used",
                "directly-verified-sanitized-reusable-finding",
            ],
            "skips": [
                "ordinary-conversation",
                "status-question",
                "one-off-fact",
                "no-reusable-evidence",
                "rsi-or-skill-learning-maintenance",
                "recursive-invocation",
            ],
        },
        "recovery": {
            "invalidSource": "repair-or-commit-source-then-rerun-plan",
            "installedDrift": (
                "preserve-state-and-evidence;do-not-deploy-or-rollback;"
                "escalate-reviewed-recovery"
            ),
            "instructionDrift": (
                "restore-exact-committed-block-preserve-surrounding-bytes-and-mode;"
                "verify-before-deploy-or-rollback"
            ),
            "failedReverseExchange": "preserve-evidence-and-escalate-ambiguous",
            "ambiguousState": "do-not-retry-or-overwrite;preserve-and-investigate",
        },
    }

    default = load_json("profiles/default.json")
    production = load_json("profiles/production.json")
    assert default["mode"] == contract["defaults"]["mode"]
    assert default["orchestration"]["hookMode"] == contract["defaults"]["hookMode"]
    assert production["activation"]["allowedTargets"] == contract["defaults"][
        "productionAllowlist"
    ]

    assert "Catalog visibility is not invocation authority" in text
    assert "codex debug prompt-input" in text
    assert "scripts/rsi_catalog_probe.py" in text
    assert "Never run either client against the live `CODEX_HOME`" in text
    assert "rollback through the exact deployment receipt" in text


def test_global_rollout_managed_block_and_cli_examples_execute_the_real_grammar() -> None:
    text = (SKILL_ROOT / "references" / "global-rollout.md").read_text(
        encoding="utf-8"
    )
    documented_block = (_one_fence(text, "rsi-managed-block") + "\n").encode(
        "utf-8"
    )
    assert documented_block == MANAGED_BLOCK

    commands = [
        line
        for line in _one_fence(text, "console").splitlines()
        if line and not line.startswith("#")
    ]
    parsed = []
    for line in commands:
        tokens = shlex.split(line)
        assert tokens[:2] == [
            "python3",
            "recursive-self-improvement/scripts/rsi_deploy.py",
        ]
        parsed.append(rsi_deploy._parse(tokens[2:]))
    assert [command for command, _options in parsed] == [
        "plan",
        "deploy",
        "verify",
        "status",
        "rollback",
    ]


def test_global_rollout_is_routed_from_every_operator_reference() -> None:
    skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "[global rollout](references/global-rollout.md)" in skill
    for relative in (
        "references/architecture.md",
        "references/lifecycle-and-policy.md",
        "references/rollout-and-testing.md",
    ):
        text = (SKILL_ROOT / relative).read_text(encoding="utf-8")
        assert "[global rollout](global-rollout.md)" in text
