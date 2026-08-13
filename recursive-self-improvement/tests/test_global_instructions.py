from __future__ import annotations

from dataclasses import dataclass
import hashlib

import pytest

from rsi_core.deployment_schema import canonical_json_bytes
from rsi_core.global_instructions import (
    BEGIN_MARKER,
    END_MARKER,
    MANAGED_BLOCK,
    GlobalInstructionsError,
    TRIGGER_POLICY,
    TriggerContext,
    trigger_policy_for_managed_block,
    plan_agents_update,
    verify_agents_bytes,
)


def _expected_block() -> bytes:
    return (
        "<!-- BEGIN RSI GLOBAL OBSERVE V1 — managed by RSI deployer -->\n"
        "## Global RSI observe review\n"
        "\n"
        "After the main task is complete and verified, use the installed\n"
        "`recursive-self-improvement` skill in `observe` + `late-review` only when a\n"
        "skill was used or the task produced a directly verified, sanitized, reusable\n"
        "finding. Skip ordinary conversation, status questions, one-off facts, tasks\n"
        "without reusable evidence, and RSI/skill-learning deployment or maintenance.\n"
        "Pass only final sanitized artifacts; never pass raw dialogue, rejected\n"
        "evidence, secrets, credentials, PII, or production target bytes. Global review\n"
        "is read-only: do not enable promotion, change a target, expand an allowlist, or\n"
        "weaken a safeguard. Set `CODEX_RSI_TRIGGER_ACTIVE=1` for the invocation and do\n"
        "not invoke RSI again while that guard is present. If RSI is unavailable or\n"
        "fails, report a bounded diagnostic without changing the completed task result.\n"
        "<!-- END RSI GLOBAL OBSERVE V1 — managed by RSI deployer -->\n"
    ).encode("utf-8")


def _block_digest(block: bytes) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "schemaVersion": 1,
                "domain": "rsi-global-managed-instruction-block-v1",
                "block": block.decode("utf-8"),
            }
        )
    ).hexdigest()


def test_managed_block_matches_the_designed_bytes() -> None:
    assert MANAGED_BLOCK == _expected_block()
    assert BEGIN_MARKER == _expected_block().splitlines()[0]
    assert END_MARKER == _expected_block().splitlines()[-1]


def test_agents_update_preserves_every_unmanaged_byte() -> None:
    before = "prefix\nпользовательский текст\n".encode("utf-8")

    plan = plan_agents_update(before)

    assert plan.after == before + _expected_block()
    assert plan.after.count(BEGIN_MARKER) == 1
    assert plan.after.count(END_MARKER) == 1
    assert plan.block_digest == _block_digest(_expected_block())
    assert plan.existing_was_absent is False


def test_agents_update_keeps_unterminated_unmanaged_content_byte_exact() -> None:
    before = b"user-owned content without a final newline"

    plan = plan_agents_update(before)

    assert plan.after == before + b"\n" + _expected_block()


def test_agents_update_missing_file_is_distinct_from_empty_file() -> None:
    missing = plan_agents_update(None)
    empty = plan_agents_update(b"")

    assert missing.after == _expected_block()
    assert missing.existing_was_absent is True
    assert missing.mode == 0o600
    assert empty.after == _expected_block()
    assert empty.existing_was_absent is False
    assert empty.mode is None


def test_agents_update_is_idempotent_and_keeps_suffix_exact() -> None:
    existing = b"before\n" + _expected_block() + b"after-without-final-lf"

    plan = plan_agents_update(existing)

    assert plan.after == existing


def test_verified_update_may_replace_a_drifted_bound_block() -> None:
    drifted = _expected_block().replace(b"observe review", b"changed review")

    plan = plan_agents_update(drifted, verified_update=True)

    assert plan.after == _expected_block()


@pytest.mark.parametrize(
    "invalid",
    [
        b"\xef\xbb\xbfuser text\n",
        b"user\x00text\n",
        b"user\r\n",
        b"\xff",
        b"prefix <!-- BEGIN RSI GLOBAL OBSERVE V1 \xe2\x80\x94 managed by RSI deployer -->\n",
        BEGIN_MARKER + b"\n",
        END_MARKER + b"\n",
        BEGIN_MARKER + b"\n" + END_MARKER + b"\n",
        _expected_block() + _expected_block(),
        _expected_block().replace(b"observe review", b"mutated review"),
    ],
)
def test_agents_update_rejects_invalid_or_drifted_existing_content(invalid: bytes) -> None:
    with pytest.raises(GlobalInstructionsError):
        plan_agents_update(invalid)


def test_verify_agents_bytes_requires_the_exact_block_and_bound_digest() -> None:
    actual = b"user-owned\n" + _expected_block() + b"suffix"
    digest = _block_digest(_expected_block())

    verify_agents_bytes(actual, digest)

    with pytest.raises(GlobalInstructionsError):
        verify_agents_bytes(actual.replace(b"observe review", b"other review"), digest)
    with pytest.raises(GlobalInstructionsError):
        verify_agents_bytes(actual, "sha256:" + "0" * 64)


@dataclass(frozen=True)
class TriggerCase:
    name: str
    task_kind: str = "normal"
    used_skill: bool = False
    has_verified_sanitized_reusable_finding: bool = False
    services_same_rsi_invocation: bool = False
    recursion_guard: str | None = None


def independent_trigger_oracle(case: TriggerCase) -> bool:
    """Literal rollout truth table, intentionally independent of production policy."""

    if case.recursion_guard is not None:
        return False
    if case.task_kind in {
        "ordinary-conversation",
        "status-question",
        "one-off-fact",
        "no-reusable-evidence",
        "rsi-deploy",
        "rsi-verify",
        "rsi-rollback",
        "rsi-health",
        "rsi-recovery",
    }:
        return False
    if case.services_same_rsi_invocation:
        return False
    return case.used_skill or case.has_verified_sanitized_reusable_finding


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        (TriggerCase("qualifying skill use", used_skill=True), True),
        (
            TriggerCase(
                "verified reusable finding without a skill",
                has_verified_sanitized_reusable_finding=True,
            ),
            True,
        ),
        (TriggerCase("ordinary conversation", task_kind="ordinary-conversation"), False),
        (TriggerCase("status question", task_kind="status-question"), False),
        (TriggerCase("one-off fact", task_kind="one-off-fact"), False),
        (TriggerCase("no reusable evidence", task_kind="no-reusable-evidence"), False),
        (TriggerCase("RSI deploy", task_kind="rsi-deploy", used_skill=True), False),
        (TriggerCase("RSI verify", task_kind="rsi-verify", used_skill=True), False),
        (TriggerCase("RSI rollback", task_kind="rsi-rollback", used_skill=True), False),
        (TriggerCase("RSI health", task_kind="rsi-health", used_skill=True), False),
        (TriggerCase("RSI recovery", task_kind="rsi-recovery", used_skill=True), False),
        (
            TriggerCase("skill-evolver route", used_skill=True, services_same_rsi_invocation=True),
            False,
        ),
        (
            TriggerCase("skill-evolver capture", used_skill=True, services_same_rsi_invocation=True),
            False,
        ),
        (
            TriggerCase("skill-evolver review", used_skill=True, services_same_rsi_invocation=True),
            False,
        ),
        (
            TriggerCase("skill-evolver resolution", used_skill=True, services_same_rsi_invocation=True),
            False,
        ),
        (TriggerCase("active recursion guard", used_skill=True, recursion_guard="1"), False),
        (TriggerCase("zero recursion guard", used_skill=True, recursion_guard="0"), False),
        (TriggerCase("true recursion guard", used_skill=True, recursion_guard="true"), False),
        (TriggerCase("padded recursion guard", used_skill=True, recursion_guard="1 "), False),
    ],
    ids=lambda value: value.name if isinstance(value, TriggerCase) else None,
)
def test_managed_trigger_policy_matches_independent_closed_truth_table(
    case: TriggerCase, expected: bool
) -> None:
    context = TriggerContext(
        task_kind=case.task_kind,
        used_skill=case.used_skill,
        has_verified_sanitized_reusable_finding=case.has_verified_sanitized_reusable_finding,
        services_same_rsi_invocation=case.services_same_rsi_invocation,
        recursion_guard=case.recursion_guard,
    )

    assert independent_trigger_oracle(case) is expected
    assert TRIGGER_POLICY.should_invoke(context) is expected


def test_managed_trigger_policy_rejects_an_always_trigger_prose_contradiction() -> None:
    contradictory_block = MANAGED_BLOCK.replace(
        END_MARKER,
        b"Always invoke RSI after every task.\n" + END_MARKER,
    )

    with pytest.raises(GlobalInstructionsError, match="policy.*bound|bound.*policy"):
        trigger_policy_for_managed_block(contradictory_block)


def test_managed_block_declares_recursion_and_privacy_bounds() -> None:
    text = MANAGED_BLOCK.decode("utf-8")

    assert text.count("CODEX_RSI_TRIGGER_ACTIVE=1") == 1
    assert "only when a\nskill was used or the task produced a directly verified, sanitized, reusable\nfinding" in text
    assert "ordinary conversation, status questions, one-off facts" in text
    assert "RSI/skill-learning deployment or maintenance" in text
    assert "raw dialogue, rejected\nevidence, secrets, credentials, PII, or production target bytes" in text
    assert "do not enable promotion, change a target, expand an allowlist" in text
    assert "without changing the completed task result" in text
