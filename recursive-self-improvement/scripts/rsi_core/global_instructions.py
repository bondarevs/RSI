"""Strict rendering and verification for the managed global RSI instructions."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .deployment_schema import canonical_json_bytes


class GlobalInstructionsError(ValueError):
    """Global instruction bytes are ambiguous, unsafe, or do not match the manifest."""


BEGIN_MARKER = "<!-- BEGIN RSI GLOBAL OBSERVE V1 — managed by RSI deployer -->".encode(
    "utf-8"
)
END_MARKER = "<!-- END RSI GLOBAL OBSERVE V1 — managed by RSI deployer -->".encode(
    "utf-8"
)
MANAGED_BLOCK = (
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

_BLOCK_DIGEST_DOMAIN = "rsi-global-managed-instruction-block-v1"
_UTF8_BOM = b"\xef\xbb\xbf"
_MANAGED_POLICY_BLOCK_DIGEST = (
    "sha256:38892209cb72f8b41f81bfe7a9a44fb4668c842e2255c7c8c1378d08ca081ebb"
)


@dataclass(frozen=True)
class AgentsUpdate:
    """A byte-exact AGENTS.md update for the transactional publisher.

    ``mode`` is ``0600`` only for a missing file.  A publisher must retain an
    existing file's independently verified safe mode when this value is ``None``.
    """

    after: bytes
    block_digest: str
    existing_was_absent: bool
    mode: int | None


@dataclass(frozen=True)
class TriggerContext:
    """Sanitized task facts used to decide whether global RSI may run."""

    task_kind: str
    used_skill: bool
    has_verified_sanitized_reusable_finding: bool
    services_same_rsi_invocation: bool
    recursion_guard: str | None


@dataclass(frozen=True)
class TriggerPolicy:
    """Closed, read-only trigger matrix bound to the managed instruction bytes."""

    managed_block_digest: str
    accepted_task_kinds: frozenset[str]
    excluded_task_kinds: frozenset[str]

    def should_invoke(self, context: TriggerContext) -> bool:
        """Return whether one completed task qualifies for the late review."""

        if type(context) is not TriggerContext:
            return False
        if (
            type(context.task_kind) is not str
            or type(context.used_skill) is not bool
            or type(context.has_verified_sanitized_reusable_finding) is not bool
            or type(context.services_same_rsi_invocation) is not bool
            or (context.recursion_guard is not None and type(context.recursion_guard) is not str)
        ):
            return False
        if context.recursion_guard is not None:
            return False
        if context.task_kind in self.excluded_task_kinds:
            return False
        if context.task_kind not in self.accepted_task_kinds:
            return False
        if context.services_same_rsi_invocation:
            return False
        return (
            context.used_skill
            or context.has_verified_sanitized_reusable_finding
        )


def _block_digest(block: bytes) -> str:
    try:
        text = block.decode("utf-8", "strict")
    except UnicodeDecodeError:  # pragma: no cover - the module constant is static
        raise GlobalInstructionsError("managed instruction block is not UTF-8") from None
    payload = canonical_json_bytes(
        {
            "schemaVersion": 1,
            "domain": _BLOCK_DIGEST_DOMAIN,
            "block": text,
        }
    )
    return "sha256:" + hashlib.sha256(payload).hexdigest()


MANAGED_BLOCK_DIGEST = _block_digest(MANAGED_BLOCK)

TRIGGER_POLICY = TriggerPolicy(
    managed_block_digest=_MANAGED_POLICY_BLOCK_DIGEST,
    accepted_task_kinds=frozenset({"normal"}),
    excluded_task_kinds=frozenset(
        {
            "ordinary-conversation",
            "status-question",
            "one-off-fact",
            "no-reusable-evidence",
            "rsi-deploy",
            "rsi-verify",
            "rsi-rollback",
            "rsi-health",
            "rsi-recovery",
        }
    ),
)
if TRIGGER_POLICY.managed_block_digest != MANAGED_BLOCK_DIGEST:
    raise GlobalInstructionsError("managed trigger policy is not bound to the exact prose")


def trigger_policy_for_managed_block(block: bytes) -> TriggerPolicy:
    """Return the closed policy only when its exact managed prose is bound."""

    _validate_text_bytes(block)
    if _block_digest(block) != TRIGGER_POLICY.managed_block_digest:
        raise GlobalInstructionsError("managed trigger policy is not bound to this prose")
    return TRIGGER_POLICY


def _validate_text_bytes(value: bytes) -> None:
    if type(value) is not bytes:
        raise GlobalInstructionsError("global instruction bytes are invalid")
    if _UTF8_BOM in value:
        raise GlobalInstructionsError("global instruction BOM is invalid")
    if b"\x00" in value or b"\r" in value:
        raise GlobalInstructionsError("global instruction control bytes are invalid")
    try:
        value.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise GlobalInstructionsError("global instructions are not strict UTF-8") from None


def _marker_positions(value: bytes, marker: bytes) -> tuple[int, ...]:
    positions: list[int] = []
    start = 0
    while True:
        position = value.find(marker, start)
        if position < 0:
            return tuple(positions)
        positions.append(position)
        start = position + len(marker)


def _is_marker_line(value: bytes, position: int, marker: bytes) -> bool:
    marker_end = position + len(marker)
    return (
        (position == 0 or value[position - 1 : position] == b"\n")
        and (marker_end == len(value) or value[marker_end : marker_end + 1] == b"\n")
    )


def _managed_block_slice(value: bytes) -> tuple[int, int] | None:
    """Return the one managed-block span, rejecting ambiguous marker framing."""

    begin_positions = _marker_positions(value, BEGIN_MARKER)
    end_positions = _marker_positions(value, END_MARKER)
    if not begin_positions and not end_positions:
        return None
    if (
        len(begin_positions) != 1
        or len(end_positions) != 1
        or not _is_marker_line(value, begin_positions[0], BEGIN_MARKER)
        or not _is_marker_line(value, end_positions[0], END_MARKER)
        or end_positions[0] < begin_positions[0]
    ):
        raise GlobalInstructionsError("managed instruction markers are unsafe")

    end = end_positions[0] + len(END_MARKER)
    if end < len(value):
        if value[end : end + 1] != b"\n":
            raise GlobalInstructionsError("managed instruction line framing is unsafe")
        end += 1
    return begin_positions[0], end


def _checked_existing_block(value: bytes) -> tuple[int, int] | None:
    _validate_text_bytes(value)
    span = _managed_block_slice(value)
    if span is not None and value[span[0] : span[1]] != MANAGED_BLOCK:
        raise GlobalInstructionsError("managed instruction block has drifted")
    return span


def plan_agents_update(
    existing: bytes | None, *, verified_update: bool = False
) -> AgentsUpdate:
    """Plan a byte-preserving update without reading or writing a live file.

    A drifted block is rejected unless a deployment transaction has already
    verified the update authority and explicitly sets ``verified_update``.
    """

    if existing is None:
        return AgentsUpdate(
            after=MANAGED_BLOCK,
            block_digest=MANAGED_BLOCK_DIGEST,
            existing_was_absent=True,
            mode=0o600,
        )
    if type(existing) is not bytes:
        raise GlobalInstructionsError("global instruction bytes are invalid")

    try:
        span = _checked_existing_block(existing)
    except GlobalInstructionsError:
        if not verified_update:
            raise
        _validate_text_bytes(existing)
        span = _managed_block_slice(existing)
        if span is None:
            raise

    if span is not None:
        before, after = span
        if existing[before:after] == MANAGED_BLOCK:
            rendered = existing
        else:
            rendered = existing[:before] + MANAGED_BLOCK + existing[after:]
    elif not existing or existing.endswith(b"\n"):
        rendered = existing + MANAGED_BLOCK
    else:
        rendered = existing + b"\n" + MANAGED_BLOCK

    _checked_existing_block(rendered)
    return AgentsUpdate(
        after=rendered,
        block_digest=MANAGED_BLOCK_DIGEST,
        existing_was_absent=False,
        mode=None,
    )


def verify_agents_bytes(actual: bytes, expected_block_digest: str) -> None:
    """Fail closed unless one exact managed block matches the bound digest."""

    if type(expected_block_digest) is not str or expected_block_digest != MANAGED_BLOCK_DIGEST:
        raise GlobalInstructionsError("managed instruction digest does not match")
    span = _checked_existing_block(actual)
    if span is None:
        raise GlobalInstructionsError("managed instruction block is missing")


__all__ = [
    "AgentsUpdate",
    "BEGIN_MARKER",
    "END_MARKER",
    "GlobalInstructionsError",
    "MANAGED_BLOCK",
    "MANAGED_BLOCK_DIGEST",
    "TRIGGER_POLICY",
    "TriggerContext",
    "TriggerPolicy",
    "plan_agents_update",
    "trigger_policy_for_managed_block",
    "verify_agents_bytes",
]
