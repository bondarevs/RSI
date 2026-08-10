from __future__ import annotations

import mmap
import os
from pathlib import Path

import pytest

from task8_support import (
    DIGEST_A,
    DIGEST_B,
    canonical_final_lf,
    filesystem_witness,
    lazy_module,
    prefixed_digest,
)


def _promotion():
    return lazy_module("rsi_core.promotion")


def _known_drift(kind: str, metadata: object) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "domain": "rsi-namespace-protected-readback-state-v1",
        "classification": "other",
        "targetReadbackView": None,
        "errorWitness": {
            "kind": "known-drift",
            "observedKind": kind,
            "rootIdentityDigest": DIGEST_A,
            "relativePath": "SKILL.md",
            "metadata": metadata,
        },
    }


def test_known_missing_drift_is_a_canonical_other_state_not_unreadable() -> None:
    module = _promotion()
    mapping = _known_drift("missing", None)
    state = module.ProtectedReadbackState.from_mapping(mapping)
    assert state.classification == "other"
    assert state.canonical_bytes == canonical_final_lf(mapping)
    assert state.digest == prefixed_digest(mapping)


@pytest.mark.parametrize(
    "mapping",
    [
        _known_drift(
            "unsafe-link",
            {
                "type": "regular-file",
                "device": 1,
                "inode": 2,
                "mode": 0o600,
                "uid": os.geteuid(),
                "nlink": 1,
                "size": 1,
            },
        ),
        _known_drift(
            "special",
            {
                "type": "symlink",
                "device": 1,
                "inode": 2,
                "mode": 0o777,
                "uid": os.geteuid(),
                "nlink": 1,
                "size": 1,
            },
        ),
        {
            **_known_drift("missing", None),
            "classification": "unreadable",
        },
    ],
)
def test_overlapping_or_mislabeled_known_drift_arms_are_rejected(mapping) -> None:
    module = _promotion()
    with pytest.raises(module.PromotionError, match="drift|readback|metadata"):
        module.ProtectedReadbackState.from_mapping(mapping)


def test_full_filesystem_witness_detects_inode_link_and_symlink_rebinding(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    artifact = target / "SKILL.md"
    artifact.write_bytes(b"trusted\n")
    before = filesystem_witness(target)

    moved = tmp_path / "moved"
    artifact.rename(moved)
    artifact.symlink_to(moved)
    after = filesystem_witness(target)

    assert before != after
    assert before[-1]["type"] == "regular-file"
    assert after[-1]["type"] == "symlink"
    assert before[-1]["inode"] != after[-1]["inode"]


def _scan_observation(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "relativePath": "SKILL.md",
        "expectedPresent": True,
        "lookupProved": True,
        "kindProved": True,
        "metadataProved": True,
        "canonicalizationProved": True,
        "numericBoundsProved": True,
        "contentReadable": True,
        "contentHashable": True,
        "observedType": "regular-file",
        "nlink": 1,
        "size": 8,
    }
    value.update(changes)
    return value


@pytest.mark.parametrize(
    ("observation", "arm", "observed_kind"),
    [
        (
            _scan_observation(observedType="missing", nlink=None, size=None),
            "known-drift",
            "missing",
        ),
        (
            _scan_observation(observedType="symlink"),
            "known-drift",
            "unsafe-link",
        ),
        (
            _scan_observation(nlink=2),
            "known-drift",
            "unsafe-link",
        ),
        (_scan_observation(observedType="dir"), "known-drift", "special"),
        (_scan_observation(observedType="fifo"), "known-drift", "special"),
        (_scan_observation(observedType="socket"), "known-drift", "special"),
        (_scan_observation(observedType="block"), "known-drift", "special"),
        (_scan_observation(observedType="char"), "known-drift", "special"),
        (
            _scan_observation(observedType="other-special"),
            "known-drift",
            "special",
        ),
        (_scan_observation(), "full-view", None),
        (
            _scan_observation(expectedPresent=False),
            "full-view",
            None,
        ),
        (
            _scan_observation(
                expectedPresent=False,
                observedType="missing",
                nlink=None,
                size=None,
            ),
            "expected-absence",
            None,
        ),
    ],
)
def test_protected_scan_classifier_is_disjoint_for_readable_observations(
    observation: dict[str, object], arm: str, observed_kind: str | None
) -> None:
    module = _promotion()
    classified = module.classify_protected_scan_observation(observation)
    assert classified.arm == arm
    assert classified.observed_kind == observed_kind


@pytest.mark.parametrize(
    ("failure", "changes"),
    [
        ("lookup", {"lookupProved": False}),
        ("kind", {"kindProved": False}),
        ("metadata", {"metadataProved": False}),
        ("canonicalization", {"canonicalizationProved": False}),
        ("numeric-bounds", {"numericBoundsProved": False}),
        ("content-read", {"contentReadable": False}),
        ("content-hash", {"contentHashable": False}),
    ],
)
def test_unconstructable_safe_regular_observation_is_unreadable_not_known_drift(
    failure: str, changes: dict[str, object]
) -> None:
    module = _promotion()
    classified = module.classify_protected_scan_observation(
        _scan_observation(**changes)
    )
    assert classified.arm == "unreadable"
    assert classified.failure_stage == failure
    assert classified.observed_kind is None


@pytest.mark.parametrize(
    ("kind", "metadata"),
    [
        ("unsafe-link", {"type": "regular-file", "nlink": 1}),
        ("unsafe-link", {"type": "dir", "nlink": 2}),
        ("special", {"type": "symlink", "nlink": 1}),
        ("special", {"type": "regular-file", "nlink": 3}),
    ],
)
def test_known_drift_type_and_link_predicates_are_mutually_exclusive(
    kind: str, metadata: dict[str, object]
) -> None:
    module = _promotion()
    complete_metadata = {
        "device": 1,
        "inode": 2,
        "mode": 0o600,
        "uid": os.geteuid(),
        "size": 1,
        **metadata,
    }
    with pytest.raises(module.PromotionError, match="known.drift|type|link|special"):
        module.ProtectedReadbackState.from_mapping(_known_drift(kind, complete_metadata))


def test_scan_selects_first_unconstructable_path_by_strict_utf8_bytes() -> None:
    module = _promotion()
    observations = {
        "z/entry": _scan_observation(relativePath="z/entry", metadataProved=False),
        "ä/entry": _scan_observation(relativePath="ä/entry", kindProved=False),
        "a/entry": _scan_observation(relativePath="a/entry", lookupProved=False),
        ".rsi-promotion-swap-" + "a" * 64: _scan_observation(
            relativePath=".rsi-promotion-swap-" + "a" * 64,
            expectedPresent=False,
            observedType="missing",
            nlink=None,
            size=None,
        ),
    }
    selected = module.select_first_protected_scan_failure(observations)
    expected = min(
        (path for path in observations if path != ".rsi-promotion-swap-" + "a" * 64),
        key=lambda path: path.encode("utf-8"),
    )
    assert selected.relative_path == expected == "a/entry"


def test_reserved_name_expected_absence_is_normal_not_missing_drift() -> None:
    module = _promotion()
    observation = _scan_observation(
        relativePath=".rsi-promotion-swap-" + "a" * 64,
        expectedPresent=False,
        observedType="missing",
        nlink=None,
        size=None,
    )
    classified = module.classify_protected_scan_observation(observation)
    assert classified.arm == "expected-absence"
    assert classified.observed_kind is None


def _sequence(*pairs: tuple[str, str]) -> list[dict[str, str]]:
    return [{"step": step, "outcome": outcome} for step, outcome in pairs]


VALID_RESULT_SEQUENCES = [
    (
        "forward-apply",
        "create-failure",
        _sequence(
            ("prepared-post-create-write", "not-performed"),
            ("protected-readback", "exact-pre"),
        ),
    ),
    (
        "unresolved-terminal",
        "post-crash-never-created",
        _sequence(("protected-readback", "exact-pre")),
    ),
    (
        "forward-apply",
        "retained-pre-exchange-failure",
        _sequence(
            ("prepared-post-create-write", "performed"),
            ("protected-readback", "exact-pre"),
        ),
    ),
    (
        "forward-apply",
        "prepared-sync-failure",
        _sequence(
            ("prepared-post-create-write", "performed-unsynced"),
            ("protected-readback", "exact-pre"),
        ),
    ),
    (
        "forward-apply",
        "commit-check-drift",
        _sequence(
            ("prepared-post-create-write", "performed"),
            ("forward-exchange", "not-performed"),
            ("protected-readback", "exact-pre"),
        ),
    ),
    (
        "forward-apply",
        "applied",
        _sequence(
            ("prepared-post-create-write", "performed"),
            ("forward-exchange", "performed"),
            ("protected-readback", "exact-post"),
        ),
    ),
    (
        "forward-apply",
        "emergency-reverse",
        _sequence(
            ("prepared-post-create-write", "performed"),
            ("forward-exchange", "performed"),
            ("protected-readback", "other"),
            ("emergency-reverse", "performed"),
            ("protected-readback", "exact-pre"),
        ),
    ),
    (
        "verifier-readback",
        "affirmed",
        _sequence(("protected-readback", "exact-post")),
    ),
    (
        "promoted-terminal",
        "resolved",
        _sequence(("protected-readback", "exact-post")),
    ),
    (
        "incident-classification",
        "drift",
        _sequence(("protected-readback", "other")),
    ),
    (
        "rollback-apply",
        "rolled-back",
        _sequence(
            ("protected-readback", "exact-post"),
            ("rollback-exchange", "performed"),
            ("protected-readback", "exact-pre"),
        ),
    ),
    (
        "prepared-post-cleanup",
        "removed-now",
        _sequence(
            ("prepared-post-cleanup", "performed"),
            ("protected-readback", "exact-pre"),
        ),
    ),
    (
        "prepared-post-cleanup",
        "already-absent-authorized",
        _sequence(
            ("prepared-post-cleanup", "not-performed"),
            ("protected-readback", "exact-pre"),
        ),
    ),
    (
        "retained-preimage-cleanup",
        "removed-now",
        _sequence(
            ("retained-preimage-cleanup", "performed"),
            ("protected-readback", "exact-post"),
        ),
    ),
    (
        "displaced-post-cleanup",
        "removed-now",
        _sequence(
            ("displaced-post-cleanup", "performed"),
            ("protected-readback", "exact-pre"),
        ),
    ),
    (
        "forward-apply",
        "create-failure-incident",
        _sequence(
            ("prepared-post-create-write", "not-performed"),
            ("protected-readback", "unreadable"),
        ),
    ),
    (
        "forward-apply",
        "forward-ambiguous",
        _sequence(
            ("prepared-post-create-write", "performed"),
            ("forward-exchange", "ambiguous"),
        ),
    ),
    (
        "rollback-apply",
        "rollback-not-performed-incident",
        _sequence(
            ("protected-readback", "exact-post"),
            ("rollback-exchange", "not-performed"),
        ),
    ),
    (
        "rollback-apply",
        "rollback-ambiguous",
        _sequence(
            ("protected-readback", "exact-post"),
            ("rollback-exchange", "ambiguous"),
        ),
    ),
    (
        "rollback-apply",
        "rollback-post-drift",
        _sequence(
            ("protected-readback", "exact-post"),
            ("rollback-exchange", "performed"),
            ("protected-readback", "other"),
        ),
    ),
    (
        "retained-preimage-cleanup",
        "cleanup-unsynced-readable",
        _sequence(
            ("retained-preimage-cleanup", "performed-unsynced"),
            ("protected-readback", "exact-post"),
        ),
    ),
    (
        "retained-preimage-cleanup",
        "cleanup-unsynced-unreadable",
        _sequence(("retained-preimage-cleanup", "performed-unsynced")),
    ),
    (
        "retained-preimage-cleanup",
        "cleanup-refused-drift",
        _sequence(
            ("retained-preimage-cleanup", "not-performed"),
            ("protected-readback", "other"),
        ),
    ),
    (
        "displaced-post-cleanup",
        "cleanup-performed-post-drift",
        _sequence(
            ("displaced-post-cleanup", "performed"),
            ("protected-readback", "unreadable"),
        ),
    ),
]


@pytest.mark.parametrize(
    ("operation_class", "causal_arm", "results"), VALID_RESULT_SEQUENCES
)
def test_each_literal_namespace_backend_result_sequence_is_admitted(
    operation_class: str, causal_arm: str, results: list[dict[str, str]]
) -> None:
    module = _promotion()
    module.validate_namespace_result_sequence(
        operation_class=operation_class,
        causal_arm=causal_arm,
        results=results,
    )


INVALID_RESULT_SEQUENCES = [
    (
        "forward-apply",
        "applied",
        _sequence(
            ("forward-exchange", "performed"),
            ("prepared-post-create-write", "performed"),
            ("protected-readback", "exact-post"),
        ),
    ),
    (
        "forward-apply",
        "applied",
        _sequence(
            ("prepared-post-create-write", "performed"),
            ("forward-exchange", "performed"),
        ),
    ),
    (
        "forward-apply",
        "applied",
        _sequence(
            ("prepared-post-create-write", "performed"),
            ("forward-exchange", "performed"),
            ("protected-readback", "exact-post"),
            ("protected-readback", "exact-post"),
        ),
    ),
    (
        "forward-apply",
        "emergency-reverse",
        _sequence(
            ("prepared-post-create-write", "performed"),
            ("forward-exchange", "performed"),
            ("protected-readback", "other"),
            ("emergency-reverse", "performed"),
            ("protected-readback", "exact-pre"),
            ("protected-readback", "exact-pre"),
        ),
    ),
    (
        "unresolved-terminal",
        "post-crash-never-created",
        _sequence(
            ("prepared-post-create-write", "not-performed"),
            ("protected-readback", "exact-pre"),
        ),
    ),
    (
        "rollback-apply",
        "rolled-back",
        _sequence(
            ("rollback-exchange", "performed"),
            ("protected-readback", "exact-pre"),
        ),
    ),
    (
        "prepared-post-cleanup",
        "removed-now",
        _sequence(
            ("retained-preimage-cleanup", "performed"),
            ("protected-readback", "exact-pre"),
        ),
    ),
]


@pytest.mark.parametrize(
    ("operation_class", "causal_arm", "results"), INVALID_RESULT_SEQUENCES
)
def test_reordered_skipped_duplicate_sixth_or_cross_operation_result_is_rejected(
    operation_class: str, causal_arm: str, results: list[dict[str, str]]
) -> None:
    module = _promotion()
    with pytest.raises(module.PromotionError, match="sequence|step|operation|result"):
        module.validate_namespace_result_sequence(
            operation_class=operation_class,
            causal_arm=causal_arm,
            results=results,
        )


@pytest.mark.parametrize(
    ("step", "outcome", "before", "after", "directory_synced", "possible_mutation"),
    [
        ("prepared-post-create-write", "performed", "absent", "present", True, True),
        ("prepared-post-create-write", "performed-unsynced", "absent", "present", False, True),
        ("forward-exchange", "performed", "pre-order", "exchanged-order", True, True),
        ("rollback-exchange", "not-performed", "pre-order", "pre-order", None, False),
        ("prepared-post-cleanup", "performed", "present", "absent", True, True),
        ("prepared-post-cleanup", "performed-unsynced", "present", "absent", False, True),
        ("prepared-post-cleanup", "performed-unsynced", "present", None, False, True),
        ("prepared-post-cleanup", "not-performed", "absent", "absent", True, False),
        ("protected-readback", "exact-pre", "exact-pre", "exact-pre", None, False),
        ("protected-readback", "other", "other", "other", None, False),
        ("protected-readback", "unreadable", "unreadable", "unreadable", None, False),
        ("emergency-reverse", "ambiguous", "exchanged-order", None, None, True),
    ],
)
def test_backend_result_transition_truth_table_is_literal(
    step: str,
    outcome: str,
    before: str,
    after: str | None,
    directory_synced: bool | None,
    possible_mutation: bool,
) -> None:
    module = _promotion()
    module.validate_namespace_backend_transition(
        step=step,
        outcome=outcome,
        before_classification=before,
        after_classification=after,
        directory_synced=directory_synced,
        possible_mutation=possible_mutation,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        {"outcome": "performed", "before": "absent", "after": "absent"},
        {"outcome": "not-performed", "before": "absent", "after": "present"},
        {"outcome": "performed-unsynced", "directory_synced": True},
        {"outcome": "ambiguous", "possible_mutation": False},
        {"outcome": "exact-post", "before": "exact-pre", "after": "exact-post"},
    ],
)
def test_backend_result_rejects_false_transition_or_outcome_claim(
    mutation: dict[str, object]
) -> None:
    module = _promotion()
    values: dict[str, object] = {
        "step": "prepared-post-create-write",
        "outcome": "performed",
        "before_classification": "absent",
        "after_classification": "present",
        "directory_synced": True,
        "possible_mutation": True,
    }
    aliases = {
        "before": "before_classification",
        "after": "after_classification",
    }
    for key, value in mutation.items():
        values[aliases.get(key, key)] = value
    with pytest.raises(module.PromotionError, match="transition|outcome|mutation|sync"):
        module.validate_namespace_backend_transition(**values)


@pytest.mark.parametrize(
    "results",
    [
        _sequence(
            ("prepared-post-create-write", "performed-unsynced"),
            ("protected-readback", "exact-pre"),
        ),
        _sequence(
            ("prepared-post-cleanup", "performed-unsynced"),
            ("protected-readback", "exact-pre"),
        ),
        _sequence(("prepared-post-cleanup", "performed-unsynced")),
    ],
)
def test_performed_unsynced_result_is_incident_only_and_never_clean_close(
    results: list[dict[str, str]],
) -> None:
    module = _promotion()
    disposition = module.namespace_result_sequence_disposition(results)
    assert disposition == "incident-only"
    assert disposition not in {"applied", "not-applied", "cleaned"}


@pytest.mark.parametrize(
    "attack",
    [
        "ancestor-rename",
        "target-name-replacement",
        "reserved-name-replacement",
        "incoming-hard-link",
        "write",
        "truncate",
        "chmod",
        "xattr",
        "preopened-fd-write",
        "writable-mmap",
        "dirty-writeback",
        "mount-alias",
        "unrelated-managed-file-write",
    ],
)
def test_lease_scope_forbids_every_noncooperative_same_uid_mutation_class(
    attack: str,
) -> None:
    module = _promotion()
    decision = module.classify_namespace_adversary_attempt(attack)
    assert decision in {"excluded", "incident"}
    assert decision != "allowed"


@pytest.mark.parametrize("attack", ["rename", "hardlink", "write", "chmod", "mmap"])
def test_changed_filesystem_witness_can_never_reclassify_as_exact(
    tmp_path: Path, attack: str
) -> None:
    module = _promotion()
    root = tmp_path / "managed"
    root.mkdir()
    target = root / "SKILL.md"
    target.write_bytes(b"trusted\n")
    other = root / "OTHER.md"
    other.write_bytes(b"other\n")
    before = filesystem_witness(root)

    if attack == "rename":
        target.rename(root / "RENAMED.md")
    elif attack == "hardlink":
        os.link(target, root / "alias")
    elif attack == "write":
        target.write_bytes(b"changed\n")
    elif attack == "chmod":
        target.chmod(0o700)
    else:
        with target.open("r+b") as stream:
            with mmap.mmap(stream.fileno(), 0) as mapped:
                mapped[0:1] = b"X"
                mapped.flush()

    after = filesystem_witness(root)
    assert before != after
    assert module.classify_filesystem_witness_change(before, after) in {
        "other",
        "unreadable",
    }


def test_unrelated_managed_member_drift_defeats_artifact_only_exact_hash(
    tmp_path: Path,
) -> None:
    module = _promotion()
    root = tmp_path / "managed"
    root.mkdir()
    target = root / "SKILL.md"
    target.write_bytes(b"same target\n")
    member = root / "reference.md"
    member.write_bytes(b"before\n")
    before = filesystem_witness(root)
    target_bytes = target.read_bytes()

    member.write_bytes(b"after\n")
    after = filesystem_witness(root)

    assert target.read_bytes() == target_bytes
    assert before != after
    assert module.classify_filesystem_witness_change(before, after) == "other"


def test_six_byte_json_escape_budget_covers_every_admitted_control_character() -> None:
    module = _promotion()
    path = "a/" + "\u0001" * 1024
    raw_utf8_bytes = len(path.encode("utf-8"))
    rendered = canonical_final_lf(path)
    assert len(rendered) <= 6 * raw_utf8_bytes + 3
    assert module.admitted_path_budget_bytes([path]) == raw_utf8_bytes
    assert module.max_json_escaped_path_bytes(raw_utf8_bytes) == 6 * raw_utf8_bytes


def test_protected_readback_outcome_must_equal_complete_state_classification() -> None:
    module = _promotion()
    state = _known_drift("missing", None)
    result = {
        "step": "protected-readback",
        "outcome": "exact-pre",
        "beforeWitnessDigest": prefixed_digest(state),
        "afterWitnessDigest": prefixed_digest(state),
    }
    with pytest.raises(module.PromotionError, match="classification|outcome|readback"):
        module.validate_protected_readback_result(result, state)


def test_digest_of_nested_error_only_cannot_replace_complete_protected_state_digest() -> None:
    module = _promotion()
    state = _known_drift("missing", None)
    result = {
        "step": "protected-readback",
        "outcome": "other",
        "beforeWitnessDigest": prefixed_digest(state["errorWitness"]),
        "afterWitnessDigest": prefixed_digest(state["errorWitness"]),
    }
    with pytest.raises(module.PromotionError, match="complete|state|digest"):
        module.validate_protected_readback_result(result, state)


def test_cross_request_scope_result_and_step_substitution_is_rejected() -> None:
    module = _promotion()
    evidence = {
        "requestDigest": DIGEST_A,
        "scopeDigest": DIGEST_B,
        "receipt": {"leaseRequestDigest": DIGEST_A, "operationClass": "rollback-apply"},
        "backendResults": [
            {
                "leaseRequestDigest": DIGEST_B,
                "operationClass": "forward-apply",
                "step": "forward-exchange",
            }
        ],
        "stepWitnesses": [{"step": "rollback-exchange"}],
    }
    with pytest.raises(module.PromotionError, match="request|scope|operation|step"):
        module.validate_namespace_evidence_cross_equalities(evidence)
