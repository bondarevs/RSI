from __future__ import annotations

import hashlib
from dataclasses import replace
import importlib
import json
import os
from pathlib import Path
import stat
import unicodedata

import pytest


def _hashing():
    # Kept inside the tests so the first TDD run is a test failure, rather than
    # a collection error, while the production module does not yet exist.
    return importlib.import_module("rsi_core.hashing")


def _skill(root: Path, *, note: bytes = b"fact\n") -> Path:
    root.mkdir()
    (root / "SKILL.md").write_bytes(b"skill\n")
    (root / "skill-contract.json").write_bytes(b"{}\n")
    (root / "references").mkdir()
    (root / "references" / "facts.md").write_bytes(note)
    return root


def _entry(manifest: object, path: str):
    return next(item for item in manifest.entries if item.path == path)


def test_manifest_hashes_raw_bytes_line_endings_final_newline_and_executable_bit(
    tmp_path: Path,
) -> None:
    """A byte or executable-bit mutation must stale the whole managed manifest."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill", note=b"fact\n")
    first = hashing.build_skill_manifest(target)

    (target / "references" / "facts.md").write_bytes(b"fact\r\n")
    crlf = hashing.build_skill_manifest(target)
    (target / "references" / "facts.md").write_bytes(b"fact")
    no_final_newline = hashing.build_skill_manifest(target)
    path = target / "references" / "facts.md"
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    executable = hashing.build_skill_manifest(target)

    assert len({first.digest, crlf.digest, no_final_newline.digest, executable.digest}) == 4
    assert _entry(first, "references/facts.md").digest == (
        "sha256:" + hashlib.sha256(b"fact\n").hexdigest()
    )
    assert _entry(executable, "references/facts.md").executable is True


def test_manifest_does_not_bind_non_executable_permission_bits(tmp_path: Path) -> None:
    """The normative mode field is one executable bit, not a full Unix mode."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill")
    path = target / "references" / "facts.md"
    path.chmod(0o600)
    private = hashing.build_skill_manifest(target)
    path.chmod(0o644)

    assert hashing.build_skill_manifest(target) == private


def test_manifest_is_deterministic_canonical_json_with_utf8_path_order(tmp_path: Path) -> None:
    """Directory enumeration order must not change canonical manifest bytes."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill")
    (target / "references" / "z.md").write_bytes(b"z")
    (target / "references" / "ä.md").write_bytes(b"a")
    manifest = hashing.build_skill_manifest(target)

    expected_paths = sorted(
        ["SKILL.md", "skill-contract.json", "references/facts.md", "references/z.md", "references/ä.md"],
        key=lambda value: value.encode("utf-8"),
    )
    assert [entry.path for entry in manifest.entries] == expected_paths
    assert manifest.canonical_bytes == hashing.canonical_json_bytes(manifest.to_mapping())
    assert manifest.digest == "sha256:" + hashlib.sha256(manifest.canonical_bytes).hexdigest()
    assert hashing.build_skill_manifest(target) == manifest


def test_manifest_nfd_only_locator_canonicalizes_equal_to_nfc_root(tmp_path: Path) -> None:
    """A lone decomposed locator has the same canonical identity as its NFC spelling."""
    hashing = _hashing()
    nfc = "café.md"
    nfd = unicodedata.normalize("NFD", nfc)
    left = _skill(tmp_path / "left")
    right = _skill(tmp_path / "right")
    (left / "references" / nfc).write_bytes(b"same")
    (right / "references" / nfd).write_bytes(b"same")

    assert hashing.build_skill_manifest(left) == hashing.build_skill_manifest(right)


@pytest.mark.parametrize("names", [("café.md", unicodedata.normalize("NFD", "café.md")), ("Fact.md", "fact.md")])
def test_manifest_rejects_normalization_and_casefold_collisions(
    tmp_path: Path, names: tuple[str, str]
) -> None:
    """Two filesystem names may never collapse to one canonical locator."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill")
    for index, name in enumerate(names):
        (target / "references" / name).write_bytes(str(index).encode())

    actual = [item.name for item in (target / "references").iterdir() if item.name != "facts.md"]
    if len(actual) == 2:
        with pytest.raises(hashing.ManifestError, match="collision"):
            hashing.build_skill_manifest(target)
    else:
        # The default macOS volume collapses case/NFC-equivalent names before
        # Python can observe two directory entries. Exercise the same closed
        # manifest admission boundary directly on that platform.
        digest = "sha256:" + "a" * 64
        entries = (
            hashing.ManifestEntry(
                path="references/" + unicodedata.normalize("NFC", names[0]),
                type="regular-file",
                byte_size=1,
                executable=False,
                digest=digest,
            ),
            hashing.ManifestEntry(
                path="references/" + unicodedata.normalize("NFC", names[1]),
                type="regular-file",
                byte_size=1,
                executable=False,
                digest=digest,
            ),
        )
        with pytest.raises(hashing.ManifestError, match="collision"):
            hashing.SkillManifest(
                tuple(sorted(entries, key=lambda item: item.path.encode("utf-8")))
            )


def test_manifest_excludes_only_declared_generated_and_runtime_files(tmp_path: Path) -> None:
    """Generated caches and env runtime data cannot perturb the normative manifest."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill")
    original = hashing.build_skill_manifest(target)
    cache = target / "scripts" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "worker.cpython-314.pyc").write_bytes(b"generated")
    (target / "scripts" / ".pytest_cache").mkdir()
    (target / "scripts" / ".pytest_cache" / "state").write_bytes(b"generated")
    (target / "references" / ".env").write_bytes(b"TOKEN=not-persisted")
    (target / "references" / ".DS_Store").write_bytes(b"generated")

    assert hashing.build_skill_manifest(target) == original


def test_manifest_records_safe_internal_symlink_text_without_following(tmp_path: Path) -> None:
    """A safe symlink is represented by its exact link text, never target bytes."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill")
    link = target / "references" / "alias.md"
    link.symlink_to("facts.md")
    manifest = hashing.build_skill_manifest(target)
    entry = _entry(manifest, "references/alias.md")

    assert entry.type == "symlink"
    assert entry.byte_size == len(b"facts.md")
    assert entry.digest == "sha256:" + hashlib.sha256(b"facts.md").hexdigest()
    assert entry.executable is False


def test_manifest_binds_different_symlink_text_with_same_resolution(tmp_path: Path) -> None:
    """Two link spellings that resolve to one file still have distinct manifests."""
    hashing = _hashing()
    left = _skill(tmp_path / "left")
    right = _skill(tmp_path / "right")
    (left / "references" / "alias.md").symlink_to("facts.md")
    (right / "references" / "alias.md").symlink_to("./facts.md")

    assert hashing.build_skill_manifest(left).digest != hashing.build_skill_manifest(right).digest


@pytest.mark.parametrize("target_text", ["../../outside", "/etc/passwd", "missing.md", "../.env"])
def test_manifest_rejects_symlink_escape_absolute_broken_or_excluded_target(
    tmp_path: Path, target_text: str
) -> None:
    """Recorded links must resolve to an existing, included, in-root entry."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill")
    (target / "references" / "alias.md").symlink_to(target_text)

    with pytest.raises(hashing.ManifestError, match="symlink"):
        hashing.build_skill_manifest(target)


def test_manifest_rejects_symlink_cycles(tmp_path: Path) -> None:
    """A textual in-root cycle may not be admitted as a safe internal link."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill")
    (target / "references" / "a.md").symlink_to("b.md")
    (target / "references" / "b.md").symlink_to("a.md")

    with pytest.raises(hashing.ManifestError, match="symlink loop"):
        hashing.build_skill_manifest(target)


def test_manifest_rejects_root_alias_hardlinks_and_special_files(tmp_path: Path) -> None:
    """Alias roots and entries whose bytes are not exclusively owned fail closed."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill")
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(hashing.ManifestError, match="root"):
        hashing.build_skill_manifest(alias)

    hardlink = target / "references" / "hard.md"
    os.link(target / "references" / "facts.md", hardlink)
    with pytest.raises(hashing.ManifestError, match="hardlink"):
        hashing.build_skill_manifest(target)
    hardlink.unlink()

    fifo = target / "references" / "pipe"
    os.mkfifo(fifo)
    try:
        with pytest.raises(hashing.ManifestError, match="special"):
            hashing.build_skill_manifest(target)
    finally:
        fifo.unlink()


def test_manifest_rejects_missing_markers_and_filesystem_root(tmp_path: Path) -> None:
    """A broad directory cannot be reinterpreted as a skill root."""
    hashing = _hashing()
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(hashing.ManifestError, match="marker"):
        hashing.build_skill_manifest(empty)
    with pytest.raises(hashing.ManifestError, match="broad root"):
        hashing.build_skill_manifest(Path("/"))


def test_manifest_enforces_entry_byte_path_depth_and_stabilization_bounds(tmp_path: Path) -> None:
    """Each finite manifest resource bound has an observable fail-closed result."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill")
    (target / "references" / "deep").mkdir()
    (target / "references" / "deep" / "more.md").write_bytes(b"0123456789")

    cases = [
        (hashing.ManifestLimits(max_entries=2), "entry"),
        (hashing.ManifestLimits(max_total_bytes=5), "byte"),
        (hashing.ManifestLimits(max_path_bytes=5), "path"),
        (hashing.ManifestLimits(max_depth=1), "depth"),
        (hashing.ManifestLimits(stabilization_attempts=1), "stabil"),
    ]
    for limits, message in cases:
        with pytest.raises(hashing.ManifestError, match=message):
            hashing.build_skill_manifest(target, limits=limits)


def test_canonical_json_and_post_image_helpers_are_strict_and_raw_bound() -> None:
    """Canonical metadata and object refs reject ambiguous or mismatched bytes."""
    hashing = _hashing()
    assert hashing.canonical_json_bytes({"b": 1, "a": "é"}) == b'{"a":"\xc3\xa9","b":1}'
    for invalid in ({1: "x"}, {"x": float("nan")}, {"x": "\ud800"}, {"x": b"raw"}):
        with pytest.raises(hashing.ManifestError):
            hashing.canonical_json_bytes(invalid)

    payload = b"exact\r\nbytes"
    ref = hashing.post_image_ref(payload)
    assert ref == "object:sha256:" + hashlib.sha256(payload).hexdigest()
    assert hashing.verify_post_image(ref, payload) == payload
    with pytest.raises(hashing.ManifestError, match="post-image"):
        hashing.verify_post_image(ref, payload + b"!")


def test_digest_and_object_ref_helpers_reject_primitive_subclasses() -> None:
    """Overridden equality/encoding methods cannot participate in digest admission."""
    hashing = _hashing()

    class ForgedReference(str):
        def __ne__(self, _other):
            return False

    class ForgedBytes(bytes):
        pass

    class ForgedString(str):
        def encode(self, *_args, **_kwargs):
            return b"forged"

    payload = b"exact"
    wrong = ForgedReference("object:sha256:" + "0" * 64)
    with pytest.raises(hashing.ManifestError, match="post-image"):
        hashing.verify_post_image(wrong, payload)
    with pytest.raises(hashing.ManifestError, match="bytes"):
        hashing.raw_sha256(ForgedBytes(payload))
    with pytest.raises(hashing.ManifestError, match="unsupported|canonical"):
        hashing.canonical_json_bytes({"value": ForgedString("text")})


def test_artifact_replacement_binds_path_bytes_mode_diff_and_whole_manifests(tmp_path: Path) -> None:
    """A one-file replacement produces an exact, versioned pre/post descriptor."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill", note=b"before\n")
    before = hashing.build_skill_manifest(target)
    replacement = hashing.ArtifactReplacement.build(
        relative_path="references/facts.md",
        pre_bytes=b"before\n",
        post_bytes=b"after\r\n",
        executable=False,
    )
    after = hashing.manifest_with_replacement(before, replacement)

    assert replacement.pre_hash == "sha256:" + hashlib.sha256(b"before\n").hexdigest()
    assert replacement.post_hash == "sha256:" + hashlib.sha256(b"after\r\n").hexdigest()
    expected_diff = {
        "domain": "rsi-artifact-replacement-v1",
        "executable": False,
        "path": "references/facts.md",
        "postHash": replacement.post_hash,
        "postByteSize": len(b"after\r\n"),
        "preHash": replacement.pre_hash,
        "schemaVersion": 1,
    }
    assert replacement.diff_digest == (
        "sha256:" + hashlib.sha256(
            json.dumps(expected_diff, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    assert before.digest != after.digest
    assert _entry(after, "references/facts.md").digest == replacement.post_hash

    with pytest.raises(hashing.ManifestError, match="pre-image"):
        hashing.manifest_with_replacement(
            before,
            hashing.ArtifactReplacement.build(
                relative_path="references/facts.md",
                pre_bytes=b"wrong",
                post_bytes=b"after",
                executable=False,
            ),
        )


def test_direct_artifact_replacement_cannot_forge_diff_or_post_size(tmp_path: Path) -> None:
    """Typed replacement objects receive the same closed semantic re-admission as bytes."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill", note=b"before\n")
    manifest = hashing.build_skill_manifest(target)
    valid = hashing.ArtifactReplacement.build(
        relative_path="references/facts.md",
        pre_bytes=b"before\n",
        post_bytes=b"after\n",
        executable=False,
    )
    for field, value in (
        ("diff_digest", "sha256:" + "f" * 64),
        ("post_byte_size", 999),
        ("executable", True),
    ):
        forged = object.__new__(hashing.ArtifactReplacement)
        for name in (
            "relative_path", "pre_hash", "post_hash", "executable", "diff_digest", "post_byte_size"
        ):
            object.__setattr__(forged, name, value if name == field else getattr(valid, name))
        with pytest.raises(hashing.ManifestError, match="replacement|diff|size|pre-image"):
            hashing.manifest_with_replacement(manifest, forged)


def test_direct_skill_manifest_rejects_bool_schema_and_mutable_fake_entries() -> None:
    """The manifest digest cannot depend on an unvalidated mutable duck type."""
    hashing = _hashing()
    entry = hashing.ManifestEntry(
        "SKILL.md", "regular-file", 1, False, "sha256:" + "a" * 64
    )
    with pytest.raises(hashing.ManifestError, match="schema"):
        hashing.SkillManifest((entry,), schema_version=True)

    class MutableEntry:
        path = "SKILL.md"
        type = "regular-file"
        byte_size = 1
        executable = False
        digest = "sha256:" + "a" * 64

        def to_mapping(self):
            return {
                "path": self.path,
                "type": self.type,
                "byteSize": self.byte_size,
                "executable": self.executable,
                "digest": self.digest,
            }

    with pytest.raises(hashing.ManifestError, match="entry"):
        hashing.SkillManifest((MutableEntry(),))


def test_direct_skill_manifest_enforces_markers_and_managed_set_domain() -> None:
    """A handcrafted manifest cannot omit/alias markers or add unmanaged locators."""
    hashing = _hashing()
    skill = hashing.ManifestEntry(
        "SKILL.md", "regular-file", 1, False, "sha256:" + "a" * 64
    )
    contract = hashing.ManifestEntry(
        "skill-contract.json", "regular-file", 1, False, "sha256:" + "b" * 64
    )
    symlink_skill = hashing.ManifestEntry(
        "SKILL.md", "symlink", 8, False, "sha256:" + "c" * 64
    )
    unmanaged = (
        hashing.ManifestEntry("random.md", "regular-file", 1, False, "sha256:" + "d" * 64),
        hashing.ManifestEntry("unknown/x", "regular-file", 1, False, "sha256:" + "e" * 64),
        hashing.ManifestEntry("references/.env", "regular-file", 1, False, "sha256:" + "f" * 64),
        hashing.ManifestEntry(".env", "regular-file", 1, False, "sha256:" + "1" * 64),
        hashing.ManifestEntry("references", "regular-file", 1, False, "sha256:" + "2" * 64),
        hashing.ManifestEntry(
            "scripts/__pycache__/x.pyc", "regular-file", 1, False, "sha256:" + "3" * 64
        ),
    )
    cases = [
        (skill,),
        (contract,),
        (symlink_skill, contract),
        (skill, contract, unmanaged[0]),
        (skill, contract, unmanaged[1]),
        (skill, contract, unmanaged[2]),
        (skill, contract, unmanaged[3]),
        (skill, contract, unmanaged[4]),
        (skill, contract, unmanaged[5]),
    ]
    for entries in cases:
        with pytest.raises(hashing.ManifestError, match="marker|contract|managed|excluded"):
            hashing.SkillManifest(
                tuple(sorted(entries, key=lambda entry: entry.path.encode("utf-8")))
            )


def test_skill_manifest_defensively_owns_entry_snapshot() -> None:
    """Mutating a caller-owned frozen entry escape hatch cannot alter manifest identity."""
    hashing = _hashing()
    skill = hashing.ManifestEntry(
        "SKILL.md", "regular-file", 1, False, "sha256:" + "a" * 64
    )
    contract = hashing.ManifestEntry(
        "skill-contract.json", "regular-file", 2, False, "sha256:" + "b" * 64
    )
    manifest = hashing.SkillManifest((skill, contract))
    before_bytes = manifest.canonical_bytes
    before_digest = manifest.digest

    object.__setattr__(skill, "digest", "sha256:" + "c" * 64)

    assert manifest.entries[0] is not skill
    assert manifest.canonical_bytes == before_bytes
    assert manifest.digest == before_digest


def test_manifest_replacement_rejects_post_construction_manifest_mutation(
    tmp_path: Path,
) -> None:
    """Exact-class identity is insufficient after an internal entry was forged."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill", note=b"before")
    manifest = hashing.build_skill_manifest(target)
    replacement = hashing.ArtifactReplacement.build(
        relative_path="references/facts.md",
        pre_bytes=b"before",
        post_bytes=b"after",
        executable=False,
    )
    marker = next(entry for entry in manifest.entries if entry.path == "SKILL.md")
    object.__setattr__(marker, "digest", "sha256:" + "9" * 64)

    assert hashing.canonical_json_digest(manifest.to_mapping()) == manifest.digest
    with pytest.raises(hashing.ManifestError, match="manifest|snapshot|mutation"):
        hashing.manifest_with_replacement(manifest, replacement)


def test_artifact_replacement_rejects_equality_overriding_digest_subclass() -> None:
    """A string subclass cannot forge closed diff-digest equality semantics."""
    hashing = _hashing()
    valid = hashing.ArtifactReplacement.build(
        relative_path="references/facts.md",
        pre_bytes=b"before",
        post_bytes=b"after",
        executable=False,
    )

    class ForgedDigest(str):
        def __ne__(self, _other):
            return False

    with pytest.raises(hashing.ManifestError, match="diff|digest"):
        hashing.ArtifactReplacement(
            valid.relative_path,
            valid.pre_hash,
            valid.post_hash,
            valid.executable,
            ForgedDigest("sha256:" + "f" * 64),
            valid.post_byte_size,
        )


def test_deep_json_and_long_symlink_chain_fail_typed_not_recursion_error(tmp_path: Path) -> None:
    """Attacker-controlled nesting and link chains are explicitly bounded."""
    hashing = _hashing()
    nested: object = None
    for _ in range(1100):
        nested = [nested]
    with pytest.raises(hashing.ManifestError, match="depth|nested"):
        hashing.canonical_json_bytes(nested)

    target = _skill(tmp_path / "skill")
    references = target / "references"
    for index in range(1100):
        destination = f"link-{index + 1}.md" if index < 1099 else "facts.md"
        (references / f"link-{index}.md").symlink_to(destination)
    with pytest.raises(hashing.ManifestError, match="symlink.*bound|symlink.*depth"):
        hashing.build_skill_manifest(target)


@pytest.mark.parametrize("wrong_name", ["References", "SCRIPTS", "skill.md"])
def test_fixed_managed_names_require_exact_actual_spelling(
    tmp_path: Path, wrong_name: str
) -> None:
    """Case-insensitive lookup cannot silently rename a normative managed locator."""
    hashing = _hashing()
    root = tmp_path / "skill"
    root.mkdir()
    (root / "SKILL.md").write_bytes(b"skill\n")
    (root / "skill-contract.json").write_bytes(b"{}\n")
    if wrong_name == "skill.md":
        (root / "SKILL.md").rename(root / wrong_name)
    else:
        (root / wrong_name).mkdir()
        (root / wrong_name / "fact.md").write_bytes(b"fact")
    with pytest.raises(hashing.ManifestError, match="spelling|collision|marker"):
        hashing.build_skill_manifest(root)


def test_skill_root_final_component_requires_exact_actual_spelling(tmp_path: Path) -> None:
    """A case-only root alias is not a canonical root identity."""
    hashing = _hashing()
    actual = _skill(tmp_path / "SkillRoot")
    alias = actual.with_name("skillroot")
    with pytest.raises(hashing.ManifestError, match="root|spelling|unavailable"):
        hashing.build_skill_manifest(alias)


def test_ancestry_component_swap_between_stat_and_open_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every opened root component must match the exact inode inspected beforehand."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill", note=b"original")
    replacement = _skill(tmp_path / "replacement", note=b"replacement")
    displaced = tmp_path / "displaced"
    real_open = hashing.os.open
    swapped = False

    def racing_open(name, flags, *args, **kwargs):
        nonlocal swapped
        if name == target.name and kwargs.get("dir_fd") is not None and not swapped:
            swapped = True
            target.rename(displaced)
            replacement.rename(target)
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(hashing.os, "open", racing_open)
    with pytest.raises(hashing.ManifestError, match="root|topology|changed"):
        hashing.build_skill_manifest(target)


def test_exact_ancestry_name_with_casefold_equivalent_sibling_is_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exact root component does not excuse a colliding case-only sibling."""
    hashing = _hashing()

    class Entry:
        def __init__(self, name: str) -> None:
            self.name = name

    class Scan:
        def __enter__(self):
            return iter((Entry("SkillRoot"), Entry("skillroot")))

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(hashing.os, "dup", lambda descriptor: descriptor)
    monkeypatch.setattr(hashing.os, "scandir", lambda _descriptor: Scan())
    assert hashing._find_exact_directory_name(123, "SkillRoot") == (True, True)


def test_empty_directories_count_toward_manifest_resource_bounds(tmp_path: Path) -> None:
    """An empty-directory tree cannot allocate an unbounded witness off-budget."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill")
    for index in range(20):
        (target / "references" / f"empty-{index:02d}").mkdir()
    with pytest.raises(hashing.ManifestError, match="entry|record"):
        hashing.build_skill_manifest(
            target,
            limits=hashing.ManifestLimits(max_entries=10),
        )


def test_directory_enumeration_is_bounded_before_name_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Excluded/unmanaged entries cannot force an unbounded pre-check list allocation."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill")
    references = target / "references"
    for index in range(20):
        (references / f"cache-{index:02d}.pyc").write_bytes(b"cache")

    real_scandir = hashing.os.scandir
    reference_identity = (references.stat().st_dev, references.stat().st_ino)
    consumed = 0

    class CountingScandir:
        def __init__(self, inner):
            self.inner = inner
            self.iterator = None

        def __enter__(self):
            nonlocal consumed
            self.iterator = iter(self.inner.__enter__())
            return self

        def __iter__(self):
            return self

        def __next__(self):
            nonlocal consumed
            consumed += 1
            if consumed > 7:
                raise AssertionError("directory enumeration exceeded its declared bound")
            return next(self.iterator)

        def __exit__(self, *args):
            return self.inner.__exit__(*args)

    def guarded_scandir(path):
        inner = real_scandir(path)
        if isinstance(path, int):
            metadata = os.fstat(path)
            if (metadata.st_dev, metadata.st_ino) == reference_identity:
                return CountingScandir(inner)
        return inner

    monkeypatch.setattr(hashing.os, "scandir", guarded_scandir)
    with pytest.raises(hashing.ManifestError, match="entry|record|enumer"):
        hashing.build_skill_manifest(
            target,
            limits=hashing.ManifestLimits(max_entries=6),
        )
    assert consumed <= 7


def test_growth_after_stat_cannot_bypass_max_file_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The opened descriptor size, not only a stale pathname stat, is bounded."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill", note=b"x")
    real_open = hashing.os.open
    grown = False

    def racing_open(name, flags, *args, **kwargs):
        nonlocal grown
        if name == "facts.md" and kwargs.get("dir_fd") is not None and not grown:
            grown = True
            (target / "references" / "facts.md").write_bytes(b"012345")
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(hashing.os, "open", racing_open)
    with pytest.raises(hashing.ManifestError, match="byte bound|changed"):
        hashing.build_skill_manifest(
            target,
            limits=hashing.ManifestLimits(max_file_bytes=5),
        )


def test_regular_to_fifo_swap_is_nonblocking_and_fails_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A type-swap race cannot block the scanner on a FIFO open."""
    hashing = _hashing()
    target = _skill(tmp_path / "skill")
    real_open = hashing.os.open
    swapped = False

    def racing_open(name, flags, *args, **kwargs):
        nonlocal swapped
        if name == "facts.md" and kwargs.get("dir_fd") is not None and not swapped:
            if not flags & getattr(os, "O_NONBLOCK", 0):
                raise AssertionError("regular-file no-follow open omitted O_NONBLOCK")
            swapped = True
            path = target / "references" / "facts.md"
            path.unlink()
            os.mkfifo(path)
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(hashing.os, "open", racing_open)
    with pytest.raises(hashing.ManifestError, match="changed|unsafe|file"):
        hashing.build_skill_manifest(target)
