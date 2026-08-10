"""Canonical Task 7 skill manifests and exact artifact byte bindings.

This digest domain is deliberately different from Task 6's full-tree target
identity.  It implements the managed-set contract from specification 12.10.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
import unicodedata
from typing import Mapping, Sequence


class ManifestError(ValueError):
    """A filesystem tree or canonical object cannot be represented safely."""


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OBJECT_REF_RE = re.compile(r"object:sha256:([0-9a-f]{64})\Z")
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_MANAGED_FILES = ("SKILL.md", "skill-contract.json")
_MANAGED_DIRECTORIES = ("agents", "profiles", "references", "scripts", "tests")
_EXCLUDED_DIRECTORIES = frozenset(
    {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis", ".git"}
)
_EXCLUDED_FILES = frozenset(
    {
        ".DS_Store",
        ".env",
        "credentials",
        "credentials.json",
        ".credentials",
        "secrets.json",
    }
)


_MAX_CANONICAL_JSON_DEPTH = 64
_MAX_ANCESTRY_DIRECTORY_ENTRIES = 65_536


def _validate_json(
    value: object, *, depth: int = 0, ancestors: set[int] | None = None
) -> None:
    if depth > _MAX_CANONICAL_JSON_DEPTH:
        raise ManifestError("canonical JSON exceeds its nested depth bound")
    if value is None or type(value) in {bool, int}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ManifestError("canonical JSON contains a non-finite number")
        return
    if type(value) is str:
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise ManifestError("canonical JSON contains invalid Unicode") from None
        return
    if isinstance(value, Mapping):
        seen = set() if ancestors is None else ancestors
        identity = id(value)
        if identity in seen:
            raise ManifestError("canonical JSON contains a nested cycle")
        seen.add(identity)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ManifestError("canonical JSON keys must be strings")
                _validate_json(key, depth=depth + 1, ancestors=seen)
                _validate_json(item, depth=depth + 1, ancestors=seen)
        finally:
            seen.remove(identity)
        return
    if isinstance(value, (list, tuple)):
        seen = set() if ancestors is None else ancestors
        identity = id(value)
        if identity in seen:
            raise ManifestError("canonical JSON contains a nested cycle")
        seen.add(identity)
        try:
            for item in value:
                _validate_json(item, depth=depth + 1, ancestors=seen)
        finally:
            seen.remove(identity)
        return
    raise ManifestError("canonical JSON contains an unsupported value")


def canonical_json_bytes(value: object) -> bytes:
    """Return strict RFC-8259-style canonical UTF-8 JSON bytes."""
    _validate_json(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ManifestError("value cannot be encoded as canonical JSON") from None


def raw_sha256(payload: bytes) -> str:
    if type(payload) is not bytes:
        raise ManifestError("raw digest input must be bytes")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def canonical_json_digest(value: object) -> str:
    return raw_sha256(canonical_json_bytes(value))


@dataclass(frozen=True, slots=True)
class ManifestLimits:
    max_entries: int = 4096
    max_total_bytes: int = 64 * 1024 * 1024
    max_file_bytes: int = 16 * 1024 * 1024
    max_path_bytes: int = 4 * 1024 * 1024
    max_depth: int = 32
    stabilization_attempts: int = 3
    max_symlink_hops: int = 64

    def __post_init__(self) -> None:
        for value in (
            self.max_entries,
            self.max_total_bytes,
            self.max_file_bytes,
            self.max_path_bytes,
            self.max_depth,
            self.stabilization_attempts,
            self.max_symlink_hops,
        ):
            if type(value) is not int or value < 1:
                raise ManifestError("manifest limits must be positive integers")


def _canonical_locator(value: str) -> str:
    if type(value) is not str:
        raise ManifestError("manifest path is invalid")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise ManifestError("manifest path is not valid UTF-8") from None
    normalized = unicodedata.normalize("NFC", value)
    path = PurePosixPath(normalized)
    if (
        not normalized
        or "\x00" in normalized
        or normalized.startswith("/")
        or "\\" in normalized
        or str(path) != normalized
        or any(part in {"", ".", ".."} for part in normalized.split("/"))
    ):
        raise ManifestError("manifest path is unsafe")
    return normalized


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    path: str
    type: str
    byte_size: int
    executable: bool
    digest: str

    def __post_init__(self) -> None:
        if type(self.path) is not str or type(self.type) is not str or type(self.digest) is not str:
            raise ManifestError("manifest entry scalar type is invalid")
        canonical = _canonical_locator(self.path)
        if canonical != self.path:
            raise ManifestError("manifest entry path is not NFC canonical")
        if self.type not in {"regular-file", "symlink"}:
            raise ManifestError("manifest entry type is invalid")
        if type(self.byte_size) is not int or self.byte_size < 0:
            raise ManifestError("manifest entry size is invalid")
        if type(self.executable) is not bool or (
            self.type == "symlink" and self.executable is not False
        ):
            raise ManifestError("manifest entry executable bit is invalid")
        if _DIGEST_RE.fullmatch(self.digest) is None:
            raise ManifestError("manifest entry digest is invalid")

    def to_mapping(self) -> dict[str, object]:
        return {
            "path": self.path,
            "type": self.type,
            "byteSize": self.byte_size,
            "executable": self.executable,
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class SkillManifest:
    entries: tuple[ManifestEntry, ...]
    schema_version: int = 1
    _canonical_snapshot: bytes = field(init=False, repr=False, compare=False)
    _snapshot_digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ManifestError("skill manifest schema version is invalid")
        if type(self.entries) is not tuple or any(
            type(entry) is not ManifestEntry for entry in self.entries
        ):
            raise ManifestError("skill manifest entry is invalid")
        owned_entries = tuple(
            ManifestEntry(
                entry.path,
                entry.type,
                entry.byte_size,
                entry.executable,
                entry.digest,
            )
            for entry in self.entries
        )
        object.__setattr__(self, "entries", owned_entries)
        paths = [entry.path for entry in owned_entries]
        if paths != sorted(paths, key=lambda value: value.encode("utf-8")):
            raise ManifestError("skill manifest entries are not canonically ordered")
        if len(paths) != len(set(paths)) or len(paths) != len({path.casefold() for path in paths}):
            raise ManifestError("skill manifest contains a path collision")
        for entry in owned_entries:
            parts = entry.path.split("/")
            if entry.path in _MANAGED_FILES:
                continue
            if (
                len(parts) < 2
                or parts[0] not in _MANAGED_DIRECTORIES
                or any(part in _EXCLUDED_DIRECTORIES for part in parts[1:-1])
                or _is_excluded(parts[-1], directory=False)
            ):
                raise ManifestError("skill manifest entry is outside the managed or excluded domain")
        by_path = {entry.path: entry for entry in owned_entries}
        if any(
            marker not in by_path or by_path[marker].type != "regular-file"
            for marker in _MANAGED_FILES
        ):
            raise ManifestError("skill manifest required markers must be regular files")
        snapshot = canonical_json_bytes(
            {
                "schemaVersion": self.schema_version,
                "domain": "rsi-skill-manifest-v1",
                "algorithm": "sha256",
                "entries": [entry.to_mapping() for entry in owned_entries],
            }
        )
        object.__setattr__(self, "_canonical_snapshot", snapshot)
        object.__setattr__(self, "_snapshot_digest", raw_sha256(snapshot))

    def _live_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "domain": "rsi-skill-manifest-v1",
            "algorithm": "sha256",
            "entries": [entry.to_mapping() for entry in self.entries],
        }

    def to_mapping(self) -> dict[str, object]:
        """Return a fresh view of the immutable construction-time snapshot."""

        try:
            value = json.loads(self._canonical_snapshot)
        except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
            raise ManifestError("skill manifest snapshot is invalid") from None
        if not isinstance(value, dict):
            raise ManifestError("skill manifest snapshot is invalid")
        return value

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_snapshot

    @property
    def digest(self) -> str:
        return self._snapshot_digest


@dataclass(frozen=True, slots=True)
class ArtifactReplacement:
    relative_path: str
    pre_hash: str
    post_hash: str
    executable: bool
    diff_digest: str
    post_byte_size: int

    def __post_init__(self) -> None:
        path = _canonical_locator(self.relative_path)
        if path != self.relative_path:
            raise ManifestError("artifact replacement path is not canonical")
        if (
            type(self.pre_hash) is not str
            or _DIGEST_RE.fullmatch(self.pre_hash) is None
            or type(self.post_hash) is not str
            or _DIGEST_RE.fullmatch(self.post_hash) is None
            or type(self.diff_digest) is not str
            or _DIGEST_RE.fullmatch(self.diff_digest) is None
            or type(self.executable) is not bool
            or type(self.post_byte_size) is not int
            or self.post_byte_size < 0
        ):
            raise ManifestError("artifact replacement digest, hash, or size is invalid")
        semantic = {
            "schemaVersion": 1,
            "domain": "rsi-artifact-replacement-v1",
            "path": path,
            "preHash": self.pre_hash,
            "postHash": self.post_hash,
            "postByteSize": self.post_byte_size,
            "executable": self.executable,
        }
        if self.diff_digest != canonical_json_digest(semantic):
            raise ManifestError("artifact replacement diff digest is invalid")

    @classmethod
    def build(
        cls,
        *,
        relative_path: str,
        pre_bytes: bytes,
        post_bytes: bytes,
        executable: bool,
    ) -> "ArtifactReplacement":
        path = _canonical_locator(relative_path)
        if not isinstance(pre_bytes, bytes) or not isinstance(post_bytes, bytes):
            raise ManifestError("artifact replacement images must be bytes")
        if type(executable) is not bool:
            raise ManifestError("artifact replacement executable bit is invalid")
        pre_hash = raw_sha256(pre_bytes)
        post_hash = raw_sha256(post_bytes)
        semantic = {
            "schemaVersion": 1,
            "domain": "rsi-artifact-replacement-v1",
            "path": path,
            "preHash": pre_hash,
            "postHash": post_hash,
            "postByteSize": len(post_bytes),
            "executable": executable,
        }
        return cls(
            path,
            pre_hash,
            post_hash,
            executable,
            canonical_json_digest(semantic),
            len(post_bytes),
        )


def manifest_with_replacement(
    manifest: SkillManifest, replacement: ArtifactReplacement
) -> SkillManifest:
    if type(manifest) is not SkillManifest or type(replacement) is not ArtifactReplacement:
        raise ManifestError("artifact replacement binding is invalid")
    try:
        current_manifest_bytes = canonical_json_bytes(manifest._live_mapping())
        if (
            type(manifest._canonical_snapshot) is not bytes
            or type(manifest._snapshot_digest) is not str
            or current_manifest_bytes != manifest._canonical_snapshot
            or raw_sha256(manifest._canonical_snapshot) != manifest._snapshot_digest
        ):
            raise ManifestError("skill manifest snapshot was mutated")
    except (ManifestError, AttributeError, TypeError, ValueError):
        raise ManifestError("skill manifest snapshot is invalid or mutated") from None
    # Recompute the closed descriptor so object.__new__/deserialization cannot
    # bypass the frozen dataclass constructor.
    try:
        replacement.__post_init__()
    except (ManifestError, AttributeError, TypeError, ValueError):
        raise ManifestError("artifact replacement binding is invalid") from None
    if not isinstance(manifest, SkillManifest) or not isinstance(
        replacement, ArtifactReplacement
    ):
        raise ManifestError("artifact replacement binding is invalid")
    matches = [entry for entry in manifest.entries if entry.path == replacement.relative_path]
    if len(matches) != 1 or matches[0].type != "regular-file":
        raise ManifestError("artifact replacement target is not one regular file")
    before = matches[0]
    if before.digest != replacement.pre_hash or before.executable != replacement.executable:
        raise ManifestError("artifact replacement pre-image does not match the manifest")
    entries = tuple(
        ManifestEntry(
            path=entry.path,
            type=entry.type,
            byte_size=replacement.post_byte_size,
            executable=entry.executable,
            digest=replacement.post_hash,
        )
        if entry.path == replacement.relative_path
        else entry
        for entry in manifest.entries
    )
    return SkillManifest(entries)


def post_image_ref(payload: bytes) -> str:
    return "object:" + raw_sha256(payload)


def verify_post_image(reference: str, payload: bytes) -> bytes:
    if (
        type(reference) is not str
        or _OBJECT_REF_RE.fullmatch(reference) is None
        or type(payload) is not bytes
        or post_image_ref(payload) != reference
    ):
        raise ManifestError("post-image reference does not match exact bytes")
    return payload


@dataclass(frozen=True, slots=True)
class _ScanResult:
    entries: tuple[ManifestEntry, ...]
    witness: tuple[tuple[object, ...], ...]


@dataclass(slots=True)
class _Ancestry:
    descriptors: list[int]
    names: list[str]

    @property
    def leaf(self) -> int:
        return self.descriptors[-1]

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)


def _find_exact_directory_name(parent: int, expected: str) -> tuple[bool, bool]:
    """Find exact/equivalent names with a fixed bound and constant memory."""

    exact = False
    conflicting_equivalent = False
    expected_folded = unicodedata.normalize("NFC", expected).casefold()
    try:
        with os.scandir(os.dup(parent)) as iterator:
            for count, entry in enumerate(iterator, start=1):
                if count > _MAX_ANCESTRY_DIRECTORY_ENTRIES:
                    raise ManifestError("skill root ancestry enumeration bound exceeded")
                actual = entry.name
                if actual == expected:
                    exact = True
                elif unicodedata.normalize("NFC", actual).casefold() == expected_folded:
                    conflicting_equivalent = True
    except OSError as error:
        raise ManifestError("skill root ancestry cannot be enumerated safely") from error
    return exact, conflicting_equivalent


def _open_root(path: Path | str) -> tuple[Path, _Ancestry]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    broad = {Path(absolute.anchor), Path.home(), Path.cwd()}
    if absolute in broad:
        raise ManifestError("broad root cannot be used as a skill")
    descriptors: list[int] = []
    names: list[str] = []
    try:
        descriptors.append(os.open(absolute.anchor, os.O_RDONLY | _DIRECTORY))
        for part in absolute.parts[1:]:
            exact, conflicting_equivalent = _find_exact_directory_name(
                descriptors[-1], part
            )
            if not exact:
                if conflicting_equivalent:
                    raise ManifestError("skill root ancestry spelling is not canonical")
                raise ManifestError("skill root is unavailable")
            if conflicting_equivalent:
                raise ManifestError("skill root ancestry spelling is ambiguous")
            try:
                metadata = os.stat(part, dir_fd=descriptors[-1], follow_symlinks=False)
            except OSError as error:
                raise ManifestError("skill root is unavailable") from error
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ManifestError("skill root uses an unsafe alias or topology")
            try:
                child = os.open(
                    part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=descriptors[-1]
                )
            except OSError as error:
                raise ManifestError("skill root cannot be opened without following links") from error
            opened = os.fstat(child)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            ):
                os.close(child)
                raise ManifestError("skill root topology changed between stat and open")
            descriptors.append(child)
            names.append(part)
        return absolute, _Ancestry(descriptors, names)
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _assert_ancestry(ancestry: _Ancestry) -> None:
    for index, name in enumerate(ancestry.names):
        try:
            exact, conflicting_equivalent = _find_exact_directory_name(
                ancestry.descriptors[index], name
            )
            if not exact or conflicting_equivalent:
                raise ManifestError("skill root ancestry spelling changed during manifest scan")
            named = os.stat(name, dir_fd=ancestry.descriptors[index], follow_symlinks=False)
            opened = os.fstat(ancestry.descriptors[index + 1])
        except OSError as error:
            raise ManifestError("skill root topology changed during manifest scan") from error
        if (
            not stat.S_ISDIR(named.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ManifestError("skill root topology changed during manifest scan")


def _metadata_witness(relative: str, metadata: os.stat_result) -> tuple[object, ...]:
    return (
        relative,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        bool(metadata.st_mode & 0o111),
    )


def _is_excluded(name: str, *, directory: bool) -> bool:
    if directory:
        return name in _EXCLUDED_DIRECTORIES
    lower = name.casefold()
    return (
        name in _EXCLUDED_FILES
        or lower.endswith((".pyc", ".pyo"))
        or lower == ".env"
        or lower.startswith(".env.")
    )


def _read_regular(
    parent: int,
    name: str,
    expected: os.stat_result,
    relative: str,
    limits: ManifestLimits,
) -> tuple[ManifestEntry, tuple[object, ...]]:
    if expected.st_nlink != 1:
        raise ManifestError("managed regular file is an unsafe hardlink")
    if expected.st_size < 0 or expected.st_size > limits.max_file_bytes:
        raise ManifestError("managed file exceeds its byte bound")
    try:
        descriptor = os.open(
            name, os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=parent
        )
    except OSError as error:
        raise ManifestError("managed file cannot be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size < 0
            or opened.st_size > limits.max_file_bytes
            or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
        ):
            raise ManifestError("managed file changed or became an unsafe hardlink")
        remaining = limits.max_file_bytes + 1
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > limits.max_file_bytes:
            raise ManifestError("managed file exceeds its byte bound")
        after = os.fstat(descriptor)
        stable_fields = (
            opened.st_dev,
            opened.st_ino,
            opened.st_nlink,
            opened.st_size,
            opened.st_mode,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        after_fields = (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mode,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if stable_fields != after_fields:
            raise ManifestError("managed file changed during manifest scan")
        if len(payload) != after.st_size:
            raise ManifestError("managed file changed during manifest scan")
        return (
            ManifestEntry(
                relative,
                "regular-file",
                len(payload),
                bool(after.st_mode & 0o111),
                raw_sha256(payload),
            ),
            _metadata_witness(relative, after),
        )
    finally:
        os.close(descriptor)


def _scan_once(root: Path | str, limits: ManifestLimits) -> _ScanResult:
    _, ancestry = _open_root(root)
    root_descriptor = ancestry.leaf
    entries: list[ManifestEntry] = []
    witness: list[tuple[object, ...]] = [_metadata_witness("", os.fstat(root_descriptor))]
    locators: set[str] = set()
    folded: set[str] = set()
    path_bytes = 0
    total_bytes = 0
    record_count = 0

    def consume_record() -> None:
        nonlocal record_count
        record_count += 1
        if record_count > limits.max_entries:
            raise ManifestError("manifest entry/record enumeration bound exceeded")

    def admit_locator(raw_parts: Sequence[str]) -> str:
        nonlocal path_bytes
        raw = "/".join(raw_parts)
        locator = _canonical_locator(unicodedata.normalize("NFC", raw))
        encoded = locator.encode("utf-8")
        path_bytes += len(encoded)
        if path_bytes > limits.max_path_bytes:
            raise ManifestError("manifest path byte bound exceeded")
        folded_locator = locator.casefold()
        if locator in locators or folded_locator in folded:
            raise ManifestError("manifest path normalization/case-fold collision")
        locators.add(locator)
        folded.add(folded_locator)
        return locator

    def add_entry(entry: ManifestEntry, metadata_witness: tuple[object, ...]) -> None:
        nonlocal total_bytes
        if len(entries) + 1 > limits.max_entries:
            raise ManifestError("manifest entry bound exceeded")
        total_bytes += entry.byte_size
        if total_bytes > limits.max_total_bytes:
            raise ManifestError("manifest byte bound exceeded")
        entries.append(entry)
        witness.append(metadata_witness)

    def scan_named(
        parent: int,
        name: str,
        raw_parts: tuple[str, ...],
        depth: int,
        *,
        already_counted: bool = False,
    ) -> None:
        if depth > limits.max_depth:
            raise ManifestError("manifest depth bound exceeded")
        if not already_counted:
            consume_record()
        try:
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise ManifestError("managed entry cannot be inspected safely") from error
        locator = admit_locator(raw_parts)
        if stat.S_ISDIR(metadata.st_mode):
            if _is_excluded(name, directory=True):
                return
            try:
                child = os.open(name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=parent)
            except OSError as error:
                raise ManifestError("managed directory cannot be opened safely") from error
            try:
                opened = os.fstat(child)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                ):
                    raise ManifestError("managed directory changed during manifest scan")
                witness.append(_metadata_witness(locator, opened))
                try:
                    with os.scandir(os.dup(child)) as iterator:
                        names = []
                        for item in iterator:
                            consume_record()
                            names.append(item.name)
                    names.sort(key=lambda value: value.encode("utf-8", "strict"))
                except (OSError, UnicodeEncodeError) as error:
                    raise ManifestError("managed directory contains an invalid UTF-8 entry") from error
                for child_name in names:
                    try:
                        child_metadata = os.stat(
                            child_name, dir_fd=child, follow_symlinks=False
                        )
                    except OSError as error:
                        raise ManifestError("managed entry cannot be inspected safely") from error
                    if _is_excluded(
                        child_name, directory=stat.S_ISDIR(child_metadata.st_mode)
                    ):
                        continue
                    scan_named(
                        child,
                        child_name,
                        (*raw_parts, child_name),
                        depth + 1,
                        already_counted=True,
                    )
                rebound = os.stat(name, dir_fd=parent, follow_symlinks=False)
                still_open = os.fstat(child)
                if (
                    (rebound.st_dev, rebound.st_ino, rebound.st_mode, rebound.st_mtime_ns, rebound.st_ctime_ns)
                    != (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_mtime_ns, opened.st_ctime_ns)
                    or _metadata_witness(locator, still_open)
                    != _metadata_witness(locator, opened)
                ):
                    raise ManifestError("managed directory changed during manifest scan")
            finally:
                os.close(child)
            return
        if stat.S_ISREG(metadata.st_mode):
            entry, item_witness = _read_regular(parent, name, metadata, locator, limits)
            add_entry(entry, item_witness)
            return
        if stat.S_ISLNK(metadata.st_mode):
            try:
                link_text = os.readlink(name, dir_fd=parent)
                link_bytes = link_text.encode("utf-8", "strict")
                rebound = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except (OSError, UnicodeEncodeError) as error:
                raise ManifestError("managed symlink text is invalid") from error
            if (
                (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_mtime_ns, metadata.st_ctime_ns)
                != (rebound.st_dev, rebound.st_ino, rebound.st_mode, rebound.st_mtime_ns, rebound.st_ctime_ns)
            ):
                raise ManifestError("managed symlink changed during manifest scan")
            add_entry(
                ManifestEntry(locator, "symlink", len(link_bytes), False, raw_sha256(link_bytes)),
                (*_metadata_witness(locator, rebound), link_text),
            )
            return
        raise ManifestError("managed tree contains a special file")

    try:
        try:
            with os.scandir(os.dup(root_descriptor)) as iterator:
                root_names = []
                for entry in iterator:
                    consume_record()
                    root_names.append(entry.name)
        except (OSError, UnicodeEncodeError) as error:
            raise ManifestError("skill root cannot be enumerated safely") from error
        fixed = (*_MANAGED_FILES, *_MANAGED_DIRECTORIES)
        for expected_name in fixed:
            equivalents = [
                name
                for name in root_names
                if unicodedata.normalize("NFC", name).casefold()
                == unicodedata.normalize("NFC", expected_name).casefold()
            ]
            if equivalents and (len(equivalents) != 1 or equivalents[0] != expected_name):
                raise ManifestError("managed root entry spelling/collision is not canonical")
        for marker in _MANAGED_FILES:
            if marker not in root_names:
                raise ManifestError("required skill marker is missing")
            try:
                marker_metadata = os.stat(marker, dir_fd=root_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                raise ManifestError("required skill marker is missing") from None
            if not stat.S_ISREG(marker_metadata.st_mode):
                raise ManifestError("required skill marker is not a regular file")
            scan_named(root_descriptor, marker, (marker,), 1, already_counted=True)
        for directory in _MANAGED_DIRECTORIES:
            try:
                metadata = os.stat(directory, dir_fd=root_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                if stat.S_ISLNK(metadata.st_mode):
                    raise ManifestError("managed directory cannot be a symlink")
                raise ManifestError("managed directory is a special entry")
            scan_named(root_descriptor, directory, (directory,), 1, already_counted=True)
        _assert_ancestry(ancestry)
        if _metadata_witness("", os.fstat(root_descriptor)) != witness[0]:
            raise ManifestError("skill root changed during manifest scan")
    finally:
        ancestry.close()

    entries.sort(key=lambda entry: entry.path.encode("utf-8"))
    # Symlinks are validated after the full managed locator set is known.
    by_path = {entry.path: entry for entry in entries}
    link_text_by_path = {
        str(item[0]): str(item[-1])
        for item in witness
        if len(item) == 10 and item[0] in by_path and by_path[str(item[0])].type == "symlink"
    }

    def resolve_link(path: str) -> str:
        current = path
        seen: set[str] = set()
        for _ in range(limits.max_symlink_hops):
            if current in seen:
                raise ManifestError("managed symlink loop is forbidden")
            seen.add(current)
            text = link_text_by_path[current]
            if not text or "\x00" in text or text.startswith("/") or "\\" in text:
                raise ManifestError("managed symlink is absolute or malformed")
            parts = current.split("/")[:-1]
            for raw_part in text.split("/"):
                if raw_part in {"", "."}:
                    continue
                if raw_part == "..":
                    if not parts:
                        raise ManifestError("managed symlink escapes the skill root")
                    parts.pop()
                else:
                    try:
                        raw_part.encode("utf-8", "strict")
                    except UnicodeEncodeError:
                        raise ManifestError("managed symlink target is not valid UTF-8") from None
                    parts.append(unicodedata.normalize("NFC", raw_part))
            target = _canonical_locator("/".join(parts))
            target_entry = by_path.get(target)
            if target_entry is None:
                raise ManifestError("managed symlink target is missing, excluded, or unsafe")
            if target_entry.type != "symlink":
                return target
            current = target
        raise ManifestError("managed symlink depth bound exceeded")

    for link_path in link_text_by_path:
        resolve_link(link_path)
    return _ScanResult(tuple(entries), tuple(sorted(witness, key=lambda item: str(item[0]).encode("utf-8"))))


def build_skill_manifest(
    root: Path | str, *, limits: ManifestLimits | None = None
) -> SkillManifest:
    """Build a stable normative managed-set manifest without following links."""
    selected = limits if limits is not None else ManifestLimits()
    if not isinstance(selected, ManifestLimits):
        raise ManifestError("manifest limits are invalid")
    previous: _ScanResult | None = None
    for _ in range(selected.stabilization_attempts):
        current = _scan_once(root, selected)
        if previous is not None and current == previous:
            return SkillManifest(current.entries)
        previous = current
    raise ManifestError("skill manifest did not stabilize within its bound")
