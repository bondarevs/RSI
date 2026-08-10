"""Trusted, read-only bindings between verified target identities and real roots."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping, Sequence

from .validation import LifecycleError


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
TARGET_BINDING_FIELDS = frozenset(
    {"name", "versionHash", "canonicalRoot", "manifestDigest", "contractDigest"}
)
CONTRACT_BINDING_FIELDS = frozenset({"canonicalRoot", "graphDigest"})
VERIFICATION_BINDING_FIELDS = frozenset({"targetRoots", "contractRoots"})
MAX_TARGET_ENTRIES = 4096
MAX_TARGET_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_ATTEMPTS = 3
MAX_CONTRACT_ROOTS = 32
MAX_CONTRACTS = 256
MAX_CONTRACT_BYTES = 4 * 1024 * 1024
MAX_FRESHNESS_WITNESS_BYTES = 16 * 1024 * 1024
MAX_FRESHNESS_PATH_BYTES = 4 * 1024 * 1024
_FRESHNESS_DOCUMENT_FIELDS = frozenset(
    {"schemaVersion", "runId", "verificationBindingDigest", "witnessDigest", "witness"}
)
_FRESHNESS_ROOT_FIELDS = frozenset({"canonicalRoot", "entries"})
_FRESHNESS_ENTRY_FIELDS = frozenset(
    {"path", "kind", "device", "inode", "mode", "links", "size", "modifiedNs", "changedNs"}
)


@dataclass(frozen=True, slots=True)
class TargetRootBinding:
    name: str
    version_hash: str
    canonical_root: str
    manifest_digest: str
    contract_digest: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "name": self.name,
            "versionHash": self.version_hash,
            "canonicalRoot": self.canonical_root,
            "manifestDigest": self.manifest_digest,
            "contractDigest": self.contract_digest,
        }


@dataclass(frozen=True, slots=True)
class ContractRootBinding:
    canonical_root: str
    graph_digest: str

    def to_mapping(self) -> dict[str, str]:
        return {"canonicalRoot": self.canonical_root, "graphDigest": self.graph_digest}


@dataclass(frozen=True, slots=True)
class MetadataEntry:
    relative_path: str
    kind: str
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int

    def to_mapping(self) -> dict[str, object]:
        return {
            "path": self.relative_path,
            "kind": self.kind,
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "links": self.links,
            "size": self.size,
            "modifiedNs": self.modified_ns,
            "changedNs": self.changed_ns,
        }


@dataclass(frozen=True, slots=True)
class RootFreshnessWitness:
    canonical_root: str
    entries: tuple[MetadataEntry, ...]

    def to_mapping(self) -> dict[str, object]:
        return {
            "canonicalRoot": self.canonical_root,
            "entries": [entry.to_mapping() for entry in self.entries],
        }


@dataclass(frozen=True, slots=True)
class VerificationFreshnessWitness:
    target_roots: tuple[RootFreshnessWitness, ...]
    contract_roots: tuple[RootFreshnessWitness, ...]

    def to_mapping(self) -> dict[str, object]:
        return {
            "targetRoots": [item.to_mapping() for item in self.target_roots],
            "contractRoots": [item.to_mapping() for item in self.contract_roots],
        }


@dataclass(slots=True)
class OpenDirectoryAncestry:
    descriptors: tuple[int, ...]
    names: tuple[str, ...]

    @property
    def leaf(self) -> int:
        return self.descriptors[-1]

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def canonical_real_root(path: Path | str) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute == Path(absolute.anchor):
        raise LifecycleError("trusted root cannot be a filesystem root")
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            raise LifecycleError("trusted root is unavailable") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise LifecycleError("trusted root cannot use a symlink alias")
        if current != absolute and not stat.S_ISDIR(metadata.st_mode):
            raise LifecycleError("trusted root topology is invalid")
    if not absolute.is_dir():
        raise LifecycleError("trusted root must be a real directory")
    return absolute


def _open_directory_ancestry(root: Path) -> OpenDirectoryAncestry:
    """Open an absolute directory without following any ancestry component."""
    if not root.is_absolute() or root == Path(root.anchor):
        raise LifecycleError("trusted root topology is invalid")
    descriptors: list[int] = []
    names: list[str] = []
    try:
        descriptors.append(os.open(root.anchor, os.O_RDONLY | _DIRECTORY))
        for part in root.parts[1:]:
            try:
                child = os.open(
                    part,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=descriptors[-1],
                )
            except OSError as error:
                raise LifecycleError("trusted root ancestry changed or became unsafe") from error
            descriptors.append(child)
            names.append(part)
        return OpenDirectoryAncestry(tuple(descriptors), tuple(names))
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _assert_directory_ancestry_bound(ancestry: OpenDirectoryAncestry) -> None:
    if (
        not isinstance(ancestry, OpenDirectoryAncestry)
        or len(ancestry.descriptors) != len(ancestry.names) + 1
    ):
        raise LifecycleError("trusted root ancestry witness is invalid")
    for index in range(len(ancestry.names) - 1, -1, -1):
        parent = ancestry.descriptors[index]
        child = ancestry.descriptors[index + 1]
        name = ancestry.names[index]
        try:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            opened = os.fstat(child)
        except OSError as error:
            raise LifecycleError("trusted root ancestry changed before terminal append") from error
        if (
            not stat.S_ISDIR(current.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise LifecycleError("trusted root ancestry changed before terminal append")


def _metadata_entry(relative_path: str, metadata: os.stat_result) -> MetadataEntry:
    if stat.S_ISDIR(metadata.st_mode):
        kind = "directory"
    elif stat.S_ISREG(metadata.st_mode):
        kind = "regular-file"
        if metadata.st_nlink != 1:
            raise LifecycleError("trusted freshness witness contains an unsafe file")
    else:
        raise LifecycleError("trusted freshness witness contains an unsupported entry")
    return MetadataEntry(
        relative_path=relative_path,
        kind=kind,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        links=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _open_relative_checked(
    parent: int, name: str, expected: os.stat_result
) -> tuple[int, os.stat_result]:
    if stat.S_ISDIR(expected.st_mode):
        flags = os.O_RDONLY | _DIRECTORY | _NOFOLLOW
    elif stat.S_ISREG(expected.st_mode):
        flags = os.O_RDONLY | _NOFOLLOW
    else:
        raise LifecycleError("trusted freshness witness contains an unsupported entry")
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as error:
        raise LifecycleError("trusted root entry changed or became unsafe") from error
    opened = os.fstat(descriptor)
    if (
        stat.S_IFMT(opened.st_mode) != stat.S_IFMT(expected.st_mode)
        or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        os.close(descriptor)
        raise LifecycleError("trusted root entry changed during freshness capture")
    return descriptor, opened


def _capture_target_freshness(root: Path) -> RootFreshnessWitness:
    canonical = canonical_real_root(root)
    ancestry = _open_directory_ancestry(canonical)
    descriptor = ancestry.leaf
    entries: list[MetadataEntry] = []
    entry_count = 0
    try:
        entries.append(_metadata_entry("", os.fstat(descriptor)))

        def walk(directory: int, prefix: tuple[str, ...]) -> None:
            nonlocal entry_count
            try:
                with os.scandir(os.dup(directory)) as iterator:
                    names = sorted((entry.name for entry in iterator), key=os.fsencode)
            except OSError as error:
                raise LifecycleError("trusted target freshness tree cannot be read safely") from error
            if entry_count + len(names) > MAX_TARGET_ENTRIES:
                raise LifecycleError("trusted target freshness witness exceeds its entry bound")
            for name in names:
                entry_count += 1
                try:
                    metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except OSError as error:
                    raise LifecycleError("trusted target freshness entry cannot be inspected") from error
                child, opened = _open_relative_checked(directory, name, metadata)
                relative_parts = (*prefix, name)
                relative = "/".join(relative_parts)
                try:
                    entries.append(_metadata_entry(relative, opened))
                    if stat.S_ISDIR(opened.st_mode):
                        walk(child, relative_parts)
                finally:
                    os.close(child)

        walk(descriptor, ())
        _assert_directory_ancestry_bound(ancestry)
    finally:
        ancestry.close()
    return RootFreshnessWitness(str(canonical), tuple(entries))


def _capture_contract_freshness(root: Path) -> RootFreshnessWitness:
    """Capture only metadata that can change the provider's contract graph."""
    canonical = canonical_real_root(root)
    ancestry = _open_directory_ancestry(canonical)
    descriptor = ancestry.leaf
    entries: list[MetadataEntry] = []
    try:
        entries.append(_metadata_entry("", os.fstat(descriptor)))
        try:
            direct = os.stat("skill-contract.json", dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            direct = None
        except OSError as error:
            raise LifecycleError("trusted contract freshness entry cannot be inspected") from error
        if direct is not None:
            child, opened = _open_relative_checked(descriptor, "skill-contract.json", direct)
            try:
                entries.append(_metadata_entry("skill-contract.json", opened))
            finally:
                os.close(child)
        else:
            try:
                with os.scandir(os.dup(descriptor)) as iterator:
                    names = sorted((entry.name for entry in iterator), key=os.fsencode)
            except OSError as error:
                raise LifecycleError("trusted contract freshness root cannot be read safely") from error
            if len(names) > MAX_TARGET_ENTRIES:
                raise LifecycleError("trusted contract freshness witness exceeds its entry bound")
            contracts = 0
            for name in names:
                try:
                    metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except OSError as error:
                    raise LifecycleError("trusted contract freshness entry cannot be inspected") from error
                if stat.S_ISLNK(metadata.st_mode):
                    raise LifecycleError("trusted contract root contains a symlink alias")
                if not stat.S_ISDIR(metadata.st_mode):
                    continue
                child, opened = _open_relative_checked(descriptor, name, metadata)
                try:
                    entries.append(_metadata_entry(name, opened))
                    try:
                        contract_metadata = os.stat(
                            "skill-contract.json", dir_fd=child, follow_symlinks=False
                        )
                    except FileNotFoundError:
                        continue
                    except OSError as error:
                        raise LifecycleError(
                            "trusted contract freshness entry cannot be inspected"
                        ) from error
                    contract, contract_opened = _open_relative_checked(
                        child, "skill-contract.json", contract_metadata
                    )
                    try:
                        entries.append(
                            _metadata_entry(f"{name}/skill-contract.json", contract_opened)
                        )
                    finally:
                        os.close(contract)
                    contracts += 1
                    if contracts > MAX_CONTRACTS:
                        raise LifecycleError(
                            "trusted contract freshness witness exceeds its contract bound"
                        )
                finally:
                    os.close(child)
        _assert_directory_ancestry_bound(ancestry)
    finally:
        ancestry.close()
    return RootFreshnessWitness(str(canonical), tuple(entries))


def _capture_verification_freshness(
    target_roots: Sequence[Path], contract_roots: Sequence[Path]
) -> VerificationFreshnessWitness:
    return VerificationFreshnessWitness(
        tuple(
            _capture_target_freshness(root)
            for root in sorted(target_roots, key=lambda item: str(item))
        ),
        tuple(
            _capture_contract_freshness(root)
            for root in sorted(contract_roots, key=lambda item: str(item))
        ),
    )


def freshness_witness_digest(witness: VerificationFreshnessWitness) -> str:
    if not isinstance(witness, VerificationFreshnessWitness):
        raise LifecycleError("trusted root freshness witness is invalid")
    return _digest(witness.to_mapping())


def encode_freshness_witness_document(
    witness: VerificationFreshnessWitness,
    *,
    run_id: str,
    verification_binding_digest: str,
) -> bytes:
    if (
        not isinstance(run_id, str)
        or not run_id
        or len(run_id) > 160
        or not isinstance(verification_binding_digest, str)
        or not _DIGEST_RE.fullmatch(verification_binding_digest)
    ):
        raise LifecycleError("historical freshness binding is invalid")
    document = {
        "schemaVersion": 1,
        "runId": run_id,
        "verificationBindingDigest": verification_binding_digest,
        "witnessDigest": freshness_witness_digest(witness),
        "witness": witness.to_mapping(),
    }
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    if len(encoded) > MAX_FRESHNESS_WITNESS_BYTES:
        raise LifecycleError("historical freshness witness exceeds its byte bound")
    return encoded


def _admit_metadata_entry(value: object) -> MetadataEntry:
    if not isinstance(value, Mapping) or set(value) != _FRESHNESS_ENTRY_FIELDS:
        raise LifecycleError("historical freshness entry is invalid")
    path = value["path"]
    kind = value["kind"]
    numeric_names = ("device", "inode", "mode", "links", "size", "modifiedNs", "changedNs")
    if (
        not isinstance(path, str)
        or not isinstance(kind, str)
        or kind not in {"directory", "regular-file"}
        or any(type(value[name]) is not int or not 0 <= value[name] <= 2**64 - 1 for name in numeric_names)
    ):
        raise LifecycleError("historical freshness entry is invalid")
    if path and (
        path.startswith("/")
        or "//" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise LifecycleError("historical freshness entry path is invalid")
    mode = int(value["mode"])
    if (kind == "directory" and not stat.S_ISDIR(mode)) or (
        kind == "regular-file" and not stat.S_ISREG(mode)
    ):
        raise LifecycleError("historical freshness entry type is invalid")
    if int(value["links"]) < 1 or (kind == "regular-file" and int(value["links"]) != 1):
        raise LifecycleError("historical freshness entry links are invalid")
    return MetadataEntry(
        path,
        kind,
        int(value["device"]),
        int(value["inode"]),
        mode,
        int(value["links"]),
        int(value["size"]),
        int(value["modifiedNs"]),
        int(value["changedNs"]),
    )


def _admit_root_freshness(value: object) -> RootFreshnessWitness:
    if not isinstance(value, Mapping) or set(value) != _FRESHNESS_ROOT_FIELDS:
        raise LifecycleError("historical root freshness witness is invalid")
    canonical = value["canonicalRoot"]
    raw_entries = value["entries"]
    if (
        not isinstance(canonical, str)
        or not os.path.isabs(canonical)
        or canonical == os.path.abspath(os.sep)
        or os.path.normpath(canonical) != canonical
        or not isinstance(raw_entries, list)
        or not raw_entries
        or len(raw_entries) > MAX_TARGET_ENTRIES + MAX_CONTRACTS + 1
    ):
        raise LifecycleError("historical root freshness witness is invalid")
    entries = tuple(_admit_metadata_entry(item) for item in raw_entries)
    if entries[0].relative_path != "" or entries[0].kind != "directory":
        raise LifecycleError("historical root freshness witness is invalid")
    by_path: dict[str, MetadataEntry] = {}
    path_bytes = 0
    for entry in entries:
        path_bytes += len(entry.relative_path.encode("utf-8"))
        if path_bytes > MAX_FRESHNESS_PATH_BYTES or entry.relative_path in by_path:
            raise LifecycleError("historical root freshness witness exceeds its path bound")
        if entry.relative_path:
            parent, _, _ = entry.relative_path.rpartition("/")
            if parent not in by_path or by_path[parent].kind != "directory":
                raise LifecycleError("historical root freshness witness order is invalid")
        by_path[entry.relative_path] = entry
    return RootFreshnessWitness(canonical, entries)


def admit_freshness_witness_document(
    data: bytes,
    *,
    run_id: str,
    verification_binding_digest: str | None,
) -> tuple[VerificationFreshnessWitness, str, str]:
    if (
        not isinstance(data, bytes)
        or not data
        or len(data) > MAX_FRESHNESS_WITNESS_BYTES
        or data.count(b"\n") != 1
        or not data.endswith(b"\n")
    ):
        raise LifecycleError("historical freshness witness framing is invalid")
    document = _strict_object(data[:-1], "historical freshness witness")
    if (
        set(document) != _FRESHNESS_DOCUMENT_FIELDS
        or document.get("schemaVersion") != 1
        or document.get("runId") != run_id
        or (
            verification_binding_digest is not None
            and document.get("verificationBindingDigest") != verification_binding_digest
        )
        or not isinstance(document.get("verificationBindingDigest"), str)
        or not _DIGEST_RE.fullmatch(str(document["verificationBindingDigest"]))
        or not isinstance(document.get("witnessDigest"), str)
        or not _DIGEST_RE.fullmatch(str(document["witnessDigest"]))
    ):
        raise LifecycleError("historical freshness witness binding is invalid")
    raw_witness = document.get("witness")
    if not isinstance(raw_witness, Mapping) or set(raw_witness) != VERIFICATION_BINDING_FIELDS:
        raise LifecycleError("historical freshness witness is invalid")
    target_values = raw_witness["targetRoots"]
    contract_values = raw_witness["contractRoots"]
    if (
        not isinstance(target_values, list)
        or not isinstance(contract_values, list)
        or not target_values
        or not contract_values
        or len(target_values) > 32
        or len(contract_values) > MAX_CONTRACT_ROOTS
    ):
        raise LifecycleError("historical freshness witness is invalid")
    witness = VerificationFreshnessWitness(
        tuple(_admit_root_freshness(item) for item in target_values),
        tuple(_admit_root_freshness(item) for item in contract_values),
    )
    target_roots, contract_roots = freshness_witness_roots(witness)
    if (
        len(set(target_roots)) != len(target_roots)
        or len(set(contract_roots)) != len(contract_roots)
        or tuple(sorted(target_roots)) != target_roots
        or tuple(sorted(contract_roots)) != contract_roots
        or freshness_witness_digest(witness) != document["witnessDigest"]
    ):
        raise LifecycleError("historical freshness witness digest is invalid")
    return (
        witness,
        str(document["witnessDigest"]),
        str(document["verificationBindingDigest"]),
    )


def freshness_witness_roots(
    witness: VerificationFreshnessWitness,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(witness, VerificationFreshnessWitness):
        raise LifecycleError("trusted root freshness witness is invalid")
    return (
        tuple(item.canonical_root for item in witness.target_roots),
        tuple(item.canonical_root for item in witness.contract_roots),
    )


def _assert_root_freshness(witness: RootFreshnessWitness) -> None:
    root = Path(witness.canonical_root)
    if not witness.entries or witness.entries[0].relative_path != "":
        raise LifecycleError("trusted root freshness witness is invalid")
    ancestry = _open_directory_ancestry(root)
    descriptor = ancestry.leaf
    try:
        if _metadata_entry("", os.fstat(descriptor)) != witness.entries[0]:
            raise LifecycleError("trusted root changed before terminal append")
        by_path = {entry.relative_path: entry for entry in witness.entries}
        if len(by_path) != len(witness.entries):
            raise LifecycleError("trusted root freshness witness is invalid")
        children: dict[str, list[MetadataEntry]] = {}
        for expected in witness.entries[1:]:
            path = expected.relative_path
            if not path or path.startswith("/") or "//" in path:
                raise LifecycleError("trusted root freshness witness is invalid")
            parent_path, _, _ = path.rpartition("/")
            parent_entry = by_path.get(parent_path)
            if parent_entry is None or parent_entry.kind != "directory":
                raise LifecycleError("trusted root freshness witness is invalid")
            children.setdefault(parent_path, []).append(expected)

        def verify_directory(parent: int, parent_path: str) -> None:
            for expected in sorted(
                children.get(parent_path, []), key=lambda item: os.fsencode(item.relative_path)
            ):
                _, _, name = expected.relative_path.rpartition("/")
                try:
                    metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except OSError as error:
                    raise LifecycleError("trusted root changed before terminal append") from error
                child, opened = _open_relative_checked(parent, name, metadata)
                try:
                    actual = _metadata_entry(expected.relative_path, opened)
                    if actual != expected:
                        raise LifecycleError("trusted root changed before terminal append")
                    if expected.kind == "directory":
                        verify_directory(child, expected.relative_path)
                    try:
                        rebound = os.stat(name, dir_fd=parent, follow_symlinks=False)
                        still_open = os.fstat(child)
                    except OSError as error:
                        raise LifecycleError(
                            "trusted root changed before terminal append"
                        ) from error
                    if (
                        _metadata_entry(expected.relative_path, rebound) != expected
                        or _metadata_entry(expected.relative_path, still_open) != expected
                    ):
                        raise LifecycleError("trusted root changed before terminal append")
                finally:
                    os.close(child)

        verify_directory(descriptor, "")
        if _metadata_entry("", os.fstat(descriptor)) != witness.entries[0]:
            raise LifecycleError("trusted root changed before terminal append")
        _assert_directory_ancestry_bound(ancestry)
    finally:
        ancestry.close()


def assert_freshness_witness(witness: VerificationFreshnessWitness) -> None:
    if not isinstance(witness, VerificationFreshnessWitness):
        raise LifecycleError("trusted root freshness witness is invalid")
    for root in (*witness.target_roots, *witness.contract_roots):
        _assert_root_freshness(root)


def _read_regular(path: Path, *, max_bytes: int = MAX_TARGET_BYTES) -> tuple[bytes, int]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        raise LifecycleError("trusted target file is unavailable") from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > max_bytes
    ):
        raise LifecycleError("trusted target contains an unsafe or overlong file")
    try:
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
    except OSError as error:
        raise LifecycleError("trusted target file cannot be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise LifecycleError("trusted target file changed during verification")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(item) for item in chunks) > max_bytes:
                raise LifecycleError("trusted target file exceeds its byte bound")
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise LifecycleError("trusted target file changed during verification")
        return b"".join(chunks), stat.S_IMODE(after.st_mode)
    finally:
        os.close(descriptor)


def _tree_entries(root: Path) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    entry_count = 0
    byte_count = 0

    def walk(directory: Path, prefix: tuple[str, ...]) -> None:
        nonlocal entry_count, byte_count
        try:
            entries = []
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    if entry_count + len(entries) + 1 > MAX_TARGET_ENTRIES:
                        raise LifecycleError("trusted target manifest exceeds its entry bound")
                    entries.append(entry)
            entries.sort(key=lambda item: os.fsencode(item.name))
        except OSError as error:
            raise LifecycleError("trusted target directory cannot be read safely") from error
        for entry in entries:
            entry_count += 1
            if entry_count > MAX_TARGET_ENTRIES:
                raise LifecycleError("trusted target manifest exceeds its entry bound")
            relative_parts = (*prefix, entry.name)
            relative = "/".join(relative_parts)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise LifecycleError("trusted target entry cannot be inspected safely") from error
            if stat.S_ISLNK(metadata.st_mode):
                raise LifecycleError("trusted target contains a symlink entry")
            path = directory / entry.name
            if stat.S_ISDIR(metadata.st_mode):
                result.append(
                    {"path": relative, "type": "directory", "mode": stat.S_IMODE(metadata.st_mode)}
                )
                walk(path, relative_parts)
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_size < 0 or byte_count + metadata.st_size > MAX_TARGET_BYTES:
                    raise LifecycleError("trusted target manifest exceeds its byte bound")
                payload, mode = _read_regular(path)
                byte_count += len(payload)
                if byte_count > MAX_TARGET_BYTES:
                    raise LifecycleError("trusted target manifest exceeds its byte bound")
                result.append(
                    {
                        "path": relative,
                        "type": "regular-file",
                        "mode": mode,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
            else:
                raise LifecycleError("trusted target contains an unsupported entry")

    walk(root, ())
    return result


def _stable_tree_digest(root: Path) -> str:
    previous: list[dict[str, object]] | None = None
    for _ in range(MAX_MANIFEST_ATTEMPTS):
        current = _tree_entries(root)
        if previous is not None and current == previous:
            return _digest(current)
        previous = current
    raise LifecycleError("trusted target manifest did not stabilize")


def _strict_object(payload: bytes, label: str) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise LifecycleError(f"trusted {label} is invalid") from None
    if not isinstance(value, dict):
        raise LifecycleError(f"trusted {label} is invalid")
    return value


def build_target_root_binding(
    root: Path | str, name: str, version_hash: str
) -> TargetRootBinding:
    canonical = canonical_real_root(root)
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise LifecycleError("verified target name is invalid")
    if not isinstance(version_hash, str) or not _DIGEST_RE.fullmatch(version_hash):
        raise LifecycleError("verified target version is invalid")
    contract_bytes, _ = _read_regular(
        canonical / "skill-contract.json", max_bytes=MAX_CONTRACT_BYTES
    )
    contract = _strict_object(contract_bytes, "target contract")
    if contract.get("name") != name:
        raise LifecycleError("verified target root does not match its declared name")
    return TargetRootBinding(
        name=name,
        version_hash=version_hash,
        canonical_root=str(canonical),
        manifest_digest=_stable_tree_digest(canonical),
        contract_digest="sha256:" + hashlib.sha256(contract_bytes).hexdigest(),
    )


def _contract_paths(root: Path) -> list[Path]:
    direct = root / "skill-contract.json"
    if direct.exists():
        return [direct]
    paths: list[Path] = []
    try:
        children = []
        with os.scandir(root) as iterator:
            for child in iterator:
                if len(children) >= MAX_TARGET_ENTRIES:
                    raise LifecycleError("trusted contract root exceeds its entry bound")
                children.append(child)
        children.sort(key=lambda item: os.fsencode(item.name))
    except OSError as error:
        raise LifecycleError("trusted contract root cannot be read safely") from error
    for child in children:
        metadata = child.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise LifecycleError("trusted contract root contains a symlink alias")
        if stat.S_ISDIR(metadata.st_mode):
            candidate = root / child.name / "skill-contract.json"
            if candidate.exists():
                paths.append(candidate)
                if len(paths) > MAX_CONTRACTS:
                    raise LifecycleError("trusted contract graph exceeds its contract bound")
    if not paths:
        raise LifecycleError("trusted contract root contains no contracts")
    return paths


def build_contract_root_binding(root: Path | str) -> ContractRootBinding:
    canonical = canonical_real_root(root)
    entries: list[dict[str, str]] = []
    names: set[str] = set()
    total_bytes = 0
    for path in _contract_paths(canonical):
        payload, _ = _read_regular(path, max_bytes=MAX_CONTRACT_BYTES)
        total_bytes += len(payload)
        if total_bytes > MAX_CONTRACT_BYTES:
            raise LifecycleError("trusted contract graph exceeds its byte bound")
        contract = _strict_object(payload, "contract graph")
        name = contract.get("name")
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name) or name in names:
            raise LifecycleError("trusted contract graph has invalid or duplicate owners")
        names.add(name)
        entries.append(
            {
                "name": name,
                "path": str(path.parent),
                "bytesDigest": "sha256:" + hashlib.sha256(payload).hexdigest(),
            }
        )
    entries.sort(key=lambda item: (item["name"], item["path"]))
    return ContractRootBinding(str(canonical), _digest(entries))


def build_verification_bindings(
    targets: Sequence[Mapping[str, str]],
    target_roots: Sequence[Path | str],
    contract_roots: Sequence[Path | str],
) -> tuple[tuple[TargetRootBinding, ...], tuple[ContractRootBinding, ...]]:
    if (
        len(target_roots) != len(targets)
        or not target_roots
        or not contract_roots
        or len(contract_roots) > MAX_CONTRACT_ROOTS
    ):
        raise LifecycleError("trusted verification roots must cover every target")
    by_name: dict[str, TargetRootBinding] = {}
    for root in target_roots:
        canonical = canonical_real_root(root)
        contract_bytes, _ = _read_regular(
            canonical / "skill-contract.json", max_bytes=MAX_CONTRACT_BYTES
        )
        name = _strict_object(contract_bytes, "target contract").get("name")
        if not isinstance(name, str) or name in by_name:
            raise LifecycleError("trusted verification target roots are ambiguous")
        target = next((item for item in targets if item.get("name") == name), None)
        if target is None:
            raise LifecycleError("trusted verification root is undeclared")
        by_name[name] = build_target_root_binding(root, name, str(target["versionHash"]))
    ordered = tuple(by_name[str(item["name"])] for item in targets)
    contracts = tuple(
        sorted(
            (build_contract_root_binding(root) for root in contract_roots),
            key=lambda item: item.canonical_root,
        )
    )
    if len({item.canonical_root for item in contracts}) != len(contracts):
        raise LifecycleError("trusted contract roots must be distinct")
    return ordered, contracts


def admit_verification_bindings(
    value: object, targets: Sequence[Mapping[str, str]]
) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != VERIFICATION_BINDING_FIELDS:
        raise LifecycleError("verification root bindings have an invalid schema")
    raw_targets = value["targetRoots"]
    raw_contracts = value["contractRoots"]
    if not isinstance(raw_targets, list) or not isinstance(raw_contracts, list):
        raise LifecycleError("verification root bindings have an invalid schema")
    target_values: list[dict[str, str]] = []
    for item in raw_targets:
        if not isinstance(item, Mapping) or set(item) != TARGET_BINDING_FIELDS:
            raise LifecycleError("verified target root binding is invalid")
        admitted = {key: item[key] for key in TARGET_BINDING_FIELDS}
        if (
            not isinstance(admitted["name"], str)
            or not _NAME_RE.fullmatch(admitted["name"])
            or any(
                not isinstance(admitted[key], str) or not _DIGEST_RE.fullmatch(admitted[key])
                for key in ("versionHash", "manifestDigest", "contractDigest")
            )
            or not isinstance(admitted["canonicalRoot"], str)
            or not os.path.isabs(admitted["canonicalRoot"])
        ):
            raise LifecycleError("verified target root binding is invalid")
        target_values.append(admitted)  # type: ignore[arg-type]
    contract_values: list[dict[str, str]] = []
    for item in raw_contracts:
        if not isinstance(item, Mapping) or set(item) != CONTRACT_BINDING_FIELDS:
            raise LifecycleError("verified contract root binding is invalid")
        if (
            not isinstance(item["canonicalRoot"], str)
            or not os.path.isabs(item["canonicalRoot"])
            or not isinstance(item["graphDigest"], str)
            or not _DIGEST_RE.fullmatch(item["graphDigest"])
        ):
            raise LifecycleError("verified contract root binding is invalid")
        contract_values.append(
            {"canonicalRoot": str(item["canonicalRoot"]), "graphDigest": str(item["graphDigest"])}
        )
    expected = [(str(item["name"]), str(item["versionHash"])) for item in targets]
    actual = [(item["name"], item["versionHash"]) for item in target_values]
    if target_values and actual != expected:
        raise LifecycleError("verified target roots do not match the observation")
    if bool(target_values) is not bool(contract_values):
        raise LifecycleError("verified target and contract roots must be bound together")
    if len({item["canonicalRoot"] for item in target_values}) != len(target_values):
        raise LifecycleError("verified target roots are ambiguous")
    if len({item["canonicalRoot"] for item in contract_values}) != len(contract_values):
        raise LifecycleError("verified contract roots are ambiguous")
    if contract_values != sorted(contract_values, key=lambda item: item["canonicalRoot"]):
        raise LifecycleError("verified contract roots are not canonical")
    return {"targetRoots": target_values, "contractRoots": contract_values}


def revalidate_verification_bindings(
    bindings: Mapping[str, object],
    supplied_target_roots: Sequence[Path | str],
    supplied_contract_roots: Sequence[Path | str],
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    target_values = bindings.get("targetRoots")
    contract_values = bindings.get("contractRoots")
    if not isinstance(target_values, list) or not isinstance(contract_values, list):
        raise LifecycleError("trusted verification root binding is unavailable")
    targets = tuple(canonical_real_root(root) for root in supplied_target_roots)
    contracts = tuple(canonical_real_root(root) for root in supplied_contract_roots)
    if sorted(str(item) for item in targets) != sorted(
        str(item["canonicalRoot"]) for item in target_values if isinstance(item, Mapping)
    ):
        raise LifecycleError("supplied target roots conflict with trusted verification")
    if sorted(str(item) for item in contracts) != sorted(
        str(item["canonicalRoot"]) for item in contract_values if isinstance(item, Mapping)
    ):
        raise LifecycleError("supplied contract roots conflict with trusted verification")
    expected_targets = {
        str(item["canonicalRoot"]): item for item in target_values if isinstance(item, Mapping)
    }
    for root in targets:
        expected = expected_targets[str(root)]
        current = build_target_root_binding(root, str(expected["name"]), str(expected["versionHash"]))
        if current.to_mapping() != dict(expected):
            raise LifecycleError("verified target manifest changed before proposal")
    expected_contracts = {
        str(item["canonicalRoot"]): item for item in contract_values if isinstance(item, Mapping)
    }
    for root in contracts:
        current = build_contract_root_binding(root)
        if current.to_mapping() != dict(expected_contracts[str(root)]):
            raise LifecycleError("verified contract root graph changed before proposal")
    return targets, contracts


def revalidate_verification_bindings_with_witness(
    bindings: Mapping[str, object],
    supplied_target_roots: Sequence[Path | str],
    supplied_contract_roots: Sequence[Path | str],
) -> tuple[tuple[Path, ...], tuple[Path, ...], VerificationFreshnessWitness]:
    """Perform the byte scan outside the journal lock and bind its metadata state.

    Metadata is captured on both sides of the full manifest/contract scan.  A
    change in that interval fails closed instead of silently rebasing the
    terminal witness to newer bytes.  The returned descriptor-relative witness
    is cheap to recheck immediately before the terminal journal append.
    """
    target_paths = tuple(canonical_real_root(root) for root in supplied_target_roots)
    contract_paths = tuple(canonical_real_root(root) for root in supplied_contract_roots)
    before = _capture_verification_freshness(target_paths, contract_paths)
    targets, contracts = revalidate_verification_bindings(
        bindings, supplied_target_roots, supplied_contract_roots
    )
    after = _capture_verification_freshness(target_paths, contract_paths)
    if before != after:
        raise LifecycleError("trusted root freshness changed during terminal verification")
    return targets, contracts, after
