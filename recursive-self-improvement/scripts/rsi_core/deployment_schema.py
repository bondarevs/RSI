"""Strict immutable wire schemas for global RSI observe deployments."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import PurePosixPath
import re
import unicodedata
from typing import Mapping


class DeploymentSchemaError(ValueError):
    """A deployment wire value is ambiguous, unsafe, or outside its schema."""


DEPLOYMENT_DOMAIN = "rsi-global-observe-deployment-v1"
RECEIPT_DOMAIN = "rsi-global-observe-receipt-v1"
PACKAGE_TREE_DOMAIN = "rsi-global-package-tree-v1"
MANIFEST_RELATIVE_PATH = ".rsi-deployment-manifest.json"
PACKAGE_RELATIVE_PATH = "recursive-self-improvement"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_OPERATION_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,199}\Z")
_MAX_JSON_DEPTH = 64
_MAX_FILE_ENTRIES = 4_096
_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_PATH_BYTES = 4 * 1024 * 1024
_MAX_PATH_DEPTH = 32

_FILE_ENTRY_KEYS = frozenset({"relativePath", "byteLength", "executable", "digest"})
_MANIFEST_KEYS = frozenset(
    {
        "schemaVersion",
        "domain",
        "sourceRepository",
        "sourceCommit",
        "packageRelativePath",
        "mode",
        "hookMode",
        "productionAllowlistDigest",
        "productionAllowlistEntryCount",
        "fileEntries",
        "sourceTreeDigest",
        "installedTreeDigest",
        "managedInstructionBlockDigest",
        "installedAt",
        "operationId",
    }
)
_RECEIPT_KEYS = frozenset(
    {"schemaVersion", "domain", "operationId", "manifestByteLength", "manifestDigest"}
)


def _plain_json_value(
    value: object, *, depth: int = 0, ancestors: set[int] | None = None
) -> object:
    if depth > _MAX_JSON_DEPTH:
        raise DeploymentSchemaError("canonical JSON exceeds its depth bound")
    if value is None or type(value) in {bool, int, str}:
        if type(value) is str:
            try:
                value.encode("utf-8", "strict")
            except UnicodeEncodeError:
                raise DeploymentSchemaError("canonical JSON contains invalid Unicode") from None
        return value
    if type(value) is float:
        raise DeploymentSchemaError("canonical JSON floats are invalid")

    seen = set() if ancestors is None else ancestors
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in seen:
            raise DeploymentSchemaError("canonical JSON contains a cycle")
        seen.add(identity)
        try:
            result: dict[str, object] = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise DeploymentSchemaError("canonical JSON keys must be strings")
                _plain_json_value(key, depth=depth + 1, ancestors=seen)
                result[key] = _plain_json_value(item, depth=depth + 1, ancestors=seen)
            return result
        finally:
            seen.remove(identity)
    if type(value) in {list, tuple}:
        identity = id(value)
        if identity in seen:
            raise DeploymentSchemaError("canonical JSON contains a cycle")
        seen.add(identity)
        try:
            return [
                _plain_json_value(item, depth=depth + 1, ancestors=seen)
                for item in value
            ]
        finally:
            seen.remove(identity)
    raise DeploymentSchemaError("canonical JSON contains an unsupported value")


def canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    """Encode one mapping as sorted compact UTF-8 JSON with exactly one final LF."""

    if not isinstance(value, Mapping):
        raise DeploymentSchemaError("canonical JSON root must be a mapping")
    plain = _plain_json_value(value)
    try:
        return (
            json.dumps(
                plain,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8", "strict")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError):
        raise DeploymentSchemaError("value cannot be encoded as canonical JSON") from None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DeploymentSchemaError("canonical JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_float(_: str) -> object:
    raise DeploymentSchemaError("canonical JSON floats are invalid")


def _reject_constant(_: str) -> object:
    raise DeploymentSchemaError("canonical JSON constants are invalid")


def _parse_canonical_mapping(payload: bytes) -> dict[str, object]:
    if type(payload) is not bytes or not payload:
        raise DeploymentSchemaError("canonical JSON bytes are invalid")
    if payload.startswith(b"\xef\xbb\xbf"):
        raise DeploymentSchemaError("canonical JSON BOM is invalid")
    if b"\r" in payload or not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise DeploymentSchemaError("canonical JSON must have exactly one final LF")
    try:
        text = payload[:-1].decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except DeploymentSchemaError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise DeploymentSchemaError("canonical JSON syntax is invalid") from None
    if not isinstance(value, dict):
        raise DeploymentSchemaError("canonical JSON root must be an object")
    if canonical_json_bytes(value) != payload:
        raise DeploymentSchemaError("JSON bytes are not canonical")
    return value


def _require_closed_mapping(
    value: object, keys: frozenset[str], *, label: str
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise DeploymentSchemaError(f"{label} schema is invalid")
    if any(type(key) is not str for key in value):
        raise DeploymentSchemaError(f"{label} schema is invalid")
    return value


def _require_digest(value: object, *, label: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise DeploymentSchemaError(f"{label} digest is invalid")
    return value


def _require_integer(
    value: object, *, label: str, minimum: int = 0, maximum: int | None = None
) -> int:
    if type(value) is not int or value < minimum or (
        maximum is not None and value > maximum
    ):
        raise DeploymentSchemaError(f"{label} integer is invalid")
    return value


def _require_operation_id(value: object) -> str:
    if type(value) is not str or _OPERATION_ID_RE.fullmatch(value) is None:
        raise DeploymentSchemaError("deployment operation ID is invalid")
    return value


def _require_nfc_utf8(value: object, *, label: str) -> str:
    if type(value) is not str or not value or unicodedata.normalize("NFC", value) != value:
        raise DeploymentSchemaError(f"{label} path is not NFC canonical")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise DeploymentSchemaError(f"{label} path is not valid UTF-8") from None
    if "\x00" in value or "\\" in value:
        raise DeploymentSchemaError(f"{label} path is unsafe")
    return value


def _require_relative_path(value: object, *, label: str) -> str:
    path_value = _require_nfc_utf8(value, label=label)
    path = PurePosixPath(path_value)
    parts = path_value.split("/")
    if (
        path.is_absolute()
        or str(path) != path_value
        or any(part in {"", ".", ".."} for part in parts)
        or len(parts) > _MAX_PATH_DEPTH
    ):
        raise DeploymentSchemaError(f"{label} path is unsafe")
    return path_value


def _require_absolute_path(value: object, *, label: str) -> str:
    path_value = _require_nfc_utf8(value, label=label)
    path = PurePosixPath(path_value)
    if path_value.startswith("//") or not path.is_absolute() or str(path) != path_value or any(
        part in {".", ".."} for part in path.parts
    ):
        raise DeploymentSchemaError(f"{label} path is not absolute canonical")
    return path_value


def _require_timestamp(value: object) -> str:
    if type(value) is not str:
        raise DeploymentSchemaError("installation timestamp is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise DeploymentSchemaError("installation timestamp is invalid") from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise DeploymentSchemaError("installation timestamp is invalid")
    return value


def _file_entries_tree_digest(entries: tuple["FileEntry", ...]) -> str:
    payload = canonical_json_bytes(
        {
            "schemaVersion": 1,
            "domain": PACKAGE_TREE_DOMAIN,
            "fileEntries": [entry.to_mapping() for entry in entries],
        }
    )
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class FileEntry:
    relative_path: str
    byte_length: int
    executable: bool
    digest: str

    def __post_init__(self) -> None:
        _require_relative_path(self.relative_path, label="file entry")
        _require_integer(
            self.byte_length,
            label="file entry byte length",
            maximum=_MAX_FILE_BYTES,
        )
        if type(self.executable) is not bool:
            raise DeploymentSchemaError("file entry executable bit is invalid")
        _require_digest(self.digest, label="file entry")

    @classmethod
    def from_mapping(cls, value: object) -> "FileEntry":
        mapping = _require_closed_mapping(value, _FILE_ENTRY_KEYS, label="file entry")
        return cls(
            relative_path=mapping["relativePath"],  # type: ignore[arg-type]
            byte_length=mapping["byteLength"],  # type: ignore[arg-type]
            executable=mapping["executable"],  # type: ignore[arg-type]
            digest=mapping["digest"],  # type: ignore[arg-type]
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "relativePath": self.relative_path,
            "byteLength": self.byte_length,
            "executable": self.executable,
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class DeploymentManifest:
    source_repository: str
    source_commit: str
    package_relative_path: str
    production_allowlist_digest: str
    file_entries: tuple[FileEntry, ...]
    source_tree_digest: str
    installed_tree_digest: str
    managed_instruction_block_digest: str
    installed_at: str
    operation_id: str
    schema_version: int = 1
    domain: str = DEPLOYMENT_DOMAIN
    mode: str = "observe"
    hook_mode: str = "late-review"
    production_allowlist_entry_count: int = 0

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise DeploymentSchemaError("deployment manifest schema version is invalid")
        if type(self.domain) is not str or self.domain != DEPLOYMENT_DOMAIN:
            raise DeploymentSchemaError("deployment manifest domain is invalid")
        _require_absolute_path(self.source_repository, label="source repository")
        if type(self.source_commit) is not str or _COMMIT_RE.fullmatch(self.source_commit) is None:
            raise DeploymentSchemaError("source commit is invalid")
        _require_relative_path(self.package_relative_path, label="package")
        if self.package_relative_path != PACKAGE_RELATIVE_PATH:
            raise DeploymentSchemaError("deployment package identity is invalid")
        if (
            type(self.mode) is not str
            or self.mode != "observe"
            or type(self.hook_mode) is not str
            or self.hook_mode != "late-review"
        ):
            raise DeploymentSchemaError("deployment mode is invalid")
        _require_digest(self.production_allowlist_digest, label="production allowlist")
        if (
            type(self.production_allowlist_entry_count) is not int
            or self.production_allowlist_entry_count != 0
        ):
            raise DeploymentSchemaError("production allowlist must be exactly empty")
        if type(self.file_entries) is not tuple or any(
            type(entry) is not FileEntry for entry in self.file_entries
        ):
            raise DeploymentSchemaError("deployment manifest file entries are invalid")
        if len(self.file_entries) > _MAX_FILE_ENTRIES:
            raise DeploymentSchemaError("deployment manifest has too many file entries")
        paths = [entry.relative_path for entry in self.file_entries]
        if paths != sorted(paths, key=lambda item: item.encode("utf-8")):
            raise DeploymentSchemaError("deployment manifest file entries are not UTF-8 sorted")
        if len(paths) != len(set(paths)):
            raise DeploymentSchemaError("deployment manifest contains duplicate file paths")
        if MANIFEST_RELATIVE_PATH in paths:
            raise DeploymentSchemaError("deployment manifest cannot contain itself")
        if sum(len(path.encode("utf-8")) for path in paths) > _MAX_PATH_BYTES:
            raise DeploymentSchemaError("deployment manifest path bytes exceed the bound")
        if sum(entry.byte_length for entry in self.file_entries) > _MAX_TOTAL_BYTES:
            raise DeploymentSchemaError("deployment manifest bytes exceed the bound")
        _require_digest(self.source_tree_digest, label="source tree")
        _require_digest(self.installed_tree_digest, label="installed tree")
        expected_tree_digest = _file_entries_tree_digest(self.file_entries)
        if (
            self.source_tree_digest != expected_tree_digest
            or self.installed_tree_digest != expected_tree_digest
        ):
            raise DeploymentSchemaError("deployment manifest tree digest is inconsistent")
        _require_digest(
            self.managed_instruction_block_digest,
            label="managed instruction block",
        )
        _require_timestamp(self.installed_at)
        _require_operation_id(self.operation_id)
        if len(canonical_json_bytes(self.to_mapping())) > MAX_MANIFEST_BYTES:
            raise DeploymentSchemaError("deployment manifest size exceeds its bound")

    @classmethod
    def from_mapping(cls, value: object) -> "DeploymentManifest":
        mapping = _require_closed_mapping(value, _MANIFEST_KEYS, label="deployment manifest")
        raw_entries = mapping["fileEntries"]
        if type(raw_entries) is not list:
            raise DeploymentSchemaError("deployment manifest file entries are invalid")
        entries = tuple(FileEntry.from_mapping(entry) for entry in raw_entries)
        return cls(
            schema_version=mapping["schemaVersion"],  # type: ignore[arg-type]
            domain=mapping["domain"],  # type: ignore[arg-type]
            source_repository=mapping["sourceRepository"],  # type: ignore[arg-type]
            source_commit=mapping["sourceCommit"],  # type: ignore[arg-type]
            package_relative_path=mapping["packageRelativePath"],  # type: ignore[arg-type]
            mode=mapping["mode"],  # type: ignore[arg-type]
            hook_mode=mapping["hookMode"],  # type: ignore[arg-type]
            production_allowlist_digest=mapping["productionAllowlistDigest"],  # type: ignore[arg-type]
            production_allowlist_entry_count=mapping["productionAllowlistEntryCount"],  # type: ignore[arg-type]
            file_entries=entries,
            source_tree_digest=mapping["sourceTreeDigest"],  # type: ignore[arg-type]
            installed_tree_digest=mapping["installedTreeDigest"],  # type: ignore[arg-type]
            managed_instruction_block_digest=mapping["managedInstructionBlockDigest"],  # type: ignore[arg-type]
            installed_at=mapping["installedAt"],  # type: ignore[arg-type]
            operation_id=mapping["operationId"],  # type: ignore[arg-type]
        )

    @classmethod
    def from_bytes(cls, payload: bytes) -> "DeploymentManifest":
        if type(payload) is not bytes or len(payload) > MAX_MANIFEST_BYTES:
            raise DeploymentSchemaError("deployment manifest size exceeds its bound")
        return cls.from_mapping(_parse_canonical_mapping(payload))

    def to_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "domain": self.domain,
            "sourceRepository": self.source_repository,
            "sourceCommit": self.source_commit,
            "packageRelativePath": self.package_relative_path,
            "mode": self.mode,
            "hookMode": self.hook_mode,
            "productionAllowlistDigest": self.production_allowlist_digest,
            "productionAllowlistEntryCount": self.production_allowlist_entry_count,
            "fileEntries": [entry.to_mapping() for entry in self.file_entries],
            "sourceTreeDigest": self.source_tree_digest,
            "installedTreeDigest": self.installed_tree_digest,
            "managedInstructionBlockDigest": self.managed_instruction_block_digest,
            "installedAt": self.installed_at,
            "operationId": self.operation_id,
        }

    def to_bytes(self) -> bytes:
        payload = canonical_json_bytes(self.to_mapping())
        if len(payload) > MAX_MANIFEST_BYTES:
            raise DeploymentSchemaError("deployment manifest size exceeds its bound")
        return payload


@dataclass(frozen=True, slots=True)
class DeploymentReceipt:
    operation_id: str
    manifest_byte_length: int
    manifest_digest: str
    schema_version: int = 1
    domain: str = RECEIPT_DOMAIN

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise DeploymentSchemaError("deployment receipt schema version is invalid")
        if type(self.domain) is not str or self.domain != RECEIPT_DOMAIN:
            raise DeploymentSchemaError("deployment receipt domain is invalid")
        _require_operation_id(self.operation_id)
        _require_integer(
            self.manifest_byte_length,
            label="manifest byte length",
            minimum=1,
            maximum=MAX_MANIFEST_BYTES,
        )
        _require_digest(self.manifest_digest, label="manifest")

    @classmethod
    def from_mapping(cls, value: object) -> "DeploymentReceipt":
        mapping = _require_closed_mapping(value, _RECEIPT_KEYS, label="deployment receipt")
        return cls(
            schema_version=mapping["schemaVersion"],  # type: ignore[arg-type]
            domain=mapping["domain"],  # type: ignore[arg-type]
            operation_id=mapping["operationId"],  # type: ignore[arg-type]
            manifest_byte_length=mapping["manifestByteLength"],  # type: ignore[arg-type]
            manifest_digest=mapping["manifestDigest"],  # type: ignore[arg-type]
        )

    @classmethod
    def from_bytes(cls, payload: bytes) -> "DeploymentReceipt":
        return cls.from_mapping(_parse_canonical_mapping(payload))

    def to_mapping(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "domain": self.domain,
            "operationId": self.operation_id,
            "manifestByteLength": self.manifest_byte_length,
            "manifestDigest": self.manifest_digest,
        }

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_mapping())


__all__ = [
    "DEPLOYMENT_DOMAIN",
    "DeploymentManifest",
    "DeploymentReceipt",
    "DeploymentSchemaError",
    "FileEntry",
    "MANIFEST_RELATIVE_PATH",
    "MAX_MANIFEST_BYTES",
    "PACKAGE_TREE_DOMAIN",
    "PACKAGE_RELATIVE_PATH",
    "RECEIPT_DOMAIN",
    "canonical_json_bytes",
]
