"""Pinned, fail-closed adapter for the provider-v2 ``skill-evolver`` CLI."""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from types import MappingProxyType
from typing import Any, Iterator, Mapping, Sequence, TYPE_CHECKING

from .sanitize import sanitize_evidence

if TYPE_CHECKING:
    from .candidates import ImprovementCandidateDraft


PINNED_PROVIDER_SHA256 = {
    "scripts/learning_log.py": "6bb49ccd528dbbcebe7d5aa6ff9bb85015fa92d0b1dedcf20d9458a5f049814b",
    "scripts/skill_contract.py": "6b2eac650a77892632f281c64f817db1b99ea117966642c5e94f1631b6c8695f",
    "skill-contract.json": "a12c223c9b2175bba3ca5ad0cbc2bb38a2432211f2816bc793e126837c8d337b",
}
REQUIRED_CAPABILITIES = frozenset(
    {
        "skill-learning.list", "skill-learning.route", "skill-learning.capture",
        "skill-learning.snapshot", "skill-learning.defer", "skill-learning.resolve",
        "skill-learning.restore", "skill-learning.validate",
        "skill-learning.guard",
    }
)
MAX_OUTPUT_BYTES = 64 * 1024
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_OPERATION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_SCOPE_RE = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*\Z")
_DEDUPE_RE = re.compile(r"[a-z0-9]+(?:[.:-][a-z0-9]+)*\Z")
_NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z")
_VALIDATE_RE = re.compile(r"OK: ([0-9]+) events(?: \(([0-9]+) pending snapshot operation(?:s)?\))?\n\Z")
_CANDIDATE_FIELDS = frozenset(
    {
        "schema_version", "event", "id", "created_at", "skill", "kind", "change_class",
        "title", "finding", "evidence", "target_hint", "confidence", "sourceSkill",
        "ownerSkill", "ownerReason", "destinationClass", "relatedSkills", "dedupeKey",
        "scope", "operationType", "operationId", "requestDigest", "review_count",
        "last_review", "needs_escalation", "status", "resolution",
    }
)
_PRIVATE_BOOTSTRAP = (
    "import os,runpy,sys;"
    "script=sys.argv.pop(1);"
    "sys.path.insert(0,os.path.dirname(script));"
    "runpy.run_path(script,run_name='__main__')"
)


class ProviderProtocolError(RuntimeError):
    code = "provider-protocol-error"


class ProviderCompatibilityError(ProviderProtocolError):
    code = "provider-incompatible"


class ProviderTimeoutError(ProviderProtocolError):
    code = "provider-timeout"


class OperationIdConflict(ProviderProtocolError):
    code = "operation-id-conflict"


@dataclass(frozen=True, slots=True)
class ProviderProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True, slots=True)
class Candidate:
    candidate_id: str
    status: str
    skill_name: str
    skill_path: str
    kind: str
    change_class: str
    title: str
    finding: str
    evidence: tuple[str, ...]
    confidence: float
    target_hint: str | None
    source_skill: str | None
    owner_skill: str | None
    destination_class: str | None
    dedupe_key: str | None
    scope: str | None
    operation_id: str | None
    request_digest: str | None
    review_count: int
    needs_escalation: bool


@dataclass(frozen=True, slots=True)
class RouteDecision:
    status: str
    owner_skill: str | None
    owner_path: str | None
    matched_scope: str | None
    reason: str
    route_binding: str | None = None


@dataclass(frozen=True, slots=True)
class CandidateRef:
    candidate_id: str
    reused: bool | None


@dataclass(frozen=True, slots=True)
class SnapshotRef:
    path: str
    manifest_digest: str


@dataclass(frozen=True, slots=True)
class ReviewRef:
    event_id: str


@dataclass(frozen=True, slots=True)
class ResolutionRef:
    event_id: str


@dataclass(frozen=True, slots=True)
class RestorePlan:
    confirmed: bool
    snapshot: str
    skill_path: str
    would_restore: tuple[str, ...]
    would_remove: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProviderValidationResult:
    event_count: int
    pending_snapshot_operations: int
    provider_digest: str


def _canonical_no_lf(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _canonical_final_lf(value: object) -> bytes:
    return _canonical_no_lf(value) + b"\n"


def _prefixed_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True, slots=True)
class ProviderWireObject:
    _value: Mapping[str, object]
    canonical_bytes: bytes

    def to_mapping(self) -> dict[str, object]:
        return json.loads(self.canonical_bytes.decode("utf-8"))


@dataclass(frozen=True, slots=True)
class BoundCandidateAuthority:
    candidate_id: str
    candidate_full_record_digest: str
    provider_authority_binding_digest: str
    task7_candidate_binding: ProviderWireObject
    task7_candidate_binding_digest: str
    capture_lineage: ProviderWireObject
    candidate_capture_lineage_binding_digest: str
    state_binding: ProviderWireObject
    candidate_state_binding_digest: str


@dataclass(frozen=True, slots=True)
class CandidateAuthority:
    candidate_id: str
    full_record: ProviderWireObject
    candidate_full_record_digest: str
    provider_authority: ProviderWireObject
    provider_authority_binding_digest: str
    provider_candidate_event_digest: str

    def bind_task7(self, mapping: Mapping[str, object]) -> BoundCandidateAuthority:
        try:
            task7 = json.loads(_canonical_no_lf(mapping))
        except (TypeError, ValueError, RecursionError):
            raise ProviderProtocolError("Task 7 candidate binding is invalid") from None
        if not isinstance(task7, dict) or set(task7) != {
            "schemaVersion", "domain", "lineage", "changeClass", "destinationClass", "evidenceRefs"
        } or task7.get("schemaVersion") != 1 or task7.get("domain") != "rsi-captured-candidate-binding-v1":
            raise ProviderProtocolError("Task 7 candidate binding schema is invalid")
        lineage7 = task7.get("lineage")
        authority = self.provider_authority.to_mapping()
        if not isinstance(lineage7, dict) or lineage7.get("candidateId") != self.candidate_id:
            raise ProviderProtocolError("Task 7 candidate lineage binding is invalid")
        expected_provider_request = "sha256:" + str(authority["providerCaptureRequestDigest"])
        if lineage7.get("providerRequestDigest") != expected_provider_request:
            raise ProviderProtocolError("Task 7 provider request digest representation is invalid")
        task7_bytes = _canonical_no_lf(task7)
        task7_digest = _prefixed_digest(task7_bytes)
        capture = {
            "schemaVersion": 1, "domain": "rsi-candidate-capture-lineage-v1",
            "candidateId": self.candidate_id,
            "providerCandidateEventDigest": authority["providerCandidateEventDigest"],
            "skillName": authority["skillName"], "skillPath": authority["skillPath"],
            "ownerSkill": authority["ownerSkill"], "changeClass": authority["changeClass"],
            "destinationClass": authority["destinationClass"],
            "captureOperationId": authority["captureOperationId"],
            "providerCaptureRequestDigest": authority["providerCaptureRequestDigest"],
            "task7CandidateBindingDigest": task7_digest,
            "providerContractDigest": authority["providerContractDigest"],
            "providerVersionDigest": authority["providerVersionDigest"],
        }
        capture_bytes = _canonical_final_lf(capture)
        state = {
            "schemaVersion": 1, "domain": "rsi-candidate-state-v1",
            "task7CandidateBinding": task7,
            "task7CandidateBindingDigest": task7_digest,
            "providerAuthority": authority,
            "providerAuthorityBindingDigest": self.provider_authority_binding_digest,
        }
        state_bytes = _canonical_final_lf(state)
        return BoundCandidateAuthority(
            self.candidate_id, self.candidate_full_record_digest,
            self.provider_authority_binding_digest,
            ProviderWireObject(MappingProxyType(task7), task7_bytes), task7_digest,
            ProviderWireObject(MappingProxyType(capture), capture_bytes), _prefixed_digest(capture_bytes),
            ProviderWireObject(MappingProxyType(state), state_bytes), _prefixed_digest(state_bytes),
        )


_HISTORICAL_FIELDS = {
    "ledgerIdentityDigest", "gateProviderContractDigest", "gateProviderVersionDigest",
    "gateProviderExecutionIdentityDigest", "ledgerProtocolVersion", "ledgerProtocolDigest",
    "foldProfileId", "foldProfileDigest", "ledgerPrefix", "latestAuthorityEventId",
    "candidateId", "candidateFullRecordDigest", "providerAuthorityBindingDigest",
    "task7CandidateBindingDigest", "candidateCaptureLineageBindingDigest",
    "candidateStateBindingDigest",
}


@dataclass(frozen=True, slots=True)
class ProviderHistoricalAuthority:
    _mapping: dict[str, object]
    candidate_id: str
    candidate_state_binding_digest: str

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, object]) -> "ProviderHistoricalAuthority":
        try:
            copied = json.loads(_canonical_no_lf(mapping))
        except (TypeError, ValueError, RecursionError):
            raise ProviderProtocolError("historical authority schema is invalid") from None
        if not isinstance(copied, dict) or set(copied) != _HISTORICAL_FIELDS:
            raise ProviderProtocolError("historical authority schema is invalid")
        prefix = copied.get("ledgerPrefix")
        if not isinstance(prefix, dict) or set(prefix) != {"byteLength", "eventCount", "lastEventId", "prefixSha256"}:
            raise ProviderProtocolError("historical ledger prefix schema is invalid")
        for key in (
            "ledgerIdentityDigest", "gateProviderContractDigest", "gateProviderVersionDigest",
            "gateProviderExecutionIdentityDigest", "ledgerProtocolDigest", "foldProfileDigest",
            "candidateFullRecordDigest", "providerAuthorityBindingDigest", "task7CandidateBindingDigest",
            "candidateCaptureLineageBindingDigest", "candidateStateBindingDigest",
        ):
            value = copied.get(key)
            if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
                raise ProviderProtocolError("historical authority digest is invalid")
        if copied.get("foldProfileId") != "rsi-provider-fold-v1" or copied.get("ledgerProtocolVersion") != "skill-learning-ledger-lock-v1":
            raise ProviderProtocolError("historical profile or protocol is invalid")
        return cls(copied, str(copied["candidateId"]), str(copied["candidateStateBindingDigest"]))

    def to_mapping(self) -> dict[str, object]:
        return json.loads(_canonical_no_lf(self._mapping))


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _unique_provider_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json(data: bytes) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    if (
        not data
        or len(data) > MAX_OUTPUT_BYTES
        or not data.endswith(b"\n")
        or b"\r" in data
        or data[:-1].endswith((b"\n", b" ", b"\t"))
    ):
        raise ProviderProtocolError("provider JSON output framing is invalid")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ProviderProtocolError("provider JSON output is malformed") from None


def _no_symlink_components(path: Path, *, require_final: bool) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    parts = absolute.parts[1:]
    for position, part in enumerate(parts):
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if require_final:
                raise ProviderCompatibilityError("provider path is unavailable") from None
            break
        if stat.S_ISLNK(metadata.st_mode):
            raise ProviderCompatibilityError("provider path uses a symlink alias")
        if position < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise ProviderCompatibilityError("provider path topology is invalid")
    return absolute


def _read_regular(path: Path) -> bytes:
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ProviderCompatibilityError("provider artifact is not a single-link regular file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ProviderCompatibilityError("provider artifact cannot be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ProviderCompatibilityError("provider artifact changed during verification")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > 2 * 1024 * 1024:
                raise ProviderCompatibilityError("provider artifact exceeds its bound")
            chunks.append(chunk)
    finally:
        os.close(descriptor)


def _validated_contract_root(path: Path) -> Path:
    """Reject aliases in the exact one-level graph discovered by the provider."""
    root = _no_symlink_components(path, require_final=True)
    if not root.is_dir():
        raise ProviderProtocolError("contract root must be a real directory")
    try:
        entries = list(os.scandir(root))
    except OSError as error:
        raise ProviderProtocolError("contract root is unavailable") from error
    direct_contract = root / "skill-contract.json"
    if direct_contract.exists():
        _read_regular(direct_contract)
        return root
    for entry in entries:
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as error:
            raise ProviderProtocolError("contract root topology is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ProviderProtocolError("contract root uses a nested symlink alias")
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        candidate = Path(entry.path) / "skill-contract.json"
        try:
            candidate_metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ProviderProtocolError("contract artifact is unavailable") from error
        if stat.S_ISLNK(candidate_metadata.st_mode):
            raise ProviderProtocolError("contract artifact uses a symlink alias")
        _read_regular(candidate)
    return root


class EvolverAdapter:
    """Execute only the exact reviewed provider bytes through a closed protocol."""

    def __init__(
        self,
        provider_root: Path | str,
        learning_home: Path | str,
        *,
        timeout_seconds: float = 15.0,
        max_output_bytes: int = MAX_OUTPUT_BYTES,
    ) -> None:
        self.provider_root = _no_symlink_components(Path(provider_root), require_final=True)
        self.learning_home = _no_symlink_components(Path(learning_home), require_final=False)
        if self.learning_home == Path(self.learning_home.anchor):
            raise ProviderCompatibilityError("learning home cannot be a filesystem root")
        if (
            self.learning_home == self.provider_root
            or self.learning_home in self.provider_root.parents
            or self.provider_root in self.learning_home.parents
        ):
            raise ProviderCompatibilityError("provider source and learning home must be disjoint")
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = min(MAX_OUTPUT_BYTES, max(1024, max_output_bytes))
        self._verified_bundle()

    def _verified_bundle(self) -> dict[str, bytes]:
        bundle: dict[str, bytes] = {}
        for relative, expected in PINNED_PROVIDER_SHA256.items():
            path = self.provider_root / relative
            data = _read_regular(path)
            if hashlib.sha256(data).hexdigest() != expected:
                raise ProviderCompatibilityError(f"provider digest mismatch: {relative}")
            bundle[relative] = data
        try:
            contract = _strict_json(bundle["skill-contract.json"] + (b"" if bundle["skill-contract.json"].endswith(b"\n") else b"\n"))
        except ProviderProtocolError as error:
            raise ProviderCompatibilityError("provider contract JSON is invalid") from error
        if not isinstance(contract, dict):
            raise ProviderCompatibilityError("provider contract must be an object")
        if set(contract) != {"schemaVersion", "name", "kind", "owns", "provides"}:
            raise ProviderCompatibilityError("provider contract has an incompatible schema")
        if contract["schemaVersion"] != 1 or contract["name"] != "skill-evolver" or contract["kind"] != "capability":
            raise ProviderCompatibilityError("provider identity is incompatible")
        provides = contract["provides"]
        if not isinstance(provides, list) or any(not isinstance(item, str) for item in provides) or frozenset(provides) != REQUIRED_CAPABILITIES or len(provides) != len(REQUIRED_CAPABILITIES):
            raise ProviderCompatibilityError("provider capabilities are incompatible")
        owns = contract["owns"]
        if not isinstance(owns, list) or not owns or any(not isinstance(item, str) for item in owns):
            raise ProviderCompatibilityError("provider ownership contract is incompatible")
        return bundle

    def _execute_verified(self, arguments: list[str]) -> ProviderProcessResult:
        bundle = self._verified_bundle()
        with tempfile.TemporaryDirectory(prefix="rsi-evolver-") as raw:
            private = Path(raw)
            os.chmod(private, 0o700)
            for name, relative in (("learning_log.py", "scripts/learning_log.py"), ("skill_contract.py", "scripts/skill_contract.py")):
                descriptor = os.open(private / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o500)
                try:
                    view = memoryview(bundle[relative])
                    offset = 0
                    while offset < len(view):
                        written = os.write(descriptor, view[offset:])
                        if written <= 0:
                            raise ProviderProtocolError("private provider copy was incomplete")
                        offset += written
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            environment = {
                "CODEX_SKILL_LEARNING_HOME": str(self.learning_home),
                "HOME": str(Path.home()),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONHASHSEED": "0",
                "PYTHONNOUSERSITE": "1",
            }
            process = subprocess.Popen(
                [
                    sys.executable, "-I", "-S", "-B", "-c", _PRIVATE_BOOTSTRAP,
                    str(private / "learning_log.py"), *arguments,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=private,
                close_fds=True,
            )
            assert process.stdout is not None and process.stderr is not None
            selector = selectors.DefaultSelector()
            streams = {process.stdout.fileno(): ("stdout", process.stdout), process.stderr.fileno(): ("stderr", process.stderr)}
            for descriptor, (_, stream) in streams.items():
                os.set_blocking(descriptor, False)
                selector.register(stream, selectors.EVENT_READ)
            output = {"stdout": bytearray(), "stderr": bytearray()}
            deadline = time.monotonic() + self.timeout_seconds
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        process.kill()
                        process.wait()
                        raise ProviderTimeoutError("provider command timed out")
                    events = selector.select(min(remaining, 0.1))
                    if not events and process.poll() is not None:
                        events = selector.select(0)
                    for key, _ in events:
                        label, stream = streams[key.fd]
                        chunk = os.read(key.fd, 8192)
                        if not chunk:
                            selector.unregister(stream)
                            continue
                        output[label].extend(chunk)
                        if len(output[label]) > self.max_output_bytes:
                            process.kill()
                            process.wait()
                            raise ProviderProtocolError("provider output exceeds byte limit")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    process.kill()
                    process.wait()
                    raise ProviderTimeoutError("provider command timed out")
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise ProviderTimeoutError("provider command timed out") from None
            finally:
                selector.close()
            return ProviderProcessResult(returncode, bytes(output["stdout"]), bytes(output["stderr"]))

    def _run(self, arguments: list[str], *, route_decision: bool = False) -> bytes | RouteDecision:
        result = self._execute_verified(arguments)
        if len(result.stdout) > self.max_output_bytes or len(result.stderr) > self.max_output_bytes:
            raise ProviderProtocolError("provider output exceeds byte limit")
        if result.returncode == 0:
            if result.stderr:
                raise ProviderProtocolError("provider emitted stderr on success")
            return result.stdout
        if result.stdout:
            raise ProviderProtocolError("failed provider command emitted stdout")
        try:
            diagnostic = result.stderr.decode("utf-8")
        except UnicodeDecodeError:
            raise ProviderProtocolError("provider diagnostic is malformed") from None
        if result.returncode == 2 and re.fullmatch(r"error: operation-id-conflict:[^\r\n]{1,1000}\n", diagnostic):
            raise OperationIdConflict("provider operation ID conflicts with its recorded request")
        if result.returncode == 2 and route_decision and diagnostic.startswith("error: ") and diagnostic.endswith("\n"):
            decision = _strict_json(diagnostic[len("error: ") :].encode("utf-8"))
            return self._parse_route(decision, unresolved_only=True)
        raise ProviderProtocolError("provider command failed with an unclassified diagnostic")

    @staticmethod
    def _operation(value: str) -> str:
        if not isinstance(value, str) or not _OPERATION_RE.fullmatch(value):
            raise ProviderProtocolError("operation ID is invalid")
        return value

    @staticmethod
    def _name(value: str) -> str:
        if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
            raise ProviderProtocolError("skill name is invalid")
        return value

    def _assert_learning_disjoint(self, path: Path, label: str) -> None:
        learning = _no_symlink_components(self.learning_home, require_final=False)
        candidate = _no_symlink_components(path, require_final=True)
        if (
            learning == candidate
            or learning in candidate.parents
            or candidate in learning.parents
        ):
            raise ProviderCompatibilityError(
                f"provider learning home must be disjoint from {label}"
            )

    def _contract_roots(self, values: Sequence[Path | str]) -> list[str]:
        roots: list[str] = []
        for value in values:
            path = _validated_contract_root(Path(value))
            self._assert_learning_disjoint(path, "contract and target roots")
            roots.append(str(path))
        result = sorted(set(roots))
        if not result:
            raise ProviderProtocolError("at least one contract root is required")
        return result

    def _has_existing_ledger(self) -> bool:
        return (self.learning_home / "events.jsonl").is_file() and (self.learning_home / "events.lock").is_file()

    def _provider_identity_digests(self) -> tuple[str, str]:
        contract = _read_regular(self.provider_root / "skill-contract.json")
        files: list[dict[str, object]] = []
        for relative in ("scripts/learning_log.py", "scripts/skill_contract.py"):
            path = self.provider_root / relative
            metadata = path.lstat()
            data = _read_regular(path)
            mode = stat.S_IMODE(metadata.st_mode)
            files.append({
                "relativePath": relative, "type": "regular", "nlink": 1,
                "mode": mode, "executable": bool(mode & 0o111), "byteSize": len(data),
                "rawSha256": _prefixed_digest(data),
            })
        version = {
            "schemaVersion": 1, "domain": "rsi-skill-evolver-provider-version-v1",
            "files": files,
        }
        return _prefixed_digest(contract), _prefixed_digest(_canonical_final_lf(version))

    @contextmanager
    def _ledger_lock(self, *, exclusive: bool) -> Iterator[None]:
        lock_path = self.learning_home / "events.lock"
        ledger_path = self.learning_home / "events.jsonl"
        home_fd = -1
        ledger_fd = -1
        try:
            home_before = self.learning_home.lstat()
            if stat.S_ISLNK(home_before.st_mode) or not stat.S_ISDIR(home_before.st_mode):
                raise ProviderProtocolError("provider learning home topology is unsafe")
            home_fd = os.open(
                self.learning_home,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            )
            opened_home = os.fstat(home_fd)
            if (opened_home.st_dev, opened_home.st_ino) != (home_before.st_dev, home_before.st_ino):
                raise ProviderProtocolError("provider learning home identity changed")
            lock_before = lock_path.lstat()
            ledger_before = ledger_path.lstat()
            if any(
                stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode) or item.st_nlink != 1
                for item in (lock_before, ledger_before)
            ):
                raise ProviderProtocolError("provider ledger topology is unsafe")
            lock_fd = os.open(
                "events.lock", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=home_fd,
            )
        except OSError as error:
            if home_fd != -1:
                os.close(home_fd)
            raise ProviderProtocolError("provider ledger lock is unavailable") from error
        except Exception:
            if home_fd != -1:
                os.close(home_fd)
            raise
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            current_home = self.learning_home.lstat()
            if (current_home.st_dev, current_home.st_ino) != (opened_home.st_dev, opened_home.st_ino):
                raise ProviderProtocolError("provider learning home changed while locking")
            current = os.stat("events.lock", dir_fd=home_fd, follow_symlinks=False)
            opened = os.fstat(lock_fd)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise ProviderProtocolError("provider ledger lock identity changed")
            ledger_fd = os.open(
                "events.jsonl", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=home_fd,
            )
            opened_ledger = os.fstat(ledger_fd)
            if (
                not stat.S_ISREG(opened_ledger.st_mode)
                or opened_ledger.st_nlink != 1
                or (opened_ledger.st_dev, opened_ledger.st_ino)
                != (ledger_before.st_dev, ledger_before.st_ino)
            ):
                raise ProviderProtocolError("provider ledger identity changed while locking")
            self._guard_ledger_fd = ledger_fd
            yield
            current_home = self.learning_home.lstat()
            current_lock = os.stat("events.lock", dir_fd=home_fd, follow_symlinks=False)
            current_ledger = os.stat("events.jsonl", dir_fd=home_fd, follow_symlinks=False)
            if (current_home.st_dev, current_home.st_ino) != (opened_home.st_dev, opened_home.st_ino):
                raise ProviderProtocolError("provider learning home changed during guard")
            if (current_lock.st_dev, current_lock.st_ino) != (opened.st_dev, opened.st_ino):
                raise ProviderProtocolError("provider ledger lock changed during guard")
            if os.fstat(home_fd).st_ctime_ns != opened_home.st_ctime_ns:
                raise ProviderProtocolError(
                    "provider learning namespace changed during guard"
                )
            opened_ledger_after = os.fstat(ledger_fd)
            if (
                (current_ledger.st_dev, current_ledger.st_ino)
                != (opened_ledger.st_dev, opened_ledger.st_ino)
                or opened_ledger_after.st_size != current_ledger.st_size
                or opened_ledger_after.st_mtime_ns != opened_ledger.st_mtime_ns
                or opened_ledger_after.st_ctime_ns != opened_ledger.st_ctime_ns
            ):
                raise ProviderProtocolError("provider ledger identity changed during guard")
        finally:
            self.__dict__.pop("_guard_ledger_fd", None)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
                if ledger_fd != -1:
                    os.close(ledger_fd)
                if home_fd != -1:
                    os.close(home_fd)

    def _read_ledger_bytes(self) -> bytes:
        guarded_fd = getattr(self, "_guard_ledger_fd", None)
        if guarded_fd is None:
            data = _read_regular(self.learning_home / "events.jsonl")
        else:
            chunks: list[bytes] = []
            offset = 0
            while True:
                chunk = os.pread(guarded_fd, 64 * 1024, offset)
                if not chunk:
                    break
                chunks.append(chunk)
                offset += len(chunk)
                if offset > 64 * 1024 * 1024:
                    raise ProviderProtocolError("provider ledger exceeds its bound")
            data = b"".join(chunks)
        if data and not data.endswith(b"\n"):
            raise ProviderProtocolError("provider ledger tail is incomplete")
        if len(data) > 64 * 1024 * 1024:
            raise ProviderProtocolError("provider ledger exceeds its bound")
        return data

    @staticmethod
    def _decode_ledger(data: bytes) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for line in data.splitlines():
            if not line or len(line) > MAX_OUTPUT_BYTES:
                raise ProviderProtocolError("provider ledger event framing is invalid")
            try:
                value = json.loads(
                    line.decode("utf-8"), object_pairs_hook=lambda pairs: _unique_provider_pairs(pairs),
                    parse_constant=_reject_constant,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                raise ProviderProtocolError("provider ledger event is malformed") from None
            provider_v1_bytes = (
                json.dumps(
                    value,
                    sort_keys=False,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
                if isinstance(value, dict)
                else b""
            )
            if (
                not isinstance(value, dict)
                or line not in {_canonical_no_lf(value), provider_v1_bytes}
            ):
                raise ProviderProtocolError("provider ledger event is non-canonical")
            result.append(value)
        return result

    def _candidate_authority_from_events(
        self, candidate_id: str, expected_skill: str, events: Sequence[dict[str, object]]
    ) -> CandidateAuthority:
        candidates = [item for item in events if item.get("event") == "candidate" and item.get("id") == candidate_id]
        if len(candidates) != 1:
            raise ProviderProtocolError("provider candidate authority is missing or ambiguous")
        candidate = candidates[0]
        skill = candidate.get("skill")
        if not isinstance(skill, dict) or skill.get("name") != expected_skill:
            raise ProviderProtocolError("provider candidate skill binding is invalid")
        reviews = [item for item in events if item.get("event") == "review" and item.get("candidate_id") == candidate_id]
        resolutions = [item for item in events if item.get("event") == "resolution" and item.get("candidate_id") == candidate_id]
        if len(resolutions) > 1:
            raise ProviderProtocolError("provider candidate has conflicting resolutions")
        resolution = resolutions[0] if resolutions else None
        status = str(resolution["decision"]) if resolution else ("deferred" if reviews else "pending")
        derived = {
            "status": status, "reviewCount": len(reviews),
            "needsEscalation": len(reviews) >= 3 and resolution is None,
            "lastReview": reviews[-1] if reviews else None,
        }
        full = {
            "schemaVersion": 1, "domain": "rsi-provider-candidate-full-record-v1",
            "candidateEvent": candidate, "reviews": reviews, "resolution": resolution,
            "derived": derived,
        }
        full_bytes = _canonical_final_lf(full)
        contract_digest, version_digest = self._provider_identity_digests()
        last_review: dict[str, object] | None = None
        if reviews:
            latest = reviews[-1]
            last_review = {
                "schemaVersion": 1, "domain": "rsi-provider-review-authority-v1",
                "reviewEventId": latest["id"], "createdAt": latest["created_at"],
                "candidateId": candidate_id, "outcome": "deferred", "reason": latest["reason"],
                "nextTrigger": latest["next_trigger"], "operationType": "defer",
                "operationId": latest["operationId"],
                "providerReviewRequestDigest": latest["requestDigest"],
            }
        authority = {
            "schemaVersion": 1, "domain": "rsi-provider-candidate-authority-v1",
            "candidateId": candidate_id,
            "providerCandidateEventDigest": hashlib.sha256(_canonical_no_lf(candidate)).hexdigest(),
            "skillName": skill["name"], "skillPath": skill["path"],
            "ownerSkill": candidate.get("ownerSkill"), "changeClass": candidate.get("change_class"),
            "destinationClass": candidate.get("destinationClass"),
            "captureOperationId": candidate.get("operationId"),
            "providerCaptureRequestDigest": candidate.get("requestDigest"),
            "status": status, "reviewCount": len(reviews),
            "needsEscalation": derived["needsEscalation"], "lastReview": last_review,
            "resolution": None if resolution is None else resolution,
            "providerContractDigest": contract_digest, "providerVersionDigest": version_digest,
        }
        authority_bytes = _canonical_final_lf(authority)
        return CandidateAuthority(
            candidate_id, ProviderWireObject(MappingProxyType(full), full_bytes),
            _prefixed_digest(full_bytes), ProviderWireObject(MappingProxyType(authority), authority_bytes),
            _prefixed_digest(authority_bytes), str(authority["providerCandidateEventDigest"]),
        )

    def get_candidate(self, candidate_id: str, expected_skill: str) -> CandidateAuthority:
        candidate_id = self._id(candidate_id)
        expected_skill = self._name(expected_skill)
        if not self._has_existing_ledger():
            raise ProviderProtocolError("existing provider ledger is unavailable")
        with self._ledger_lock(exclusive=False):
            return self._candidate_authority_from_events(
                candidate_id, expected_skill, self._decode_ledger(self._read_ledger_bytes())
            )

    @contextmanager
    def guard_candidate(
        self, candidate_id: str, expected_skill: str, mode: str,
        expected: BoundCandidateAuthority,
    ) -> Iterator[BoundCandidateAuthority]:
        if mode not in {"new-apply", "rollback"} or not isinstance(expected, BoundCandidateAuthority):
            raise ProviderProtocolError("candidate guard authority is invalid")
        with self._ledger_lock(exclusive=True):
            current = self._candidate_authority_from_events(
                self._id(candidate_id), self._name(expected_skill),
                self._decode_ledger(self._read_ledger_bytes()),
            ).bind_task7(expected.task7_candidate_binding.to_mapping())
            digest_tuple = (
                current.candidate_full_record_digest, current.provider_authority_binding_digest,
                current.task7_candidate_binding_digest, current.candidate_capture_lineage_binding_digest,
                current.candidate_state_binding_digest,
            )
            wanted = (
                expected.candidate_full_record_digest, expected.provider_authority_binding_digest,
                expected.task7_candidate_binding_digest, expected.candidate_capture_lineage_binding_digest,
                expected.candidate_state_binding_digest,
            )
            if digest_tuple != wanted:
                raise ProviderProtocolError("candidate guard authority digest drift")
            provider = current.state_binding.to_mapping()["providerAuthority"]
            if mode == "new-apply" and (
                provider["status"] not in {"pending", "deferred"}
                or provider["reviewCount"] > 2
                or provider["needsEscalation"] is not False
                or provider["resolution"] is not None
            ):
                raise ProviderProtocolError("candidate is escalated or ineligible for new apply")
            yield current
            after = self._candidate_authority_from_events(
                self._id(candidate_id), self._name(expected_skill),
                self._decode_ledger(self._read_ledger_bytes()),
            ).bind_task7(expected.task7_candidate_binding.to_mapping())
            if after.candidate_state_binding_digest != current.candidate_state_binding_digest:
                raise ProviderProtocolError("candidate authority changed during guard")

    def _expected_fold_profile(self) -> tuple[str, str]:
        module = Path(__file__).with_name("provider_fold_v1.py")
        profile = {
            "schemaVersion": 1, "profileId": "rsi-provider-fold-v1",
            "supportedProviderEventSchemaVersions": [1],
            "parserModuleDigest": _prefixed_digest(_read_regular(module)),
        }
        return profile["profileId"], _prefixed_digest(_canonical_final_lf(profile))

    def _expected_protocol_digest(self) -> str:
        protocol = {
            "schemaVersion": 1, "protocolVersion": "skill-learning-ledger-lock-v1",
            "ledgerName": "events.jsonl", "lockName": "events.lock", "appendOnly": True,
            "lockMode": "flock-exclusive-writers", "eventFraming": "strict-jsonl-final-lf",
            "syncOrder": "ledger-then-parent",
        }
        return _prefixed_digest(_canonical_final_lf(protocol))

    @contextmanager
    def guard_historical_prefix(
        self, expected: ProviderHistoricalAuthority | Mapping[str, object], *,
        expected_skill: str, task7_binding: Mapping[str, object], purpose: str,
    ) -> Iterator[BoundCandidateAuthority]:
        if not isinstance(expected, ProviderHistoricalAuthority) or purpose != "revalidate":
            raise ProviderProtocolError("historical prefix authority schema is invalid")
        mapping = expected.to_mapping()
        profile_id, profile_digest = self._expected_fold_profile()
        if mapping["foldProfileId"] != profile_id or mapping["foldProfileDigest"] != profile_digest or mapping["ledgerProtocolDigest"] != self._expected_protocol_digest():
            raise ProviderProtocolError("historical profile/protocol digest is incompatible")
        with self._ledger_lock(exclusive=True):
            ledger = self._read_ledger_bytes()
            prefix = mapping["ledgerPrefix"]
            assert isinstance(prefix, dict)
            byte_length = prefix["byteLength"]
            if type(byte_length) is not int or byte_length < 0 or byte_length > len(ledger):
                raise ProviderProtocolError("historical prefix length is invalid")
            data = ledger[:byte_length]
            events = self._decode_ledger(data)
            if (
                _prefixed_digest(data) != prefix["prefixSha256"]
                or len(events) != prefix["eventCount"]
                or not events
                or events[-1].get("id") != prefix["lastEventId"]
            ):
                raise ProviderProtocolError("historical ledger prefix digest is invalid")
            current = self._candidate_authority_from_events(
                expected.candidate_id, self._name(expected_skill), events
            ).bind_task7(task7_binding)
            contract_digest, version_digest = self._provider_identity_digests()
            ledger_identity = {
                "schemaVersion": 1, "domain": "rsi-provider-ledger-v1",
                "canonicalLearningHome": str(self.learning_home.resolve()),
                "gateProviderContractDigest": contract_digest,
                "gateProviderVersionDigest": version_digest,
            }
            checks = {
                "ledgerIdentityDigest": _prefixed_digest(_canonical_final_lf(ledger_identity)),
                "gateProviderContractDigest": contract_digest,
                "gateProviderVersionDigest": version_digest,
                "candidateFullRecordDigest": current.candidate_full_record_digest,
                "providerAuthorityBindingDigest": current.provider_authority_binding_digest,
                "task7CandidateBindingDigest": current.task7_candidate_binding_digest,
                "candidateCaptureLineageBindingDigest": current.candidate_capture_lineage_binding_digest,
                "candidateStateBindingDigest": current.candidate_state_binding_digest,
            }
            if any(mapping[key] != value for key, value in checks.items()):
                raise ProviderProtocolError("historical candidate authority digest mismatch")
            yield current

    @contextmanager
    def guard_historical_prefixes(
        self, expectations: Sequence[tuple[ProviderHistoricalAuthority, str, Mapping[str, object]]], *,
        purpose: str,
    ) -> Iterator[tuple[BoundCandidateAuthority, ...]]:
        if purpose != "revalidate" or not expectations:
            raise ProviderProtocolError("historical batch expectation is invalid")
        keys = [item[0].candidate_id for item in expectations if isinstance(item, tuple) and len(item) == 3]
        if len(keys) != len(expectations) or len(set(keys)) != len(keys):
            raise ProviderProtocolError("historical batch expectations must be unique")
        # A batch uses one direct ledger lock; validate each prefix from the same bytes.
        with self._ledger_lock(exclusive=True):
            ledger = self._read_ledger_bytes()
            results: list[BoundCandidateAuthority] = []
            for expected, skill, task7 in expectations:
                if not isinstance(expected, ProviderHistoricalAuthority):
                    raise ProviderProtocolError("historical batch expectation schema is invalid")
                mapping = expected.to_mapping()
                profile_id, profile_digest = self._expected_fold_profile()
                if mapping["foldProfileId"] != profile_id or mapping["foldProfileDigest"] != profile_digest or mapping["ledgerProtocolDigest"] != self._expected_protocol_digest():
                    raise ProviderProtocolError("historical batch profile is incompatible")
                prefix = mapping["ledgerPrefix"]
                assert isinstance(prefix, dict)
                length = prefix["byteLength"]
                data = ledger[:length] if type(length) is int and 0 <= length <= len(ledger) else b""
                events = self._decode_ledger(data)
                if _prefixed_digest(data) != prefix["prefixSha256"] or len(events) != prefix["eventCount"]:
                    raise ProviderProtocolError("historical batch prefix is invalid")
                bound = self._candidate_authority_from_events(expected.candidate_id, self._name(skill), events).bind_task7(task7)
                if bound.candidate_state_binding_digest != mapping["candidateStateBindingDigest"]:
                    raise ProviderProtocolError("historical batch authority mismatch")
                results.append(bound)
            yield tuple(results)

    def list_pending(self, skill_name: str) -> list[Candidate]:
        requested = self._name(skill_name)
        if self._has_existing_ledger():
            with self._ledger_lock(exclusive=False):
                events = self._decode_ledger(self._read_ledger_bytes())
                candidates: list[Candidate] = []
                for item in events:
                    if item.get("event") != "candidate":
                        continue
                    skill = item.get("skill")
                    if not isinstance(skill, dict) or skill.get("name") != requested:
                        continue
                    candidate_id = str(item["id"])
                    reviews = [
                        event
                        for event in events
                        if event.get("event") == "review"
                        and event.get("candidate_id") == candidate_id
                    ]
                    resolutions = [
                        event
                        for event in events
                        if event.get("event") == "resolution"
                        and event.get("candidate_id") == candidate_id
                    ]
                    if len(resolutions) > 1:
                        raise ProviderProtocolError(
                            "provider candidate has conflicting resolutions"
                        )
                    resolution = resolutions[0] if resolutions else None
                    if resolution is not None:
                        continue
                    folded = dict(item)
                    folded["change_class"] = folded.get("change_class") or (
                        "behavior"
                        if folded.get("kind") == "script-opportunity"
                        else "knowledge"
                    )
                    folded.update(
                        review_count=len(reviews),
                        needs_escalation=len(reviews) >= 3 and resolution is None,
                        status=(
                            str(resolution["decision"])
                            if resolution is not None
                            else "deferred" if reviews else "pending"
                        ),
                    )
                    if reviews:
                        folded["last_review"] = reviews[-1]
                    if resolution is not None:
                        folded["resolution"] = resolution
                    candidate = self._parse_candidate(folded)
                    if candidate.status in {"pending", "deferred"}:
                        candidates.append(candidate)
                return candidates
        stdout = self._run(["list", "--status", "pending", "--skill", requested, "--json"])
        assert isinstance(stdout, bytes)
        value = _strict_json(stdout)
        if not isinstance(value, list):
            raise ProviderProtocolError("provider candidate list is not an array")
        candidates = [self._parse_candidate(item) for item in value]
        if any(item.skill_name != requested or item.status not in {"pending", "deferred"} for item in candidates):
            raise ProviderProtocolError("provider pending-list binding is invalid")
        return candidates

    def route(self, scope: str, contract_roots: Sequence[Path | str]) -> RouteDecision:
        if not isinstance(scope, str) or len(scope) > 200 or not _SCOPE_RE.fullmatch(scope):
            raise ProviderProtocolError("route scope is invalid")
        arguments = ["route", "--include-binding"]
        for root in self._contract_roots(contract_roots):
            arguments.extend(["--contract-root", root])
        arguments.extend(["--scope", scope])
        output = self._run(arguments, route_decision=True)
        if isinstance(output, RouteDecision):
            return output
        return self._parse_route(_strict_json(output), unresolved_only=False)

    def route_capture(
        self,
        candidate: "ImprovementCandidateDraft",
        contract_roots: Sequence[Path | str],
        route_binding: str,
    ) -> CandidateRef:
        self._capture_candidate(candidate)
        if not isinstance(route_binding, str) or not _DIGEST_RE.fullmatch(route_binding):
            raise ProviderProtocolError("expected route binding is invalid")
        arguments = [
            "route-capture", "--operation-id", self._operation(candidate.operation_id),
            "--expected-route-binding", route_binding,
        ]
        for root in self._contract_roots(contract_roots):
            arguments.extend(["--contract-root", root])
        arguments.extend(
            [
                "--source-skill", self._name(candidate.source_skill), "--scope", candidate.scope,
                "--destination-class", candidate.destination_class, "--dedupe-key", candidate.dedupe_key,
            ]
        )
        for related in sorted(set(candidate.related_skills)):
            arguments.extend(["--related-skill", self._name(related)])
        arguments.extend(
            [
                "--kind", candidate.kind, "--change-class", candidate.change_class,
                "--title", candidate.title, "--finding", candidate.finding,
            ]
        )
        for evidence in sorted(set(candidate.evidence)):
            arguments.extend(["--evidence", evidence])
        if candidate.target_hint is not None:
            arguments.extend(["--target-hint", candidate.target_hint])
        arguments.extend(["--confidence", repr(candidate.confidence)])
        stdout = self._run(arguments)
        assert isinstance(stdout, bytes)
        return CandidateRef(self._id_line(stdout), None)

    @staticmethod
    def _guarded_authority_arguments(
        authority: BoundCandidateAuthority | None,
        expires_at: str | None,
        *, include_candidate: bool,
    ) -> list[str]:
        if (authority is None) != (expires_at is None):
            raise ProviderProtocolError(
                "guarded provider authority and expiry are required together"
            )
        if authority is None:
            return []
        if not isinstance(authority, BoundCandidateAuthority):
            raise ProviderProtocolError("guarded provider authority is invalid")
        if not isinstance(expires_at, str) or not _TIMESTAMP_RE.fullmatch(expires_at):
            raise ProviderProtocolError("guarded provider authority expiry is invalid")
        arguments = [
            "--authority-schema-version", "2",
            "--expected-candidate-full-record-digest",
            authority.candidate_full_record_digest,
            "--expected-provider-authority-binding-digest",
            authority.provider_authority_binding_digest,
            "--task7-candidate-binding-digest",
            authority.task7_candidate_binding_digest,
            "--candidate-capture-lineage-binding-digest",
            authority.candidate_capture_lineage_binding_digest,
            "--expected-candidate-state-binding-digest",
            authority.candidate_state_binding_digest,
            "--authority-expires-at", expires_at,
        ]
        if include_candidate:
            arguments[2:2] = ["--candidate-id", authority.candidate_id]
        return arguments

    def _operation_event(self, operation_type: str, operation_id: str) -> dict[str, object] | None:
        if not self._has_existing_ledger():
            return None
        with self._ledger_lock(exclusive=False):
            events = self._decode_ledger(self._read_ledger_bytes())
        matches = [
            event for event in events
            if event.get("operationType") == operation_type
            and event.get("operationId") == operation_id
            and event.get("event") in ({"snapshot"} if operation_type == "snapshot" else {"resolution"})
        ]
        if len(matches) > 1:
            raise ProviderProtocolError("provider operation replay is ambiguous")
        return matches[0] if matches else None

    @staticmethod
    def _guarded_authority_event_fields(
        authority: BoundCandidateAuthority,
        expires_at: str,
        *, include_candidate: bool,
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "authoritySchemaVersion": 2,
            "expectedCandidateFullRecordDigest": authority.candidate_full_record_digest,
            "expectedProviderAuthorityBindingDigest": authority.provider_authority_binding_digest,
            "task7CandidateBindingDigest": authority.task7_candidate_binding_digest,
            "candidateCaptureLineageBindingDigest": authority.candidate_capture_lineage_binding_digest,
            "expectedCandidateStateBindingDigest": authority.candidate_state_binding_digest,
            "authorityExpiresAt": expires_at,
        }
        if include_candidate:
            result["candidateId"] = authority.candidate_id
        return result

    def snapshot(
        self, skill_name: str, skill_path: Path | str, phase: str,
        operation_id: str, git_sha: str | None = None, *,
        candidate_authority: BoundCandidateAuthority | None = None,
        authority_expires_at: str | None = None,
    ) -> SnapshotRef:
        requested_skill = self._name(skill_name)
        target = _no_symlink_components(Path(skill_path), require_final=True)
        self._assert_learning_disjoint(target, "snapshot target")
        if not target.is_dir() or phase not in {"manual", "pre", "post"}:
            raise ProviderProtocolError("snapshot request is invalid")
        arguments = ["snapshot", "--operation-id", self._operation(operation_id), "--skill-name", requested_skill, "--skill-path", str(target), "--phase", phase]
        if git_sha is not None:
            if not isinstance(git_sha, str) or not _GIT_SHA_RE.fullmatch(git_sha):
                raise ProviderProtocolError("snapshot git SHA is invalid")
            arguments.extend(["--git-sha", git_sha])
        arguments.extend(self._guarded_authority_arguments(
            candidate_authority, authority_expires_at, include_candidate=True
        ))
        try:
            stdout = self._run(arguments)
        except ProviderProtocolError:
            replay = self._operation_event("snapshot", operation_id)
            if replay is None or candidate_authority is None:
                raise
            expected_replay = {
                "skill": {"name": requested_skill, "path": str(target)},
                "phase": phase,
                "git_sha": git_sha,
                **self._guarded_authority_event_fields(
                    candidate_authority, authority_expires_at or "",
                    include_candidate=True,
                ),
            }
            if any(replay.get(key) != value for key, value in expected_replay.items()):
                raise OperationIdConflict(
                    "provider snapshot replay conflicts with the guarded request"
                )
            stdout = (str(replay.get("snapshot_path", "")) + "\n").encode("utf-8")
        assert isinstance(stdout, bytes)
        snapshot = self._path_line(stdout)
        learning = self.learning_home.resolve(strict=True)
        supplied_snapshot = _no_symlink_components(Path(snapshot), require_final=True)
        resolved = supplied_snapshot.resolve(strict=True)
        try:
            relative = resolved.relative_to(learning)
        except ValueError:
            raise ProviderProtocolError("snapshot path is outside the provider learning home")
        if len(relative.parts) != 3 or relative.parts[:2] != ("snapshots", requested_skill):
            raise ProviderProtocolError("snapshot path has an incompatible provider layout")
        manifest = resolved / "manifest.json"
        data = _read_regular(manifest)
        _strict_json(data + (b"" if data.endswith(b"\n") else b"\n"))
        return SnapshotRef(str(resolved), "sha256:" + hashlib.sha256(data).hexdigest())

    def defer(self, candidate_id: str, reason: str, next_trigger: str, operation_id: str) -> ReviewRef:
        arguments = ["defer", self._id(candidate_id), "--operation-id", self._operation(operation_id), "--reason", self._safe_provider_text(reason, "review reason", 1000), "--next-trigger", self._safe_provider_text(next_trigger, "review next trigger", 500)]
        stdout = self._run(arguments)
        assert isinstance(stdout, bytes)
        return ReviewRef(self._id_line(stdout))

    def resolve(
        self, candidate_id: str, decision: str, reason: str,
        artifacts: Sequence[str], operation_id: str, *,
        candidate_authority: BoundCandidateAuthority | None = None,
        authority_expires_at: str | None = None,
    ) -> ResolutionRef:
        if decision not in {"promoted", "rejected", "superseded"}:
            raise ProviderProtocolError("resolution decision is invalid")
        admitted_candidate_id = self._id(candidate_id)
        admitted_reason = self._safe_provider_text(reason, "resolution reason", 1000)
        admitted_artifacts = [self._relative(artifact) for artifact in artifacts]
        arguments = ["resolve", admitted_candidate_id, "--operation-id", self._operation(operation_id), "--decision", decision, "--reason", admitted_reason]
        for artifact in admitted_artifacts:
            arguments.extend(["--artifact", artifact])
        arguments.extend(self._guarded_authority_arguments(
            candidate_authority, authority_expires_at, include_candidate=False
        ))
        try:
            stdout = self._run(arguments)
        except ProviderProtocolError:
            replay = self._operation_event("resolve", operation_id)
            if replay is None or candidate_authority is None:
                raise
            expected_replay = {
                "candidate_id": admitted_candidate_id,
                "decision": decision,
                "reason": admitted_reason,
                "artifacts": admitted_artifacts,
                **self._guarded_authority_event_fields(
                    candidate_authority, authority_expires_at or "",
                    include_candidate=False,
                ),
            }
            if any(replay.get(key) != value for key, value in expected_replay.items()):
                raise OperationIdConflict(
                    "provider resolution replay conflicts with the guarded request"
                )
            stdout = (str(replay.get("id", "")) + "\n").encode("utf-8")
        assert isinstance(stdout, bytes)
        return ResolutionRef(self._id_line(stdout))

    def restore_preview(self, snapshot_ref: SnapshotRef, skill_path: Path | str) -> RestorePlan:
        snapshot = _no_symlink_components(Path(snapshot_ref.path), require_final=True)
        target = _no_symlink_components(Path(skill_path), require_final=True)
        self._assert_learning_disjoint(target, "restore target")
        try:
            relative = snapshot.resolve(strict=True).relative_to(self.learning_home.resolve(strict=True))
        except (OSError, ValueError):
            raise ProviderProtocolError("snapshot is outside the provider learning home") from None
        if len(relative.parts) != 3 or relative.parts[0] != "snapshots":
            raise ProviderProtocolError("snapshot path has an incompatible provider layout")
        manifest = _read_regular(snapshot / "manifest.json")
        _strict_json(manifest + (b"" if manifest.endswith(b"\n") else b"\n"))
        actual_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
        if snapshot_ref.manifest_digest != actual_digest:
            raise ProviderProtocolError("snapshot manifest digest binding is invalid")
        output = self._run(["restore", "--snapshot", str(snapshot), "--skill-path", str(target)])
        assert isinstance(output, bytes)
        value = _strict_json(output)
        if not isinstance(value, dict) or set(value) != {"confirmed", "snapshot", "skillPath", "wouldRestore", "wouldRemove"}:
            raise ProviderProtocolError("restore preview schema is invalid")
        if value["confirmed"] is not False or value["snapshot"] != str(snapshot) or value["skillPath"] != str(target):
            raise ProviderProtocolError("restore preview binding is invalid")
        restore = self._relative_list(value["wouldRestore"])
        remove = self._relative_list(value["wouldRemove"])
        return RestorePlan(False, str(snapshot), str(target), restore, remove)

    def validate(self) -> ProviderValidationResult:
        if self._has_existing_ledger():
            with self._ledger_lock(exclusive=False):
                events = self._decode_ledger(self._read_ledger_bytes())
                pending_snapshots = sum(
                    item.get("event") == "snapshot-prepare" for item in events
                )
                return ProviderValidationResult(
                    len(events), pending_snapshots,
                    PINNED_PROVIDER_SHA256["scripts/learning_log.py"],
                )
        output = self._run(["validate"])
        assert isinstance(output, bytes)
        try:
            text = output.decode("ascii")
        except UnicodeDecodeError:
            raise ProviderProtocolError("provider validation output is malformed") from None
        match = _VALIDATE_RE.fullmatch(text)
        if match is None:
            raise ProviderProtocolError("provider validation output is malformed")
        return ProviderValidationResult(int(match.group(1)), int(match.group(2) or 0), PINNED_PROVIDER_SHA256["scripts/learning_log.py"])

    @staticmethod
    def _parse_route(value: object, *, unresolved_only: bool) -> RouteDecision:
        fields = {"status", "owner_skill", "owner_path", "matched_scope", "reason"}
        if (
            not isinstance(value, dict)
            or fields - set(value)
            or not isinstance(value.get("reason"), str)
            or not value["reason"]
            or len(value["reason"]) > 1000
        ):
            raise ProviderProtocolError("route decision schema is invalid")
        status = value["status"]
        reason = EvolverAdapter._safe_provider_text(value["reason"], "route reason", 1000)
        if unresolved_only:
            if status not in {"needs-owner", "ownership-conflict"}:
                raise ProviderProtocolError("provider failure is not a routing decision")
        elif status != "resolved":
            raise ProviderProtocolError("successful route did not resolve an owner")
        if status == "resolved":
            if set(value) != fields | {"route_binding"}:
                raise ProviderProtocolError("bound route decision schema is invalid")
            owner = value["owner_skill"]
            scope = value["matched_scope"]
            path = value["owner_path"]
            binding = value["route_binding"]
            if not isinstance(owner, str) or not _NAME_RE.fullmatch(owner) or not isinstance(scope, str) or not _SCOPE_RE.fullmatch(scope) or not isinstance(path, str) or not isinstance(binding, str) or not _DIGEST_RE.fullmatch(binding):
                raise ProviderProtocolError("resolved route fields are invalid")
            owner_path = _no_symlink_components(Path(path), require_final=True)
            if not owner_path.is_dir():
                raise ProviderProtocolError("resolved owner path is invalid")
            return RouteDecision("resolved", owner, str(owner_path), scope, reason, binding)
        if set(value) != fields:
            raise ProviderProtocolError("unresolved route decision schema is invalid")
        if any(value[field] is not None for field in ("owner_skill", "owner_path", "matched_scope")):
            raise ProviderProtocolError("unresolved route contains owner identity")
        return RouteDecision(str(status), None, None, None, reason, None)

    @staticmethod
    def _parse_candidate(value: object) -> Candidate:
        required = {
            "schema_version", "event", "id", "created_at", "skill", "kind", "change_class",
            "title", "finding", "evidence", "target_hint", "confidence", "review_count",
            "needs_escalation", "status",
        }
        if not isinstance(value, dict) or required - set(value) or set(value) - _CANDIDATE_FIELDS:
            raise ProviderProtocolError("provider candidate schema is invalid")
        if value["schema_version"] != 1 or value["event"] != "candidate":
            raise ProviderProtocolError("provider candidate version is invalid")
        if not isinstance(value["created_at"], str) or not _TIMESTAMP_RE.fullmatch(value["created_at"]):
            raise ProviderProtocolError("provider candidate timestamp is invalid")
        skill = value["skill"]
        if not isinstance(skill, dict) or set(skill) != {"name", "path"} or not isinstance(skill["name"], str) or not _NAME_RE.fullmatch(skill["name"]) or not isinstance(skill["path"], str) or not skill["path"]:
            raise ProviderProtocolError("provider candidate skill is invalid")
        evidence = value["evidence"]
        confidence = value["confidence"]
        if not isinstance(evidence, list) or not 1 <= len(evidence) <= 5 or any(not isinstance(item, str) or not item or len(item) > 1200 for item in evidence):
            raise ProviderProtocolError("provider candidate evidence is invalid")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            raise ProviderProtocolError("provider candidate confidence is invalid")
        if value["kind"] not in {"procedure", "gotcha", "fact", "reference", "script-opportunity"} or value["change_class"] not in {"knowledge", "behavior"}:
            raise ProviderProtocolError("provider candidate enums are invalid")
        if value["status"] not in {"pending", "deferred", "promoted", "rejected", "superseded"}:
            raise ProviderProtocolError("provider candidate status is invalid")
        if not isinstance(value["target_hint"], (str, type(None))):
            raise ProviderProtocolError("provider candidate target hint is invalid")
        if isinstance(value["target_hint"], str):
            EvolverAdapter._relative(value["target_hint"])
        review_count = value["review_count"]
        if type(review_count) is not int or review_count < 0 or type(value["needs_escalation"]) is not bool:
            raise ProviderProtocolError("provider candidate review state is invalid")
        routed = {"sourceSkill", "ownerSkill", "ownerReason", "destinationClass", "relatedSkills", "dedupeKey", "scope"}
        present = routed & set(value)
        if present and present != routed:
            raise ProviderProtocolError("provider candidate routing is incomplete")
        if present:
            if (
                not isinstance(value["sourceSkill"], str)
                or not _NAME_RE.fullmatch(value["sourceSkill"])
                or not isinstance(value["ownerSkill"], str)
                or not _NAME_RE.fullmatch(value["ownerSkill"])
                or value["ownerSkill"] != skill["name"]
                or not isinstance(value["ownerReason"], str)
                or not value["ownerReason"]
                or len(value["ownerReason"]) > 500
                or value["destinationClass"] not in {"skill", "reference", "script", "profile", "agents"}
                or not isinstance(value["relatedSkills"], list)
                or any(not isinstance(item, str) or not _NAME_RE.fullmatch(item) for item in value["relatedSkills"])
                or not isinstance(value["dedupeKey"], str)
                or not _DEDUPE_RE.fullmatch(value["dedupeKey"])
                or not isinstance(value["scope"], str)
                or not _SCOPE_RE.fullmatch(value["scope"])
            ):
                raise ProviderProtocolError("provider candidate routing fields are invalid")
        operation = {"operationType", "operationId", "requestDigest"} & set(value)
        if operation and operation != {"operationType", "operationId", "requestDigest"}:
            raise ProviderProtocolError("provider candidate operation binding is incomplete")
        if operation and (
            value["operationType"] != "capture"
            or not isinstance(value["operationId"], str)
            or not _OPERATION_RE.fullmatch(value["operationId"])
            or not isinstance(value["requestDigest"], str)
            or not _DIGEST_RE.fullmatch(value["requestDigest"])
        ):
            raise ProviderProtocolError("provider candidate operation binding is invalid")
        if "last_review" in value:
            review = value["last_review"]
            base_review = {
                "schema_version", "event", "id", "created_at", "candidate_id", "outcome",
                "reason", "next_trigger",
            }
            operation_review = {"operationType", "operationId", "requestDigest"}
            if (
                not isinstance(review, dict)
                or frozenset(review) not in {frozenset(base_review), frozenset(base_review | operation_review)}
                or review.get("schema_version") != 1
                or review.get("event") != "review"
                or review.get("candidate_id") != value["id"]
                or review.get("outcome") != "deferred"
                or not isinstance(review.get("id"), str)
                or not _ID_RE.fullmatch(str(review["id"]))
                or not isinstance(review.get("created_at"), str)
                or not _TIMESTAMP_RE.fullmatch(str(review["created_at"]))
            ):
                raise ProviderProtocolError("provider candidate last review is invalid")
            try:
                EvolverAdapter._safe_provider_text(review["reason"], "provider review reason", 1000)
                EvolverAdapter._safe_provider_text(review["next_trigger"], "provider review next trigger", 500)
            except ProviderProtocolError:
                raise ProviderProtocolError("provider candidate last review is invalid") from None
            if operation_review <= set(review) and (
                review["operationType"] != "defer"
                or not isinstance(review["operationId"], str)
                or not _OPERATION_RE.fullmatch(review["operationId"])
                or not isinstance(review["requestDigest"], str)
                or not _DIGEST_RE.fullmatch(review["requestDigest"])
            ):
                raise ProviderProtocolError("provider candidate last review operation is invalid")
        if review_count == 0 and "last_review" in value or review_count > 0 and "last_review" not in value:
            raise ProviderProtocolError("provider candidate review count is inconsistent")
        status = value["status"]
        resolution = value.get("resolution")
        resolved = status in {"promoted", "rejected", "superseded"}
        if (
            status == "pending" and review_count != 0
            or status == "deferred" and review_count == 0
            or resolved is not (resolution is not None)
            or value["needs_escalation"] is not (review_count >= 3 and not resolved)
        ):
            raise ProviderProtocolError("provider candidate folded status state is inconsistent")
        if resolution is not None:
            base_resolution = {
                "schema_version", "event", "id", "created_at", "candidate_id", "decision",
                "reason", "artifacts",
            }
            operation_resolution = {"operationType", "operationId", "requestDigest"}
            if (
                not isinstance(resolution, dict)
                or frozenset(resolution) not in {
                    frozenset(base_resolution),
                    frozenset(base_resolution | operation_resolution),
                }
                or resolution.get("schema_version") != 1
                or resolution.get("event") != "resolution"
                or resolution.get("candidate_id") != value["id"]
                or resolution.get("decision") != status
                or not isinstance(resolution.get("id"), str)
                or not _ID_RE.fullmatch(str(resolution["id"]))
                or not isinstance(resolution.get("created_at"), str)
                or not _TIMESTAMP_RE.fullmatch(str(resolution["created_at"]))
                or not isinstance(resolution.get("artifacts"), list)
            ):
                raise ProviderProtocolError("provider candidate resolution is invalid")
            try:
                EvolverAdapter._safe_provider_text(resolution["reason"], "provider resolution reason", 1000)
                for artifact in resolution["artifacts"]:
                    EvolverAdapter._relative(artifact)
            except ProviderProtocolError:
                raise ProviderProtocolError("provider candidate resolution is invalid") from None
            if operation_resolution <= set(resolution) and (
                resolution["operationType"] != "resolve"
                or not isinstance(resolution["operationId"], str)
                or not _OPERATION_RE.fullmatch(resolution["operationId"])
                or not isinstance(resolution["requestDigest"], str)
                or not _DIGEST_RE.fullmatch(resolution["requestDigest"])
            ):
                raise ProviderProtocolError("provider candidate resolution operation is invalid")
        return Candidate(
            candidate_id=EvolverAdapter._id(value["id"]),
            status=EvolverAdapter._text(value["status"], 32),
            skill_name=skill["name"], skill_path=skill["path"],
            kind=EvolverAdapter._text(value["kind"], 64),
            change_class=EvolverAdapter._text(value["change_class"], 32),
            title=EvolverAdapter._text(value["title"], 120),
            finding=EvolverAdapter._text(value["finding"], 2000),
            evidence=tuple(evidence), confidence=float(confidence),
            target_hint=value["target_hint"] if isinstance(value["target_hint"], str) else None,
            source_skill=value.get("sourceSkill") if isinstance(value.get("sourceSkill"), str) else None,
            owner_skill=value.get("ownerSkill") if isinstance(value.get("ownerSkill"), str) else None,
            destination_class=value.get("destinationClass") if isinstance(value.get("destinationClass"), str) else None,
            dedupe_key=value.get("dedupeKey") if isinstance(value.get("dedupeKey"), str) else None,
            scope=value.get("scope") if isinstance(value.get("scope"), str) else None,
            operation_id=value.get("operationId") if isinstance(value.get("operationId"), str) else None,
            request_digest=value.get("requestDigest") if isinstance(value.get("requestDigest"), str) else None,
            review_count=review_count, needs_escalation=value["needs_escalation"],
        )

    @staticmethod
    def _safe_candidate_text(value: object, label: str, limit: int) -> str:
        return EvolverAdapter._safe_provider_text(value, f"candidate {label}", limit)

    @staticmethod
    def _safe_provider_text(value: object, label: str, limit: int) -> str:
        text = EvolverAdapter._text(value, limit)
        admitted = sanitize_evidence([{"kind": "candidate", "summary": text}])
        if (
            admitted.rejected_count
            or admitted.truncated_count
            or len(admitted.accepted) != 1
            or admitted.accepted[0]["summary"] != text
        ):
            raise ProviderProtocolError(f"{label} is unsafe")
        return text

    @staticmethod
    def _capture_candidate(candidate: object) -> None:
        from .candidates import ImprovementCandidateDraft

        if not isinstance(candidate, ImprovementCandidateDraft):
            raise ProviderProtocolError("capture candidate type is invalid")
        if not _ID_RE.fullmatch(candidate.evaluation_id):
            raise ProviderProtocolError("capture candidate evaluation is invalid")
        EvolverAdapter._operation(candidate.operation_id)
        EvolverAdapter._name(candidate.source_skill)
        EvolverAdapter._name(candidate.target_skill)
        if (
            candidate.kind not in {"procedure", "gotcha", "fact", "reference", "script-opportunity"}
            or candidate.change_class not in {"knowledge", "behavior"}
            or candidate.destination_class not in {"skill", "reference", "script", "profile", "agents"}
            or candidate.risk not in {"low", "medium", "high"}
        ):
            raise ProviderProtocolError("capture candidate enums are invalid")
        compatible = {
            "knowledge": {"skill", "reference", "agents"},
            "behavior": {"skill", "script", "profile", "agents"},
        }
        if candidate.destination_class not in compatible[candidate.change_class]:
            raise ProviderProtocolError("capture candidate destination is incompatible")
        if candidate.kind == "script-opportunity" and (candidate.change_class, candidate.destination_class) != ("behavior", "script"):
            raise ProviderProtocolError("capture candidate script opportunity is incompatible")
        if len(candidate.scope) > 200 or not _SCOPE_RE.fullmatch(candidate.scope):
            raise ProviderProtocolError("capture candidate scope is invalid")
        if len(candidate.dedupe_key) > 200 or not _DEDUPE_RE.fullmatch(candidate.dedupe_key):
            raise ProviderProtocolError("capture candidate dedupe key is invalid")
        EvolverAdapter._safe_candidate_text(candidate.scope, "scope", 200)
        EvolverAdapter._safe_candidate_text(candidate.dedupe_key, "dedupe key", 200)
        if (
            not isinstance(candidate.related_skills, tuple)
            or len(candidate.related_skills) > 32
            or tuple(sorted(set(candidate.related_skills))) != candidate.related_skills
        ):
            raise ProviderProtocolError("capture candidate related skills are invalid")
        for related in candidate.related_skills:
            EvolverAdapter._name(related)
        if (
            not isinstance(candidate.evidence, tuple)
            or not 1 <= len(candidate.evidence) <= 5
            or tuple(sorted(set(candidate.evidence))) != candidate.evidence
        ):
            raise ProviderProtocolError("capture candidate evidence is invalid")
        for evidence in candidate.evidence:
            EvolverAdapter._safe_candidate_text(evidence, "evidence", 1200)
        EvolverAdapter._safe_candidate_text(candidate.title, "title", 120)
        EvolverAdapter._safe_candidate_text(candidate.finding, "finding", 2000)
        if candidate.target_hint is not None:
            EvolverAdapter._relative(candidate.target_hint)
            EvolverAdapter._safe_candidate_text(candidate.target_hint, "target hint", 500)
        if type(candidate.confidence) is not float or not math.isfinite(candidate.confidence) or not 0 <= candidate.confidence <= 1:
            raise ProviderProtocolError("capture candidate confidence is invalid")
        semantic = candidate.canonical_mapping()
        operation = str(semantic.pop("operationId"))
        expected = "rsi-capture-" + hashlib.sha256(
            json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        ).hexdigest()[:48]
        if operation != expected:
            raise ProviderProtocolError("capture candidate operation binding is invalid")

    @staticmethod
    def _text(value: object, limit: int) -> str:
        if not isinstance(value, str) or not value or len(value) > limit or "\x00" in value:
            raise ProviderProtocolError("provider request text is invalid")
        return value

    @staticmethod
    def _id(value: object) -> str:
        if not isinstance(value, str) or not _ID_RE.fullmatch(value):
            raise ProviderProtocolError("provider identifier is invalid")
        return value

    @staticmethod
    def _id_line(value: bytes) -> str:
        if not value.endswith(b"\n") or value.count(b"\n") != 1:
            raise ProviderProtocolError("provider identifier output is malformed")
        try:
            return EvolverAdapter._id(value[:-1].decode("ascii"))
        except UnicodeDecodeError:
            raise ProviderProtocolError("provider identifier output is malformed") from None

    @staticmethod
    def _path_line(value: bytes) -> str:
        if not value.endswith(b"\n") or value.count(b"\n") != 1:
            raise ProviderProtocolError("provider path output is malformed")
        try:
            path = value[:-1].decode("utf-8")
        except UnicodeDecodeError:
            raise ProviderProtocolError("provider path output is malformed") from None
        if not path or "\x00" in path or not Path(path).is_absolute():
            raise ProviderProtocolError("provider path output is unsafe")
        return path

    @staticmethod
    def _relative(value: object) -> str:
        text = EvolverAdapter._text(value, 500)
        path = PurePosixPath(text)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or "\\" in text:
            raise ProviderProtocolError("provider artifact path is unsafe")
        return text

    @staticmethod
    def _relative_list(value: object) -> tuple[str, ...]:
        if not isinstance(value, list) or len(value) > 4096:
            raise ProviderProtocolError("restore path list is invalid")
        result = tuple(EvolverAdapter._relative(item) for item in value)
        if tuple(sorted(set(result))) != result:
            raise ProviderProtocolError("restore path list is not canonical")
        return result
