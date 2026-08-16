"""Bounded catalog visibility probes with disposable client homes."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile


CATALOG_PROMPT = (
    "Report only whether the model-visible skill catalog contains "
    "recursive-self-improvement. Do not invoke any skill."
)
SKILL_BODY_SENTINEL = (
    "Operate as the control plane for evidence-backed role-skill improvement."
)
_CATALOG_FILES = ("SKILL.md", "agents/openai.yaml")
_MAX_CLIENT_OUTPUT_BYTES = 16 * 1024 * 1024
_MAX_VERSION_CHARS = 160
_CLIENT_TIMEOUT_SECONDS = 120
_VERSION = re.compile(r"(?<![0-9])([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?)")
_STATE_NAMES = frozenset(
    {
        "deployment",
        "deployments",
        "event",
        "events",
        "events.jsonl",
        "observation",
        "observations",
        "observations.jsonl",
        "provider",
        "provider-home",
        "provider-ledger",
        "report",
        "reports",
        "reports.jsonl",
        "rsi",
        "rsi-deployments-v1",
        "rsi-state",
    }
)
_STATE_PREFIXES = (
    ".rsi-",
    "deployment-",
    "deployment_",
    "event-",
    "event_",
    "observation-",
    "observation_",
    "provider-",
    "provider_",
    "report-",
    "report_",
    "rsi-",
    "rsi_",
)


class CatalogProbeError(RuntimeError):
    """A catalog client or protected-state gate failed closed."""


@dataclass(frozen=True, slots=True)
class CatalogClientResult:
    client_name: str
    version: str
    catalog_entry_count: int
    model_locator: Path
    verified_locator: Path
    catalog_surface_digest: str
    isolated_home_change_count: int
    skill_body_absent: bool

    def to_mapping(self) -> dict[str, object]:
        return {
            "catalogEntryCount": self.catalog_entry_count,
            "catalogSurfaceDigest": self.catalog_surface_digest,
            "client": self.client_name,
            "isolatedHomeChangeCount": self.isolated_home_change_count,
            "modelLocator": os.fspath(self.model_locator),
            "skillBodyAbsent": self.skill_body_absent,
            "verifiedLocator": os.fspath(self.verified_locator),
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class CatalogProbeReport:
    clients: tuple[CatalogClientResult, ...]
    deployment_operation_id: str
    deployment_source_commit: str
    deployment_tree_digest: str

    def to_mapping(self) -> dict[str, object]:
        return {
            "clients": [client.to_mapping() for client in self.clients],
            "deployment": {
                "operationId": self.deployment_operation_id,
                "sourceCommit": self.deployment_source_commit,
                "treeDigest": self.deployment_tree_digest,
                "verified": True,
            },
            "protectedWitnessesUnchanged": True,
            "schemaVersion": 1,
            "status": "complete",
        }


def _surface_snapshot(root: Path) -> tuple[tuple[str, int, int, str], ...]:
    rows: list[tuple[str, int, int, str]] = []
    for relative in _CATALOG_FILES:
        path = root / relative
        try:
            metadata = os.lstat(path)
        except OSError:
            raise CatalogProbeError("verified catalog surface is unavailable") from None
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise CatalogProbeError("verified catalog surface is not a private regular file")
        try:
            payload = path.read_bytes()
        except OSError:
            raise CatalogProbeError("verified catalog surface cannot be read") from None
        rows.append(
            (
                relative,
                stat.S_IMODE(metadata.st_mode),
                len(payload),
                hashlib.sha256(payload).hexdigest(),
            )
        )
    return tuple(rows)


def _surface_digest(snapshot: tuple[tuple[str, int, int, str], ...]) -> str:
    payload = json.dumps(
        snapshot,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _attested_surface_snapshot(surface: object) -> tuple[tuple[str, int, int, str], ...]:
    try:
        surface.verify()
        files = surface.files
    except (AttributeError, OSError, ValueError):
        raise CatalogProbeError("attested catalog surface is unavailable") from None
    rows: list[tuple[str, int, int, str]] = []
    for item in files:
        rows.append(
            (
                item.relative_path,
                0o700 if item.executable else 0o600,
                item.byte_length,
                item.digest.removeprefix("sha256:"),
            )
        )
    if tuple(row[0] for row in rows) != _CATALOG_FILES:
        raise CatalogProbeError("attested catalog surface is incomplete")
    return tuple(rows)


def _write_private_file(path: Path, payload: bytes, *, executable: bool) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o700 if executable else 0o600,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("catalog projection write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except OSError:
        raise CatalogProbeError("catalog surface projection failed") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _tree_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    rows: list[tuple[object, ...]] = []
    try:
        paths = (root, *root.rglob("*"))
        ordered = sorted(paths, key=lambda path: os.fsencode(path.relative_to(root)))
    except OSError:
        raise CatalogProbeError("isolated client home cannot be enumerated") from None
    for path in ordered:
        try:
            metadata = os.lstat(path)
        except OSError:
            raise CatalogProbeError("isolated client home changed while scanning") from None
        relative = "." if path == root else path.relative_to(root).as_posix()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISREG(metadata.st_mode):
            try:
                payload = path.read_bytes()
            except OSError:
                raise CatalogProbeError("isolated client file cannot be read") from None
            evidence: object = (len(payload), hashlib.sha256(payload).hexdigest())
            kind = "regular"
        elif stat.S_ISDIR(metadata.st_mode):
            evidence, kind = None, "directory"
        elif stat.S_ISLNK(metadata.st_mode):
            try:
                evidence = os.readlink(path)
            except OSError:
                raise CatalogProbeError("isolated client link cannot be read") from None
            kind = "symlink"
        else:
            evidence, kind = None, "special"
        rows.append((relative, kind, mode, metadata.st_nlink, evidence))
    return tuple(rows)


def _change_count(
    before: tuple[tuple[object, ...], ...],
    after: tuple[tuple[object, ...], ...],
) -> int:
    left = {str(row[0]): row[1:] for row in before}
    right = {str(row[0]): row[1:] for row in after}
    return sum(left.get(path) != right.get(path) for path in left.keys() | right.keys())


def _assert_no_unexpected_state(
    snapshot: tuple[tuple[object, ...], ...],
) -> None:
    allowed_projection = {
        "codex-home/skills",
        "codex-home/skills/recursive-self-improvement",
        "codex-home/skills/recursive-self-improvement/SKILL.md",
        "codex-home/skills/recursive-self-improvement/agents",
        "codex-home/skills/recursive-self-improvement/agents/openai.yaml",
    }
    for row in snapshot:
        relative = str(row[0])
        if relative == "." or relative in allowed_projection:
            continue
        if relative == "codex-home/skills/.system" or relative.startswith(
            "codex-home/skills/.system/"
        ):
            continue
        components = relative.split("/")
        for component in components:
            lowered = component.lower()
            if (
                lowered == "recursive-self-improvement"
                or lowered in _STATE_NAMES
                or lowered.startswith(_STATE_PREFIXES)
            ):
                raise CatalogProbeError(
                    "catalog client created unexpected RSI or provider state"
                )


def _description(skill_payload: bytes) -> str:
    try:
        text = skill_payload.decode("utf-8")
    except UnicodeDecodeError:
        raise CatalogProbeError("verified SKILL.md is not UTF-8") from None
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise CatalogProbeError("verified SKILL.md frontmatter is invalid")
    frontmatter = text.split("\n---\n", 1)[0][4:]
    descriptions = [
        line.removeprefix("description: ")
        for line in frontmatter.splitlines()
        if line.startswith("description: ")
    ]
    if len(descriptions) != 1 or not descriptions[0]:
        raise CatalogProbeError("verified skill description is unavailable")
    return descriptions[0]


def _client_environment(run_root: Path, codex_home: Path) -> dict[str, str]:
    isolated_home = run_root / "home"
    isolated_tmp = run_root / "tmp"
    npm_cache = run_root / "npm-cache"
    for directory in (isolated_home, isolated_tmp, npm_cache):
        directory.mkdir(mode=0o700)
    environment = {
        "CODEX_HOME": os.fspath(codex_home),
        "HOME": os.fspath(isolated_home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": os.environ.get("PATH", os.defpath),
        "TMPDIR": os.fspath(isolated_tmp),
        "npm_config_cache": os.fspath(npm_cache),
    }
    for name in (
        "ALL_PROXY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "all_proxy",
        "https_proxy",
        "http_proxy",
        "no_proxy",
    ):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _run_client(
    command: tuple[str, ...],
    arguments: tuple[str, ...],
    *,
    run_root: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    try:
        process = subprocess.Popen(
            [*command, *arguments],
            cwd=run_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except OSError:
        raise CatalogProbeError("catalog client is unavailable") from None
    try:
        from .global_rollout import _capture_bounded

        return_code, stdout_bytes, stderr_bytes = _capture_bounded(
            process,
            deadline_seconds=_CLIENT_TIMEOUT_SECONDS,
            max_capture_bytes=_MAX_CLIENT_OUTPUT_BYTES,
            context="catalog client",
        )
    except RuntimeError as error:
        raise CatalogProbeError(str(error)) from None
    if return_code != 0:
        raise CatalogProbeError(f"catalog client failed with exit code {return_code}")
    return subprocess.CompletedProcess(
        args=[*command, *arguments],
        returncode=return_code,
        stdout=stdout_bytes,
        stderr=stderr_bytes,
    )


def probe_catalog_client(
    catalog_surface: object,
    run_root: Path,
    *,
    command: tuple[str, ...],
    client_name: str,
) -> CatalogClientResult:
    """Project verified catalog bytes into one disposable client home."""

    if (
        type(command) is not tuple
        or not command
        or any(type(item) is not str or not item or "\x00" in item for item in command)
        or type(client_name) is not str
        or re.fullmatch(r"[a-z][a-z0-9-]{0,31}", client_name) is None
    ):
        raise CatalogProbeError("catalog client descriptor is invalid")
    from .global_rollout import AttestedCatalogSurface

    if type(catalog_surface) is not AttestedCatalogSurface or not isinstance(
        run_root, Path
    ):
        raise CatalogProbeError("catalog probe requires an attested surface and Path root")
    installed_root = Path(os.path.abspath(catalog_surface.installed_root))
    run_root = Path(os.path.abspath(run_root))
    if run_root.exists():
        raise CatalogProbeError("catalog probe requires a fresh run root")
    canonical_parent = run_root.parent.resolve(strict=True)
    canonical_run = canonical_parent / run_root.name
    if (
        canonical_run == installed_root
        or canonical_run in installed_root.parents
        or installed_root in canonical_run.parents
    ):
        raise CatalogProbeError("catalog probe roots overlap")

    surface_before = _attested_surface_snapshot(catalog_surface)
    surface_digest = _surface_digest(surface_before)
    try:
        skill_payload = catalog_surface.payload("SKILL.md")
    except ValueError:
        raise CatalogProbeError("attested SKILL.md is unavailable") from None
    description = _description(skill_payload)

    canonical_run.mkdir(mode=0o700)
    codex_home = canonical_run / "codex-home"
    projected = codex_home / "skills" / "recursive-self-improvement"
    (projected / "agents").mkdir(parents=True, mode=0o700)
    for item in catalog_surface.files:
        _write_private_file(
            projected / item.relative_path,
            item.payload_bytes,
            executable=item.executable,
        )
    projected_before = _surface_snapshot(projected)
    environment = _client_environment(canonical_run, codex_home)
    disposable_before = _tree_snapshot(canonical_run)

    version_result = _run_client(
        command,
        ("--version",),
        run_root=canonical_run,
        environment=environment,
    )
    try:
        version = version_result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise CatalogProbeError("catalog client version is not UTF-8") from None
    if not version or len(version) > _MAX_VERSION_CHARS or "\n" in version:
        raise CatalogProbeError("catalog client version is invalid")

    prompt_result = _run_client(
        command,
        ("debug", "prompt-input", CATALOG_PROMPT),
        run_root=canonical_run,
        environment=environment,
    )
    try:
        payload = json.loads(prompt_result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CatalogProbeError("catalog client returned invalid JSON") from None
    if type(payload) is not list:
        raise CatalogProbeError("catalog client returned a non-array prompt")
    try:
        rendered = "\n".join(
            item["text"]
            for message in payload
            for item in message.get("content", [])
            if item.get("type") == "input_text" and type(item.get("text")) is str
        )
    except (AttributeError, KeyError, TypeError):
        raise CatalogProbeError("catalog client prompt schema is invalid") from None

    rows = [
        line
        for line in rendered.splitlines()
        if line.startswith("- recursive-self-improvement:")
    ]
    expected_locator = projected / "SKILL.md"
    expected_row = (
        f"- recursive-self-improvement: {description} "
        f"(file: {os.fspath(expected_locator)})"
    )
    if "### Available skills" not in rendered or rows != [expected_row]:
        raise CatalogProbeError("catalog client did not expose one exact RSI row")
    if SKILL_BODY_SENTINEL in rendered:
        raise CatalogProbeError("catalog client injected the RSI skill body")

    projected_after = _surface_snapshot(projected)
    surface_after = _attested_surface_snapshot(catalog_surface)
    if projected_after != projected_before or surface_after != surface_before:
        raise CatalogProbeError("catalog probe changed a catalog surface")
    disposable_after = _tree_snapshot(canonical_run)
    _assert_no_unexpected_state(disposable_after)
    isolated_changes = _change_count(disposable_before, disposable_after)
    return CatalogClientResult(
        client_name=client_name,
        version=version,
        catalog_entry_count=1,
        model_locator=expected_locator,
        verified_locator=catalog_surface.verified_locator("SKILL.md"),
        catalog_surface_digest=surface_digest,
        isolated_home_change_count=isolated_changes,
        skill_body_absent=True,
    )


def _latest_command(npx: str, root: Path) -> tuple[tuple[str, ...], str]:
    resolver = root / "latest-resolver"
    resolver.mkdir(mode=0o700)
    codex_home = resolver / "codex-home"
    codex_home.mkdir(mode=0o700)
    environment = _client_environment(resolver, codex_home)
    try:
        completed = _run_client(
            (npx, "--yes", "@openai/codex@latest"),
            ("--version",),
            run_root=resolver,
            environment=environment,
        )
    except CatalogProbeError as error:
        raise CatalogProbeError(f"latest Codex resolution failed: {error}") from None
    try:
        rendered = completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise CatalogProbeError("latest Codex version is not UTF-8") from None
    matches = _VERSION.findall(rendered)
    if len(matches) != 1:
        raise CatalogProbeError("latest Codex version cannot be pinned exactly")
    _assert_no_unexpected_state(_tree_snapshot(resolver))
    return (npx, "--yes", f"@openai/codex@{matches[0]}"), matches[0]


def _live_witness(authority: object) -> tuple[object, ...]:
    from .global_rollout import (
        _capture_optional_path_witness,
        _capture_protected_tree_witness,
        _capture_repository_witness,
    )

    paths = authority.deployment_paths
    protected_trees = (
        paths.skills_root,
        *authority.target_roots,
    )
    strict_paths = (
        paths.installed_root,
        paths.agents_file,
        paths.state_root,
        authority.provider_home,
        authority.provider_ledger,
    )
    unique_trees: list[Path] = []
    for path in protected_trees:
        if path not in unique_trees:
            unique_trees.append(path)
    unique_strict: list[Path] = []
    for path in strict_paths:
        if path not in unique_strict:
            unique_strict.append(path)
    return (
        _capture_repository_witness(authority.source_repository),
        *(
            (os.fspath(path), _capture_protected_tree_witness(path))
            for path in unique_trees
        ),
        *(
            _capture_optional_path_witness(path, label="catalog probe protected root")
            for path in unique_strict
        ),
    )


def run_live_catalog_probe() -> CatalogProbeReport:
    """Verify live authority and run mandatory local/latest isolated probes."""

    from .deployment import GlobalRsiDeployer
    from .global_rollout import DryRunAuthority, attest_installed_snapshot

    local = shutil.which("codex")
    npx = shutil.which("npx")
    if local is None or npx is None:
        raise CatalogProbeError("local Codex and npx are both required")
    authority = DryRunAuthority.live()
    deployer = GlobalRsiDeployer(authority.deployment_paths)
    status_before = deployer.verify()
    if (
        status_before.state != "verified"
        or status_before.verified is not True
        or status_before.operation_id is None
        or status_before.source_commit is None
        or status_before.tree_digest is None
    ):
        raise CatalogProbeError("live RSI deployment is not verified")
    witness_before = _live_witness(authority)
    snapshot = None
    clients: tuple[CatalogClientResult, ...] | None = None
    primary_error: Exception | None = None
    try:
        snapshot = attest_installed_snapshot(
            authority.deployment_paths.installed_root,
            deployer,
        )
        catalog_surface = snapshot.catalog_surface()
        with tempfile.TemporaryDirectory(prefix="rsi-catalog-probe-") as raw_root:
            root = Path(raw_root).resolve(strict=True)
            latest, latest_version = _latest_command(npx, root)
            local_result = probe_catalog_client(
                catalog_surface,
                root / "local",
                command=(local,),
                client_name="local",
            )
            latest_result = probe_catalog_client(
                catalog_surface,
                root / "latest",
                command=latest,
                client_name="latest",
            )
            if _VERSION.findall(latest_result.version) != [latest_version]:
                raise CatalogProbeError(
                    "latest Codex execution version differs from its exact pin"
                )
            clients = (local_result, latest_result)
    except Exception as error:
        primary_error = error
    comparison_error: Exception | None = None
    status_after = None
    witness_after = None
    try:
        status_after = deployer.verify()
        witness_after = _live_witness(authority)
    except Exception as error:
        comparison_error = error
    finally:
        if snapshot is not None:
            snapshot.close()
    if (
        comparison_error is not None
        or status_after != status_before
        or witness_after != witness_before
    ):
        raise CatalogProbeError("catalog probe changed a protected live witness") from (
            primary_error if primary_error is not None else comparison_error
        )
    if primary_error is not None:
        raise primary_error
    if clients is None:
        raise CatalogProbeError("catalog clients did not complete")
    return CatalogProbeReport(
        clients=clients,
        deployment_operation_id=status_before.operation_id,
        deployment_source_commit=status_before.source_commit,
        deployment_tree_digest=status_before.tree_digest,
    )


__all__ = [
    "CatalogClientResult",
    "CatalogProbeError",
    "CatalogProbeReport",
    "probe_catalog_client",
    "run_live_catalog_probe",
]
