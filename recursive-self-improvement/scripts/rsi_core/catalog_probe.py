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
        completed = subprocess.run(
            [*command, *arguments],
            cwd=run_root,
            env=environment,
            check=False,
            capture_output=True,
            timeout=_CLIENT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise CatalogProbeError("catalog client is unavailable") from None
    if (
        completed.returncode != 0
        or len(completed.stdout) > _MAX_CLIENT_OUTPUT_BYTES
        or len(completed.stderr) > _MAX_CLIENT_OUTPUT_BYTES
    ):
        raise CatalogProbeError("catalog client failed or exceeded its output bound")
    return completed


def probe_catalog_client(
    installed_root: Path,
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
    if not isinstance(installed_root, Path) or not isinstance(run_root, Path):
        raise CatalogProbeError("catalog probe roots must be Paths")
    installed_root = Path(os.path.abspath(installed_root))
    run_root = Path(os.path.abspath(run_root))
    try:
        installed_metadata = os.lstat(installed_root)
    except OSError:
        raise CatalogProbeError("verified installed package is unavailable") from None
    if not stat.S_ISDIR(installed_metadata.st_mode) or run_root.exists():
        raise CatalogProbeError("catalog probe requires a real package and fresh run root")
    canonical_installed = installed_root.resolve(strict=True)
    canonical_parent = run_root.parent.resolve(strict=True)
    canonical_run = canonical_parent / run_root.name
    if (
        canonical_run == canonical_installed
        or canonical_run in canonical_installed.parents
        or canonical_installed in canonical_run.parents
    ):
        raise CatalogProbeError("catalog probe roots overlap")

    surface_before = _surface_snapshot(canonical_installed)
    surface_digest = _surface_digest(surface_before)
    skill_payload = (canonical_installed / "SKILL.md").read_bytes()
    description = _description(skill_payload)

    canonical_run.mkdir(mode=0o700)
    codex_home = canonical_run / "codex-home"
    projected = codex_home / "skills" / "recursive-self-improvement"
    (projected / "agents").mkdir(parents=True, mode=0o700)
    for relative in _CATALOG_FILES:
        source = canonical_installed / relative
        destination = projected / relative
        shutil.copy2(source, destination, follow_symlinks=False)
    projected_before = _surface_snapshot(projected)
    client_home_before = _tree_snapshot(codex_home)
    environment = _client_environment(canonical_run, codex_home)

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
    surface_after = _surface_snapshot(canonical_installed)
    if projected_after != projected_before or surface_after != surface_before:
        raise CatalogProbeError("catalog probe changed a catalog surface")
    isolated_changes = _change_count(
        client_home_before,
        _tree_snapshot(codex_home),
    )
    return CatalogClientResult(
        client_name=client_name,
        version=version,
        catalog_entry_count=1,
        model_locator=expected_locator,
        verified_locator=canonical_installed / "SKILL.md",
        catalog_surface_digest=surface_digest,
        isolated_home_change_count=isolated_changes,
        skill_body_absent=True,
    )


def _latest_command(npx: str, root: Path) -> tuple[str, ...]:
    resolver = root / "latest-resolver"
    resolver.mkdir(mode=0o700)
    codex_home = resolver / "codex-home"
    codex_home.mkdir(mode=0o700)
    environment = _client_environment(resolver, codex_home)
    completed = _run_client(
        (npx, "--yes", "@openai/codex@latest"),
        ("--version",),
        run_root=resolver,
        environment=environment,
    )
    try:
        rendered = completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise CatalogProbeError("latest Codex version is not UTF-8") from None
    matches = _VERSION.findall(rendered)
    if len(matches) != 1:
        raise CatalogProbeError("latest Codex version cannot be pinned exactly")
    return (npx, "--yes", f"@openai/codex@{matches[0]}")


def _live_witness(authority: object) -> tuple[object, ...]:
    from .global_rollout import (
        _capture_optional_path_witness,
        _capture_repository_witness,
    )

    paths = authority.deployment_paths
    protected_paths = (
        paths.skills_root,
        paths.agents_file,
        paths.state_root,
        authority.provider_home,
        authority.provider_ledger,
        *authority.target_roots,
    )
    unique: list[Path] = []
    for path in protected_paths:
        if path not in unique:
            unique.append(path)
    return (
        _capture_repository_witness(authority.source_repository),
        *(
            _capture_optional_path_witness(path, label="catalog probe protected root")
            for path in unique
        ),
    )


def run_live_catalog_probe() -> CatalogProbeReport:
    """Verify live authority and run mandatory local/latest isolated probes."""

    from .deployment import GlobalRsiDeployer
    from .global_rollout import DryRunAuthority

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
    with tempfile.TemporaryDirectory(prefix="rsi-catalog-probe-") as raw_root:
        root = Path(raw_root).resolve(strict=True)
        latest = _latest_command(npx, root)
        clients = (
            probe_catalog_client(
                authority.deployment_paths.installed_root,
                root / "local",
                command=(local,),
                client_name="local",
            ),
            probe_catalog_client(
                authority.deployment_paths.installed_root,
                root / "latest",
                command=latest,
                client_name="latest",
            ),
        )
    status_after = deployer.verify()
    witness_after = _live_witness(authority)
    if status_after != status_before or witness_after != witness_before:
        raise CatalogProbeError("catalog probe changed a protected live witness")
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
