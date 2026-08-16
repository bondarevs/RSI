from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

import pytest


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CODEX = shutil.which("codex")
NPX = shutil.which("npx")
RUN_LATEST_CODEX = os.environ.get("RSI_TEST_LATEST_CODEX") == "1"
CATALOG_PROMPT = (
    "Report only whether the model-visible skill catalog contains "
    "recursive-self-improvement. Do not invoke any skill."
)
SKILL_BODY_SENTINEL = (
    "Operate as the control plane for evidence-backed role-skill improvement."
)
EXPECTED_SKILL_DESCRIPTION = (
    "Use only during or after a completed, verified skill-driven task to preserve "
    "and evaluate evidence-backed reusable findings without changing role goals or "
    "weakening safeguards. Use for recurring role-skill evidence, validated "
    "improvements, ownership audits, defragmentation, or cross-skill RSI reports. "
    "Do not use for ordinary conversation, status questions, one-off facts, tasks "
    "without reusable evidence, or RSI/skill-learning deployment and maintenance."
)


def _tree_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    result: list[tuple[object, ...]] = []
    for path in sorted((root, *root.rglob("*")), key=lambda item: os.fsencode(item)):
        metadata = os.lstat(path)
        relative = "." if path == root else path.relative_to(root).as_posix()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISREG(metadata.st_mode):
            payload = path.read_bytes()
            kind = "regular"
            evidence: object = (len(payload), hashlib.sha256(payload).hexdigest())
        elif stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
            evidence = None
        elif stat.S_ISLNK(metadata.st_mode):
            kind = "symlink"
            evidence = os.readlink(path)
        else:
            kind = "special"
            evidence = None
        result.append((relative, kind, mode, metadata.st_nlink, evidence))
    return tuple(result)


def _install_catalog_surface(package_root: Path, installed: Path) -> None:
    (installed / "agents").mkdir(parents=True)
    shutil.copy2(package_root / "SKILL.md", installed / "SKILL.md")
    shutil.copy2(
        package_root / "agents/openai.yaml",
        installed / "agents/openai.yaml",
    )


def _render_fresh_catalog(
    package_root: Path,
    run_root: Path,
    *,
    command: tuple[str, ...] | None = None,
) -> tuple[str, Path]:
    selected = (CODEX,) if command is None else command
    assert selected and all(type(item) is str and item for item in selected)
    run_root.mkdir(parents=True)
    codex_home = run_root / "codex-home"
    installed = codex_home / "skills" / "recursive-self-improvement"
    _install_catalog_surface(package_root, installed)
    isolated_home = run_root / "isolated-home"
    isolated_home.mkdir()
    environment = {
        "CODEX_HOME": os.fspath(codex_home),
        "HOME": os.fspath(isolated_home),
        "PATH": os.environ["PATH"],
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
    }
    completed = subprocess.run(
        [*selected, "debug", "prompt-input", CATALOG_PROMPT],
        cwd=run_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert type(payload) is list
    rendered = "\n".join(
        item["text"]
        for message in payload
        for item in message.get("content", [])
        if item.get("type") == "input_text" and type(item.get("text")) is str
    )
    return rendered, codex_home


@pytest.mark.parametrize(
    ("client_name", "command"),
    [
        pytest.param(
            "local",
            (CODEX,),
            marks=pytest.mark.skipif(CODEX is None, reason="Codex CLI is unavailable"),
        ),
        pytest.param(
            "latest",
            (NPX, "--yes", "@openai/codex@latest"),
            marks=pytest.mark.skipif(
                NPX is None or not RUN_LATEST_CODEX,
                reason="set RSI_TEST_LATEST_CODEX=1 for the mandatory network gate",
            ),
        ),
    ],
)
def test_catalog_probe_confines_real_client_system_sync(
    tmp_path: Path,
    client_name: str,
    command: tuple[str, ...],
) -> None:
    assert all(item is not None for item in command)
    exact_command = tuple(str(item) for item in command)

    unsafe_home = tmp_path / "unsafe-codex-home"
    unsafe_installed = unsafe_home / "skills" / "recursive-self-improvement"
    _install_catalog_surface(PACKAGE_ROOT, unsafe_installed)
    unsafe_before = _tree_snapshot(unsafe_home)

    _render_fresh_catalog(
        PACKAGE_ROOT,
        tmp_path / "unsafe-run",
        command=exact_command,
    )
    direct_run_home = tmp_path / "unsafe-run" / "codex-home"
    direct_after_client = _tree_snapshot(direct_run_home)
    assert direct_after_client != unsafe_before
    assert (direct_run_home / "skills" / ".system").is_dir()

    probe_module = PACKAGE_ROOT / "scripts" / "rsi_core" / "catalog_probe.py"
    assert probe_module.is_file(), (
        f"real {client_name} catalog rendering synchronized .system inside its "
        "active CODEX_HOME, but the isolated catalog probe is missing"
    )
    catalog_probe = importlib.import_module("rsi_core.catalog_probe")

    protected_home = tmp_path / "protected-codex-home"
    protected_installed = (
        protected_home / "skills" / "recursive-self-improvement"
    )
    _install_catalog_surface(PACKAGE_ROOT, protected_installed)
    protected_before = _tree_snapshot(protected_home)

    result = catalog_probe.probe_catalog_client(
        protected_installed,
        tmp_path / "isolated-probe",
        command=exact_command,
        client_name=client_name,
    )

    assert _tree_snapshot(protected_home) == protected_before
    assert result.client_name == client_name
    assert result.catalog_entry_count == 1
    assert result.verified_locator == protected_installed / "SKILL.md"
    assert result.model_locator != result.verified_locator
    assert result.isolated_home_change_count > 0
    assert result.skill_body_absent is True


@pytest.mark.skipif(CODEX is None, reason="Codex CLI is unavailable")
def test_fresh_codex_catalog_lists_rsi_without_invoking_it(tmp_path: Path) -> None:
    rendered, codex_home = _render_fresh_catalog(PACKAGE_ROOT, tmp_path / "visible")

    assert "### Available skills" in rendered
    assert rendered.count("- recursive-self-improvement:") == 1
    assert f"- recursive-self-improvement: {EXPECTED_SKILL_DESCRIPTION}" in rendered
    assert os.fspath(
        codex_home / "skills/recursive-self-improvement/SKILL.md"
    ) in rendered
    assert SKILL_BODY_SENTINEL not in rendered


@pytest.mark.skipif(CODEX is None, reason="Codex CLI is unavailable")
def test_disabled_policy_is_not_model_visible(tmp_path: Path) -> None:
    disabled = tmp_path / "disabled-package"
    _install_catalog_surface(PACKAGE_ROOT, disabled)
    metadata_path = disabled / "agents/openai.yaml"
    metadata = metadata_path.read_text(encoding="utf-8")
    assert metadata.count("allow_implicit_invocation: true") == 1
    metadata_path.write_text(
        metadata.replace(
            "allow_implicit_invocation: true",
            "allow_implicit_invocation: false",
        ),
        encoding="utf-8",
    )

    rendered, codex_home = _render_fresh_catalog(disabled, tmp_path / "disabled")

    assert "- recursive-self-improvement:" not in rendered
    assert os.fspath(
        codex_home / "skills/recursive-self-improvement/SKILL.md"
    ) not in rendered


@pytest.mark.skipif(CODEX is None, reason="Codex CLI is unavailable")
def test_catalog_probe_preserves_source_and_creates_no_rsi_state(tmp_path: Path) -> None:
    protected = tmp_path / "protected" / "witness.bin"
    protected.parent.mkdir()
    protected.write_bytes(b"protected-before\n")
    package_before = _tree_snapshot(PACKAGE_ROOT)

    _render_fresh_catalog(PACKAGE_ROOT, tmp_path / "zero-write")

    assert _tree_snapshot(PACKAGE_ROOT) == package_before
    assert protected.read_bytes() == b"protected-before\n"
    assert not list(tmp_path.rglob("events.jsonl"))
    assert not list(tmp_path.rglob("observations.jsonl"))
    assert not list(tmp_path.rglob("reports.jsonl"))
    assert not list(tmp_path.rglob("rsi-deployments-v1"))
