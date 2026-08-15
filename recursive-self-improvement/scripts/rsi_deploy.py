#!/usr/bin/env python3
"""Strict live CLI for the transactional global RSI observe deployment."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import stat
import sys
from typing import Mapping


# Read-only commands must not leave import caches even when the caller forgot -B.
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

MAX_OUTPUT_BYTES = 64 * 1024
EXIT_COMPLETE = 0
EXIT_INVALID = 2
EXIT_NOT_INSTALLED = 3
EXIT_CONFLICT = 4
EXIT_INTEGRITY = 5
EXIT_UNSUPPORTED = 6
EXIT_AMBIGUOUS = 9

_COMMANDS = frozenset({"plan", "deploy", "verify", "status", "rollback"})
_READ_ONLY = frozenset({"verify", "status"})


class _CliGrammarError(ValueError):
    pass


def _canonical(value: Mapping[str, object]) -> bytes:
    from rsi_core.deployment_schema import canonical_json_bytes

    payload = canonical_json_bytes(value)
    if len(payload) <= MAX_OUTPUT_BYTES:
        return payload
    return canonical_json_bytes(
        {
            "command": "",
            "error": {
                "code": "output-bound",
                "message": "deployment result exceeded its output bound",
            },
            "schemaVersion": 1,
            "status": "failed",
        }
    )


def _failure(command: str, code: str, message: str) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "command": command,
        "status": "failed",
        "error": {"code": code, "message": message},
    }


def _parse_pairs(tokens: list[str], required: frozenset[str]) -> dict[str, str]:
    if len(tokens) % 2:
        raise _CliGrammarError("command options require values")
    result: dict[str, str] = {}
    for position in range(0, len(tokens), 2):
        option, value = tokens[position : position + 2]
        if option not in required or option in result:
            raise _CliGrammarError("command contains an unknown or duplicate option")
        if not value or value.startswith("-") or "\x00" in value:
            raise _CliGrammarError("command option value is invalid")
        result[option] = value
    if set(result) != set(required):
        raise _CliGrammarError("command is missing a required option")
    return result


def _parse(argv: list[str]) -> tuple[str, dict[str, str]]:
    if type(argv) is not list or not argv or any(type(item) is not str for item in argv):
        raise _CliGrammarError("one deployment command is required")
    command = argv[0]
    if command not in _COMMANDS:
        raise _CliGrammarError("deployment command is unknown")
    tail = argv[1:]
    if command in _READ_ONLY:
        if tail:
            raise _CliGrammarError("read-only command accepts no options")
        return command, {}
    if command == "plan":
        return command, _parse_pairs(tail, frozenset({"--source-repo"}))
    if command == "deploy":
        return command, _parse_pairs(
            tail, frozenset({"--source-repo", "--operation-id"})
        )
    return command, _parse_pairs(
        tail, frozenset({"--receipt-id", "--operation-id"})
    )


def _status_mapping(value: object) -> dict[str, object]:
    return {
        "state": value.state,
        "installed": value.installed,
        "verified": value.verified,
        "operationId": value.operation_id,
        "sourceCommit": value.source_commit,
        "treeDigest": value.tree_digest,
        "manifestDigest": value.manifest_digest,
        "receiptDigest": value.receipt_digest,
    }


def _plan_mapping(value: object) -> dict[str, object]:
    return {
        "eligible": value.eligible,
        "action": value.action,
        "sourceRepository": value.source_repository,
        "sourceCommit": value.source_commit,
        "sourceTreeDigest": value.source_tree_digest,
        "managedInstructionBlockDigest": value.managed_instruction_block_digest,
        "mode": value.mode,
        "hookMode": value.hook_mode,
        "productionAllowlistEntryCount": value.production_allowlist_entry_count,
    }


def _receipt_mapping(value: object) -> dict[str, object]:
    return value.to_mapping()


def _exception_result(command: str, error: Exception) -> tuple[int, bytes]:
    from rsi_core.deployment import (
        DeploymentAmbiguousError,
        DeploymentError,
        DeploymentLockTimeout,
        DeploymentOperationConflict,
        DeploymentSourceError,
        DeploymentUnsupported,
    )
    from rsi_core.deployment_fs import DeploymentIntegrityError
    from rsi_core.deployment_schema import DeploymentSchemaError

    if isinstance(error, DeploymentAmbiguousError):
        code, name, message = (
            EXIT_AMBIGUOUS,
            "ambiguous-state",
            "deployment state is ambiguous; preserved evidence requires recovery",
        )
    elif isinstance(error, (DeploymentOperationConflict, DeploymentLockTimeout)):
        code, name, message = (
            EXIT_CONFLICT,
            "operation-conflict",
            "deployment operation conflicts with immutable or concurrent authority",
        )
    elif isinstance(error, DeploymentUnsupported):
        code, name, message = (
            EXIT_UNSUPPORTED,
            "unsupported",
            "required atomic deployment capability is unavailable",
        )
    elif isinstance(error, (DeploymentIntegrityError, DeploymentSchemaError)):
        code, name, message = (
            EXIT_INTEGRITY,
            "integrity-failure",
            "deployment identity or installed state failed verification",
        )
    elif isinstance(error, (DeploymentSourceError, DeploymentError, OSError, ValueError)):
        code, name, message = (
            EXIT_INVALID,
            "invalid-request",
            "deployment request could not be admitted safely",
        )
    else:
        code, name, message = (
            EXIT_INTEGRITY,
            "internal-failure",
            "deployment operation failed closed",
        )
    return code, _canonical(_failure(command, name, message))


def _execute(argv: list[str], deployer: object) -> tuple[int, bytes]:
    """Execute an already-authorized deployer; test injection stays in Python."""

    command = argv[0] if argv and isinstance(argv[0], str) else ""
    try:
        command, options = _parse(argv)
        if command == "plan":
            result = deployer.plan(Path(options["--source-repo"]))
            status, mapping = "complete", _plan_mapping(result)
        elif command == "deploy":
            result = deployer.deploy(
                Path(options["--source-repo"]), options["--operation-id"]
            )
            status, mapping = "complete", _receipt_mapping(result)
        elif command == "rollback":
            result = deployer.rollback(
                options["--receipt-id"], options["--operation-id"]
            )
            status, mapping = "complete", _receipt_mapping(result)
        else:
            result = deployer.verify() if command == "verify" else deployer.status()
            mapping = _status_mapping(result)
            status = result.state
            if result.state == "not-installed":
                return EXIT_NOT_INSTALLED, _canonical(
                    {
                        "schemaVersion": 1,
                        "command": command,
                        "status": status,
                        "result": mapping,
                    }
                )
            if not result.verified:
                if result.state == "busy":
                    return EXIT_CONFLICT, _canonical(
                        _failure(command, "operation-conflict", "deployment status is busy")
                    )
                return EXIT_INTEGRITY, _canonical(
                    _failure(
                        command,
                        "integrity-failure",
                        "installed deployment failed verification",
                    )
                )
        return EXIT_COMPLETE, _canonical(
            {
                "schemaVersion": 1,
                "command": command,
                "status": status,
                "result": mapping,
            }
        )
    except _CliGrammarError:
        return EXIT_INVALID, _canonical(
            _failure(command, "invalid-arguments", "deployment command arguments are invalid")
        )
    except Exception as error:
        return _exception_result(command, error)


def _live_codex_home() -> Path:
    try:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    except (KeyError, OSError):
        raise RuntimeError("current-user home is unavailable") from None
    if not home.is_absolute():
        raise RuntimeError("current-user home is unavailable")
    return home / ".codex"


def _live_installed_script() -> Path:
    return (
        _live_codex_home()
        / "skills"
        / "recursive-self-improvement"
        / "scripts"
        / "rsi_deploy.py"
    )


def _source_read_only_absence(command: str) -> tuple[int, bytes] | None:
    """Classify a definitely absent installation without importing source RSI."""

    codex_home = _live_codex_home()
    installed_root = codex_home / "skills" / "recursive-self-improvement"
    state_root = codex_home / "rsi-deployments-v1"
    try:
        installed = os.lstat(installed_root)
    except FileNotFoundError:
        installed = None
    except OSError:
        return EXIT_INTEGRITY, _canonical(
            _failure(command, "integrity-failure", "installed deployment path is unavailable")
        )
    if installed is not None:
        if (
            not stat.S_ISDIR(installed.st_mode)
            or installed.st_uid != os.geteuid()
            or installed.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            return EXIT_INTEGRITY, _canonical(
                _failure(
                    command,
                    "integrity-failure",
                    "installed deployment root has unsafe identity",
                )
            )
        return None
    try:
        os.lstat(state_root)
    except FileNotFoundError:
        return EXIT_NOT_INSTALLED, _canonical(
            {
                "schemaVersion": 1,
                "command": command,
                "status": "not-installed",
                "result": {
                    "state": "not-installed",
                    "installed": False,
                    "verified": False,
                    "operationId": None,
                    "sourceCommit": None,
                    "treeDigest": None,
                    "manifestDigest": None,
                    "receiptDigest": None,
                },
            }
        )
    except OSError:
        pass
    return EXIT_INTEGRITY, _canonical(
        _failure(
            command,
            "integrity-failure",
            "deployment authority exists without an installed package",
        )
    )


def _same_regular_file(first: Path, second: Path) -> bool:
    try:
        one = os.stat(first, follow_symlinks=False)
        two = os.stat(second, follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISREG(one.st_mode)
        and stat.S_ISREG(two.st_mode)
        and (one.st_dev, one.st_ino) == (two.st_dev, two.st_ino)
    )


def _reexec_installed_read_only(argv: list[str]) -> None:
    """Run verify/status from the pinned package, never the mutable source."""

    if not argv or argv[0] not in _READ_ONLY:
        return
    installed = _live_installed_script()
    current = Path(__file__)
    if _same_regular_file(current, installed):
        return
    try:
        metadata = os.stat(installed, follow_symlinks=False)
    except OSError:
        raise RuntimeError("installed deployment CLI is unavailable") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise RuntimeError("installed deployment CLI provenance is invalid")
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    os.execve(
        sys.executable,
        [sys.executable, "-B", os.fspath(installed), *argv],
        environment,
    )


def main(argv: list[str] | None = None) -> int:
    command = list(sys.argv[1:] if argv is None else argv)
    try:
        parsed_command, _options = _parse(command)
        if parsed_command in _READ_ONLY:
            absent = _source_read_only_absence(parsed_command)
            if absent is not None:
                code, payload = absent
                sys.stdout.buffer.write(payload)
                sys.stdout.buffer.flush()
                return code
        _reexec_installed_read_only(command)
        from rsi_core.deployment import GlobalRsiDeployer

        code, payload = _execute(command, GlobalRsiDeployer())
    except _CliGrammarError:
        code, payload = EXIT_INVALID, _canonical(
            _failure(
                command[0] if command and isinstance(command[0], str) else "",
                "invalid-arguments",
                "deployment command arguments are invalid",
            )
        )
    except Exception as error:
        code, payload = _exception_result(command[0] if command else "", error)
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
