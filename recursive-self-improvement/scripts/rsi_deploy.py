#!/usr/bin/env python3
"""Strict live CLI for the transactional global RSI observe deployment."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
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
                paths = getattr(deployer, "paths", None)
                state_root = getattr(paths, "state_root", None)
                if result.operation_id is None and isinstance(state_root, Path):
                    try:
                        nonempty = any(os.scandir(state_root))
                    except FileNotFoundError:
                        nonempty = False
                    except OSError:
                        nonempty = True
                    if nonempty:
                        return EXIT_INTEGRITY, _canonical(
                            _failure(
                                command,
                                "integrity-failure",
                                "unbound deployment state is not empty",
                            )
                        )
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
                if result.state == "ambiguous":
                    return EXIT_AMBIGUOUS, _canonical(
                        _failure(
                            command,
                            "ambiguous-state",
                            "deployment state is ambiguous; preserved evidence requires recovery",
                        )
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


def _running_attested_snapshot() -> bool:
    return globals().get("__rsi_attested_snapshot__") is True


def _exec_attested_read_only(argv: list[str], deployer: object) -> None:
    """Replace this process with FD-pinned, fully attested installed Python."""

    from rsi_core.global_rollout import attest_installed_snapshot

    installed = getattr(getattr(deployer, "paths", None), "installed_root", None)
    if not isinstance(installed, Path):
        raise RuntimeError("installed deployment authority is unavailable")
    snapshot = attest_installed_snapshot(installed, deployer)
    try:
        command, descriptors = snapshot.execution_spec(
            "scripts/rsi_deploy.py", argv
        )
        for descriptor in descriptors:
            os.set_inheritable(descriptor, True)
        environment = {
            "PATH": os.defpath,
            "HOME": os.fspath(_live_codex_home().parent),
            "TZ": "UTC",
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        os.execve(sys.executable, command, environment)
    finally:
        snapshot.close()


def main(argv: list[str] | None = None) -> int:
    command = list(sys.argv[1:] if argv is None else argv)
    try:
        parsed_command, _options = _parse(command)
        from rsi_core.deployment import GlobalRsiDeployer

        deployer = GlobalRsiDeployer()
        if parsed_command in _READ_ONLY and not _running_attested_snapshot():
            status = deployer.verify() if parsed_command == "verify" else deployer.status()
            if status.state == "verified" and status.verified:
                _exec_attested_read_only(command, deployer)
        code, payload = _execute(command, deployer)
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
