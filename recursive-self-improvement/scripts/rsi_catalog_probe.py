#!/usr/bin/env python3
"""Attested local/latest Codex catalog probe with isolated client homes."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys


sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"


def _canonical(value: dict[str, object]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _running_attested_snapshot() -> bool:
    return globals().get("__rsi_attested_snapshot__") is True


def _exec_attested() -> None:
    from rsi_core.deployment import GlobalRsiDeployer
    from rsi_core.global_rollout import attest_installed_snapshot

    deployer = GlobalRsiDeployer()
    snapshot = attest_installed_snapshot(deployer.paths.installed_root, deployer)
    try:
        command, descriptors = snapshot.execution_spec(
            "scripts/rsi_catalog_probe.py", []
        )
        for descriptor in descriptors:
            os.set_inheritable(descriptor, True)
        environment = {
            "HOME": os.fspath(Path.home()),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", os.defpath),
            "PYTHONDONTWRITEBYTECODE": "1",
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
        os.execve(sys.executable, command, environment)
    finally:
        snapshot.close()


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        payload = {
            "error": {"code": "invalid-arguments", "message": "probe accepts no arguments"},
            "schemaVersion": 1,
            "status": "failed",
        }
        sys.stdout.buffer.write(_canonical(payload))
        return 2
    try:
        if not _running_attested_snapshot():
            _exec_attested()
            raise RuntimeError("attested execution did not replace the process")
        from rsi_core.catalog_probe import run_live_catalog_probe

        payload = run_live_catalog_probe().to_mapping()
        code = 0
    except Exception as error:
        payload = {
            "error": {
                "code": "probe-failed",
                "message": str(error)[:240] or "catalog probe failed closed",
            },
            "schemaVersion": 1,
            "status": "failed",
        }
        code = 2
    sys.stdout.buffer.write(_canonical(payload))
    sys.stdout.buffer.flush()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
