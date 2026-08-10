import json
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]


def load_json(relative_path: str) -> dict:
    path = SKILL_ROOT / relative_path
    assert path.is_file(), f"Missing required package file: {relative_path}"
    return json.loads(path.read_text(encoding="utf-8"))


def test_package_default_mode_is_observe() -> None:
    default_profile = load_json("profiles/default.json")

    assert default_profile["mode"] == "observe"


def test_production_allowlist_is_empty() -> None:
    production_profile = load_json("profiles/production.json")

    assert production_profile["activation"]["allowedTargets"] == []


def test_implicit_invocation_is_disabled() -> None:
    metadata = (SKILL_ROOT / "agents/openai.yaml").read_text(encoding="utf-8")

    assert "allow_implicit_invocation: false" in metadata


def test_contract_kind_is_role() -> None:
    contract = load_json("skill-contract.json")

    assert contract["kind"] == "role"
