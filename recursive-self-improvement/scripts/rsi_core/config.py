"""Fail-closed configuration and production identity activation."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping


class ConfigError(ValueError):
    pass


MODE_RANK = {"off": 0, "observe": 1, "propose": 2, "promote-safe": 3}
_DEFAULT_KEYS = {"schemaVersion", "mode", "orchestration", "local", "global", "defragmentation", "promotion", "storage", "limits"}
_PRODUCTION_KEYS = {"schemaVersion", "baseProfile", "mode", "orchestration", "activation", "promotion"}
_ACTIVATION_KEYS = {"stageAttestationRequired", "stageAttestationRef", "hookAttestationRef", "allowedTargets"}


def canonical_json_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _load_object(source: Mapping[str, Any] | Path | str | None) -> dict[str, Any] | None:
    if source is None:
        return None
    if isinstance(source, Mapping):
        return dict(source)
    try:
        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = item
            return result
        value = json.loads(Path(source).read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return dict(value) if isinstance(value, Mapping) else None


def _valid_mode(value: object) -> bool:
    return isinstance(value, str) and value in MODE_RANK


def _valid_layer(value: Mapping[str, Any], *, default: bool = False) -> bool:
    if set(value) - _DEFAULT_KEYS or ("schemaVersion" in value and value["schemaVersion"] != 1) or ("mode" in value and not _valid_mode(value["mode"])):
        return False
    if default and (value.get("schemaVersion") != 1 or not _valid_mode(value.get("mode"))):
        return False
    for section in ("orchestration", "local", "global", "defragmentation", "promotion", "storage", "limits"):
        if section in value and not isinstance(value[section], Mapping):
            return False
        if isinstance(value.get(section), Mapping) and any(not isinstance(item, (bool, int, str)) for item in value[section].values()):
            return False
    return not default or value["mode"] == "observe"


def _safe_default(source: Mapping[str, Any] | Path | str | None) -> tuple[dict[str, Any], bool]:
    value = _load_object(source)
    if value is None or not _valid_layer(value, default=True):
        return {"schemaVersion": 1, "mode": "observe", "promotion": {"allowKnowledge": False}}, False
    return value, True


def _tighten(base: Mapping[str, Any], layer: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in layer.items():
        if key in {"schemaVersion", "activation", "baseProfile"}:
            continue
        prior = merged.get(key)
        if key == "mode":
            merged[key] = min((str(prior), str(value)), key=MODE_RANK.__getitem__)
        elif isinstance(prior, Mapping) and isinstance(value, Mapping):
            inner = dict(prior)
            for name, candidate in value.items():
                # Lower layers can only set an already declared boolean false,
                # or repeat an existing non-boolean value.
                if name in inner and isinstance(inner[name], bool) and isinstance(candidate, bool):
                    inner[name] = inner[name] and candidate
                elif name in inner and inner[name] == candidate:
                    inner[name] = candidate
            merged[key] = inner
        elif prior == value:
            merged[key] = value
    return merged


def _safe_profile_path(root: Path, hint: object) -> Path:
    if not isinstance(hint, str) or not hint:
        raise ConfigError("unsafe target RSI profile hint")
    value = Path(hint)
    if value.is_absolute() or ".." in value.parts:
        raise ConfigError("unsafe target RSI profile hint")
    resolved = (root / value).resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise ConfigError("unsafe target RSI profile hint")
    return resolved


def _target_contract(root: Path | None) -> tuple[dict[str, Any] | None, Path | None]:
    if root is None:
        return None, None
    contract = _load_object(root / "skill-contract.json")
    if contract is None:
        return None, None
    if contract.get("schemaVersion") != 1 or not isinstance(contract.get("name"), str) or not contract["name"] or contract.get("kind") != "role":
        return None, None
    profiles = contract.get("profiles", {})
    if not isinstance(profiles, Mapping) or ("rsi" in profiles and not isinstance(profiles["rsi"], str)):
        return None, None
    links = contract.get("directlyLinkedReferences", [])
    if not isinstance(links, list) or not all(isinstance(item, str) for item in links):
        return None, None
    if "rsi" not in profiles:
        return contract, None
    try:
        return contract, _safe_profile_path(root, profiles["rsi"])
    except ConfigError:
        return None, None


def _manifest(root: Path, contract: Mapping[str, Any]) -> dict[str, Any] | None:
    manifest = _load_object(root / "registration-manifest.json")
    allowed = {"schemaVersion", "entryId", "skillName", "canonicalRoot", "aliases", "dependencies", "files"}
    if manifest is None or set(manifest) != allowed or manifest.get("schemaVersion") != 1:
        return None
    if manifest.get("skillName") != contract.get("name") or manifest.get("canonicalRoot") != str(root.resolve()):
        return None
    if not all(isinstance(manifest.get(key), list) and all(isinstance(item, str) for item in manifest[key]) for key in ("aliases", "dependencies", "files")):
        return None
    return manifest


def _match_entry(entries: object, root: Path | None, contract: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if root is None or contract is None or not isinstance(entries, list):
        return None
    manifest = _manifest(root, contract)
    if manifest is None:
        return None
    manifest_digest = canonical_json_digest(manifest)
    identity = canonical_json_digest({"canonicalRoot": str(root.resolve()), "registrationManifestDigest": manifest_digest})
    required = {"entryId", "skillName", "canonicalRoot", "registrationManifestDigest", "canonicalRootIdentityDigest", "contractHash"}
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != required or not all(isinstance(entry.get(k), str) and entry[k] for k in required):
            continue
        if entry["entryId"] == manifest["entryId"] and entry["skillName"] == contract["name"] and entry["canonicalRoot"] == str(root.resolve()) and entry["registrationManifestDigest"] == manifest_digest and entry["canonicalRootIdentityDigest"] == identity and entry["contractHash"] == canonical_json_digest(contract):
            return dict(entry)
    return None


def _valid_production(overlay: Mapping[str, Any]) -> bool:
    activation = overlay.get("activation")
    promotion = overlay.get("promotion")
    return set(overlay) == _PRODUCTION_KEYS and overlay.get("schemaVersion") == 1 and overlay.get("baseProfile") == "default" and overlay.get("mode") == "promote-safe" and isinstance(overlay.get("orchestration"), Mapping) and set(overlay["orchestration"]) == {"hookMode"} and overlay["orchestration"].get("hookMode") == "coordinated" and isinstance(promotion, Mapping) and set(promotion) == {"allowKnowledge", "allowLowRiskBehavior", "allowMaterialChanges"} and all(isinstance(promotion[key], bool) for key in promotion) and isinstance(activation, Mapping) and set(activation) == _ACTIVATION_KEYS and activation.get("stageAttestationRequired") is True and isinstance(activation.get("stageAttestationRef"), str) and isinstance(activation.get("hookAttestationRef"), str) and isinstance(activation.get("allowedTargets"), list)


def _trusted(verifier: Callable[..., bool] | None, ref: object, entry: Mapping[str, Any]) -> bool:
    if verifier is None or not isinstance(ref, str) or not ref:
        return False
    try:
        return verifier(ref, dict(entry)) is True
    except Exception:
        return False


@dataclass(frozen=True)
class EffectiveConfig:
    mode: str
    promotion: Mapping[str, Any]
    values: Mapping[str, Any] = field(repr=False)
    target_root: Path | None = None
    target_contract: Mapping[str, Any] | None = None
    target_profile_path: Path | None = None
    allowed_target: Mapping[str, Any] | None = None
    production_active: bool = False
    control_plane: object | None = None
    provider_compatible: bool = False
    reasons: tuple[str, ...] = ()


def load_effective_config(*, default_profile: Mapping[str, Any] | Path | str | None = None, production_overlay: Mapping[str, Any] | Path | str | None = None, platform_policy: Mapping[str, Any] | Path | str | None = None, runtime: Mapping[str, Any] | None = None, target_root: Path | str | None = None, environment: Mapping[str, str] | None = None, attestation_verifier: Callable[..., bool] | None = None, control_plane_manifests: list[Mapping[str, Any]] | None = None, provider_compatible: bool = False) -> EffectiveConfig:
    package_root = Path(__file__).resolve().parents[2]
    default, valid_default = _safe_default(default_profile if default_profile is not None else package_root / "profiles" / "default.json")
    root = Path(target_root).resolve() if target_root is not None else None
    contract, profile_path = _target_contract(root)
    target_profile = _load_object(profile_path) if profile_path is not None else {}
    overlay = _load_object(production_overlay)
    reasons: list[str] = [] if valid_default else ["invalid-default-profile"]
    if profile_path is not None and target_profile is None:
        target_profile = {}
        reasons.append("invalid-target-profile")
    control_plane = None
    active = False
    entry = None
    if overlay is not None and _valid_production(overlay) and contract is not None:
        entry = _match_entry(overlay["activation"]["allowedTargets"], root, contract)
        try:
            from .policy import ControlPlaneIdentitySet
            control_plane = ControlPlaneIdentitySet.from_registration_manifests(control_plane_manifests or ())
        except (ValueError, TypeError):
            control_plane = None
        active = entry is not None and control_plane is not None and _trusted(attestation_verifier, overlay["activation"]["stageAttestationRef"], entry) and _trusted(attestation_verifier, overlay["activation"]["hookAttestationRef"], entry)
    if active:
        selected = _tighten(default, overlay)
        selected["mode"] = "promote-safe"
        selected["orchestration"] = dict(overlay["orchestration"])
    else:
        selected = dict(default)
        selected["mode"] = "observe"  # default/untrusted input can never activate mutation
        if production_overlay is not None:
            reasons.append("inactive-production")
    if "invalid-target-profile" in reasons:
        selected["mode"] = "observe"
    for layer in (_load_object(platform_policy) if platform_policy is not None else {}, runtime or {}, target_profile or {}):
        if not layer:
            continue
        if not isinstance(layer, Mapping) or not _valid_layer(layer):
            selected["mode"] = "observe"
            reasons.append("invalid-lower-layer")
            continue
        selected = _tighten(selected, layer)
    env = dict(os.environ if environment is None else environment)
    if env.get("CODEX_RSI_ENABLED") == "0": selected["mode"] = "off"; reasons.append("kill-switch:CODEX_RSI_ENABLED")
    if env.get("CODEX_RSI_MODE") == "observe": selected["mode"] = "observe"; reasons.append("kill-switch:CODEX_RSI_MODE")
    if env.get("CODEX_SKILL_AUTO_PROMOTE") == "0": selected = _tighten(selected, {"schemaVersion": 1, "mode": selected["mode"], "promotion": {"autoPromote": False}}); reasons.append("kill-switch:CODEX_SKILL_AUTO_PROMOTE")
    return EffectiveConfig(str(selected["mode"]), dict(selected.get("promotion", {})), selected, root, contract, profile_path, entry if active else None, active, control_plane, provider_compatible is True, tuple(reasons))
