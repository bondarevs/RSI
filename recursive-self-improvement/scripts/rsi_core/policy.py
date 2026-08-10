"""Strict V1 pre-capture and promotion admission gates."""
from __future__ import annotations
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping
from .config import EffectiveConfig,canonical_json_digest
from .sanitize import sanitize_evidence

@dataclass(frozen=True)
class GateDecision:
    disposition:str; reasons:tuple[str,...]; admitted:Mapping[str,Any]|None=None
    @property
    def allowed(self)->bool:return self.disposition=="allow"

@dataclass(frozen=True)
class SkillRootProof:
    owner:str
    canonical_root:Path
    entry_id:str
    manifest_digest:str
    registration_identity_digest:str
    contract_digest:str
    registered_roots:frozenset[Path]

class SkillRootProofError(ValueError):
    def __init__(self,reason:str):
        super().__init__(reason)
        self.reason=reason

class TrustedSkillRootResolver:
    """Builds skill-root proofs from a trusted, immutable registry snapshot."""

    _MANIFEST_KEYS=frozenset({"schemaVersion","entryId","skillName","canonicalRoot","aliases","dependencies","files"})

    def __init__(self,manifests:Iterable[Mapping[str,Any]]):
        indexed:dict[str,Mapping[str,Any]]={}
        entry_ids:set[str]=set()
        roots:set[Path]=set()
        for source in manifests:
            if not isinstance(source,Mapping) or set(source)!=self._MANIFEST_KEYS or source.get("schemaVersion")!=1:
                raise ValueError("invalid skill registration")
            if not all(isinstance(source.get(key),str) and source[key] for key in ("entryId","skillName","canonicalRoot")):
                raise ValueError("invalid skill registration")
            if not all(isinstance(source.get(key),list) and all(isinstance(item,str) for item in source[key]) for key in ("aliases","dependencies","files")):
                raise ValueError("invalid skill registration")
            root=Path(source["canonicalRoot"])
            if not root.is_absolute() or str(root.resolve())!=source["canonicalRoot"]:
                raise ValueError("non-canonical skill registration root")
            owner=source["skillName"]
            entry_id=source["entryId"]
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(?::[A-Za-z0-9][A-Za-z0-9._-]*)+:v[1-9][0-9]*",entry_id):
                raise ValueError("skill registration identity must be versioned")
            if owner in indexed or entry_id in entry_ids or root in roots:
                raise ValueError("duplicate skill registration identity")
            indexed[owner]=_freeze(dict(source))
            entry_ids.add(entry_id)
            roots.add(root)
        if not indexed or any(dependency not in indexed for entry in indexed.values() for dependency in entry["dependencies"]):
            raise ValueError("incomplete skill registry closure")
        self._indexed=MappingProxyType(indexed)
        self._roots=frozenset(roots)

    @classmethod
    def from_registration_manifests(cls,manifests:Iterable[Mapping[str,Any]])->"TrustedSkillRootResolver":
        return cls(manifests)

    @staticmethod
    def _load_registered_object(path:Path)->dict[str,Any]:
        if not path.is_file() or path.is_symlink():
            raise SkillRootProofError("invalid-skill-root-marker")
        try:
            def unique(pairs:list[tuple[str,object]])->dict[str,object]:
                result:dict[str,object]={}
                for key,value in pairs:
                    if key in result:raise ValueError("duplicate JSON key")
                    result[key]=value
                return result
            value=json.loads(path.read_text(encoding="utf-8"),object_pairs_hook=unique)
        except (OSError,UnicodeError,json.JSONDecodeError,ValueError) as exc:
            raise SkillRootProofError("invalid-skill-root-marker") from exc
        if not isinstance(value,dict):raise SkillRootProofError("invalid-skill-root-marker")
        return value

    def __call__(self,_candidate:Mapping[str,Any],config:EffectiveConfig)->SkillRootProof:
        contract=config.target_contract
        root=config.target_root
        allowed=config.allowed_target
        if not isinstance(contract,Mapping) or not isinstance(contract.get("name"),str) or root is None:
            raise SkillRootProofError("ownership-not-resolved")
        owner=contract["name"]
        registered=self._indexed.get(owner)
        if registered is None:
            raise SkillRootProofError("ownership-not-resolved")
        canonical_root=Path(registered["canonicalRoot"])
        if root.resolve()!=canonical_root:
            raise SkillRootProofError("ownership-not-resolved")
        for entry in self._indexed.values():
            entry_root=Path(entry["canonicalRoot"])
            on_disk=self._load_registered_object(entry_root/"registration-manifest.json")
            if canonical_json_digest(on_disk)!=canonical_json_digest(_plain(entry)):raise SkillRootProofError("registration-state-mismatch")
            skill_marker=entry_root/"SKILL.md"
            contract_marker=entry_root/"skill-contract.json"
            if not skill_marker.is_file() or skill_marker.is_symlink():raise SkillRootProofError("invalid-skill-root-marker")
            entry_contract=self._load_registered_object(contract_marker)
            if entry_contract.get("name")!=entry["skillName"]:raise SkillRootProofError("contract-owner-mismatch")
        if any(canonical_root!=other and canonical_root in other.parents for other in self._roots):
            raise SkillRootProofError("aggregate-skill-root")
        disk_contract=self._load_registered_object(canonical_root/"skill-contract.json")
        disk_manifest=self._load_registered_object(canonical_root/"registration-manifest.json")
        if disk_contract!=dict(contract) or canonical_json_digest(disk_manifest)!=canonical_json_digest(_plain(registered)):
            raise SkillRootProofError("ownership-not-resolved")
        manifest_digest=canonical_json_digest(disk_manifest)
        contract_digest=canonical_json_digest(disk_contract)
        identity_digest=canonical_json_digest({"canonicalRoot":str(canonical_root),"registrationManifestDigest":manifest_digest})
        expected={
            "entryId":registered["entryId"],
            "skillName":owner,
            "canonicalRoot":str(canonical_root),
            "registrationManifestDigest":manifest_digest,
            "canonicalRootIdentityDigest":identity_digest,
            "contractHash":contract_digest,
        }
        if not isinstance(allowed,Mapping) or dict(allowed)!=expected:
            raise SkillRootProofError("ownership-not-resolved")
        return SkillRootProof(owner,canonical_root,registered["entryId"],manifest_digest,identity_digest,contract_digest,self._roots)

class ControlPlaneIdentitySet:
    REQUIRED=frozenset({"rsi","skill-evolver","evaluator","metrics","safeguards"})
    def __init__(self,roots:Iterable[Path|str]):
        values=[]
        for root in roots:
            path=Path(root)
            if not path.is_absolute():raise ValueError("control-plane root must be absolute")
            values.append(path.resolve())
        self.roots=frozenset(values)
    @classmethod
    def from_registration_manifests(cls, manifests:Iterable[Mapping[str,Any]])->"ControlPlaneIdentitySet":
        indexed={}
        for manifest in manifests:
            required={"schemaVersion","skillName","canonicalRoot","aliases","dependencies","files"}
            if not isinstance(manifest,Mapping) or set(manifest)!=required or manifest.get("schemaVersion")!=1 or not isinstance(manifest.get("skillName"),str) or not isinstance(manifest.get("canonicalRoot"),str) or not all(isinstance(manifest.get(k),list) and all(isinstance(x,str) for x in manifest[k]) for k in ("aliases","dependencies","files")):
                raise ValueError("invalid control-plane registration")
            if manifest["skillName"] in indexed:raise ValueError("duplicate control-plane registration")
            indexed[manifest["skillName"]]=manifest
        if not cls.REQUIRED <= set(indexed):raise ValueError("required control-plane registration absent")
        roots=[]; todo=list(cls.REQUIRED); seen=set()
        while todo:
            name=todo.pop()
            if name in seen:continue
            if name not in indexed:raise ValueError("control-plane dependency absent")
            seen.add(name); entry=indexed[name]
            roots.extend([entry["canonicalRoot"],*entry["aliases"]]); todo.extend(entry["dependencies"])
        return cls(roots)
    def overlaps(self,path:Path|str)->bool:
        candidate=Path(path).resolve(strict=False)
        return any(candidate==root or candidate in root.parents or root in candidate.parents for root in self.roots)

def _normal(value:str)->str:return unicodedata.normalize("NFC",value).casefold()
def _path_reason(relative:object,root:Path|None)->str|None:
    if not isinstance(relative,str) or not relative:return "unsafe-target-path"
    path=Path(relative)
    if path.is_absolute() or ".." in path.parts or path==Path(".") or (len(path.parts)==1 and path.parts[0] in {"references","scripts","profiles","tests"}):return "unsafe-target-path"
    if root is None or root.resolve() in {Path("/"),Path.home().resolve(),Path.cwd().resolve()} or any(not marker.is_file() or marker.is_symlink() for marker in (root/"SKILL.md",root/"skill-contract.json",root/"registration-manifest.json")):return "broad-or-invalid-skill-root"
    current=root.resolve()
    for part in path.parts:
        if current.is_dir():
            same=[child.name for child in current.iterdir() if _normal(child.name)==_normal(part)]
            if len(same)>1 or (same and part not in same):return "unicode-casefold-path-collision"
        current/=part
    resolved=(root/path).resolve(strict=False)
    if resolved!=root and root not in resolved.parents:return "symlink-escape"
    return None
def _strict_candidate(candidate:Mapping[str,Any])->str|None:
    required={"findingEvidenceStatus","changeClass","destinationClass","relativePath","singleArtifact","scope","risk","evidence","proposedContent"}
    if set(candidate)!=required:return "invalid-candidate-schema"
    if not isinstance(candidate["findingEvidenceStatus"],str) or not isinstance(candidate["changeClass"],str) or not isinstance(candidate["destinationClass"],str) or not isinstance(candidate["relativePath"],str) or len(candidate["relativePath"])>240 or not isinstance(candidate["scope"],Mapping) or set(candidate["scope"])!={"owner"} or not isinstance(candidate["scope"].get("owner"),str) or not candidate["scope"]["owner"] or len(candidate["scope"]["owner"])>200 or not isinstance(candidate["risk"],str) or not isinstance(candidate["evidence"],list) or len(candidate["evidence"])<1 or len(candidate["evidence"])>5 or not isinstance(candidate["proposedContent"],str) or len(candidate["proposedContent"])>1200 or not isinstance(candidate["singleArtifact"],bool):return "invalid-candidate-schema"
    return None
def _declarative(category:object,text:str)->bool:
    if not isinstance(category,str) or len(text)>400 or text!=text.strip() or "\n" in text or not re.fullmatch(r"[^.!?;:,]{3,399}\.",text):return False
    word=r"(?:[\w][\w'/-]*-<[\w-]+>|<[\w-]+>|[\w][\w'/-]*)"
    forms={
        "fact":(
            rf"(?:A|An) (?:{word} ){{1,6}}fact\.",
            rf"(?:The|This|That|These|Those) (?:{word} ){{1,8}}(?:is|are|was|were|has|have|contains|returns|records|supports|uses|provides|includes|matches|equals|remains|requires) (?:{word} ?)+\.",
        ),
        "limitation":(
            rf"(?:A|An|The|This) (?:{word} ){{0,5}}(?:limitation|constraint|restriction) (?:is|applies|prevents|allows only|supports only) (?:{word} ?)+\.",
            rf"(?:The|This) (?:{word} ){{1,6}}(?:is|are) (?:not |only |unavailable|limited|unsupported)(?:{word} ?)*\.",
        ),
        "prerequisite":(
            rf"(?:A|The|This) prerequisite (?:is|requires) (?:{word} ?)+\.",
            rf"(?:A|An|The|This) (?:{word} ){{1,7}}(?:is|are) required\.",
        ),
        "read-only-verification":(
            rf"(?:Read-only|The read-only) (?:verification|check|validation) (?:checks|compares|reads|inspects|reports|records|verifies) (?:{word} ?)+\.",
        ),
    }
    return any(re.fullmatch(pattern,text,re.I) for pattern in forms.get(category,()))
def _freeze(value:Any)->Any:
    if isinstance(value,Mapping):return MappingProxyType({key:_freeze(item) for key,item in value.items()})
    if isinstance(value,(list,tuple)):return tuple(_freeze(item) for item in value)
    return value
def _plain(value:Any)->Any:
    if isinstance(value,Mapping):return {key:_plain(item) for key,item in value.items()}
    if isinstance(value,(list,tuple)):return [_plain(item) for item in value]
    return value
def evaluate_admission(candidate:Mapping[str,Any],config:EffectiveConfig,ownership_resolver:Any=None)->GateDecision:
    schema=_strict_candidate(candidate)
    if schema:return GateDecision("reject",(schema,))
    evidence=sanitize_evidence(candidate["evidence"]); content=sanitize_evidence([{ "kind":"finding", "summary":candidate["proposedContent"] }])
    reasons=[]
    if candidate["findingEvidenceStatus"]!="verified":reasons.append("evidence-not-verified")
    if evidence.rejected_count or evidence.truncated_count or len(evidence.accepted)!=len(candidate["evidence"]) or content.rejected_count:reasons.append("evidence-not-sanitized")
    proof_reason=None
    try: ownership=ownership_resolver(candidate,config) if ownership_resolver else None
    except SkillRootProofError as exc: ownership=None;proof_reason=exc.reason
    except Exception: ownership=None
    expected_owner=config.target_contract.get("name") if config.target_contract else None
    allowed=config.allowed_target
    proof_valid=isinstance(ownership,SkillRootProof) and ownership.owner==candidate["scope"]["owner"]==expected_owner and config.target_root is not None and ownership.canonical_root==config.target_root.resolve() and isinstance(allowed,Mapping) and ownership.entry_id==allowed.get("entryId") and ownership.manifest_digest==allowed.get("registrationManifestDigest") and ownership.registration_identity_digest==allowed.get("canonicalRootIdentityDigest") and ownership.contract_digest==allowed.get("contractHash")
    if not proof_valid:
        reasons.append("ownership-not-resolved")
        if proof_reason and proof_reason!="ownership-not-resolved":reasons.append(proof_reason)
    if config.provider_compatible is not True:reasons.append("provider-incompatible")
    if candidate["risk"]!="low":reasons.append("risk-not-auto-eligible")
    path_reason=_path_reason(candidate["relativePath"],config.target_root)
    if path_reason:reasons.append(path_reason)
    if config.mode in {"off","observe"}:reasons.append("mode-does-not-permit-capture")
    if config.mode=="promote-safe" and (not config.production_active or config.control_plane is None):reasons.append("production-not-active")
    elif config.control_plane is not None and (config.control_plane.overlaps(config.target_root) or (not path_reason and config.control_plane.overlaps(config.target_root/str(candidate["relativePath"])))):reasons.append("control-plane-overlap")
    if reasons:return GateDecision("reject",tuple(reasons))
    admitted=_freeze({**candidate,"evidence":evidence.accepted,"proposedContent":content.accepted[0]["summary"]})
    if candidate["changeClass"]=="behavior":return GateDecision("manual-only",("v1-behavior-live-apply-forbidden",),admitted)
    if candidate["changeClass"] in {"material","global","defrag"}:return GateDecision("proposal-only",("material-global-defrag-proposal-only",),admitted)
    if candidate["changeClass"]!="knowledge":return GateDecision("reject",("unknown-change-class",))
    if config.mode=="propose":return GateDecision("proposal-only",("mode-does-not-permit-promotion",),admitted)
    if config.promotion.get("allowKnowledge") is not True:return GateDecision("proposal-only",("knowledge-promotion-disabled",),admitted)
    if candidate["singleArtifact"] is not True:return GateDecision("proposal-only",("v1-requires-single-artifact",),admitted)
    root=config.target_root; path=root/str(candidate["relativePath"])
    if candidate["destinationClass"]=="reference":
        links=config.target_contract.get("directlyLinkedReferences",[]) if config.target_contract else []
        if not str(candidate["relativePath"]).startswith("references/") or str(candidate["relativePath"]) not in links:return GateDecision("reject",("reference-not-trusted-linked-destination",))
        if not path.is_file() or path.is_symlink():return GateDecision("reject",("reference-must-be-regular-file",))
        categories=config.target_contract.get("rsiAdmission",{}) if config.target_contract else {}
        category=categories.get(candidate["relativePath"]) if isinstance(categories,Mapping) else None
        if not _declarative(category,content.accepted[0]["summary"]):return GateDecision("proposal-only",("reference-content-not-declarative",),admitted)
        return GateDecision("allow",(),admitted)
    if candidate["destinationClass"]=="skill-body":
        categories=config.target_contract.get("rsiAdmission",{}) if config.target_contract else {}
        category=categories.get("SKILL.md") if isinstance(categories,Mapping) else None
        if candidate["relativePath"]!="SKILL.md" or not _declarative(category,content.accepted[0]["summary"]):return GateDecision("proposal-only",("skill-body-not-narrow-declarative",),admitted)
        return GateDecision("allow",(),admitted)
    if candidate["destinationClass"] in {"script","profile","agents","contract","tests","evaluator","metrics"}:return GateDecision("proposal-only",("knowledge-destination-reclassified",),admitted)
    return GateDecision("reject",("unknown-destination-class",))
