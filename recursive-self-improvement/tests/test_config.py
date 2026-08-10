from __future__ import annotations
import json
from pathlib import Path
import pytest
from rsi_core.config import canonical_json_digest, load_effective_config

def write(path:Path,value:object)->None:path.write_text(json.dumps(value),encoding="utf-8")
def control(tmp_path:Path)->list[dict[str,object]]:
    output=[]
    for name in ("rsi","skill-evolver","evaluator","metrics","safeguards"):
        root=tmp_path/f"cp-{name}";root.mkdir()
        output.append({"schemaVersion":1,"skillName":name,"canonicalRoot":str(root.resolve()),"aliases":[],"dependencies":[],"files":["SKILL.md"]})
    return output
def target(tmp_path:Path)->tuple[Path,dict[str,object],dict[str,object]]:
    root=tmp_path/"target";root.mkdir();(root/"references").mkdir();(root/"references/facts.md").write_text("A fact.",encoding="utf-8");(root/"SKILL.md").write_text("body",encoding="utf-8")
    contract={"schemaVersion":1,"name":"target","kind":"role","userOwned":True,"directlyLinkedReferences":["references/facts.md"],"rsiAdmission":{"references/facts.md":"fact","SKILL.md":"fact"}};write(root/"skill-contract.json",contract)
    manifest={"schemaVersion":1,"entryId":"production:target:v1","skillName":"target","canonicalRoot":str(root.resolve()),"aliases":[str((tmp_path/"target-alias").resolve())],"dependencies":[],"files":["SKILL.md","references/facts.md"]};write(root/"registration-manifest.json",manifest)
    return root,contract,manifest
def overlay(root:Path,contract:dict[str,object],manifest:dict[str,object])->dict[str,object]:
    digest=canonical_json_digest(manifest)
    entry={"entryId":"production:target:v1","skillName":"target","canonicalRoot":str(root.resolve()),"registrationManifestDigest":digest,"canonicalRootIdentityDigest":canonical_json_digest({"canonicalRoot":str(root.resolve()),"registrationManifestDigest":digest}),"contractHash":canonical_json_digest(contract)}
    return {"schemaVersion":1,"baseProfile":"default","mode":"promote-safe","orchestration":{"hookMode":"coordinated"},"activation":{"stageAttestationRequired":True,"stageAttestationRef":"stage","hookAttestationRef":"hook","allowedTargets":[entry]},"promotion":{"allowKnowledge":True,"allowLowRiskBehavior":False,"allowMaterialChanges":False}}
def active(tmp_path:Path):
    root,contract,manifest=target(tmp_path)
    return load_effective_config(default_profile={"schemaVersion":1,"mode":"observe","promotion":{"allowKnowledge":True}},production_overlay=overlay(root,contract,manifest),target_root=root,attestation_verifier=lambda *_:True,control_plane_manifests=control(tmp_path),provider_compatible=True)

def test_only_strict_selected_verified_production_can_enable_mutation(tmp_path:Path)->None:
    assert load_effective_config(default_profile={"schemaVersion":1,"mode":"promote-safe"},target_root=tmp_path).mode=="observe"
    config=active(tmp_path)
    assert config.mode=="promote-safe" and config.production_active

@pytest.mark.parametrize("mutate",["unknown","missing-stage","bad-contract","bad-manifest"])
def test_malformed_deployment_input_collapses_to_observe(tmp_path:Path,mutate:str)->None:
    root,contract,manifest=target(tmp_path);value=overlay(root,contract,manifest)
    if mutate=="unknown":value["unknown"]=True
    elif mutate=="missing-stage":value["activation"].pop("stageAttestationRequired")
    elif mutate=="bad-contract":write(root/"skill-contract.json",{"schemaVersion":2})
    else:write(root/"registration-manifest.json",{"schemaVersion":1})
    result=load_effective_config(default_profile={"schemaVersion":1,"mode":"observe"},production_overlay=value,target_root=root,attestation_verifier=lambda *_:1,control_plane_manifests=control(tmp_path))
    assert result.mode=="observe" and not result.production_active

def test_registration_manifest_alias_and_contents_bind_allowlist_identity(tmp_path:Path)->None:
    root,contract,manifest=target(tmp_path);value=overlay(root,contract,manifest);manifest["files"].append("agents/openai.yaml");write(root/"registration-manifest.json",manifest)
    result=load_effective_config(default_profile={"schemaVersion":1,"mode":"observe"},production_overlay=value,target_root=root,attestation_verifier=lambda *_:True,control_plane_manifests=control(tmp_path))
    assert result.mode=="observe"

def test_unknown_lower_layer_and_truthy_verifier_fail_closed(tmp_path:Path)->None:
    root,contract,manifest=target(tmp_path)
    result=load_effective_config(default_profile={"schemaVersion":1,"mode":"observe"},production_overlay=overlay(root,contract,manifest),runtime={"newPermission":True},target_root=root,attestation_verifier=lambda *_:1,control_plane_manifests=control(tmp_path))
    assert result.mode=="observe"

def test_absent_control_plane_registration_blocks_production(tmp_path:Path)->None:
    root,contract,manifest=target(tmp_path)
    result=load_effective_config(default_profile={"schemaVersion":1,"mode":"observe"},production_overlay=overlay(root,contract,manifest),target_root=root,attestation_verifier=lambda *_:True,control_plane_manifests=[])
    assert result.mode=="observe"
@pytest.mark.parametrize("field",["entryId","skillName","canonicalRoot","registrationManifestDigest","canonicalRootIdentityDigest","contractHash"])
def test_each_allowlist_identity_field_is_exact(tmp_path:Path,field:str)->None:
    root,contract,manifest=target(tmp_path);value=overlay(root,contract,manifest);value["activation"]["allowedTargets"][0][field]="tampered"
    result=load_effective_config(default_profile={"schemaVersion":1,"mode":"observe","promotion":{"allowKnowledge":True}},production_overlay=value,target_root=root,attestation_verifier=lambda *_:True,control_plane_manifests=control(tmp_path))
    assert result.mode=="observe"
def test_kill_switch_precedes_verified_production(tmp_path:Path)->None:
    root,contract,manifest=target(tmp_path)
    result=load_effective_config(default_profile={"schemaVersion":1,"mode":"observe","promotion":{"allowKnowledge":True}},production_overlay=overlay(root,contract,manifest),target_root=root,attestation_verifier=lambda *_:True,control_plane_manifests=control(tmp_path),environment={"CODEX_RSI_ENABLED":"0"})
    assert result.mode=="off"
def test_target_contract_preserves_other_contract_and_profile_keys_but_bad_rsi_profile_fails_closed(tmp_path:Path)->None:
    root,contract,manifest=target(tmp_path);contract["capabilities"]={"other":"value"};contract["profiles"]={"other":"profiles/x.json","rsi":"profiles/rsi.json"};(root/"profiles").mkdir();(root/"profiles/rsi.json").write_text('{"mode":"propose","mode":"off"}',encoding="utf-8");write(root/"skill-contract.json",contract)
    result=load_effective_config(default_profile={"schemaVersion":1,"mode":"observe"},production_overlay=overlay(root,contract,manifest),target_root=root,attestation_verifier=lambda *_:True,control_plane_manifests=control(tmp_path))
    assert result.mode=="observe" and "invalid-target-profile" in result.reasons
