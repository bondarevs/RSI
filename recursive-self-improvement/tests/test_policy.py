from __future__ import annotations
import json
import os
from pathlib import Path
import pytest
import rsi_core.policy as policy
from rsi_core.config import load_effective_config
from rsi_core.policy import ControlPlaneIdentitySet,evaluate_admission
from test_config import active,control,overlay,target,write
def candidate(**changes:object)->dict[str,object]:
    value={"findingEvidenceStatus":"verified","changeClass":"knowledge","destinationClass":"reference","relativePath":"references/facts.md","singleArtifact":True,"scope":{"owner":"target"},"risk":"low","evidence":[{"kind":"test","summary":"checks passed"}],"proposedContent":"A verified fact."};value.update(changes);return value
def resolved(candidate,config):return registered_resolver(config)(candidate,config)
def registered_resolver(config,*registrations:dict[str,object]):
    target_manifest=json.loads((config.target_root/"registration-manifest.json").read_text(encoding="utf-8"))
    return policy.TrustedSkillRootResolver.from_registration_manifests([target_manifest,*registrations])
def active_category(tmp_path:Path,category:str):
    root,contract,manifest=target(tmp_path)
    contract["rsiAdmission"]["references/facts.md"]=category
    write(root/"skill-contract.json",contract)
    return load_effective_config(
        default_profile={"schemaVersion":1,"mode":"observe","promotion":{"allowKnowledge":True}},
        production_overlay=overlay(root,contract,manifest),
        target_root=root,
        attestation_verifier=lambda *_:True,
        control_plane_manifests=control(tmp_path),
        provider_compatible=True,
    )
def test_reference_requires_trusted_regular_linked_file_and_declarative_content(tmp_path:Path)->None:
    cfg=active(tmp_path)
    assert evaluate_admission(candidate(),cfg,resolved).allowed
    assert evaluate_admission(candidate(relativePath="scripts/tool.py"),cfg,resolved).disposition=="reject"
    assert evaluate_admission(candidate(proposedContent="Run the deployment."),cfg,resolved).disposition=="reject"
def test_admission_sanitizes_evidence_and_rejects_claimed_flags_and_bad_prerequisites(tmp_path:Path)->None:
    cfg=active(tmp_path)
    decision=evaluate_admission(candidate(evidence=[{"kind":"tool","summary":"Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}]),cfg,resolved)
    assert decision.disposition=="reject" and "evidence-not-sanitized" in decision.reasons
    decision=evaluate_admission(candidate(risk="high"),cfg,lambda _: {"status":"unknown"})
    assert decision.disposition=="reject" and set(decision.reasons)>={"ownership-not-resolved","risk-not-auto-eligible"}
def test_strict_candidate_schema_does_not_accept_legacy_assertions(tmp_path:Path)->None:
    assert evaluate_admission(candidate(sanitized=True,general=True),active(tmp_path),resolved).reasons==("invalid-candidate-schema",)
def test_admission_scans_proposed_content_and_uses_trusted_provider_state(tmp_path:Path)->None:
    cfg=active(tmp_path)
    assert evaluate_admission(candidate(proposedContent="Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"),cfg,resolved).disposition=="reject"
    cfg=cfg.__class__(**{**cfg.__dict__,"provider_compatible":False})
    assert "provider-incompatible" in evaluate_admission(candidate(),cfg,resolved).reasons
def test_control_plane_builder_closes_dependencies_and_aliases(tmp_path:Path)->None:
    manifests=[]
    for name in ("rsi","skill-evolver","evaluator","metrics","safeguards","dependency"):
        root=tmp_path/name;root.mkdir();manifests.append({"schemaVersion":1,"skillName":name,"canonicalRoot":str(root),"aliases":[],"dependencies":["dependency"] if name=="rsi" else [],"files":[]})
    alias=tmp_path/"alias";os.symlink(tmp_path/"rsi",alias);manifests[0]["aliases"]=[str(alias)]
    identities=ControlPlaneIdentitySet.from_registration_manifests(manifests)
    assert identities.overlaps(alias) and identities.overlaps(tmp_path/"dependency")
@pytest.mark.parametrize("change,destination,expected",[("knowledge","reference","allow"),("knowledge","skill-body","allow"),("knowledge","script","proposal-only"),("knowledge","profile","proposal-only"),("knowledge","agents","proposal-only"),("knowledge","contract","proposal-only"),("knowledge","tests","proposal-only"),("knowledge","evaluator","proposal-only"),("knowledge","metrics","proposal-only"),("behavior","reference","manual-only"),("material","reference","proposal-only")])
def test_v1_matrix_cells(tmp_path:Path,change:str,destination:str,expected:str)->None:
    path="SKILL.md" if destination=="skill-body" else "references/facts.md"
    assert evaluate_admission(candidate(changeClass=change,destinationClass=destination,relativePath=path),active(tmp_path),resolved).disposition==expected
def test_propose_can_propose_but_observe_cannot_capture_and_missing_permission_denies_auto(tmp_path:Path)->None:
    cfg=active(tmp_path); proposed=cfg.__class__(**{**cfg.__dict__,"mode":"propose"}); assert evaluate_admission(candidate(),proposed,resolved).disposition=="proposal-only"
    observed=cfg.__class__(**{**cfg.__dict__,"mode":"observe"}); assert evaluate_admission(candidate(),observed,resolved).disposition=="reject"
    no_permission=cfg.__class__(**{**cfg.__dict__,"promotion":{}}); assert evaluate_admission(candidate(),no_permission,resolved).disposition=="proposal-only"
@pytest.mark.parametrize("path",["/tmp/x","../x","references/../x"])
def test_unsafe_paths_are_rejected(tmp_path:Path,path:str)->None:
    assert evaluate_admission(candidate(relativePath=path),active(tmp_path),resolved).disposition=="reject"
def test_unicode_symlink_and_broad_root_rejected(tmp_path:Path)->None:
    cfg=active(tmp_path);assert evaluate_admission(candidate(relativePath="REFERENCES/facts.md"),cfg,resolved).disposition=="reject"
    outside=tmp_path/"outside";outside.write_text("x");os.symlink(outside,cfg.target_root/"references"/"link.md");assert evaluate_admission(candidate(relativePath="references/link.md"),cfg,resolved).disposition=="reject"
    broad=cfg.__class__(**{**cfg.__dict__,"target_root":Path.home()});assert evaluate_admission(candidate(),broad,resolved).disposition=="reject"
def test_sanitized_generalized_candidate_is_returned_without_raw_task_identifier(tmp_path:Path)->None:
    raw="ticket-ABC123 passed";decision=evaluate_admission(candidate(evidence=[{"kind":"test","summary":raw}],proposedContent="A ticket-ABC123 fact."),active(tmp_path),resolved)
    assert decision.allowed and raw not in str(decision.admitted) and decision.admitted["evidence"][0]["summary"]=="task-<id> passed"
@pytest.mark.parametrize(
    "content",
    [
        "Restart the service.",
        "Enable logging.",
        "Configure the hook.",
        "Always restart the service.",
        "Use this command.",
        "Never disable logging.",
        "You must deploy.",
        "If tests fail, do Y.",
    ],
)
def test_general_directives_are_not_declarative(content:str,tmp_path:Path)->None:
    assert evaluate_admission(candidate(proposedContent=content),active(tmp_path),resolved).disposition!="allow"
@pytest.mark.parametrize(
    "category,content",
    [
        ("fact", "A verified fact."),
        ("limitation", "This limitation applies offline."),
        ("prerequisite", "A prerequisite is a verified test."),
        ("read-only-verification", "Read-only verification checks the report."),
    ],
)
def test_declarative_boundaries_remain_eligible(category:str,content:str,tmp_path:Path)->None:
    cfg=active_category(tmp_path,category)
    assert evaluate_admission(candidate(proposedContent=content),cfg,resolved).allowed
def test_owner_root_mismatch_and_symlink_marker_are_rejected(tmp_path:Path)->None:
    cfg=active(tmp_path)
    mismatch=lambda _:{"status":"resolved","owner":"other","canonicalRoot":str(cfg.target_root)}
    assert evaluate_admission(candidate(),cfg,mismatch).disposition=="reject"
    real=cfg.target_root/"SKILL.real";real.write_text("x");(cfg.target_root/"SKILL.md").unlink();os.symlink(real,cfg.target_root/"SKILL.md")
    assert evaluate_admission(candidate(),cfg,resolved).disposition=="reject"

def test_exact_leaf_registered_owner_root_is_accepted(tmp_path:Path)->None:
    cfg=active(tmp_path)
    assert evaluate_admission(candidate(),cfg,registered_resolver(cfg)).allowed

def test_aggregate_root_containing_another_registered_skill_is_rejected(tmp_path:Path)->None:
    cfg=active(tmp_path)
    child=cfg.target_root/"nested-skill"
    child.mkdir()
    (child/"SKILL.md").write_text("body",encoding="utf-8")
    (child/"skill-contract.json").write_text(
        json.dumps({"schemaVersion":1,"name":"nested","kind":"role"}),encoding="utf-8"
    )
    nested_manifest={
        "schemaVersion":1,
        "entryId":"production:nested:v1",
        "skillName":"nested",
        "canonicalRoot":str(child.resolve()),
        "aliases":[],
        "dependencies":[],
        "files":["SKILL.md"],
    }
    (child/"registration-manifest.json").write_text(json.dumps(nested_manifest),encoding="utf-8")
    decision=evaluate_admission(candidate(),cfg,registered_resolver(cfg,nested_manifest))
    assert decision.disposition=="reject"
    assert "aggregate-skill-root" in decision.reasons

def test_mutable_resolver_claim_is_not_a_skill_root_proof(tmp_path:Path)->None:
    cfg=active(tmp_path)
    mutable=lambda _candidate,_config:{"status":"resolved","owner":"target","canonicalRoot":str(cfg.target_root)}
    assert evaluate_admission(candidate(),cfg,mutable).disposition=="reject"

def test_skill_root_proof_is_bound_to_versioned_allowlist_identity(tmp_path:Path)->None:
    cfg=active(tmp_path)
    tampered={**cfg.allowed_target,"registrationManifestDigest":"sha256:"+"0"*64}
    tampered_cfg=cfg.__class__(**{**cfg.__dict__,"allowed_target":tampered})
    decision=evaluate_admission(candidate(),tampered_cfg,registered_resolver(cfg))
    assert decision.disposition=="reject"
    assert "ownership-not-resolved" in decision.reasons

def test_trusted_resolver_rejects_an_unversioned_registration_identity(tmp_path:Path)->None:
    cfg=active(tmp_path)
    manifest=json.loads((cfg.target_root/"registration-manifest.json").read_text(encoding="utf-8"))
    manifest["entryId"]="production:target"
    with pytest.raises(ValueError,match="versioned"):
        policy.TrustedSkillRootResolver.from_registration_manifests([manifest])
def test_capture_dispositions_return_sanitized_payload(tmp_path:Path)->None:
    cfg=active(tmp_path); raw="ticket-ABC123 passed"; proposed=cfg.__class__(**{**cfg.__dict__,"mode":"propose"})
    proposal=evaluate_admission(candidate(evidence=[{"kind":"test","summary":raw}]),proposed,resolved)
    manual=evaluate_admission(candidate(changeClass="behavior",evidence=[{"kind":"test","summary":raw}]),cfg,resolved)
    assert proposal.admitted and manual.admitted and raw not in str(proposal.admitted)+str(manual.admitted)

@pytest.mark.parametrize(
    "changes,expected",
    [
        ({"proposedContent":"Restart the service."},"proposal-only"),
        ({"destinationClass":"skill-body","relativePath":"SKILL.md","proposedContent":"Enable logging."},"proposal-only"),
        ({"destinationClass":"script"},"proposal-only"),
        ({"destinationClass":"profile"},"proposal-only"),
        ({"destinationClass":"agents"},"proposal-only"),
        ({"destinationClass":"contract"},"proposal-only"),
        ({"destinationClass":"tests"},"proposal-only"),
        ({"destinationClass":"evaluator"},"proposal-only"),
        ({"destinationClass":"metrics"},"proposal-only"),
        ({"changeClass":"behavior"},"manual-only"),
        ({"changeClass":"material"},"proposal-only"),
        ({"changeClass":"global"},"proposal-only"),
        ({"changeClass":"defrag"},"proposal-only"),
    ],
)
def test_every_capture_disposition_returns_the_same_immutable_sanitized_payload(
    changes:dict[str,object],expected:str,tmp_path:Path
)->None:
    raw="ticket-ABC123 passed"
    decision=evaluate_admission(
        candidate(evidence=[{"kind":"test","summary":raw}],**changes),
        active(tmp_path),
        resolved,
    )
    assert decision.disposition==expected
    assert decision.admitted is not None
    assert raw not in str(decision.admitted)
    assert decision.admitted["evidence"][0]["summary"]=="task-<id> passed"
    with pytest.raises(TypeError):
        decision.admitted["risk"]="high"
    with pytest.raises(TypeError):
        decision.admitted["scope"]["owner"]="other"
    with pytest.raises(TypeError):
        decision.admitted["evidence"][0]["summary"]="changed"

@pytest.mark.parametrize(
    "changes",
    [
        {"changeClass":"unknown"},
        {"destinationClass":"unknown"},
        {"relativePath":"references/unregistered.md"},
    ],
)
def test_rejection_dispositions_never_carry_admitted_content(changes:dict[str,object],tmp_path:Path)->None:
    decision=evaluate_admission(candidate(**changes),active(tmp_path),resolved)
    assert decision.disposition=="reject"
    assert decision.admitted is None
def test_real_default_observe_without_control_plane_rejects_without_crash(tmp_path:Path)->None:
    from rsi_core.config import load_effective_config
    cfg=load_effective_config(default_profile={"schemaVersion":1,"mode":"observe"},target_root=tmp_path)
    assert evaluate_admission(candidate(),cfg,resolved).disposition=="reject"
