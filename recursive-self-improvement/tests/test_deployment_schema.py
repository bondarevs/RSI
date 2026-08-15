from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import unicodedata

import pytest

import rsi_core.deployment_schema as deployment_schema
from rsi_core.deployment_schema import (
    DeploymentManifest,
    DeploymentReceipt,
    DeploymentSchemaError,
    FileEntry,
    canonical_json_bytes,
)


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
TREE_DIGEST = "sha256:216fe03013da28e67ed8062a49536f56b8e6e7e1405c2e80d6496b072e294f39"
MANIFEST_MAX_BYTES = 16 * 1024 * 1024


def manifest_fixture() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "domain": "rsi-global-observe-deployment-v1",
        "sourceRepository": "/srv/rsi",
        "sourceCommit": "1" * 40,
        "packageRelativePath": "recursive-self-improvement",
        "mode": "observe",
        "hookMode": "late-review",
        "productionAllowlistDigest": DIGEST_A,
        "productionAllowlistEntryCount": 0,
        "fileEntries": [
            {
                "relativePath": "SKILL.md",
                "byteLength": 6,
                "executable": False,
                "digest": DIGEST_B,
            },
            {
                "relativePath": "scripts/run.py",
                "byteLength": 8,
                "executable": True,
                "digest": DIGEST_C,
            },
        ],
        "sourceTreeDigest": TREE_DIGEST,
        "installedTreeDigest": TREE_DIGEST,
        "managedInstructionBlockDigest": DIGEST_A,
        "operationRequestDigest": DIGEST_D,
        "installedAt": "2026-08-13T10:11:12Z",
        "operationId": "deploy-20260813-101112",
    }


def valid_manifest_bytes() -> bytes:
    return canonical_json_bytes(manifest_fixture())


def receipt_fixture() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "domain": "rsi-global-observe-receipt-v1",
        "operationId": "deploy-20260813-101112",
        "manifestByteLength": 1234,
        "manifestDigest": DIGEST_A,
    }


def _manifest_with_wire_length(byte_length: int) -> tuple[dict[str, object], bytes]:
    value = manifest_fixture()
    baseline = canonical_json_bytes(value)
    padding = byte_length - len(baseline)
    assert padding >= 0
    value["sourceRepository"] = str(value["sourceRepository"]) + "r" * padding
    payload = canonical_json_bytes(value)
    assert len(payload) == byte_length
    return value, payload


@pytest.fixture(scope="module")
def manifest_size_boundaries() -> tuple[
    tuple[dict[str, object], bytes], tuple[dict[str, object], bytes]
]:
    return (
        _manifest_with_wire_length(MANIFEST_MAX_BYTES),
        _manifest_with_wire_length(MANIFEST_MAX_BYTES + 1),
    )


def test_manifest_has_exact_canonical_bytes_and_acyclic_membership() -> None:
    expected = (
        b'{"domain":"rsi-global-observe-deployment-v1","fileEntries":'
        b'[{"byteLength":6,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
        b'"executable":false,"relativePath":"SKILL.md"},'
        b'{"byteLength":8,"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",'
        b'"executable":true,"relativePath":"scripts/run.py"}],'
        b'"hookMode":"late-review","installedAt":"2026-08-13T10:11:12Z",'
        b'"installedTreeDigest":"sha256:216fe03013da28e67ed8062a49536f56b8e6e7e1405c2e80d6496b072e294f39",'
        b'"managedInstructionBlockDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"mode":"observe","operationId":"deploy-20260813-101112",'
        b'"operationRequestDigest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",'
        b'"packageRelativePath":"recursive-self-improvement",'
        b'"productionAllowlistDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"productionAllowlistEntryCount":0,"schemaVersion":1,"sourceCommit":"1111111111111111111111111111111111111111",'
        b'"sourceRepository":"/srv/rsi",'
        b'"sourceTreeDigest":"sha256:216fe03013da28e67ed8062a49536f56b8e6e7e1405c2e80d6496b072e294f39"}\n'
    )

    encoded = canonical_json_bytes(manifest_fixture())

    assert encoded == expected
    assert b'.rsi-deployment-manifest.json' not in encoded
    assert DeploymentManifest.from_bytes(encoded).to_bytes() == encoded


def test_manifest_accepts_exact_wire_size_bound(
    manifest_size_boundaries: tuple[
        tuple[dict[str, object], bytes], tuple[dict[str, object], bytes]
    ],
) -> None:
    (value, payload), _ = manifest_size_boundaries

    assert DeploymentManifest.from_mapping(value).to_bytes() == payload
    assert DeploymentManifest.from_bytes(payload).to_bytes() == payload


def test_manifest_rejects_wire_size_bound_plus_one_in_construction_and_parsing(
    manifest_size_boundaries: tuple[
        tuple[dict[str, object], bytes], tuple[dict[str, object], bytes]
    ],
) -> None:
    _, (value, payload) = manifest_size_boundaries

    with pytest.raises(DeploymentSchemaError, match="size|bound"):
        DeploymentManifest.from_mapping(value)
    with pytest.raises(DeploymentSchemaError, match="size|bound"):
        DeploymentManifest.from_bytes(payload)


def test_oversized_manifest_is_rejected_before_json_decode(
    manifest_size_boundaries: tuple[
        tuple[dict[str, object], bytes], tuple[dict[str, object], bytes]
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, (_, payload) = manifest_size_boundaries

    def unexpected_decode(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("oversized manifest reached json.loads")

    monkeypatch.setattr(deployment_schema.json, "loads", unexpected_decode)
    with pytest.raises(DeploymentSchemaError, match="size|bound"):
        DeploymentManifest.from_bytes(payload)


def test_manifest_and_entries_are_immutable_owned_values() -> None:
    source = manifest_fixture()
    manifest = DeploymentManifest.from_mapping(source)
    source_entries = source["fileEntries"]
    assert isinstance(source_entries, list)
    source_entries.clear()

    assert len(manifest.file_entries) == 2
    assert isinstance(manifest.file_entries, tuple)
    with pytest.raises(FrozenInstanceError):
        manifest.operation_id = "replacement"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        manifest.file_entries[0].digest = DIGEST_A  # type: ignore[misc]


@pytest.mark.parametrize("field", ["sourceTreeDigest", "installedTreeDigest"])
def test_manifest_rejects_validly_formed_tree_digest_inconsistent_with_entries(
    field: str,
) -> None:
    value = manifest_fixture()
    value[field] = DIGEST_D

    with pytest.raises(DeploymentSchemaError, match="tree digest"):
        DeploymentManifest.from_mapping(value)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("sourceRepository", "//srv/rsi"),
        ("packageRelativePath", "another-package"),
    ],
)
def test_manifest_rejects_noncanonical_source_or_wrong_package_identity(
    field: str, invalid: str
) -> None:
    value = manifest_fixture()
    value[field] = invalid

    with pytest.raises(DeploymentSchemaError):
        DeploymentManifest.from_mapping(value)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def malformed_manifest_payloads() -> list[tuple[str, bytes]]:
    dropped = manifest_fixture()
    dropped.pop("mode")
    additional = manifest_fixture()
    additional["unexpected"] = None
    bad_digest = manifest_fixture()
    bad_digest["sourceTreeDigest"] = "d" * 64
    bad_mode = manifest_fixture()
    bad_mode["mode"] = "promote"
    self_member = manifest_fixture()
    assert isinstance(self_member["fileEntries"], list)
    self_member["fileEntries"].append(
        {
            "relativePath": ".rsi-deployment-manifest.json",
            "byteLength": 1,
            "executable": False,
            "digest": DIGEST_A,
        }
    )
    bool_integer = manifest_fixture()
    bool_integer["productionAllowlistEntryCount"] = False
    float_integer = manifest_fixture()
    float_integer["fileEntries"][0]["byteLength"] = 6.0  # type: ignore[index]
    non_nfc = manifest_fixture()
    non_nfc["fileEntries"][0]["relativePath"] = unicodedata.normalize(  # type: ignore[index]
        "NFD", "café.md"
    )
    unsorted = manifest_fixture()
    unsorted["fileEntries"] = list(reversed(unsorted["fileEntries"]))  # type: ignore[arg-type]
    invalid_operation = manifest_fixture()
    invalid_operation["operationId"] = "../deploy"

    valid = valid_manifest_bytes()
    duplicate = valid.replace(b'"mode":"observe"', b'"mode":"observe","mode":"observe"')
    return [
        ("missing key", _json_bytes(dropped)),
        ("additional key", _json_bytes(additional)),
        ("duplicate key", duplicate),
        ("unprefixed digest", _json_bytes(bad_digest)),
        ("non-observe mode", _json_bytes(bad_mode)),
        ("manifest self member", _json_bytes(self_member)),
        ("boolean integer", _json_bytes(bool_integer)),
        ("float", _json_bytes(float_integer)),
        ("non-NFC path", _json_bytes(non_nfc)),
        ("noncanonical entry order", _json_bytes(unsorted)),
        ("invalid operation id", _json_bytes(invalid_operation)),
        ("BOM", b"\xef\xbb\xbf" + valid),
        ("CRLF", valid[:-1] + b"\r\n"),
        ("bytes after final LF", valid + b"x"),
        ("second final LF", valid + b"\n"),
        ("noncanonical object order", b'{"schemaVersion":1}\n'),
    ]


@pytest.mark.parametrize(("label", "payload"), malformed_manifest_payloads())
def test_manifest_rejects_every_malformed_wire_arm(label: str, payload: bytes) -> None:
    with pytest.raises(DeploymentSchemaError):
        DeploymentManifest.from_bytes(payload)


@pytest.mark.parametrize(
    "mapping",
    [
        {},
        {
            "relativePath": "file",
            "byteLength": 1,
            "executable": False,
            "digest": DIGEST_A,
            "extra": 1,
        },
        {
            "relativePath": "/absolute",
            "byteLength": 1,
            "executable": False,
            "digest": DIGEST_A,
        },
        {
            "relativePath": "../escape",
            "byteLength": 1,
            "executable": False,
            "digest": DIGEST_A,
        },
    ],
)
def test_file_entry_parser_is_closed_and_path_safe(mapping: dict[str, object]) -> None:
    with pytest.raises(DeploymentSchemaError):
        FileEntry.from_mapping(mapping)


def test_receipt_round_trips_exact_canonical_binding() -> None:
    encoded = canonical_json_bytes(receipt_fixture())

    receipt = DeploymentReceipt.from_bytes(encoded)

    assert receipt.to_bytes() == encoded
    assert receipt.manifest_byte_length == 1234
    assert receipt.manifest_digest == DIGEST_A


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.pop("manifestDigest"),
        lambda value: value.update(extra=True),
        lambda value: value.update(schemaVersion=True),
        lambda value: value.update(manifestByteLength=False),
        lambda value: value.update(manifestDigest="a" * 64),
        lambda value: value.update(operationId="bad/id"),
    ],
)
def test_receipt_rejects_nonclosed_or_invalid_bindings(mutation) -> None:
    value = receipt_fixture()
    mutation(value)
    with pytest.raises(DeploymentSchemaError):
        DeploymentReceipt.from_mapping(value)


@pytest.mark.parametrize("operation_id", ["A", "Deploy-1", "a.b", "a:b"])
@pytest.mark.parametrize("schema", ["manifest", "receipt"])
def test_operation_ids_reject_casefold_and_receipt_path_alias_grammar(
    operation_id: str, schema: str
) -> None:
    value = manifest_fixture() if schema == "manifest" else receipt_fixture()
    value["operationId"] = operation_id
    parser = (
        DeploymentManifest.from_mapping
        if schema == "manifest"
        else DeploymentReceipt.from_mapping
    )

    with pytest.raises(DeploymentSchemaError, match="operation ID"):
        parser(value)


def test_admitted_operation_ids_make_marker_and_manifest_paths_casefold_injective() -> None:
    candidates = ["a", "a.manifest", "A"]
    admitted: list[str] = []
    for operation_id in candidates:
        value = receipt_fixture()
        value["operationId"] = operation_id
        try:
            admitted.append(DeploymentReceipt.from_mapping(value).operation_id)
        except DeploymentSchemaError:
            pass

    paths = [
        path
        for operation_id in admitted
        for path in (f"{operation_id}.json", f"{operation_id}.manifest.json")
    ]
    assert len(paths) == len({path.casefold() for path in paths})


def test_valid_operation_id_paths_are_pairwise_casefold_distinct() -> None:
    operation_ids = ["a", "a-manifest", "a_manifest", "a0", "0"]
    receipts = []
    for operation_id in operation_ids:
        value = receipt_fixture()
        value["operationId"] = operation_id
        receipts.append(DeploymentReceipt.from_mapping(value))

    paths = [
        path
        for receipt in receipts
        for path in (
            f"{receipt.operation_id}.json",
            f"{receipt.operation_id}.manifest.json",
        )
    ]
    assert len(paths) == len({path.casefold() for path in paths})


class ForgedString(str):
    pass


@pytest.mark.parametrize("field", ["domain", "mode", "hookMode"])
def test_manifest_rejects_string_subclasses_in_fixed_wire_fields(field: str) -> None:
    value = manifest_fixture()
    value[field] = ForgedString(value[field])  # type: ignore[arg-type]

    with pytest.raises(DeploymentSchemaError):
        DeploymentManifest.from_mapping(value)


def test_receipt_rejects_string_subclass_domain() -> None:
    value = receipt_fixture()
    value["domain"] = ForgedString(value["domain"])  # type: ignore[arg-type]

    with pytest.raises(DeploymentSchemaError):
        DeploymentReceipt.from_mapping(value)


@pytest.mark.parametrize(
    "value",
    [
        {"float": 1.0},
        {"bad": "\ud800"},
        {1: "non-string key"},
    ],
)
def test_canonical_json_rejects_values_outside_strict_wire_domain(value: object) -> None:
    with pytest.raises(DeploymentSchemaError):
        canonical_json_bytes(value)  # type: ignore[arg-type]


def test_canonical_json_rejects_cycles() -> None:
    value: dict[str, object] = {}
    value["self"] = value
    with pytest.raises(DeploymentSchemaError, match="cycle"):
        canonical_json_bytes(value)
