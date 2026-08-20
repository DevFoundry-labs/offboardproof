from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import World
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from offboardproof.db import connection_for
from offboardproof.enums import Role
from offboardproof.errors import ConfigurationError
from offboardproof.evidence_v2 import build_evidence_v2, write_evidence_v2
from offboardproof.evidence_verification import EvidenceVerificationError, verify_evidence_v2
from offboardproof.worker import Worker


def _complete(world: World, *, key: str) -> str:
    case = world.create(key=key)
    world.plan_and_approve(str(case["id"]))
    worker = Worker(world.settings)
    while worker.run_once():
        pass
    view = world.service.case_view(str(case["id"]))
    manual = next(item for item in view["controls"] if item["manual"] == 1)
    completed = world.service.complete_manual(
        world.actors[Role.MANAGER],
        str(case["id"]),
        manual["id"],
        "Synthetic evidence confirmation TEST-V2",
    )
    assert completed["state"] == "completed"
    return str(case["id"])


def _configure_key(world: World, tmp_path: Path) -> tuple[Ed25519PrivateKey, Path]:
    private_key = Ed25519PrivateKey.generate()
    key_file = tmp_path / "evidence-signing.key"
    key_file.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    world.settings.signing_key_file = key_file.resolve()
    world.settings.signing_key_id = "pilot-2026-q3"
    world.settings.require_signed_evidence = True
    public_file = tmp_path / "evidence-signing.pub"
    public_file.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_key, public_file


def _expect_code(code: int, evidence: Path, manifest: Path, public_key: Path) -> None:
    with pytest.raises(EvidenceVerificationError) as raised:
        verify_evidence_v2(evidence, manifest, public_key)
    assert raised.value.exit_code == code


def test_signed_export_is_deterministic_and_verifies(world: World, tmp_path: Path) -> None:
    _private_key, public_file = _configure_key(world, tmp_path)
    case_id = _complete(world, key="evidence-v2-0001")
    connection = connection_for(world.settings)
    try:
        payload = build_evidence_v2(connection, case_id)
        evidence, manifest, first_digest = write_evidence_v2(connection, world.settings, case_id)
        _, _, second_digest = write_evidence_v2(connection, world.settings, case_id)
        artifact = connection.execute(
            "SELECT * FROM evidence_artifacts WHERE case_id=? AND schema_version=2",
            (case_id,),
        ).fetchone()
    finally:
        connection.close()

    assert payload["schema_version"] == 2
    assert payload["completion"]["event_hash"]
    assert payload["retention"]["retention_until"]
    assert payload["retention"]["policy_snapshot"] == "default-365-days"
    assert first_digest == second_digest
    assert artifact is not None and artifact["signing_status"] == "signed"
    result = verify_evidence_v2(evidence, manifest, public_file)
    assert result["valid"] is True
    assert result["origin"] == "trusted_key_match"
    assert result["key_id"] == "pilot-2026-q3"


def test_tampering_and_wrong_trust_anchor_fail(world: World, tmp_path: Path) -> None:
    _private_key, public_file = _configure_key(world, tmp_path)
    case_id = _complete(world, key="evidence-v2-0002")
    connection = connection_for(world.settings)
    try:
        evidence, manifest, _ = write_evidence_v2(connection, world.settings, case_id)
    finally:
        connection.close()

    original_evidence = evidence.read_bytes()
    evidence.write_bytes(original_evidence + b" ")
    _expect_code(3, evidence, manifest, public_file)
    evidence.write_bytes(original_evidence)

    manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
    signature = manifest_value["signature"]["value"]
    manifest_value["signature"]["value"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    manifest.write_text(json.dumps(manifest_value), encoding="utf-8")
    _expect_code(4, evidence, manifest, public_file)

    connection = connection_for(world.settings)
    try:
        _, manifest, _ = write_evidence_v2(connection, world.settings, case_id)
    finally:
        connection.close()
    wrong_key = Ed25519PrivateKey.generate()
    wrong_public = tmp_path / "wrong.pub"
    wrong_public.write_bytes(
        wrong_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    _expect_code(5, evidence, manifest, wrong_public)

    connection = connection_for(world.settings)
    try:
        _, manifest, _ = write_evidence_v2(connection, world.settings, case_id)
    finally:
        connection.close()
    manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
    embedded = manifest_value["public_key"]["value"]
    manifest_value["public_key"]["value"] = ("A" if embedded[0] != "A" else "B") + embedded[1:]
    manifest.write_text(json.dumps(manifest_value), encoding="utf-8")
    _expect_code(5, evidence, manifest, public_file)


def test_signing_key_rotation_preserves_historical_manifest(world: World, tmp_path: Path) -> None:
    _private_key, original_public = _configure_key(world, tmp_path)
    case_id = _complete(world, key="evidence-v2-rotation")
    connection = connection_for(world.settings)
    try:
        evidence, manifest, _ = write_evidence_v2(connection, world.settings, case_id)
        original_manifest = manifest.read_bytes()
    finally:
        connection.close()

    replacement = Ed25519PrivateKey.generate()
    replacement_file = tmp_path / "replacement.key"
    replacement_file.write_bytes(replacement.private_bytes_raw())
    replacement_public = tmp_path / "replacement.pub"
    replacement_public.write_bytes(replacement.public_key().public_bytes_raw())
    world.settings.signing_key_file = replacement_file.resolve()
    world.settings.signing_key_id = "pilot-2026-q4"
    connection = connection_for(world.settings)
    try:
        write_evidence_v2(connection, world.settings, case_id)
    finally:
        connection.close()

    assert manifest.read_bytes() == original_manifest
    assert verify_evidence_v2(evidence, manifest, original_public)["valid"] is True
    _expect_code(5, evidence, manifest, replacement_public)


def test_unsigned_export_is_explicit_and_not_implicitly_trusted(world: World, tmp_path: Path) -> None:
    case_id = _complete(world, key="evidence-v2-0003")
    connection = connection_for(world.settings)
    try:
        evidence, manifest, _ = write_evidence_v2(connection, world.settings, case_id)
        artifact = connection.execute(
            "SELECT signing_status FROM evidence_artifacts WHERE case_id=? AND schema_version=2",
            (case_id,),
        ).fetchone()
    finally:
        connection.close()
    public_file = tmp_path / "unused.pub"
    public_file.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    _expect_code(6, evidence, manifest, public_file)
    assert artifact is not None and artifact["signing_status"] == "unsigned"


def test_required_signing_failure_does_not_complete_case(world: World) -> None:
    world.settings.require_signed_evidence = True
    case = world.create(key="evidence-required-0001")
    world.plan_and_approve(str(case["id"]))
    worker = Worker(world.settings)
    while worker.run_once():
        pass
    view = world.service.case_view(str(case["id"]))
    manual = next(item for item in view["controls"] if item["manual"] == 1)
    with pytest.raises(ConfigurationError, match="no signing key"):
        world.service.complete_manual(
            world.actors[Role.MANAGER],
            str(case["id"]),
            manual["id"],
            "Synthetic required signing failure",
        )
    failed = world.service.case_view(str(case["id"]))
    assert failed["state"] == "exception"
    assert failed["completed_at"] is None
    assert any(item["category"] == "evidence_signing" for item in failed["exceptions"])
    assert not any(event["event_type"] == "case.completed" for event in world.service.audit_events(str(case["id"])))
