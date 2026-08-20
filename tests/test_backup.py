from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from conftest import World, write_owner_only
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from offboardproof.backup import BackupService
from offboardproof.enums import Role
from offboardproof.errors import ConfigurationError
from offboardproof.util import canonical_json, sha256_text
from offboardproof.worker import Worker


def _complete(world: World, *, key: str = "backup-case-0001") -> None:
    case = world.create(key=key)
    world.plan_and_approve(str(case["id"]))
    worker = Worker(world.settings)
    while worker.run_once():
        pass
    view = world.service.case_view(str(case["id"]))
    manual = next(control for control in view["controls"] if control["manual"] == 1)
    world.service.complete_manual(
        world.actors[Role.MANAGER],
        str(case["id"]),
        manual["id"],
        "Synthetic backup evidence TEST-BACKUP",
    )


def test_backup_and_scratch_restore_verify(world: World) -> None:
    _complete(world)
    secret = world.settings.database_path.parent / "must-not-back-up.secret"
    secret.write_text("not-a-real-secret", encoding="utf-8")
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        backup = root / "backup"
        scratch = root / "scratch"
        service = BackupService(world.settings)
        created = service.create(world.actors[Role.OPERATOR], backup)
        assert created["file_count"] >= 5
        assert not any(path.name == secret.name for path in backup.rglob("*"))
        verified = service.verify(backup)
        assert verified.valid
        assert verified.unsigned_evidence_count == 1
        restored = service.restore_verify(backup, scratch)
        assert restored["database_integrity"] == "ok"
        assert restored["foreign_key_violations"] == 0
        assert restored["audit_chain_valid"] is True


def test_backup_detects_changed_and_unsafe_inventory_entries(world: World) -> None:
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        backup = root / "backup"
        service = BackupService(world.settings)
        service.create(world.actors[Role.SECURITY], backup)
        config = backup / "config" / "settings.json"
        config.write_text("changed", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="digest verification"):
            service.verify(backup)

        second = root / "second"
        service.create(world.actors[Role.SECURITY], second)
        inventory_path = second / "inventory.json"
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        inventory["entries"][0]["path"] = "../escape"
        stable = {"schema_version": inventory["schema_version"], "entries": inventory["entries"]}
        inventory["inventory_sha256"] = sha256_text(canonical_json(stable))
        inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
        with pytest.raises(ConfigurationError, match="unsafe path"):
            service.verify(second)


def test_signed_backup_verifies_public_trust_material(world: World) -> None:
    private_key = Ed25519PrivateKey.generate()
    key_path = world.settings.database_path.parent / "backup-signing.key"
    write_owner_only(key_path, private_key.private_bytes_raw())
    world.settings.signing_key_file = key_path.resolve()
    world.settings.signing_key_id = "backup-signing-key"
    world.settings.require_signed_evidence = True
    _complete(world)
    with TemporaryDirectory() as temporary:
        service = BackupService(world.settings)
        backup = Path(temporary) / "signed-backup"
        service.create(world.actors[Role.ADMIN], backup)
        verified = service.verify(backup)
        assert verified.signed_evidence_verified == 1
        assert verified.unsigned_evidence_count == 0


def test_backup_rejects_unsafe_destinations_and_extra_files(world: World) -> None:
    service = BackupService(world.settings)
    with pytest.raises(ConfigurationError, match="outside the repository"):
        service.create(world.actors[Role.OPERATOR], Path.cwd() / "unsafe-backup")
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        nonempty = root / "nonempty"
        nonempty.mkdir()
        (nonempty / "existing").write_text("occupied", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="new or empty"):
            service.create(world.actors[Role.OPERATOR], nonempty)
        backup = root / "backup"
        service.create(world.actors[Role.OPERATOR], backup)
        (backup / "extra").write_text("unlisted", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="unlisted"):
            service.verify(backup)


def test_backup_preserves_public_keys_for_historical_rotation(world: World) -> None:
    first_key = Ed25519PrivateKey.generate()
    first_path = world.settings.database_path.parent / "first.key"
    write_owner_only(first_path, first_key.private_bytes_raw())
    world.settings.signing_key_file = first_path.resolve()
    world.settings.signing_key_id = "rotation-first"
    world.settings.require_signed_evidence = True
    _complete(world, key="backup-rotation-first")

    second_key = Ed25519PrivateKey.generate()
    second_path = world.settings.database_path.parent / "second.key"
    write_owner_only(second_path, second_key.private_bytes_raw())
    world.settings.signing_key_file = second_path.resolve()
    world.settings.signing_key_id = "rotation-second"
    _complete(world, key="backup-rotation-second")

    with TemporaryDirectory() as temporary:
        backup = Path(temporary) / "rotated-backup"
        service = BackupService(world.settings)
        service.create(world.actors[Role.SECURITY], backup)
        verified = service.verify(backup)
        assert verified.signed_evidence_verified == 2
        assert (backup / "public-keys" / "rotation-first.pub").is_file()
        assert (backup / "public-keys" / "rotation-second.pub").is_file()
