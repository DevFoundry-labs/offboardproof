from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from offboardproof.audit import verify_chain
from offboardproof.auth import Actor, require_role
from offboardproof.config import Settings
from offboardproof.db import connection_for, migrate
from offboardproof.enums import Role
from offboardproof.errors import ConfigurationError
from offboardproof.evidence_signing import b64url_decode, load_signing_key, write_public_key
from offboardproof.evidence_verification import EvidenceVerificationError, verify_evidence_v2
from offboardproof.util import canonical_json, iso_now, sha256_text


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _safe_relative(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ConfigurationError("Backup inventory contains an unsafe path")
    return path


@dataclass(frozen=True)
class BackupVerification:
    valid: bool
    file_count: int
    audit_event_count: int
    signed_evidence_verified: int
    unsigned_evidence_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "file_count": self.file_count,
            "audit_event_count": self.audit_event_count,
            "signed_evidence_verified": self.signed_evidence_verified,
            "unsigned_evidence_count": self.unsigned_evidence_count,
        }


class BackupService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _prepare_empty_directory(self, destination: Path) -> Path:
        destination = destination.resolve()
        repository_root = Path(__file__).resolve().parents[2]
        forbidden = [repository_root, self.settings.evidence_dir.resolve()]
        if any(_inside(destination, path) for path in forbidden):
            raise ConfigurationError("Backup destination must be outside the repository and evidence directory")
        if destination.exists():
            if not destination.is_dir() or any(destination.iterdir()):
                raise ConfigurationError("Backup destination must be a new or empty directory")
        else:
            destination.mkdir(parents=True)
        return destination

    def create(self, actor: Actor, destination: Path) -> dict[str, Any]:
        require_role(actor, Role.OPERATOR, Role.SECURITY)
        destination = self._prepare_empty_directory(destination)
        database_dir = destination / "database"
        evidence_dir = destination / "evidence"
        public_dir = destination / "public-keys"
        config_dir = destination / "config"
        for directory in (database_dir, evidence_dir, public_dir, config_dir):
            directory.mkdir()

        backup_database = database_dir / "offboardproof.db"
        source = connection_for(self.settings)
        target = sqlite3.connect(backup_database)
        try:
            source.backup(target)
        finally:
            target.close()

        entries: list[dict[str, Any]] = []
        entries.append(self._entry(destination, backup_database, kind="database"))
        historical_public_keys: dict[str, bytes] = {}
        try:
            artifacts = source.execute(
                """
                SELECT id, path, manifest_path, schema_version, signing_status,
                       signing_key_id, public_key_fingerprint
                FROM evidence_artifacts ORDER BY id
                """
            ).fetchall()
            for artifact in artifacts:
                for field, kind in (("path", "evidence"), ("manifest_path", "manifest")):
                    value = artifact[field]
                    if not value:
                        continue
                    original = Path(value).resolve()
                    if not original.is_file() or not _inside(original, self.settings.evidence_dir.resolve()):
                        raise ConfigurationError("Evidence artifact path is missing or outside the evidence directory")
                    copied = evidence_dir / str(artifact["id"]) / original.name
                    copied.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(original, copied)
                    entries.append(
                        self._entry(
                            destination,
                            copied,
                            kind=kind,
                            artifact_id=str(artifact["id"]),
                            signing_key_id=artifact["signing_key_id"],
                        )
                    )
                    if kind == "manifest" and artifact["signing_status"] == "signed":
                        try:
                            manifest = json.loads(original.read_text(encoding="utf-8"))
                            key_id = str(artifact["signing_key_id"])
                            raw_public = b64url_decode(manifest["public_key"]["value"])
                            fingerprint = hashlib.sha256(raw_public).hexdigest()
                            if (
                                len(raw_public) != 32
                                or fingerprint != artifact["public_key_fingerprint"]
                                or fingerprint != manifest["public_key"]["fingerprint_sha256"]
                                or (key_id in historical_public_keys and historical_public_keys[key_id] != raw_public)
                            ):
                                raise ConfigurationError("Signed evidence public-key metadata is inconsistent")
                            historical_public_keys[key_id] = raw_public
                        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                            raise ConfigurationError("Signed evidence manifest is malformed") from exc
        finally:
            source.close()

        for key_id, raw_public in sorted(historical_public_keys.items()):
            public_path = public_dir / f"{key_id}.pub"
            public_path.write_bytes(raw_public)
            entries.append(self._entry(destination, public_path, kind="public_key", key_id=key_id))

        signing_key = load_signing_key(self.settings)
        if signing_key is not None and signing_key.key_id not in historical_public_keys:
            public_path = public_dir / f"{signing_key.key_id}.pub"
            write_public_key(signing_key, public_path)
            entries.append(self._entry(destination, public_path, kind="public_key", key_id=signing_key.key_id))

        safe_config = {
            "schema_version": 1,
            "default_retention_days": self.settings.default_retention_days,
            "default_retention_policy_id": self.settings.default_retention_policy_id,
            "max_retention_days": self.settings.max_retention_days,
            "require_signed_evidence": self.settings.require_signed_evidence,
            "signing_key_id": self.settings.signing_key_id,
            "enable_external_writes": self.settings.enable_external_writes,
        }
        config_path = config_dir / "settings.json"
        config_path.write_text(json.dumps(safe_config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        entries.append(self._entry(destination, config_path, kind="configuration"))

        stable_inventory = {"schema_version": 1, "entries": sorted(entries, key=lambda item: item["path"])}
        inventory = {
            **stable_inventory,
            "created_at": iso_now(),
            "inventory_sha256": sha256_text(canonical_json(stable_inventory)),
        }
        inventory_path = destination / "inventory.json"
        inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {
            "backup": str(destination),
            "file_count": len(entries) + 1,
            "inventory_sha256": inventory["inventory_sha256"],
        }

    @staticmethod
    def _entry(root: Path, path: Path, *, kind: str, **metadata: Any) -> dict[str, Any]:
        return {
            "path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": _sha256_file(path),
            "kind": kind,
            **metadata,
        }

    def verify(self, backup: Path) -> BackupVerification:
        backup = backup.resolve()
        inventory_path = backup / "inventory.json"
        try:
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            entries = inventory["entries"]
            stable = {"schema_version": inventory["schema_version"], "entries": entries}
            if inventory["inventory_sha256"] != sha256_text(canonical_json(stable)):
                raise ConfigurationError("Backup inventory digest is invalid")
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ConfigurationError("Backup inventory is missing or malformed") from exc

        expected = {"inventory.json"}
        by_artifact: dict[str, dict[str, Path]] = {}
        public_keys: dict[str, Path] = {}
        for entry in entries:
            relative = _safe_relative(entry["path"])
            expected.add(relative.as_posix())
            path = (backup / relative).resolve()
            if not _inside(path, backup) or not path.is_file():
                raise ConfigurationError("Backup inventory references a missing or unsafe file")
            if path.stat().st_size != entry["size"] or _sha256_file(path) != entry["sha256"]:
                raise ConfigurationError(f"Backup file failed digest verification: {relative.as_posix()}")
            artifact_id = entry.get("artifact_id")
            if artifact_id:
                by_artifact.setdefault(str(artifact_id), {})[str(entry["kind"])] = path
            if entry.get("kind") == "public_key" and entry.get("key_id"):
                public_keys[str(entry["key_id"])] = path

        actual = {path.relative_to(backup).as_posix() for path in backup.rglob("*") if path.is_file()}
        if actual != expected:
            raise ConfigurationError("Backup contains missing or unlisted files")

        database = backup / "database" / "offboardproof.db"
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        try:
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ConfigurationError("Backup database integrity check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise ConfigurationError("Backup database foreign-key check failed")
            chain_valid, event_count, _ = verify_chain(connection)
            if not chain_valid:
                raise ConfigurationError("Backup audit chain is invalid")
            signed_verified = 0
            unsigned_count = 0
            for artifact in connection.execute(
                "SELECT id, signing_status, signing_key_id FROM evidence_artifacts WHERE schema_version=2"
            ).fetchall():
                paths = by_artifact.get(str(artifact["id"]), {})
                if "evidence" not in paths or "manifest" not in paths:
                    raise ConfigurationError("Backup is missing a v2 evidence pair")
                if artifact["signing_status"] == "signed":
                    public_key = public_keys.get(str(artifact["signing_key_id"]))
                    if public_key is None:
                        raise ConfigurationError("Backup is missing a trusted public key")
                    try:
                        verify_evidence_v2(paths["evidence"], paths["manifest"], public_key)
                    except EvidenceVerificationError as exc:
                        raise ConfigurationError("Backup signed evidence verification failed") from exc
                    signed_verified += 1
                elif artifact["signing_status"] == "unsigned":
                    unsigned_count += 1
        finally:
            connection.close()
        return BackupVerification(True, len(expected), event_count, signed_verified, unsigned_count)

    def restore_verify(self, backup: Path, scratch: Path, *, migrate_schema: bool = False) -> dict[str, Any]:
        verification = self.verify(backup)
        scratch = self._prepare_empty_directory(scratch)
        restored_database = scratch / "offboardproof.db"
        shutil.copy2(backup.resolve() / "database" / "offboardproof.db", restored_database)
        restored_evidence = scratch / "evidence"
        source_evidence = backup.resolve() / "evidence"
        if source_evidence.exists():
            shutil.copytree(source_evidence, restored_evidence)
        restored_settings = Settings(database_path=restored_database, evidence_dir=restored_evidence)
        if migrate_schema:
            migrate(restored_settings)
        connection = connection_for(restored_settings)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
            chain_valid, event_count, broken = verify_chain(connection)
        finally:
            connection.close()
        return {
            **verification.as_dict(),
            "scratch": str(scratch),
            "database_integrity": integrity,
            "foreign_key_violations": len(foreign_keys),
            "audit_chain_valid": chain_valid,
            "audit_event_count": event_count,
            "broken_audit_event": broken,
        }
