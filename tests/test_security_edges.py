from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from offboardproof.config import Settings
from offboardproof.errors import ConfigurationError, WebhookAuthenticationError
from offboardproof.evidence_signing import load_public_key, load_signing_key, write_public_key
from offboardproof.evidence_verification import EvidenceVerificationError, verify_evidence_v2
from offboardproof.webhooks.config import load_credential
from offboardproof.webhooks.signature import parse_timestamp, verify_signature


def test_signing_key_configuration_formats_and_failures(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    raw_file = tmp_path / "raw.key"
    raw_file.write_bytes(private_key.private_bytes_raw())
    settings = Settings(signing_key_file=raw_file.resolve(), signing_key_id="raw-key")
    loaded = load_signing_key(settings)
    assert loaded is not None and loaded.key_id == "raw-key"

    public_file = tmp_path / "public.pem"
    write_public_key(loaded, public_file)
    assert load_public_key(public_file).public_bytes_raw() == private_key.public_key().public_bytes_raw()
    raw_public = tmp_path / "public.raw"
    raw_public.write_bytes(private_key.public_key().public_bytes_raw())
    assert load_public_key(raw_public).public_bytes_raw() == private_key.public_key().public_bytes_raw()

    with pytest.raises(ConfigurationError, match="SIGNING_KEY_ID"):
        load_signing_key(Settings(signing_key_file=raw_file.resolve()))
    with pytest.raises(ConfigurationError, match="absolute readable"):
        load_signing_key(Settings(signing_key_file=Path("relative.key"), signing_key_id="bad"))
    with pytest.raises(ConfigurationError, match="no signing key"):
        load_signing_key(Settings(require_signed_evidence=True))

    password = b"correct horse battery staple"
    encrypted = tmp_path / "encrypted.pem"
    encrypted.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        )
    )
    password_file = tmp_path / "password.txt"
    password_file.write_bytes(password + b"\n")
    encrypted_settings = Settings(
        signing_key_file=encrypted.resolve(),
        signing_key_password_file=password_file.resolve(),
        signing_key_id="encrypted-key",
    )
    assert load_signing_key(encrypted_settings) is not None
    password_file.write_text("wrong", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="could not be loaded"):
        load_signing_key(encrypted_settings)
    password_file.write_bytes(b"")
    with pytest.raises(ConfigurationError, match="password file is empty"):
        load_signing_key(encrypted_settings)

    missing_public = tmp_path / "missing.pub"
    with pytest.raises(ValueError, match="does not exist"):
        load_public_key(missing_public)
    invalid_public = tmp_path / "invalid.pub"
    invalid_public.write_bytes(b"invalid")
    with pytest.raises(ValueError, match="could not be loaded"):
        load_public_key(invalid_public)


def _webhook_config(tmp_path: Path, secret_file: Path) -> Path:
    config = tmp_path / "webhook.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "sources": {
                    "source-one": {
                        "active": True,
                        "actor_id": "service-actor",
                        "current_key": {"key_id": "current", "secret_file": str(secret_file.resolve())},
                        "previous_key": {
                            "key_id": "previous",
                            "secret_file": str(secret_file.resolve()),
                            "accept_until": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return config.resolve()


def test_webhook_configuration_and_signature_negative_paths(tmp_path: Path) -> None:
    secret_file = tmp_path / "secret"
    secret_file.write_bytes(b"x" * 32)
    now = datetime.now(UTC)
    settings = Settings(webhook_config_file=_webhook_config(tmp_path, secret_file))
    assert load_credential(settings, source_id="source-one", key_id="current", now=now).actor_id == "service-actor"

    for source, key in (("missing", "current"), ("source-one", "missing"), ("source-one", "previous")):
        with pytest.raises(WebhookAuthenticationError, match="authentication failed"):
            load_credential(settings, source_id=source, key_id=key, now=now)

    secret_file.write_bytes(b"short")
    with pytest.raises(WebhookAuthenticationError):
        load_credential(settings, source_id="source-one", key_id="current", now=now)
    with pytest.raises(WebhookAuthenticationError):
        load_credential(Settings(), source_id="source-one", key_id="current", now=now)

    document = json.loads(settings.webhook_config_file.read_text(encoding="utf-8"))  # type: ignore[union-attr]
    document["schema_version"] = 2
    settings.webhook_config_file.write_text(json.dumps(document), encoding="utf-8")  # type: ignore[union-attr]
    with pytest.raises(WebhookAuthenticationError):
        load_credential(settings, source_id="source-one", key_id="current", now=now)

    document["schema_version"] = 1
    document["sources"]["source-one"]["active"] = False
    settings.webhook_config_file.write_text(json.dumps(document), encoding="utf-8")  # type: ignore[union-attr]
    with pytest.raises(WebhookAuthenticationError):
        load_credential(settings, source_id="source-one", key_id="current", now=now)

    for value in ("", " 1", "+1", "1.0", "not-time"):
        with pytest.raises(WebhookAuthenticationError):
            parse_timestamp(value, now=now, skew_seconds=300)
    with pytest.raises(WebhookAuthenticationError):
        parse_timestamp(str(int(now.timestamp()) - 301), now=now, skew_seconds=300)
    with pytest.raises(WebhookAuthenticationError):
        verify_signature(
            secret=b"x" * 32,
            timestamp_text=str(int(now.timestamp())),
            delivery_id="short",
            raw_body=b"{}",
            signature_header="bad",
        )
    with pytest.raises(WebhookAuthenticationError):
        verify_signature(
            secret=b"x" * 32,
            timestamp_text=str(int(now.timestamp())),
            delivery_id="delivery-valid",
            raw_body=b"{}",
            signature_header="sha256=" + "0" * 64,
        )


def test_evidence_verifier_rejects_malformed_and_unsupported_inputs(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    manifest = tmp_path / "manifest.json"
    public_key = tmp_path / "public.key"
    public_key.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes_raw())

    evidence.write_text("not-json", encoding="utf-8")
    manifest.write_text("{}", encoding="utf-8")
    with pytest.raises(EvidenceVerificationError) as malformed:
        verify_evidence_v2(evidence, manifest, public_key)
    assert malformed.value.exit_code == 2

    evidence.write_text('{"schema_version":1}', encoding="utf-8")
    manifest.write_text('{"manifest_schema_version":1}', encoding="utf-8")
    with pytest.raises(EvidenceVerificationError) as unsupported:
        verify_evidence_v2(evidence, manifest, public_key)
    assert unsupported.value.exit_code == 2

    evidence.write_text('{"schema_version":2}', encoding="utf-8")
    manifest.write_text('{"manifest_schema_version":1,"signing_status":"unsigned"}', encoding="utf-8")
    with pytest.raises(EvidenceVerificationError) as unsigned:
        verify_evidence_v2(evidence, manifest, public_key)
    assert unsigned.value.exit_code == 6
