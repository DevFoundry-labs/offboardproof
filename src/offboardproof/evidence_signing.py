from __future__ import annotations

import base64
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from offboardproof.config import Settings
from offboardproof.errors import ConfigurationError


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    return hashlib.sha256(public_key_bytes(public_key)).hexdigest()


@dataclass(frozen=True)
class SigningKey:
    key_id: str
    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()


def _absolute_file(path: Path | None, label: str) -> Path:
    if path is None or not path.is_absolute() or not path.is_file():
        raise ConfigurationError(f"{label} must be an absolute readable file")
    return path


def load_signing_key(settings: Settings) -> SigningKey | None:
    if settings.signing_key_file is None:
        if settings.require_signed_evidence:
            raise ConfigurationError("Signed evidence is required but no signing key file is configured")
        return None
    if not settings.signing_key_id:
        raise ConfigurationError("OFFBOARDPROOF_SIGNING_KEY_ID is required when signing is enabled")
    key_path = _absolute_file(settings.signing_key_file, "OFFBOARDPROOF_SIGNING_KEY_FILE")
    if os.name != "nt" and stat.S_IMODE(key_path.stat().st_mode) & 0o077:
        raise ConfigurationError("Signing key file permissions must not grant group or other access")
    password: bytes | None = None
    if settings.signing_key_password_file is not None:
        password_path = _absolute_file(
            settings.signing_key_password_file,
            "OFFBOARDPROOF_SIGNING_KEY_PASSWORD_FILE",
        )
        password = password_path.read_bytes().rstrip(b"\r\n")
        if not password:
            raise ConfigurationError("Signing key password file is empty")
    key_bytes = key_path.read_bytes()
    try:
        if len(key_bytes) == 32 and password is None:
            private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        else:
            loaded = serialization.load_pem_private_key(key_bytes, password=password)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise ConfigurationError("Signing key must be Ed25519")
            private_key = loaded
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("Signing key could not be loaded") from exc
    return SigningKey(key_id=settings.signing_key_id, private_key=private_key)


def load_public_key(path: Path) -> Ed25519PublicKey:
    if not path.is_file():
        raise ValueError("Trusted public key file does not exist")
    value = path.read_bytes()
    try:
        if len(value) == 32:
            return Ed25519PublicKey.from_public_bytes(value)
        loaded = serialization.load_pem_public_key(value)
        if not isinstance(loaded, Ed25519PublicKey):
            raise ValueError("Trusted public key must be Ed25519")
        return loaded
    except (TypeError, ValueError) as exc:
        raise ValueError("Trusted public key could not be loaded") from exc


def write_public_key(signing_key: SigningKey, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(
        signing_key.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
