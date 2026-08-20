from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from offboardproof.evidence_signing import b64url_decode, load_public_key, public_key_fingerprint
from offboardproof.util import canonical_json


@dataclass(frozen=True)
class EvidenceVerificationError(Exception):
    exit_code: int
    result: dict[str, Any]


def _fail(code: int, reason: str) -> EvidenceVerificationError:
    return EvidenceVerificationError(code, {"valid": False, "reason": reason})


def verify_evidence_v2(evidence_path: Path, manifest_path: Path, trusted_public_key: Path) -> dict[str, Any]:
    try:
        evidence_bytes = evidence_path.read_bytes()
        manifest_bytes = manifest_path.read_bytes()
        if len(evidence_bytes) > 10 * 1024 * 1024 or len(manifest_bytes) > 1024 * 1024:
            raise _fail(2, "input_too_large")
        evidence = json.loads(evidence_bytes)
        manifest = json.loads(manifest_bytes)
    except EvidenceVerificationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail(2, "malformed_input") from exc
    if evidence.get("schema_version") != 2 or manifest.get("manifest_schema_version") != 1:
        raise _fail(2, "unsupported_schema")
    if manifest.get("signing_status") == "unsigned":
        raise _fail(6, "unsigned_evidence")
    try:
        statement = manifest["statement"]
        signature_info = manifest["signature"]
        public_info = manifest["public_key"]
        if statement["domain"] != "offboardproof.evidence.signature.v1":
            raise _fail(2, "unsupported_signing_domain")
        if signature_info["algorithm"] != "Ed25519":
            raise _fail(2, "unsupported_algorithm")
        digest = hashlib.sha256(evidence_bytes).hexdigest()
        if digest != statement["evidence_sha256"]:
            raise _fail(3, "evidence_digest_mismatch")
        if statement["case_id"] != evidence["case"]["id"]:
            raise _fail(3, "case_id_mismatch")
        if statement["completion_event_hash"] != evidence["completion"]["event_hash"]:
            raise _fail(3, "completion_hash_mismatch")
        trusted = load_public_key(trusted_public_key)
        trusted_fingerprint = public_key_fingerprint(trusted)
        embedded_bytes = b64url_decode(public_info["value"])
        if len(embedded_bytes) != 32 or hashlib.sha256(embedded_bytes).hexdigest() != public_info["fingerprint_sha256"]:
            raise _fail(5, "embedded_key_mismatch")
        if trusted_fingerprint != public_info["fingerprint_sha256"]:
            raise _fail(5, "trust_anchor_mismatch")
        statement_bytes = canonical_json(statement).encode("utf-8")
        trusted.verify(b64url_decode(signature_info["value"]), statement_bytes)
    except EvidenceVerificationError:
        raise
    except InvalidSignature as exc:
        raise _fail(4, "signature_invalid") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise _fail(2, "malformed_manifest") from exc
    assurance = evidence.get("assurance", {})
    assurance_kind = (
        "observed_only"
        if assurance.get("acknowledged_controls", 0) == 0
        and assurance.get("human_attested_controls", 0) == 0
        and assurance.get("waived_controls", 0) == 0
        else "mixed_observed_and_acknowledged"
    )
    return {
        "valid": True,
        "integrity": "verified",
        "origin": "trusted_key_match",
        "assurance": assurance_kind,
        "case_id": statement["case_id"],
        "key_id": statement["key_id"],
        "evidence_sha256": statement["evidence_sha256"],
    }
