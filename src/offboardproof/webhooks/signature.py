from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime

from offboardproof.errors import WebhookAuthenticationError

SIGNATURE_PATTERN = re.compile(r"^sha256=([0-9a-f]{64})$")
DELIVERY_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{8,128}$")
SIGNED_DOMAIN = b"offboardproof.webhook.v1\n"


def parse_timestamp(value: str, *, now: datetime, skew_seconds: int) -> int:
    if not value or not value.isascii() or not value.isdigit():
        raise WebhookAuthenticationError("Webhook authentication failed")
    try:
        timestamp = int(value)
    except ValueError as exc:
        raise WebhookAuthenticationError("Webhook authentication failed") from exc
    if abs(int(now.timestamp()) - timestamp) > skew_seconds:
        raise WebhookAuthenticationError("Webhook authentication failed")
    return timestamp


def verify_signature(
    *,
    secret: bytes,
    timestamp_text: str,
    delivery_id: str,
    raw_body: bytes,
    signature_header: str,
) -> None:
    if DELIVERY_PATTERN.fullmatch(delivery_id) is None:
        raise WebhookAuthenticationError("Webhook authentication failed")
    match = SIGNATURE_PATTERN.fullmatch(signature_header)
    if match is None:
        raise WebhookAuthenticationError("Webhook authentication failed")
    signed_bytes = (
        SIGNED_DOMAIN + timestamp_text.encode("ascii") + b"\n" + delivery_id.encode("utf-8") + b"\n" + raw_body
    )
    expected = hmac.new(secret, signed_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, match.group(1)):
        raise WebhookAuthenticationError("Webhook authentication failed")


def sign_for_testing(*, secret: bytes, timestamp: int, delivery_id: str, raw_body: bytes) -> str:
    timestamp_text = str(timestamp)
    signed_bytes = (
        SIGNED_DOMAIN + timestamp_text.encode("ascii") + b"\n" + delivery_id.encode("utf-8") + b"\n" + raw_body
    )
    return "sha256=" + hmac.new(secret, signed_bytes, hashlib.sha256).hexdigest()
