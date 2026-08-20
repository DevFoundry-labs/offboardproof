from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from offboardproof.config import Settings
from offboardproof.errors import WebhookAuthenticationError
from offboardproof.util import parse_utc

GENERIC_AUTH_MESSAGE = "Webhook authentication failed"


@dataclass(frozen=True)
class WebhookCredential:
    actor_id: str
    secret: bytes


def _fail() -> WebhookAuthenticationError:
    return WebhookAuthenticationError(GENERIC_AUTH_MESSAGE)


def _load_secret(path_value: object) -> bytes:
    if not isinstance(path_value, str):
        raise _fail()
    path = Path(path_value)
    if not path.is_absolute() or not path.is_file():
        raise _fail()
    secret = path.read_bytes()
    if len(secret) < 32:
        raise _fail()
    return secret


def load_credential(
    settings: Settings,
    *,
    source_id: str,
    key_id: str,
    now: datetime,
) -> WebhookCredential:
    config_path = settings.webhook_config_file
    if config_path is None or not config_path.is_absolute() or not config_path.is_file():
        raise _fail()
    try:
        document: dict[str, Any] = json.loads(config_path.read_text(encoding="utf-8"))
        if document.get("schema_version") != 1:
            raise _fail()
        source = document["sources"][source_id]
        if not isinstance(source, dict) or source.get("active") is not True:
            raise _fail()
        actor_id = source["actor_id"]
        if not isinstance(actor_id, str) or not actor_id:
            raise _fail()

        current = source.get("current_key")
        if isinstance(current, dict) and current.get("key_id") == key_id:
            return WebhookCredential(actor_id=actor_id, secret=_load_secret(current.get("secret_file")))

        previous = source.get("previous_key")
        if isinstance(previous, dict) and previous.get("key_id") == key_id:
            accept_until = previous.get("accept_until")
            if not isinstance(accept_until, str) or now > parse_utc(accept_until):
                raise _fail()
            return WebhookCredential(actor_id=actor_id, secret=_load_secret(previous.get("secret_file")))
    except WebhookAuthenticationError:
        raise
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise _fail() from exc
    raise _fail()
