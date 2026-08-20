from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from offboardproof.auth import authenticate, create_actor
from offboardproof.config import Settings
from offboardproof.db import SCHEMA_VERSION, connection_for, migrate
from offboardproof.enums import Role
from offboardproof.errors import AuthorizationError, ConfigurationError
from offboardproof.providers.factory import get_provider
from offboardproof.util import canonical_json, normalize_email, parse_utc, sha256_text


@given(st.dictionaries(st.text(max_size=10), st.integers(), max_size=5))
def test_canonical_json_and_hash_are_stable(value: dict[str, int]) -> None:
    assert canonical_json(value) == canonical_json(dict(reversed(list(value.items()))))
    assert len(sha256_text(canonical_json(value))) == 64


def test_email_and_time_normalization() -> None:
    assert normalize_email(" ALEX@EXAMPLE.TEST ") == "alex@example.test"
    assert parse_utc("2026-08-10T10:00:00+04:00") == datetime(2026, 8, 10, 6, tzinfo=UTC)
    with pytest.raises(ValueError):
        normalize_email("not-an-email")
    with pytest.raises(ValueError):
        parse_utc("2026-08-10T10:00:00")


def test_authentication_and_migration(tmp_path) -> None:  # type: ignore[no-untyped-def]
    settings = Settings(database_path=tmp_path / "db.sqlite", evidence_dir=tmp_path / "evidence")
    assert migrate(settings) == SCHEMA_VERSION
    assert migrate(settings) == SCHEMA_VERSION
    connection = connection_for(settings)
    try:
        actor, token = create_actor(connection, "Auditor", Role.AUDITOR)
        assert authenticate(connection, token) == actor
        with pytest.raises(AuthorizationError):
            authenticate(connection, "not-a-valid-token-value")
        with pytest.raises(ValueError):
            create_actor(connection, " ", Role.HR)
        with pytest.raises(ConfigurationError):
            get_provider("unknown", connection, settings)
        with pytest.raises(ConfigurationError):
            get_provider("google", connection, settings)
    finally:
        connection.close()
