from __future__ import annotations

import sqlite3

from offboardproof.config import Settings
from offboardproof.errors import ConfigurationError
from offboardproof.providers.base import Provider
from offboardproof.providers.google import GoogleWorkspaceProvider
from offboardproof.providers.mock import MockProvider


def get_provider(name: str, connection: sqlite3.Connection, settings: Settings) -> Provider:
    if name == "mock":
        return MockProvider(connection)
    if name == "google":
        if settings.google_service_account_file is None:
            raise ConfigurationError("Google provider requires OFFBOARDPROOF_GOOGLE_SERVICE_ACCOUNT_FILE")
        return GoogleWorkspaceProvider(
            service_account_file=settings.google_service_account_file,
            delegated_admin=settings.google_delegated_admin or "",
            writes_enabled=settings.enable_external_writes,
        )
    raise ConfigurationError(f"Provider '{name}' is not configured or supported")
