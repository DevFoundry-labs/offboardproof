from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path

from offboardproof.config import Settings

SCHEMA_VERSION = 1


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=15, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextmanager
def transaction(connection: sqlite3.Connection) -> Generator[sqlite3.Connection, None, None]:
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
    except Exception:
        connection.rollback()
        raise
    else:
        connection.commit()


def migrate(settings: Settings) -> int:
    settings.ensure_directories()
    connection = connect(settings.database_path)
    try:
        current = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if current > SCHEMA_VERSION:
            raise RuntimeError(f"Database schema version {current} is newer than supported {SCHEMA_VERSION}")
        for version in range(current + 1, SCHEMA_VERSION + 1):
            migration_path = files("offboardproof").joinpath("migrations", f"{version:04d}_initial.sql")
            sql = migration_path.read_text(encoding="utf-8")
            connection.executescript(sql)
            connection.execute(f"PRAGMA user_version = {version}")
        return SCHEMA_VERSION
    finally:
        connection.close()


def connection_for(settings: Settings) -> sqlite3.Connection:
    return connect(settings.database_path)
