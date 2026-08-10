from __future__ import annotations

import hashlib
import secrets
import sqlite3
from dataclasses import dataclass

from offboardproof.enums import Role
from offboardproof.errors import AuthorizationError
from offboardproof.util import iso_now, new_id


@dataclass(frozen=True)
class Actor:
    id: str
    name: str
    role: Role


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_actor(connection: sqlite3.Connection, name: str, role: Role) -> tuple[Actor, str]:
    token = f"obp_{secrets.token_urlsafe(32)}"
    actor = Actor(id=new_id(), name=name.strip(), role=role)
    if not actor.name:
        raise ValueError("Actor name is required")
    connection.execute(
        """
        INSERT INTO actors (id, name, role, token_digest, token_prefix, active, created_at)
        VALUES (?, ?, ?, ?, ?, 1, ?)
        """,
        (actor.id, actor.name, actor.role.value, token_digest(token), token[:12], iso_now()),
    )
    return actor, token


def authenticate(connection: sqlite3.Connection, token: str) -> Actor:
    if not token or len(token) < 20:
        raise AuthorizationError("A valid bearer token is required")
    row = connection.execute(
        "SELECT id, name, role, active FROM actors WHERE token_digest = ?",
        (token_digest(token),),
    ).fetchone()
    if row is None or not bool(row["active"]):
        raise AuthorizationError("The bearer token is invalid or inactive")
    return Actor(id=row["id"], name=row["name"], role=Role(row["role"]))


def require_role(actor: Actor, *roles: Role) -> None:
    if actor.role is Role.ADMIN:
        return
    if actor.role not in roles:
        allowed = ", ".join(role.value for role in roles)
        raise AuthorizationError(f"Role '{actor.role.value}' is not authorized; required: {allowed}")
