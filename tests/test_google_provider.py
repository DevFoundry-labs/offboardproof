from __future__ import annotations

from dataclasses import dataclass

import pytest
import requests

from offboardproof.errors import ConfigurationError, NotFoundError, ProviderError
from offboardproof.providers.base import ActionRequest
from offboardproof.providers.google import GoogleWorkspaceProvider


class FakeCredentials:
    valid = True
    token = "synthetic-access-token"

    def with_subject(self, _subject: str) -> FakeCredentials:
        return self

    def refresh(self, _request: object) -> None:
        self.valid = True


@dataclass
class FakeResponse:
    status_code: int = 200
    payload: dict[str, object] | None = None
    headers: dict[str, str] | None = None

    def __post_init__(self) -> None:
        self.headers = self.headers or {"x-request-id": "request-123"}

    def json(self) -> dict[str, object]:
        return self.payload or {}


class FakeSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.status = 200
        self.raise_timeout = False

    def request(self, method: str, url: str, **_kwargs: object) -> FakeResponse:
        if self.raise_timeout:
            raise requests.Timeout("synthetic timeout")
        self.calls.append((method, url))
        if "/users/" in url and method == "GET":
            return FakeResponse(self.status, {"id": "user-1", "suspended": False})
        if url.endswith("/groups"):
            return FakeResponse(self.status, {"groups": [{"email": "vpn@example.test"}]})
        return FakeResponse(self.status)


@pytest.fixture
def provider(tmp_path, monkeypatch) -> GoogleWorkspaceProvider:  # type: ignore[no-untyped-def]
    credentials_file = tmp_path / "credentials.json"
    credentials_file.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        "offboardproof.providers.google.service_account.Credentials.from_service_account_file",
        lambda *_args, **_kwargs: FakeCredentials(),
    )
    return GoogleWorkspaceProvider(
        service_account_file=credentials_file,
        delegated_admin="admin@example.test",
        writes_enabled=True,
        session=FakeSession(),  # type: ignore[arg-type]
    )


def _action(operation: str, target: str = "alex@example.test") -> ActionRequest:
    return ActionRequest(
        action_id="action-1",
        idempotency_key="case:action-1",
        operation=operation,
        subject_email="alex@example.test",
        target=target,
        desired={},
    )


def test_google_discovery_and_bounded_operations(provider: GoogleWorkspaceProvider) -> None:
    discovery = provider.discover("alex@example.test")
    assert discovery.external_id == "user-1"
    assert discovery.groups == ("vpn@example.test",)
    assert provider.execute(_action("suspend_account")).external_reference == "request-123"
    assert provider.execute(_action("sign_out_sessions")).acknowledged
    assert provider.execute(_action("remove_group", "vpn@example.test")).details == {"http_status": 200}
    assert provider.observe(_action("suspend_account")).satisfied is False
    sign_out = provider.observe(_action("sign_out_sessions"))
    assert sign_out.quality == "acknowledged_only" and not sign_out.satisfied
    assert provider.observe(_action("remove_group", "absent@example.test")).satisfied
    with pytest.raises(ProviderError):
        provider.execute(_action("delete_account"))


def test_google_safety_and_http_failures(provider: GoogleWorkspaceProvider, tmp_path) -> None:  # type: ignore[no-untyped-def]
    provider.writes_enabled = False
    with pytest.raises(ConfigurationError):
        provider.execute(_action("suspend_account"))
    provider.writes_enabled = True
    session = provider.session
    assert isinstance(session, FakeSession)
    session.status = 404
    with pytest.raises(NotFoundError):
        provider.discover("alex@example.test")
    session.status = 429
    with pytest.raises(ProviderError, match="retryable") as retry:
        provider.discover("alex@example.test")
    assert retry.value.retryable
    session.raise_timeout = True
    with pytest.raises(ProviderError) as timeout:
        provider.execute(_action("suspend_account"))
    assert timeout.value.outcome_unknown
    with pytest.raises(ConfigurationError):
        GoogleWorkspaceProvider(
            service_account_file=tmp_path / "missing.json",
            delegated_admin="admin@example.test",
            writes_enabled=False,
        )
