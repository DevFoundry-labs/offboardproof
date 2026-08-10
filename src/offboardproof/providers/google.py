from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import service_account

from offboardproof.errors import ConfigurationError, NotFoundError, ProviderError
from offboardproof.providers.base import ActionReceipt, ActionRequest, Discovery, Observation

BASE_URL = "https://admin.googleapis.com/admin/directory/v1"
SCOPES = (
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/admin.directory.user.security",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.member",
)


class GoogleWorkspaceProvider:
    name = "google"

    def __init__(
        self,
        *,
        service_account_file: Path,
        delegated_admin: str,
        writes_enabled: bool,
        session: requests.Session | None = None,
    ) -> None:
        if not service_account_file.is_file():
            raise ConfigurationError(
                "Google service-account file was not found; set OFFBOARDPROOF_GOOGLE_SERVICE_ACCOUNT_FILE"
            )
        if not delegated_admin:
            raise ConfigurationError("Google delegated admin is required; set OFFBOARDPROOF_GOOGLE_DELEGATED_ADMIN")
        credentials = service_account.Credentials.from_service_account_file(  # type: ignore[no-untyped-call]
            service_account_file, scopes=SCOPES
        ).with_subject(delegated_admin)
        self.credentials = credentials
        self.writes_enabled = writes_enabled
        self.session = session or requests.Session()

    def _headers(self) -> dict[str, str]:
        if not self.credentials.valid:
            self.credentials.refresh(GoogleAuthRequest())
        return {
            "Authorization": f"Bearer {self.credentials.token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        try:
            response = self.session.request(
                method,
                f"{BASE_URL}{path}",
                headers=self._headers(),
                timeout=(5, 20),
                **kwargs,
            )
        except requests.Timeout as exc:
            raise ProviderError(
                "Google Workspace request timed out; reconcile before retrying",
                retryable=True,
                outcome_unknown=method.upper() not in {"GET", "HEAD"},
            ) from exc
        except requests.RequestException as exc:
            raise ProviderError("Google Workspace network request failed", retryable=True) from exc

        if response.status_code == 404:
            raise NotFoundError("Google Workspace user or group membership was not found")
        if response.status_code in {408, 429, 500, 502, 503, 504}:
            raise ProviderError(
                f"Google Workspace returned retryable HTTP {response.status_code}",
                retryable=True,
                outcome_unknown=method.upper() not in {"GET", "HEAD"},
                external_reference=response.headers.get("x-request-id"),
            )
        if response.status_code >= 400:
            raise ProviderError(
                "Google Workspace rejected the request with HTTP "
                f"{response.status_code}; check delegated admin permissions and scopes",
                external_reference=response.headers.get("x-request-id"),
            )
        return response

    def discover(self, subject_email: str) -> Discovery:
        key = quote(subject_email, safe="")
        user_response = self._request("GET", f"/users/{key}")
        user = user_response.json()
        groups: list[str] = []
        page_token: str | None = None
        while True:
            params = {"userKey": subject_email, "maxResults": 200}
            if page_token:
                params["pageToken"] = page_token
            group_response = self._request("GET", "/groups", params=params)
            payload = group_response.json()
            groups.extend(group["email"] for group in payload.get("groups", []))
            page_token = payload.get("nextPageToken")
            if not page_token:
                break
        return Discovery(
            subject_email=subject_email,
            external_id=str(user["id"]),
            suspended=bool(user.get("suspended", False)),
            signed_out=None,
            groups=tuple(sorted(groups)),
            raw={"suspension_reason": user.get("suspensionReason")},
        )

    def execute(self, request: ActionRequest) -> ActionReceipt:
        if not self.writes_enabled:
            raise ConfigurationError(
                "External writes are disabled; set "
                "OFFBOARDPROOF_ENABLE_EXTERNAL_WRITES=true after reviewing the plan and scopes"
            )
        user_key = quote(request.subject_email, safe="")
        if request.operation == "suspend_account":
            response = self._request("PATCH", f"/users/{user_key}", json={"suspended": True})
        elif request.operation == "sign_out_sessions":
            response = self._request("POST", f"/users/{user_key}/signOut", json={})
        elif request.operation == "remove_group":
            group_key = quote(request.target, safe="")
            response = self._request("DELETE", f"/groups/{group_key}/members/{user_key}")
        else:
            raise ProviderError(f"Google Workspace does not support operation '{request.operation}'")
        return ActionReceipt(
            external_reference=response.headers.get("x-request-id", f"google:{request.action_id}"),
            details={"http_status": response.status_code},
        )

    def observe(self, request: ActionRequest) -> Observation:
        discovery = self.discover(request.subject_email)
        if request.operation == "suspend_account":
            return Observation(
                external_id=discovery.external_id,
                observed={"suspended": discovery.suspended},
                satisfied=discovery.suspended,
            )
        if request.operation == "remove_group":
            present = any(group.lower() == request.target.lower() for group in discovery.groups)
            return Observation(
                external_id=discovery.external_id,
                observed={"group": request.target, "present": present},
                satisfied=not present,
            )
        if request.operation == "sign_out_sessions":
            return Observation(
                external_id=discovery.external_id,
                observed={"sign_out_observable": False},
                satisfied=False,
                quality="acknowledged_only",
            )
        raise ProviderError(f"Google Workspace cannot observe operation '{request.operation}'")
