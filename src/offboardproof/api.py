import hashlib
import re
import sqlite3
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError

from offboardproof import __version__
from offboardproof.auth import Actor, authenticate, require_role
from offboardproof.config import Settings
from offboardproof.db import connection_for, migrate
from offboardproof.enums import Role
from offboardproof.errors import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    OffboardProofError,
    PayloadTooLargeError,
    UnsupportedMediaTypeError,
    WebhookAuthenticationError,
    WebhookValidationError,
)
from offboardproof.evidence import build_evidence
from offboardproof.retention import RetentionService
from offboardproof.schemas import (
    ApprovalCreate,
    CaseCreate,
    LegalHoldCreate,
    LegalHoldRelease,
    ManualComplete,
    RequeueCreate,
    WaiverCreate,
)
from offboardproof.service import WorkflowService
from offboardproof.webhooks.config import load_credential
from offboardproof.webhooks.schemas import WebhookEvent
from offboardproof.webhooks.service import WebhookService
from offboardproof.webhooks.signature import parse_timestamp, verify_signature
from offboardproof.worker import Worker

bearer = HTTPBearer(auto_error=False)


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or Settings()
    migrate(app_settings)
    service = WorkflowService(app_settings)
    worker = Worker(app_settings)
    webhook_service = WebhookService(app_settings, service)
    retention_service = RetentionService(app_settings)

    app = FastAPI(
        title="OffboardProof API",
        version=__version__,
        description=(
            "Verification-first employee offboarding with digest-bound approvals, "
            "recoverable actions, and audit evidence."
        ),
    )
    app.state.settings = app_settings
    app.state.service = service
    app.state.webhook_service = webhook_service
    app.state.retention_service = retention_service

    @app.middleware("http")
    async def request_correlation(request: Request, call_next: Any) -> Any:
        supplied = request.headers.get("x-request-id")
        request_id = supplied if supplied and re.fullmatch(r"[A-Za-z0-9._~-]{8,128}", supplied) else str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    def current_actor(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> Actor:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise AuthorizationError("Authorization: Bearer <token> is required")
        connection = connection_for(app_settings)
        try:
            return authenticate(connection, credentials.credentials)
        finally:
            connection.close()

    ActorDep = Annotated[Actor, Depends(current_actor)]

    @app.exception_handler(OffboardProofError)
    async def domain_error(_: Request, exc: OffboardProofError) -> JSONResponse:
        code = status.HTTP_400_BAD_REQUEST
        if isinstance(exc, AuthorizationError):
            code = status.HTTP_403_FORBIDDEN
        elif isinstance(exc, WebhookAuthenticationError):
            code = status.HTTP_401_UNAUTHORIZED
        elif isinstance(exc, PayloadTooLargeError):
            code = status.HTTP_413_CONTENT_TOO_LARGE
        elif isinstance(exc, UnsupportedMediaTypeError):
            code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        elif isinstance(exc, NotFoundError):
            code = status.HTTP_404_NOT_FOUND
        elif isinstance(exc, ConflictError):
            code = status.HTTP_409_CONFLICT
        return JSONResponse(
            status_code=code,
            content={"error": {"code": exc.__class__.__name__, "message": str(exc)}},
        )

    @app.exception_handler(sqlite3.Error)
    async def database_error(_: Request, exc: sqlite3.Error) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": {
                    "code": "DatabaseUnavailable",
                    "message": "The local database operation failed; check filesystem access and logs.",
                }
            },
        )

    @app.exception_handler(ValueError)
    async def value_error(_: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": {"code": "InvalidRequest", "message": str(exc)}},
        )

    @app.get("/health/live", tags=["health"])
    def live() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/health/ready", tags=["health"])
    def ready() -> dict[str, str]:
        connection = connection_for(app_settings)
        try:
            connection.execute("SELECT 1").fetchone()
            return {"status": "ready"}
        finally:
            connection.close()

    @app.post("/v1/cases", status_code=status.HTTP_201_CREATED, tags=["cases"])
    def create_case(
        body: CaseCreate,
        actor: ActorDep,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
    ) -> dict[str, Any]:
        return service.create_case(actor, body, idempotency_key)

    @app.post("/v1/intake/webhooks/{source_id}", tags=["intake"])
    async def intake_webhook(source_id: str, request: Request) -> JSONResponse:
        if re.fullmatch(r"[a-z][a-z0-9_-]{1,63}", source_id) is None:
            raise WebhookAuthenticationError("Webhook authentication failed")
        content_type = request.headers.get("content-type", "").lower().replace(" ", "")
        if content_type not in {"application/json", "application/json;charset=utf-8"}:
            raise UnsupportedMediaTypeError("Content-Type must be application/json")

        security_headers = {
            "offboardproof-delivery",
            "offboardproof-timestamp",
            "offboardproof-key-id",
            "offboardproof-signature",
        }
        values: dict[str, str] = {}
        for name in security_headers:
            raw_values = [
                value.decode("latin-1")
                for header, value in request.scope["headers"]
                if header.decode("latin-1").lower() == name
            ]
            if len(raw_values) != 1:
                raise WebhookAuthenticationError("Webhook authentication failed")
            values[name] = raw_values[0]

        now = datetime.now(UTC)
        timestamp_text = values["offboardproof-timestamp"]
        parse_timestamp(timestamp_text, now=now, skew_seconds=app_settings.webhook_timestamp_skew_seconds)

        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > app_settings.webhook_max_body_bytes:
                raise PayloadTooLargeError("Webhook body exceeds the configured limit")
        raw_body = bytes(body)
        credential = load_credential(
            app_settings,
            source_id=source_id,
            key_id=values["offboardproof-key-id"],
            now=now,
        )
        delivery_id = values["offboardproof-delivery"]
        verify_signature(
            secret=credential.secret,
            timestamp_text=timestamp_text,
            delivery_id=delivery_id,
            raw_body=raw_body,
            signature_header=values["offboardproof-signature"],
        )
        payload_sha256 = hashlib.sha256(raw_body).hexdigest()
        try:
            event = WebhookEvent.model_validate_json(raw_body)
            event.validate_clock(now)
        except (ValidationError, ValueError) as exc:
            webhook_service.record_rejection(
                source_id=source_id,
                actor_id=credential.actor_id,
                delivery_id=delivery_id,
                payload_sha256=payload_sha256,
                reason_code="invalid_event_schema",
            )
            raise WebhookValidationError("Authenticated webhook event failed schema validation") from exc

        result = webhook_service.accept(
            source_id=source_id,
            actor_id=credential.actor_id,
            delivery_id=delivery_id,
            event=event,
            payload_sha256=payload_sha256,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK if result.replayed else status.HTTP_202_ACCEPTED,
            content=result.as_dict(),
        )

    @app.get("/v1/cases", tags=["cases"])
    def list_cases(actor: ActorDep, limit: int = 100) -> list[dict[str, Any]]:
        require_role(actor, Role.HR, Role.MANAGER, Role.OPERATOR, Role.SECURITY, Role.AUDITOR)
        return service.list_cases(limit)

    @app.get("/v1/cases/{case_id}", tags=["cases"])
    def get_case(case_id: str, actor: ActorDep) -> dict[str, Any]:
        require_role(actor, Role.HR, Role.MANAGER, Role.OPERATOR, Role.SECURITY, Role.AUDITOR)
        return service.case_view(case_id)

    @app.post("/v1/cases/{case_id}/plan", tags=["workflow"])
    def plan_case(case_id: str, actor: ActorDep) -> dict[str, Any]:
        return service.plan_case(actor, case_id)

    @app.post("/v1/cases/{case_id}/approve", tags=["workflow"])
    def approve_case(case_id: str, body: ApprovalCreate, actor: ActorDep) -> dict[str, Any]:
        return service.approve_case(
            actor,
            case_id,
            decision=body.decision,
            reason=body.reason,
            as_role=body.as_role,
        )

    @app.post("/v1/cases/{case_id}/controls/{control_id}/complete", tags=["workflow"])
    def complete_manual(case_id: str, control_id: str, body: ManualComplete, actor: ActorDep) -> dict[str, Any]:
        return service.complete_manual(actor, case_id, control_id, body.evidence_note)

    @app.post("/v1/cases/{case_id}/controls/{control_id}/waive", tags=["workflow"])
    def waive_control(case_id: str, control_id: str, body: WaiverCreate, actor: ActorDep) -> dict[str, Any]:
        return service.waive_control(actor, case_id, control_id, reason=body.reason, expires_at=body.expires_at)

    @app.post("/v1/exceptions/{exception_id}/requeue", tags=["workflow"])
    def requeue(exception_id: str, body: RequeueCreate, actor: ActorDep) -> dict[str, Any]:
        return service.requeue_exception(actor, exception_id, body.resolution_note)

    @app.post("/v1/cases/{case_id}/verify", tags=["workflow"])
    def verify(case_id: str, actor: ActorDep) -> dict[str, Any]:
        require_role(actor, Role.OPERATOR, Role.SECURITY)
        return worker.verify_case(case_id)

    @app.get("/v1/cases/{case_id}/audit", tags=["evidence"])
    def audit(case_id: str, actor: ActorDep) -> list[dict[str, Any]]:
        require_role(actor, Role.OPERATOR, Role.SECURITY, Role.AUDITOR)
        return service.audit_events(case_id)

    @app.get("/v1/cases/{case_id}/evidence", tags=["evidence"])
    def evidence(case_id: str, actor: ActorDep) -> dict[str, Any]:
        require_role(actor, Role.OPERATOR, Role.SECURITY, Role.AUDITOR)
        connection = connection_for(app_settings)
        try:
            return build_evidence(connection, case_id)
        finally:
            connection.close()

    @app.get("/v1/metrics/summary", tags=["operations"])
    def metrics(actor: ActorDep) -> dict[str, int | float]:
        require_role(actor, Role.OPERATOR, Role.SECURITY, Role.AUDITOR)
        return service.metrics()

    @app.post("/v1/cases/{case_id}/legal-holds", status_code=status.HTTP_201_CREATED, tags=["retention"])
    def create_legal_hold(case_id: str, body: LegalHoldCreate, actor: ActorDep) -> dict[str, Any]:
        return retention_service.create_hold(actor, case_id, body.reason)

    @app.post("/v1/cases/{case_id}/legal-holds/release", tags=["retention"])
    def release_legal_hold(case_id: str, body: LegalHoldRelease, actor: ActorDep) -> dict[str, Any]:
        return retention_service.release_hold(actor, case_id, body.reason)

    @app.get("/v1/retention/report", tags=["retention"])
    def retention_report(actor: ActorDep, as_of: datetime | None = None) -> dict[str, Any]:
        return retention_service.report(actor, as_of or datetime.now(UTC))

    return app


app = create_app()
