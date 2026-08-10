import sqlite3
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

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
)
from offboardproof.evidence import build_evidence
from offboardproof.schemas import (
    ApprovalCreate,
    CaseCreate,
    ManualComplete,
    RequeueCreate,
    WaiverCreate,
)
from offboardproof.service import WorkflowService
from offboardproof.worker import Worker

bearer = HTTPBearer(auto_error=False)


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or Settings()
    migrate(app_settings)
    service = WorkflowService(app_settings)
    worker = Worker(app_settings)

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
    def metrics(actor: ActorDep) -> dict[str, int]:
        require_role(actor, Role.OPERATOR, Role.SECURITY, Role.AUDITOR)
        return service.metrics()

    return app


app = create_app()
