from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import typer
import uvicorn

from offboardproof.api import create_app
from offboardproof.audit import append_event, verify_chain
from offboardproof.auth import Actor, authenticate, create_actor
from offboardproof.config import Settings
from offboardproof.db import connection_for, migrate, transaction
from offboardproof.enums import ApprovalDecision, RiskTier, Role
from offboardproof.evidence import build_evidence, write_evidence
from offboardproof.logging_config import configure_logging
from offboardproof.providers.mock import MockProvider
from offboardproof.schemas import CaseCreate
from offboardproof.service import WorkflowService
from offboardproof.worker import Worker

app = typer.Typer(
    name="offboardproof",
    help="Verification-first employee offboarding with approvals and audit evidence.",
    no_args_is_help=True,
)


def _settings(database: Path | None = None) -> Settings:
    settings = Settings()
    if database is not None:
        settings.database_path = database
        settings.evidence_dir = database.parent / "evidence"
    return settings


def _actor(settings: Settings) -> Actor:
    token = os.getenv("OFFBOARDPROOF_TOKEN", "")
    if not token:
        raise typer.BadParameter("Set OFFBOARDPROOF_TOKEN to a token created with 'offboardproof token-create'.")
    connection = connection_for(settings)
    try:
        return authenticate(connection, token)
    finally:
        connection.close()


def _print(value: Any) -> None:
    typer.echo(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


@app.command("init")
def initialize(
    database: Annotated[Path | None, typer.Option(help="SQLite database path.")] = None,
) -> None:
    settings = _settings(database)
    version = migrate(settings)
    _print({"database": str(settings.database_path), "schema_version": version})


@app.command("token-create")
def token_create(
    name: Annotated[str, typer.Option(help="Human-readable actor name.")],
    role: Annotated[Role, typer.Option(help="Authorized role.")],
    database: Annotated[Path | None, typer.Option(help="SQLite database path.")] = None,
) -> None:
    settings = _settings(database)
    migrate(settings)
    connection = connection_for(settings)
    try:
        with transaction(connection):
            actor, token = create_actor(connection, name, role)
            append_event(
                connection,
                actor_id=actor.id,
                event_type="actor.created",
                payload={"actor_id": actor.id, "name": actor.name, "role": actor.role.value},
            )
        _print(
            {
                "actor": {"id": actor.id, "name": actor.name, "role": actor.role.value},
                "token": token,
                "warning": "Store this token securely; it will not be shown again.",
            }
        )
    finally:
        connection.close()


@app.command("mock-seed")
def mock_seed(
    email: Annotated[str, typer.Option(help="Synthetic account email.")],
    group: Annotated[list[str] | None, typer.Option(help="Group email; repeatable.")] = None,
    fail_once: Annotated[str | None, typer.Option(help="Operation to fail once.")] = None,
    database: Annotated[Path | None, typer.Option(help="SQLite database path.")] = None,
) -> None:
    settings = _settings(database)
    migrate(settings)
    connection = connection_for(settings)
    try:
        MockProvider(connection).seed_account(
            email.strip().lower(), groups=tuple(group or []), fail_once_operation=fail_once
        )
        _print({"seeded": email.strip().lower(), "groups": group or [], "fail_once": fail_once})
    finally:
        connection.close()


@app.command("case-create")
def case_create(
    email: Annotated[str, typer.Option()],
    name: Annotated[str, typer.Option()],
    transfer_owner: Annotated[str, typer.Option()],
    idempotency_key: Annotated[str, typer.Option()],
    provider: Annotated[str, typer.Option()] = "mock",
    risk: Annotated[RiskTier, typer.Option()] = RiskTier.STANDARD,
    effective_at: Annotated[str | None, typer.Option(help="ISO-8601 timestamp; defaults to now.")] = None,
    database: Annotated[Path | None, typer.Option()] = None,
) -> None:
    settings = _settings(database)
    migrate(settings)
    actor = _actor(settings)
    effective = datetime.fromisoformat(effective_at.replace("Z", "+00:00")) if effective_at else datetime.now(UTC)
    request = CaseCreate(
        subject_email=email,
        subject_name=name,
        transfer_owner=transfer_owner,
        effective_at=effective,
        risk_tier=risk,
        provider=provider,
    )
    _print(WorkflowService(settings).create_case(actor, request, idempotency_key))


@app.command("case-plan")
def case_plan(
    case_id: Annotated[str, typer.Argument()],
    database: Annotated[Path | None, typer.Option()] = None,
) -> None:
    settings = _settings(database)
    _print(WorkflowService(settings).plan_case(_actor(settings), case_id))


@app.command("case-approve")
def case_approve(
    case_id: Annotated[str, typer.Argument()],
    reason: Annotated[str, typer.Option()],
    decision: Annotated[ApprovalDecision, typer.Option()] = ApprovalDecision.APPROVED,
    as_role: Annotated[str | None, typer.Option(help="Admin-only role override.")] = None,
    database: Annotated[Path | None, typer.Option()] = None,
) -> None:
    settings = _settings(database)
    _print(
        WorkflowService(settings).approve_case(
            _actor(settings), case_id, decision=decision, reason=reason, as_role=as_role
        )
    )


@app.command("manual-complete")
def manual_complete(
    case_id: Annotated[str, typer.Argument()],
    control_id: Annotated[str, typer.Argument()],
    evidence_note: Annotated[str, typer.Option()],
    database: Annotated[Path | None, typer.Option()] = None,
) -> None:
    settings = _settings(database)
    _print(WorkflowService(settings).complete_manual(_actor(settings), case_id, control_id, evidence_note))


@app.command("case-show")
def case_show(
    case_id: Annotated[str, typer.Argument()],
    database: Annotated[Path | None, typer.Option()] = None,
) -> None:
    _print(WorkflowService(_settings(database)).case_view(case_id))


@app.command("case-verify")
def case_verify(
    case_id: Annotated[str, typer.Argument()],
    database: Annotated[Path | None, typer.Option()] = None,
) -> None:
    _print(Worker(_settings(database)).verify_case(case_id))


@app.command("worker")
def worker_command(
    once: Annotated[bool, typer.Option(help="Process at most one job.")] = False,
    max_jobs: Annotated[int, typer.Option(min=1, max=10000)] = 100,
    poll_seconds: Annotated[float, typer.Option(min=0.1, max=60)] = 1.0,
    database: Annotated[Path | None, typer.Option()] = None,
) -> None:
    settings = _settings(database)
    migrate(settings)
    worker = Worker(settings)
    processed = 0
    while processed < max_jobs:
        did_work = worker.run_once()
        if did_work:
            processed += 1
            if once:
                break
        elif once:
            break
        else:
            time.sleep(poll_seconds)
    _print({"processed_jobs": processed})


@app.command("evidence-export")
def evidence_export(
    case_id: Annotated[str, typer.Argument()],
    output: Annotated[Path | None, typer.Option(help="Optional safe destination file.")] = None,
    database: Annotated[Path | None, typer.Option()] = None,
) -> None:
    settings = _settings(database)
    connection = connection_for(settings)
    try:
        payload = build_evidence(connection, case_id)
        if output is None:
            _print(payload)
            return
        output = output.resolve()
        if output.exists() and not output.is_file():
            raise typer.BadParameter("Output must be a file path")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _print({"output": str(output), "bundle_sha256": payload["bundle_sha256"]})
    finally:
        connection.close()


@app.command("audit-verify")
def audit_verify(
    database: Annotated[Path | None, typer.Option()] = None,
) -> None:
    settings = _settings(database)
    connection = connection_for(settings)
    try:
        valid, count, broken = verify_chain(connection)
        _print({"valid": valid, "event_count": count, "broken_event": broken})
        if not valid:
            raise typer.Exit(code=2)
    finally:
        connection.close()


@app.command("serve")
def serve(
    host: Annotated[str, typer.Option()] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535)] = 8000,
    database: Annotated[Path | None, typer.Option()] = None,
) -> None:
    settings = _settings(database)
    configure_logging(settings.log_level)
    uvicorn.run(create_app(settings), host=host, port=port, log_config=None)


@app.command("demo")
def demo(
    output_dir: Annotated[Path, typer.Option(help="Directory for synthetic demo artifacts.")] = Path(
        ".offboardproof-demo"
    ),
) -> None:
    start = time.perf_counter()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    database = output_dir / "demo.db"
    if database.exists():
        database.unlink()
    settings = Settings(
        database_path=database,
        evidence_dir=output_dir / "evidence",
        retry_delays_seconds="0,0,0",
        enable_external_writes=False,
    )
    migrate(settings)
    connection = connection_for(settings)
    try:
        with transaction(connection):
            _admin, _ = create_actor(connection, "Demo Admin", Role.ADMIN)
            hr, _ = create_actor(connection, "Demo HR", Role.HR)
            manager, _ = create_actor(connection, "Demo Manager", Role.MANAGER)
            operator, _ = create_actor(connection, "Demo Operator", Role.OPERATOR)
        MockProvider(connection).seed_account(
            "alex@example.test",
            groups=("engineering@example.test", "vpn@example.test"),
            fail_once_operation="sign_out_sessions",
        )
    finally:
        connection.close()

    service = WorkflowService(settings)
    case = service.create_case(
        hr,
        CaseCreate(
            subject_email="alex@example.test",
            subject_name="Alex Morgan",
            transfer_owner="manager@example.test",
            effective_at=datetime.now(UTC) - timedelta(seconds=1),
            risk_tier=RiskTier.STANDARD,
            provider="mock",
        ),
        "demo-alex-001",
    )
    replay = service.create_case(
        hr,
        CaseCreate(
            subject_email="alex@example.test",
            subject_name="Alex Morgan",
            transfer_owner="manager@example.test",
            effective_at=datetime.now(UTC) - timedelta(seconds=1),
            risk_tier=RiskTier.STANDARD,
            provider="mock",
        ),
        "demo-alex-001",
    )
    assert replay["id"] == case["id"]
    case = service.plan_case(operator, case["id"])
    service.approve_case(
        hr,
        case["id"],
        decision=ApprovalDecision.APPROVED,
        reason="HR confirmed departure authority and effective time.",
    )
    service.approve_case(
        manager,
        case["id"],
        decision=ApprovalDecision.APPROVED,
        reason="Manager confirmed transfer ownership.",
    )
    worker = Worker(settings)
    processed_jobs = 0
    while worker.run_once():
        processed_jobs += 1
        if processed_jobs > 20:
            raise RuntimeError("Demo exceeded expected job count")
    case = service.case_view(case["id"])
    manual = next(control for control in case["controls"] if control["manual"] == 1)
    case = service.complete_manual(
        manager,
        case["id"],
        manual["id"],
        "Synthetic demo: manager confirmed data-transfer handoff in ticket DEMO-42.",
    )
    if case["state"] != "completed":
        raise RuntimeError(f"Demo did not complete; final state was {case['state']}")
    connection = connection_for(settings)
    try:
        evidence_path, evidence_digest = write_evidence(connection, settings, case["id"])
        valid, event_count, broken = verify_chain(connection)
    finally:
        connection.close()
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    result = {
        "scenario": "Synthetic Alex Morgan offboarding",
        "case_id": case["id"],
        "final_state": case["state"],
        "controls_total": len(case["controls"]),
        "controls_verified_or_acknowledged": sum(
            control["state"] in {"verified", "acknowledged", "waived"} for control in case["controls"]
        ),
        "duplicate_trigger_suppressed": replay["id"] == case["id"],
        "transient_failure_recovered": processed_jobs
        > len([control for control in case["controls"] if control["manual"] == 0]),
        "processed_job_attempts": processed_jobs,
        "audit_chain_valid": valid,
        "audit_event_count": event_count,
        "broken_audit_event": broken,
        "evidence_path": str(evidence_path),
        "evidence_file_sha256": evidence_digest,
        "elapsed_ms": elapsed_ms,
        "measurement_limit": (
            "This is a deterministic synthetic workflow measurement, not customer ROI. "
            "The 14-step manual baseline in docs/demo.md must be validated with design partners."
        ),
    }
    result_path = output_dir / "demo-result.json"
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _print(result)


if __name__ == "__main__":
    app()
