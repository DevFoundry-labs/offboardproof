# OffboardProof Requirements

## Product

- **Value proposition:** Coordinate employee access removal, require authorized approvals, independently verify final state, and produce an audit-ready evidence package.
- **Problem:** Small IT teams use tickets, scripts, admin consoles, chat, spreadsheets, and screenshots to offboard people. Provider success responses do not prove the final state, while unsupported systems become invisible manual work.
- **Target users:** IT operators, HR approvers, managers, security approvers, MSP operators, and read-only auditors in organizations with roughly 20–500 staff.
- **Primary trigger:** An authorized HR/operator submits a departure case with subject identity, effective time, risk tier, and transfer owner.
- **Completion event:** Every required control is independently verified or explicitly waived by an authorized security approver; a content-hashed evidence bundle is generated.
- **Manual workflow today:** Receive HR request → resolve identity → inventory access → decide transfer/retention → suspend/sign out/remove groups → chase manual app owners → take screenshots → recheck inconsistently → reconstruct proof during audit.
- **Frequency/pain:** Every departure, contractor expiry, or role change; directional hypothesis is 30–180 active minutes plus security and audit exposure.
- **Primary use case:** Suspend and sign out a Google Workspace user, remove configured group memberships, complete manual controls, verify observed state, and export evidence.
- **Approval points:** HR confirms authority/effective time; manager confirms transfer owner; security approval is required for high-risk cases and all waivers. Material plan changes invalidate approvals.
- **Common exceptions:** Ambiguous identity, missing transfer owner, insufficient provider scope, rate limit/timeout, uncertain external outcome, shared/service account dependency, failed verification, unsupported provider, and missing manual evidence.
- **Notifications:** v0.1 emits durable notification audit events and exposes pending/overdue work via API/CLI; outbound email is a later adapter.
- **Audit evidence:** Actor/service identity, case/policy/plan versions, proposed action, approval, attempt, external receipt, independent observation, exception/waiver, artifact hash, and timestamps.
- **Success metric:** In the reproducible demo, reduce operator commands/steps while proving replay safety, approval enforcement, recovery, verification, and a regenerable evidence package. Design-partner target is ≥95% controls verified/waived by deadline and ≥60% lower active time.
- **Why now:** SaaS access is distributed; action-capable automation increases the need for least-privilege authority and observed-state evidence; small teams lack affordable verification-first tooling.
- **Differentiator:** Intended → provider-acknowledged → independently observed state, plus first-class manual controls.
- **Deployment:** Local-first single-organization service using SQLite WAL, CLI, REST API, and one worker. External writes are disabled unless explicitly enabled.

## Primary Workflow Contract

```text
Trigger: Authorized POST /v1/cases or equivalent CLI command.
Inputs: Subject email/external ID, display name, effective time, transfer owner,
        risk tier, provider connection, idempotency key.
Preconditions: Actor role authorized; configured policy exists; subject identity is unambiguous.
Actors / roles: HR, manager, operator, security, auditor, service worker.
Systems involved: OffboardProof; mock/manual provider; optional Google Workspace Admin SDK.
Documents / data involved: Case request, provider observations, manual evidence files/notes,
                           approvals, action receipts, evidence JSON.
Normalization/extraction: Trim/case-normalize emails and provider identifiers; parse UTC times.
Deterministic validations: Required fields, role authorization, state transitions, policy controls,
                           action-plan digest, approval freshness, idempotency, final-state predicates.
Routing/decision rules: Low risk requires HR + manager; high risk adds security. Unsupported actions
                        become manual controls. Retryable provider failures schedule bounded retry.
AI-assisted decisions: None in v0.1.
Required approval gates: Policy-defined roles approve the current plan digest before execution.
Actions executed: Suspend primary account, sign out sessions, remove configured groups, or record
                  manual control completion. External writes require explicit server configuration.
Notifications: Durable event for approval required, exception raised, case completed.
Success state: All required controls VERIFIED or WAIVED; evidence bundle hash stored.
Failure states: REJECTED, CANCELLED, EXCEPTION; RETRY_PENDING is represented by a leased job.
Retry policy: Three bounded attempts with exponential delay; permanent/unknown outcomes reconcile
              before another external write.
Idempotency: Unique trigger key per organization; unique action key per case/control/plan version.
Exception queue: Safe summary, failed step, retryability, attempts, owner, due time, provider receipt.
Manual recovery: Operator resolves evidence or requeues after correcting configuration; verification reruns.
Audit events: Case received/planned, approval/rejection, action started/result, observation, exception,
              retry, control verified/waived, case completed, export generated.
Retention/privacy: Local SQLite database; evidence files remain local; no AI/external analytics.
Success metric: Demo report records steps, elapsed time, controls, retries, exceptions, and duplicate suppression.
```

## Functional Requirements

- **FR-001:** Accept a departure case with a unique idempotency key and return the existing case on replay.
- **FR-002:** Normalize subject identity and reject ambiguous or invalid identifiers.
- **FR-003:** Build a versioned action plan from provider capabilities and policy controls.
- **FR-004:** Require policy-defined actor roles to approve the exact action-plan digest.
- **FR-005:** Invalidate prior approvals after a material plan change.
- **FR-006:** Prevent execution before approvals and effective time.
- **FR-007:** Execute supported provider actions through a narrow adapter interface.
- **FR-008:** Default to external writes disabled and surface a corrective configuration error.
- **FR-009:** Persist jobs, attempts, leases, action receipts, and retry classification.
- **FR-010:** Reconcile uncertain outcomes before repeating an external write.
- **FR-011:** Convert permanent/expired failures into an inspectable exception.
- **FR-012:** Allow authorized reprocessing of a retryable/resolved exception.
- **FR-013:** Model unsupported provider actions as manual controls requiring evidence.
- **FR-014:** Independently observe provider state and evaluate deterministic verification predicates.
- **FR-015:** Close a case only when every required control is verified or validly waived.
- **FR-016:** Allow only security actors to waive controls with reason and expiry.
- **FR-017:** Record append-only, previous-hash-linked audit events for every material transition.
- **FR-018:** Export a deterministic JSON evidence bundle with a SHA-256 digest.
- **FR-019:** Expose case, approval, exception, verification, audit, and health endpoints.
- **FR-020:** Provide CLI commands for database initialization, token creation, server/worker, demo, and evidence export.
- **FR-021:** Provide mock/manual adapters and a real Google Workspace adapter for user suspension, session sign-out, group removal, and verification.
- **FR-022:** Expose measurable demo statistics without presenting them as real customer ROI.

## Non-Functional Requirements

- **NFR-001 Security:** All protected endpoints require high-entropy bearer tokens stored only as SHA-256 digests; role checks are deny-by-default.
- **NFR-002 Safety:** External writes are opt-in and require current approvals; destructive account deletion is unsupported.
- **NFR-003 Reliability:** Durable SQLite state survives restart; leases expire; bounded retries distinguish retryable, permanent, and uncertain outcomes.
- **NFR-004 Privacy:** No telemetry or AI calls; logs redact tokens and avoid full sensitive payloads.
- **NFR-005 Performance:** Local API p95 under 250 ms for non-provider requests on the documented demo hardware; 1,000 audit events export under two seconds.
- **NFR-006 Portability:** Python 3.12+ on Windows and Linux; paths use `pathlib`; SQLite foreign keys and WAL are enabled.
- **NFR-007 Observability:** Structured JSON logs include request/correlation and case/job identifiers; health and operational summary endpoints exist.
- **NFR-008 Maintainability:** Typed schemas, cohesive modules, migration versioning, provider contract tests, and no circular provider/domain dependency.
- **NFR-009 Accessibility:** CLI output is plain text/JSON and does not rely on color; OpenAPI is available for assistive clients.
- **NFR-010 Quality:** Ruff, mypy, pytest, build, migration, secret, and dependency checks pass before release.

## Acceptance Criteria

The end-to-end test must prove: accepted trigger, normalized input, deterministic plan, enforced HR/manager approval, authorized provider action, independent verification, duplicate-trigger suppression, retry after transient failure, permanent failure to exception, exception reprocessing/manual completion, complete audit history, deterministic evidence export, and measured demo output. No endpoint or worker path may bypass the required plan digest approvals.

## Non-goals for v0.1

- Provisioning/joiner workflows, autonomous account deletion, device wipe, mailbox/file transfer, broad HRIS/IdP support, multi-tenant SaaS, browser UI, AI recommendations, or claimed regulatory certification.
