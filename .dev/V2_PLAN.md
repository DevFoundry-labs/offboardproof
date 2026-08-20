# OffboardProof V2 Plan

Status: ENGINEERING IMPLEMENTED AT RISK — DESIGN-PARTNER GATE STILL OPEN

Created: 2026-08-17

Assumption: "V2" means the next meaningful release after v0.1.0, provisionally v0.2.0—not a multi-year 2.0 rewrite.

## 1. Product thesis

V2 should make OffboardProof credible for a real single-organization pilot. It should not chase a broad connector catalog, multi-tenancy, or a dashboard before the core workflow is used with real offboarding cases.

The release thesis is:

> Accept an authenticated departure from an external system, produce cryptographically verifiable evidence with an explicit lifecycle, and measure whether operators complete offboarding faster without weakening approval or verification guarantees.

## 2. Target user outcome

An IT/security operator can connect an HR or ITSM system to OffboardProof, process a real departure through the existing approval and verification workflow, give an auditor a portable evidence bundle plus public verification material, and report completion/exception metrics without sending employee data to a hosted analytics service.

## 3. North-star and guardrail metrics

### North-star

- Percentage of pilot cases whose required controls reach verified, acknowledged, or validly waived state by the policy deadline and whose evidence verifies offline.

### Supporting metrics

- Median operator active minutes per case.
- Median time from authorized trigger to containment.
- Percentage of controls independently observed versus acknowledged, human-attested, or waived.
- Exceptions per case, retry recovery rate, and median exception age.
- Duplicate triggers suppressed and duplicate external writes prevented.
- Evidence verification success rate after export and transfer.

### Guardrails

- Zero execution without current digest-bound approvals.
- Zero webhook replay resulting in a second case or action.
- Zero evidence bundles labeled independently verified when only acknowledged.
- Zero private signing keys, webhook secrets, or bearer tokens stored in evidence or logs.
- No automatic deletion in V2; retention expiry is reported and gated for explicit follow-up.

The current 14-touch baseline and 60% active-time reduction target remain hypotheses until measured with design partners.

## 4. Proposed committed scope

### Epic A — Design-partner validation and measurement

Deliverables:

- Interview guide and workflow inventory for 5–8 operators, approvers, or auditors across at least 3 organizations.
- Sanitized baseline worksheet covering trigger source, manual touches, elapsed time, active time, exceptions, proof requested, and systems involved.
- Pilot runbook using synthetic identities first and real identities only under the partner's data-handling policy.
- Local-only metric export for the north-star and supporting metrics.
- Decision record confirming or revising the V2 scope after discovery.

Exit criteria:

- At least 3 participants confirm the verification/evidence problem is recurring and material.
- At least 2 organizations can name a viable signed trigger source and will evaluate the evidence bundle.
- At least 1 pilot can run Google Workspace or the mock provider end to end.

If these criteria are not met, stop connector expansion and revisit the target user/problem.

### Epic B — Authenticated webhook intake

Capabilities:

- `POST /v1/intake/webhooks/{source}` accepts a versioned canonical event contract.
- Verify an HMAC-SHA256 signature over the raw body plus timestamp before parsing.
- Enforce timestamp skew, body-size limit, content type, source/key identifier, and a unique delivery identifier.
- Store only a secret digest/identifier or load secrets from environment/file-backed configuration; never persist plaintext webhook secrets.
- Support active and previous keys during a bounded rotation window.
- Map a valid event into the existing `CaseCreate` path so case and action idempotency invariants remain unchanged.
- Return the same case on a repeated valid delivery; reject stale, malformed, or signature-invalid deliveries without creating state.
- Add structured, non-sensitive audit events for accepted, replayed, and rejected deliveries.

Acceptance tests:

- Valid signature creates one case.
- Same delivery and same semantic case replay safely.
- Same delivery ID with a different body is rejected as a conflict.
- Invalid signature, stale timestamp, oversized body, wrong content type, and unknown key ID create no case.
- Rotation accepts the previous key only within its configured window.
- Logs and API errors do not disclose the secret, signature, or sensitive body.

### Epic C — Evidence schema v2 and signatures

Capabilities:

- Version the evidence envelope independently from the application release.
- Keep deterministic canonical JSON as the signed payload.
- Generate an Ed25519 signature over the final evidence digest.
- Include algorithm, key ID, public-key fingerprint, evidence digest, completion cutoff, and schema version in a detached manifest.
- Add `offboardproof evidence-verify` and a read-only API verification endpoint.
- Export the public key in a portable format; load the private key from an operator-controlled path or signing-provider adapter.
- Fail closed when the configured signing key is unreadable or has unsafe permissions where the operating system exposes that check.
- Preserve an explicit unsigned mode for local evaluation, labeled `unsigned` rather than silently appearing sealed.
- Define signing-key rotation without invalidating historical bundles.

Acceptance tests:

- A transferred evidence bundle verifies without database access.
- Any changed evidence byte, manifest field, signature, or public key fails verification.
- Historical evidence verifies after signing-key rotation.
- Re-export at the same completion cutoff produces the same canonical evidence digest.
- The private key never appears in SQLite, logs, API responses, evidence, fixtures, or source control.

Reference: https://cryptography.io/en/stable/hazmat/primitives/asymmetric/serialization/

### Epic D — Evidence lifecycle without unsafe deletion

Capabilities:

- Add organization-level default retention days and case-level `retention_until`.
- Add security-authorized legal hold with reason, actor, timestamp, and release event.
- Expose expiring/expired evidence in API, CLI, metrics, and audit events.
- Add a deterministic retention dry-run report listing records and files that would be affected.
- Document backup, restore, legal hold, and filesystem/database coordination.

Explicit V2 limit:

- V2 does not physically purge evidence or promise secure erasure from SQLite, WAL files, backups, or storage media. A later release may add a separately approved purge workflow after recovery and legal requirements are validated.

Acceptance tests:

- Retention date is deterministic and visible in the signed evidence metadata.
- Legal hold prevents an item from appearing as purge-eligible.
- Only security/admin roles can create or release a hold.
- Retention configuration changes are audit logged and do not rewrite historical completion evidence.

### Epic E — Pilot hardening

Capabilities:

- Correlation/request IDs propagated through API, worker, provider, and audit events.
- Backup/restore commands and a tested restore drill for database plus evidence files.
- Documented upgrade from schema v1 to v2 with rollback boundaries.
- Operational endpoints for queue depth, oldest queued job, open/overdue exceptions, and evidence awaiting signature.
- Load and fault tests for 100 concurrent intake deliveries, 10,000 audit events, lease expiry, crash-before-receipt, crash-after-receipt, and database restart.
- Redaction tests for every structured log/error field.

## 5. Conditional scope

### Microsoft Entra ID adapter

Implement only if at least two credible pilot organizations require Entra ID or one committed pilot cannot proceed without it.

A bounded adapter appears technically feasible using Microsoft Graph v1.0 for direct membership discovery, group-member removal, session revocation, and user updates. The implementation must preserve the existing observed-versus-acknowledged distinction and must append `/$ref` when removing a group member; omitting it can delete the directory object when broader permissions are present.

Required discovery before commitment:

- Exact least-privilege application permissions and admin roles.
- Behavior for dynamic, role-assignable, nested, and hidden-membership groups.
- Observable postcondition and propagation delay for `accountEnabled=false` and `revokeSignInSessions`.
- National-cloud base URLs and tenant configuration boundaries.
- Contract fixtures for throttling, eventual consistency, partial permissions, and external users.

References:

- https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/api/group-delete-members?view=graph-rest-1.0

### Google audit correlation spike

Time-box a spike to determine whether Reports API events can add useful corroboration after session sign-out. Do not promote a sign-out control from `acknowledged` to `verified` unless an event can be causally and reliably tied to the administrative action. Google's login report includes `logout`, but that alone does not prove that the Admin SDK `users.signOut` operation invalidated every session.

References:

- https://developers.google.com/workspace/admin/reports/v1/guides/manage-audit-login
- https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login

## 6. Explicit non-goals

- Browser dashboard.
- Multi-tenant SaaS, organization isolation, billing, or hosted control plane.
- PostgreSQL/multi-worker migration.
- OIDC/SSO replacing local actor tokens.
- Automatic evidence deletion or claimed secure erasure.
- Account deletion, device wipe, mailbox/Drive transfer, or joiner/mover workflows.
- Broad HRIS/ITSM connector catalog.
- AI-generated policy or remediation decisions.
- Claimed compliance certification.

These remain candidates for later releases. They should not displace pilot learning or core assurance work.

## 7. Delivery sequence

### Phase 0 — Validate (decision gate)

1. Conduct interviews and capture baselines.
2. Select pilot trigger source and evidence consumer.
3. Confirm data handling, retention, and signing-key ownership.
4. Decide whether Entra is committed, conditional, or deferred.

### Phase 1 — Freeze contracts

1. Write webhook event schema and threat model.
2. Write evidence schema v2 and signature manifest specification.
3. Write retention/hold state model and migration plan.
4. Add acceptance tests before production code.

### Phase 2 — Build vertical slices

1. Signed webhook to idempotent case creation.
2. Completed case to signed portable evidence and offline verification.
3. Retention metadata to dry-run/hold operations.
4. Metrics and operator visibility across the complete path.

### Phase 3 — Pilot hardening

1. Fault, replay, migration, backup/restore, and redaction tests.
2. Synthetic tenant rehearsal with external writes disabled, then enabled under a reviewed plan.
3. Pilot run, measurement, and issue review.
4. Resolve release blockers and publish v0.2.0.

## 8. Release gates

- All v0.1.0 safety and quality gates remain mandatory.
- At least 90% branch-aware coverage for new security-critical modules.
- Independent signature verification from the built wheel in a clean environment.
- Webhook replay/fuzz/property tests and timing-safe signature comparison.
- Migration test from a real v0.1.0 fixture plus clean install.
- Backup/restore drill reproduces audit-chain and evidence verification.
- Threat-model review has no unresolved critical/high finding.
- No externally mutable action is enabled by default.
- Pilot report distinguishes synthetic measurements from observed partner results.

## 9. Proposed issue breakdown

1. V2 discovery: interview guide, baseline worksheet, and scope decision record.
2. Specify canonical webhook event and signature protocol.
3. Implement webhook source/key configuration and rotation.
4. Implement replay-safe webhook endpoint and rejection audit.
5. Specify evidence schema v2 and detached manifest.
6. Implement Ed25519 signing and public-key export.
7. Implement offline evidence verification CLI/API.
8. Add retention metadata and migration.
9. Add legal hold and retention dry-run.
10. Add queue/evidence/exception operational metrics.
11. Add backup/restore command and drill.
12. Run Google audit-correlation spike.
13. Decide and, if gated in, specify Entra provider contract.
14. Execute synthetic rehearsal and design-partner pilot.
15. Publish v0.2.0 with measured results and explicit assurance limits.

No GitHub issues should be opened until the product thesis, pilot source, and committed/conditional scope are approved.

## 10. Working assumptions accepted for continued planning

1. The next release is provisionally v0.2.0 rather than a 2.0 reset.
2. Generic HMAC webhook intake anchors the trigger contract.
3. The deployment operator owns and rotates evidence-signing keys.
4. Entra remains conditional on the pilot-demand gate.

These are recorded in `.dev/v2/DECISIONS.md` and remain reversible before implementation.

## 11. Remaining decisions

1. Is a Google Workspace pilot available, and is Entra required by a committed pilot?
2. What retention and legal-hold obligations apply to the first pilot's evidence?
3. What minimum pilot evidence would justify work on a UI, SSO, PostgreSQL, or additional connectors?
