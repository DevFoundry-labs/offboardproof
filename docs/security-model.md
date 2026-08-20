# Security model

## Assets and trust boundaries

Protected assets include employee identifiers, workflow timing, group membership, approvals, provider credentials, actor tokens, audit records, and evidence. The API caller, local host/filesystem, worker process, SQLite database, and external identity provider are separate trust boundaries.

## Controls

- Actor tokens are 256-bit random values shown once; only SHA-256 digests are stored.
- Role checks protect creation, planning, approval, execution support, waivers, audit reads, and evidence reads.
- Plan-bound approvals prevent authorization from carrying over to changed work.
- External writes need an explicit safety flag in addition to provider configuration.
- Provider requests have timeouts and bounded retry classification.
- SQL values are parameterized. API request bodies reject unknown fields.
- Audit events are chained with SHA-256 over canonical JSON and can be verified offline.
- Evidence v2 is signed with an operator-controlled Ed25519 key and verified against an independently supplied public-key trust anchor.
- Webhooks are authenticated over exact raw bytes with HMAC-SHA256, bounded skew, generic authentication failures, and replay-safe identifiers.
- Retention/legal-hold operations are role-gated; reporting is non-destructive and physical purge is not implemented.
- Backup inventories are digested, evidence is reverified, restores are limited to new scratch locations, and private keys/webhook secrets are excluded.
- CI performs linting, strict type checks, tests, dependency audit, secret detection, packaging, and CodeQL analysis.

## Residual risks

- SHA-256 chaining detects later alteration but is not an external timestamp. Ed25519 evidence signatures add portable integrity and origin only when the verifier obtained the trusted public key through an authenticated channel.
- SQLite encryption at rest is delegated to the host volume. Use full-disk encryption and restrictive ACLs.
- Bearer tokens are not an enterprise identity protocol. Put the service behind an SSO-aware proxy for shared deployments.
- Acknowledged provider actions are weaker evidence than observed final state.
- Evidence includes personal and access data. Apply retention, legal hold, export, and deletion rules appropriate to your jurisdiction.
- Domain-wide delegation is powerful. Use a dedicated service account, least-privilege scopes, admin approval, credential rotation, and audit monitoring.

This release is a workflow-control foundation, not a compliance certification. Design-partner validation remains required before pilot or ROI claims.
