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
- Evidence records the exact control quality and explicit assurance limitations.
- CI performs linting, strict type checks, tests, dependency audit, secret detection, packaging, and CodeQL analysis.

## Residual risks

- SHA-256 chaining detects later alteration but is not an external timestamp or digital signature. A privileged database operator could rewrite the entire chain.
- SQLite encryption at rest is delegated to the host volume. Use full-disk encryption and restrictive ACLs.
- Bearer tokens are not an enterprise identity protocol. Put the service behind an SSO-aware proxy for shared deployments.
- Acknowledged provider actions are weaker evidence than observed final state.
- Evidence includes personal and access data. Apply retention, legal hold, export, and deletion rules appropriate to your jurisdiction.
- Domain-wide delegation is powerful. Use a dedicated service account, least-privilege scopes, admin approval, credential rotation, and audit monitoring.

This release is a workflow-control foundation, not a compliance certification.
