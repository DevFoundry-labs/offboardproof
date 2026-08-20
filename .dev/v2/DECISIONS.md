# V2 Working Decisions

These decisions began as planning assumptions on 2026-08-17 and are updated as implementation and discovery progress.

## V2-005: Engineering may proceed at risk without treating M0 as passed

Decision: The product owner explicitly directed full V2 continuation on 2026-08-20. Engineering may implement and verify the generic committed slices before discovery completes, but the project must not fabricate interviews, claim pilot validation, expand conditional provider scope, or publish ROI/compliance claims.

Status: accepted for engineering; M0 remains an open pilot and release-evidence gate.

## V2-001: Treat V2 as v0.2.0

Decision: evolve v0.1.0 without a rewrite or stability reset.

Reason: the current workflow invariants, API, SQLite model, and provider boundary are useful foundations. No evidence justifies a 2.0 reset.

## V2-002: Anchor intake on a generic HMAC protocol

Decision: specify one vendor-neutral signed event and build vendor adapters outside or in front of the core endpoint.

Reason: it validates the trust/replay boundary once and avoids committing to an HRIS before pilot demand is known.

## V2-003: Operator owns signing keys

Decision: V2 loads an operator-controlled private key from outside the repository/database and exports portable public verification material.

Reason: a local-first product should not introduce a hosted signing dependency. A signing-provider interface may later support HSM/KMS systems.

## V2-004: Entra is conditional

Decision: commit Entra only when the discovery gate shows at least two credible pilots need it or one committed pilot is blocked without it.

Reason: provider breadth is expensive and can distract from validating the evidence workflow.

## V2-005: No physical purge

Decision: implement retention truth, legal holds, and dry-run visibility, but no automated deletion.

Reason: SQLite pages, WAL, backups, snapshots, and storage media make secure-erasure claims unsafe without a separate architecture and recovery policy.

## V2-006: Trusted origin requires an external trust anchor

Decision: offline verification requires a supplied trusted public key or pinned fingerprint by default.

Reason: accepting only a public key shipped beside a signature proves integrity against accidental change but does not establish who signed it.

## V2-007: Planning changes remain local

Decision: do not open milestones/issues, commit, push, or modify the release until the user approves the planning package.

Reason: issue topology and public commitments should follow scope review, not precede it.
