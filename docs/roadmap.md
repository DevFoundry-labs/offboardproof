# Roadmap

The roadmap is evidence-led; items are candidates, not commitments.

## Near term

- Design-partner validation of control sets and evidence exports.
- Microsoft Entra ID provider contract.

## Implemented for v0.2.0

- Signed evidence manifests with explicit external trust anchors.
- Configurable retention snapshots, legal holds, and dry-run reporting without physical deletion.
- Webhook intake with signature verification, rotation windows, replay controls, and safe rejection handling.
- Online backup, inventory verification, and scratch-only restore drills.

## Later

- PostgreSQL and safe multi-worker leasing.
- SSO/OIDC and organization isolation.
- ITSM/HRIS connectors, notifications, and approval reminders.
- Independent audit-log correlation for acknowledgement-only controls.
- Minimal operator interface built on the stable API.

The project will not add broad connector coverage at the expense of observable postconditions and explicit failure semantics.
