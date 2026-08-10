# Demonstration

Run `offboardproof demo`. The scenario uses only synthetic `.test` identities and a deterministic local provider.

The workflow models a 14-touch manual baseline: intake, identity lookup, access inventory, plan review, two approvals, account suspension, session invalidation, two group removals, transfer confirmation, exception follow-up, evidence assembly, and audit review. This count is a hypothesis for design-partner validation—not measured customer ROI.

The command proves executable properties instead: duplicate intake returns the same case, approvals bind to the plan digest, one injected transient failure is recovered, final provider state is observed, manual evidence is required, the case reaches `completed`, and the audit chain validates. It writes `demo-result.json`, a SQLite database, and a SHA-256-addressed evidence bundle.
