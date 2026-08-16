# V2 Design-Partner Discovery Guide

Status: READY FOR INTERVIEWS

Execution files:

- `RECRUITMENT_SCRIPT.md` provides the invitation, eligibility screen, and consent opening.
- `DISCOVERY_TRACKER.md` tracks recruitment, coverage, and the M0 gate without names or contact details.
- `INTERVIEW_RECORD_TEMPLATE.md` is copied once per completed interview and stores only sanitized findings.
- `SCOPE_DECISION_TEMPLATE.md` is completed after the discovery set; it is the decision artifact for V2-01.

Do not count an interview toward the gate until its sanitized record is complete. Keep scheduling details and participant contact information outside this repository.

## Goal

Determine whether organizations will use and trust a verification-first offboarding workflow, which trigger/provider must anchor the pilot, and which evidence/retention requirements are real rather than assumed.

This is problem and workflow discovery, not a product pitch. Do not ask participants to share employee names, live credentials, confidential screenshots, or tenant configuration.

## Participant mix

Target 5–8 conversations across at least 3 organizations:

- 2–3 IT operators or MSP technicians who execute departures.
- 1–2 HR or line-manager approvers.
- 1–2 security, compliance, or audit evidence consumers.
- At least one organization with Google Workspace; record Entra demand without forcing it.

## Interview questions

1. Walk through the last completed departure from the first authorized signal to the point you considered it done.
2. Which system originated the request, and how did you know it was authorized?
3. Which steps were automated, manual, checked later, or assumed successful?
4. What access or ownership transfer is most often forgotten?
5. What exceptions create the most delay or risk?
6. Who can approve timing, ownership transfer, high-risk handling, and exceptions?
7. What proves that suspension, session invalidation, and group removal actually happened?
8. When an API times out, how do you decide whether to retry?
9. What evidence has an auditor, insurer, customer, or incident reviewer requested?
10. How is that evidence retained, held, exported, or deleted today?
11. Which identities/providers are mandatory for a pilot: Google Workspace, Entra ID, another IdP, or manual systems?
12. Could the trigger system send a signed webhook? If not, what export or middleware is realistic?
13. Who would own webhook secrets and evidence-signing keys?
14. What data is unacceptable in logs, metrics, evidence, or support channels?
15. What result after 5–10 cases would make you continue using this?

## Baseline worksheet

Capture ranges when exact measurements are unavailable:

| Field | Value |
|---|---|
| Organization alias | |
| Participant role | |
| Approximate employee count | |
| Departures/role changes per month | |
| Trigger source | |
| Primary identity provider | |
| Number of systems/controls touched | |
| Human handoffs | |
| Operator active minutes | |
| End-to-end elapsed time | |
| Time to primary containment | |
| Rework/duplicate actions | |
| Exceptions and typical age | |
| Approval roles | |
| Evidence requested/produced | |
| Retention/legal-hold requirement | |
| Pilot blocker | |
| Success threshold | |

## Pilot acceptance

A partner is pilot-ready when:

- A named operator and evidence consumer will evaluate results.
- The trigger source and provider path are known.
- Synthetic rehearsal is allowed before real identities.
- Approval roles and success states are documented.
- Credential/key ownership and data handling are agreed.
- The partner accepts the product's observed/acknowledged distinction.
- Baseline and outcome metrics can be captured without sending PII externally.

## Scope decision rubric

Score each candidate capability 0–3 for frequency, pain/risk, pilot necessity, observable postcondition, setup feasibility, and reuse across partners.

- 14–18: commit to V2.
- 9–13: conditional spike or follow-up release.
- 0–8: defer.

Security invariants and release gates are mandatory regardless of score.

## Interview synthesis

After each interview, record:

- confirmed facts versus participant estimates
- repeated workflow pattern
- evidence gap
- requested capability
- observable success condition
- integration/setup constraint
- disconfirming evidence
- scope score

After the discovery set, publish a short decision record: keep/revise/stop thesis, committed pilot path, conditional items, explicit deferrals, baseline ranges, and measurable release success criteria.
