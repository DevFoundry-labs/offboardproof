# Google Workspace provider

The Google adapter is intentionally bounded to Directory API operations needed by the first control set:

- update the user `suspended` property;
- invoke `users.signOut`;
- list group memberships and remove a member.

Configure a dedicated service account with domain-wide delegation and the narrow scopes documented by Google. Set `OFFBOARDPROOF_GOOGLE_SERVICE_ACCOUNT_FILE`, `OFFBOARDPROOF_GOOGLE_DELEGATED_ADMIN`, and only after a dry-run review set `OFFBOARDPROOF_ENABLE_EXTERNAL_WRITES=true`.

Primary references:

- [Directory users resource](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users)
- [Sign a user out](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/signOut)
- [Manage groups](https://developers.google.com/workspace/admin/directory/v1/guides/manage-groups)
- [Manage group members](https://developers.google.com/workspace/admin/directory/v1/guides/manage-group-members)
- [Domain-wide delegation](https://developers.google.com/identity/protocols/oauth2/service-account)
- [OAuth scope catalog](https://developers.google.com/identity/protocols/oauth2/scopes)

## Assurance limit

Suspension and group membership can be queried after mutation. The sign-out endpoint accepts a request but Google does not expose a matching per-user final-state field. OffboardProof therefore stores its receipt as `acknowledged`; it does not relabel it `verified`. Operators should pair this with Google audit logs or another independent signal when their assurance policy requires one.

Start with a test organizational unit, synthetic users, and external writes disabled. Validate scopes and behavior in your own tenant before production use.
