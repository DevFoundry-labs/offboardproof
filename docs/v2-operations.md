# V2 operations

V2 adds secure webhook intake, signed evidence, retention governance, and recoverable backup verification. It remains local-first and single-organization.

## Authenticated webhook intake

Set `OFFBOARDPROOF_WEBHOOK_CONFIG_FILE` to an absolute JSON configuration path. Secret paths inside that file must also be absolute, point outside the repository/database/evidence directories, and contain at least 32 bytes. The format and signing bytes are defined in `.dev/v2/WEBHOOK_SPEC.md`.

Send `POST /v1/intake/webhooks/{source_id}` with one instance of each security header:

- `OffboardProof-Delivery`
- `OffboardProof-Timestamp`
- `OffboardProof-Key-Id`
- `OffboardProof-Signature`

Sign the unmodified body bytes. Reformatting the JSON after signing invalidates the request. Replays return the original case; identifier reuse with different authenticated content returns a conflict.

## Evidence signing and verification

Configure an absolute Ed25519 private-key path, stable key ID, and optional password-file path. Pilot environments should set `OFFBOARDPROOF_REQUIRE_SIGNED_EVIDENCE=true`. If required signing fails, case completion is rolled back and an operational exception is opened.

Distribute the exported public key through an authenticated channel. The manifest's embedded public key is a transport copy, not a trust anchor.

```powershell
offboardproof evidence-public-key-export --output D:\trusted\pilot.pub
offboardproof evidence-export-v2 <case-id>
offboardproof evidence-verify --evidence <case.evidence.v2.json> --manifest <case.evidence.v2.manifest.json> --trusted-public-key D:\trusted\pilot.pub
```

## Retention and legal holds

Cases snapshot their retention date and policy identifier when created. Security or admin actors can create/release legal holds through the API. The retention report classifies cases but never deletes or moves records:

```powershell
offboardproof retention-report --as-of 2027-08-17T00:00:00Z
```

`expired_review_required` means a human/legal review is required. It is not authorization to purge.

## Backup and restore drill

Backups must use a new or empty directory outside the repository and evidence directory. They include an SQLite online backup, referenced evidence/manifest files, public keys, a safe configuration snapshot, and a digested inventory. Actor token digests remain in SQLite; raw tokens, webhook secrets, private signing keys, password files, and `.env` files are never copied by the backup command.

```powershell
offboardproof backup-create --destination D:\offboardproof-backup
offboardproof backup-verify --backup D:\offboardproof-backup
offboardproof restore-verify --backup D:\offboardproof-backup --scratch D:\offboardproof-restore-check
```

Restore verification writes only to a new scratch directory. V2 has no command that overwrites the live database.

## Assurance limits

- Signed evidence proves integrity and origin only relative to the verifier's trusted public key.
- Provider acknowledgements remain weaker than observed final state.
- Retention reporting does not provide secure erasure.
- Entra ID remains deferred pending design-partner demand.
- Design-partner discovery is still required before pilot, ROI, or compliance claims.
