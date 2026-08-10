# Security policy

## Supported versions

Security fixes are provided for the latest released minor version.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's **Report a vulnerability** flow in this repository's Security tab. Include affected version, impact, reproduction steps, and any proposed mitigation. We aim to acknowledge reports within three business days.

## Deployment expectations

OffboardProof is an alpha, self-hosted service. Put the API behind TLS and an authenticated reverse proxy, restrict filesystem access to the database/evidence directories, rotate actor tokens, keep provider credentials outside the repository, and back up the SQLite database together with evidence. External provider writes are disabled by default.

See [docs/security-model.md](docs/security-model.md) for threat boundaries and residual risk.
