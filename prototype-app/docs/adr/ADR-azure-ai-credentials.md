# ADR: Azure AI Security credentials

## Status

Approved for implementation.

## Decision

NoScan runs on AWS Fargate and Render, so Azure managed identity is not the
pilot default. A five-day implementation spike will validate external workload
federation independently for both hosting paths. Until a path passes issuer,
subject, audience, refresh, revocation, and tenant-isolation tests, the pilot
uses a dedicated Azure AI Security service principal with an encrypted client
secret.

The existing Azure infrastructure-discovery principal may be reused only after
the generated permission-diff test passes and a tenant administrator explicitly
approves the additional permissions.

The pilot does not implement that reuse path. It reuses only the tenant-scoped
subscription target metadata and requires a separate Azure AI Security
credential profile. Sharing the existing infrastructure-discovery principal
requires a later governance change with the permission-diff and tenant-admin
approval controls above.

Client-secret creation, replacement, verification, promotion, expiry warnings,
and revocation are pilot requirements. Plaintext credentials may exist only in
the request that creates or rotates a profile and in memory while acquiring an
Azure token. They are forbidden in browser responses, durable jobs, AI Security
tables other than encrypted credential columns, observations, evidence, logs,
and telemetry.

## Federation spike exit

Federation is enabled per hosting path only when all of the following pass:

- stable OIDC issuer and documented availability guarantee;
- tenant-specific subject and audience binding;
- unattended token refresh for jobs longer than one access-token lifetime;
- customer Entra setup and revocation procedure;
- replay and cross-tenant token rejection;
- operational monitoring and emergency disablement.

Failure keeps `WORKLOAD_FEDERATION` unavailable and does not block the encrypted
client-secret pilot.
