# P0 production runbook

## Credential incident gate

1. Freeze merges and deployments and create the private incident record outside this repository.
2. Rotate the email-provider key and JWT signing key in the hosting platform. Deploy, verify email, revoke the old key, and require all users to authenticate again.
3. Review provider/authentication/deployment logs from the first exposed commit through revocation.
4. Create a restricted offline repository backup for incident retention.
5. Use `git filter-repo --replace-text <private-replacements-file>` to remove the revoked values from every branch and tag. Never commit the replacements file.
6. Force-push branches and tags during a maintenance window. Rebase/close open pull requests, invalidate stale CI artifacts, and require fresh clones.
7. Run `gitleaks git --config .gitleaks.toml --log-opts=--all` and keep the merge freeze until it passes.

Use Render environment groups and secret files. Production secrets must not be shared with previews, and migration-role credentials must not be attached to the web service.

## Customer-validation data waiver

The backup/restore acceptance gate may be waived only for an explicitly non-production
customer-validation database when all data is synthetic and disposable, no production
connector credentials are stored, and complete database recreation is the agreed recovery
strategy. Record the waiver before migration and keep the environment labelled preproduction.

This waiver applies to the initial ScoutGrid Render database created on 2026-07-14. The
database contains demo/test data only, and the owner has accepted rebuild-and-reseed as the
recovery objective. It does not waive schema migration, role separation, RLS, secret handling,
or cross-tenant denial tests. The waiver expires before the first real customer dataset or
production credential is accepted; at that point a paid persistent database, automated
backup/PITR, and a tested restore are mandatory.

## Tenant migration commands

Report only against a restored production clone:

```sh
BOOTSTRAP_REPORT_ONLY=true ./backend/scripts/run-render-migration.sh
```

Execute the migration job with migration-role database credentials:

```sh
BOOTSTRAP_REPORT_ONLY=false ./backend/scripts/run-render-migration.sh
```

For the first production platform-owner login, enable one-time setup-link delivery only on
the temporary migrator:

```sh
PLATFORM_OWNER_SETUP_LINK_ENABLED=true \
PLATFORM_OWNER_SETUP_EMAIL=owner@example.com \
PLATFORM_OWNER_SETUP_APP_BASE_URL=https://scoutgrid.io \
PLATFORM_OWNER_SETUP_TOKEN_TTL_MINUTES=30 \
BOOTSTRAP_REPORT_ONLY=false \
./backend/scripts/run-render-migration.sh
```

The migrator also requires `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, and
`RESEND_FROM_DOMAIN`. It stores only the setup-token hash and commits it only after Resend
accepts delivery. The raw token and URL are never included in the bootstrap report. Do not
configure these setup-link variables on the permanent web service. If the platform owner
already has a password, the operation fails unless the separately approved
`PLATFORM_OWNER_SETUP_ALLOW_REISSUE=true` override is supplied.

The production bootstrap also reconciles the configured platform-owner identity and
`PLATFORM_OWNER` global role before issuing the link. This makes a clean database
bootstrappable without relying on the permanent runtime service to create the first
operator identity.

The migrator uses a 30-second advisory-lock timeout, a five-minute statement timeout, migrates the template first, then one canary, then batches of ten, and stops at the first failure. After a successful run, the temporary Render web service stays in a completion-only maintenance state until it is deleted; this prevents Render's supervisor from restarting the container and executing the privileged bootstrap again. Preserve version-42 additions on application rollback; do not run a destructive down migration.

Before production, restore and verify a PostgreSQL backup, clear all reported drift on a production clone, validate row counts and foreign keys, run cross-tenant denial tests with the real runtime role, then monitor authentication failures, RLS denials, schema status, and tenant error rates for 24 hours.
