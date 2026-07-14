# P0 production runbook

## Credential incident gate

1. Freeze merges and deployments and create the private incident record outside this repository.
2. Rotate the email-provider key and JWT signing key in the hosting platform. Deploy, verify email, revoke the old key, and require all users to authenticate again.
3. Review provider/authentication/deployment logs from the first exposed commit through revocation.
4. Create a restricted offline repository backup for incident retention.
5. Use `git filter-repo --replace-text <private-replacements-file>` to remove the revoked values from every branch and tag. Never commit the replacements file.
6. Force-push branches and tags during a maintenance window. Rebase/close open pull requests, invalidate stale CI artifacts, and require fresh clones.
7. Run `gitleaks git --config .gitleaks.toml --log-opts=--all` and keep the merge freeze until it passes.

Use Render environment groups/secret files or Railway sealed variables. Production secrets must not be shared with previews, and migration-role credentials must not be attached to the web service.

## Tenant migration commands

Report only against a restored production clone:

```sh
APP_SCHEMA_MIGRATION_ENABLED=true APP_SCHEMA_MIGRATION_REPORT_ONLY=true java -jar app.jar
```

Execute the migration job with migration-role database credentials:

```sh
APP_SCHEMA_MIGRATION_ENABLED=true APP_SCHEMA_MIGRATION_REPORT_ONLY=false java -jar app.jar
```

The migrator uses a 30-second advisory-lock timeout, a five-minute statement timeout, migrates the template first, then one canary, then batches of ten, and stops at the first failure. Preserve version-42 additions on application rollback; do not run a destructive down migration.

Before production, restore and verify a PostgreSQL backup, clear all reported drift on a production clone, validate row counts and foreign keys, run cross-tenant denial tests with the real runtime role, then monitor authentication failures, RLS denials, schema status, and tenant error rates for 24 hours.
