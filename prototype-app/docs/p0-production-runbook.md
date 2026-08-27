# Production schema migration runbook

The permanent runtime service must use the restricted runtime database role. Platform and tenant migrations run only from the temporary schema-migrator service through `backend/scripts/run-render-migration.sh`.

## Configuration preflight

Before creating or restarting the temporary service, validate its environment without starting maintenance mode, Java, or making a database connection:

```sh
/app/scripts/run-render-migration.sh --validate-env-only
```

`MIGRATION_DB_HOST` accepts a DNS hostname or IPv4 address only. Do not supply a URL, path, embedded port, whitespace, or IPv6 address. `MIGRATION_DB_PORT` must be an integer from 1 through 65535. Database names, migration/runtime usernames and passwords, and the shared credential-encryption key must be nonblank.

The wrapper constructs a bounded PostgreSQL JDBC URL, exports `EXPECTED_DB_NAME` from `MIGRATION_DB_NAME`, and starts the migrator only after validation succeeds. Java then verifies the JDBC shape, connects with bounded login/connect/socket timeouts, and compares `current_user` and `current_database()` with the configured values before acquiring the migration lock.

Bootstrap reports use:

- `preflight_db_config` for malformed configuration or database/user mismatches;
- `preflight_db_connectivity` for authentication, network, timeout, or identity-query failures.

Reports never contain credentials or a complete JDBC URL.

## Completion checks

After bootstrap reports success, verify the platform history is at the packaged platform target, every active tenant projection is `CURRENT` at the packaged tenant target, and `/actuator/health/readiness` is UP. The temporary migrator intentionally stays in its completion-only maintenance state until an operator verifies the report and deletes the service.
