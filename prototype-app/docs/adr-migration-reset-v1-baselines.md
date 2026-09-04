# ADR: Independent V1 migration baselines

The platform and tenant Flyway lines restart at V1. Platform V1 owns `public`, `platform`, and creation of an empty `tenant_default`; tenant V1 owns all tenant tables, indexes, constraints, foreign keys, RLS policies, and tenant-safe seed data. Flyway history, credentials, runtime/demo records, and transient approval records are excluded.

Migration files are append-only. Never edit, delete, rename, or move an applied `V*.sql`; use the next sequential version on that migration line. Pull requests must be rebased and merged through the merge queue/up-to-date branch, with migration validation and PostgreSQL integration required. Every reset or new migration is validated against fresh PostgreSQL; golden API fixtures remain unchanged unless a reviewed behavior change requires it.

Before resetting an environment, inventory it, confirm it contains no customer data, pause workers, export the database, and retain the backup until acceptance. Record the backup location in the change ticket. Drop/recreate schemas and Flyway history together, use the privileged Render bootstrap path, verify health/RLS/fingerprints, reseed approved demo data, and re-enable jobs. Shared and production resets require explicit operator access and data-owner approval.
