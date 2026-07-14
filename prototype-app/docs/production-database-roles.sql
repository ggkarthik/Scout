-- Run as the database administrator. Supply role names through psql variables:
--   psql -v migration_role=scout_migration -v runtime_role=scout_runtime -f production-database-roles.sql
-- Set passwords with the hosting platform/database console; never place passwords in this file.

SELECT format('CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS', :'migration_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'migration_role')
\gexec

SELECT format('CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS', :'runtime_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'runtime_role')
\gexec

GRANT USAGE ON SCHEMA platform, tenant_default TO :"runtime_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA platform, tenant_default TO :"runtime_role";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA platform, tenant_default TO :"runtime_role";
REVOKE CREATE ON SCHEMA platform, tenant_default FROM :"runtime_role";

SELECT format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, :'runtime_role') FROM platform.tenants
\gexec
SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO %I', schema_name, :'runtime_role') FROM platform.tenants
\gexec
SELECT format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I', schema_name, :'runtime_role') FROM platform.tenants
\gexec
SELECT format('REVOKE CREATE ON SCHEMA %I FROM %I', schema_name, :'runtime_role') FROM platform.tenants
\gexec

-- Transfer protected object ownership to the migration role as part of the DBA rollout.
-- The runtime role must own none of the protected schemas or tables.
