-- Converge tenant schemas with the tenant_default template for three objects that
-- were only ever created/shaped by the PLATFORM migration line (postgres_reset) and
-- therefore never reproduced by the tenant line:
--
--   1. demo_requests.uk_demo_requests_active_email  -- platform V46 (template only)
--   2. ingestion_jobs.uk_ingestion_jobs_dedupe_active -- platform V16 (different expr text)
--   3. demo_invites RLS policy tenant_isolation       -- template carries a permissive
--        variant; real tenants carry the strict V42 form
--
-- The control plane applies this migration to the tenant_default template first and
-- then to every tenant, so recreating each object with identical DDL on both sides
-- makes the structural fingerprint converge. This unblocks the fingerprint check in
-- ProductionBootstrapCli.migrateAndMark (which otherwise never marks a tenant CURRENT).
--
-- No behavior change for real tenants: they already carry the strict demo_invites
-- policy; only the template is normalised down to the strict form (never the reverse,
-- which would reintroduce the empty-context cross-tenant read the template variant allows).
--
-- ${tenantId}/${tenantSchema} are validated values supplied by the control plane.
DO $v67$
DECLARE
    target_tenant uuid := '${tenantId}'::uuid;
    target_schema text := '${tenantSchema}';
    tenant_id_nullable boolean;
    predicate text;
BEGIN
    IF current_schema() <> target_schema THEN
        RAISE EXCEPTION 'Tenant migration search_path mismatch: expected %, got %', target_schema, current_schema();
    END IF;

    -- 1) demo_requests: supersede duplicate active rows, then (re)create the partial
    --    unique index with canonical DDL (mirrors platform V46 exactly).
    UPDATE demo_requests request
       SET status = 'SUPERSEDED',
           rejection_reason = coalesce(request.rejection_reason, 'Superseded by a newer active request')
      FROM (
        SELECT id,
               row_number() OVER (PARTITION BY lower(email) ORDER BY requested_at DESC, id DESC) AS request_rank
          FROM demo_requests
         WHERE status IN ('PENDING', 'SENT', 'ERROR')
      ) ranked
     WHERE request.id = ranked.id
       AND ranked.request_rank > 1;

    DROP INDEX IF EXISTS uk_demo_requests_active_email;
    CREATE UNIQUE INDEX uk_demo_requests_active_email
        ON demo_requests (lower(email))
        WHERE status IN ('PENDING', 'SENT', 'ERROR');

    -- 2) ingestion_jobs: recreate the dedupe index with canonical DDL (mirrors platform
    --    V16 exactly) so the stored predicate text matches on both template and tenants.
    DROP INDEX IF EXISTS uk_ingestion_jobs_dedupe_active;
    CREATE UNIQUE INDEX uk_ingestion_jobs_dedupe_active
        ON ingestion_jobs (dedupe_key)
        WHERE status IN ('QUEUED', 'RUNNING');

    -- 3) demo_invites: normalise the RLS policy to the strict per-tenant form produced by
    --    tenant/V42__enforce_tenant_rls.sql. The predicate is generated with the same
    --    format() expression V42 uses, so the resulting policy text is byte-identical to
    --    what real tenants already have (no-op there) and the template converges to it.
    SELECT is_nullable = 'YES'
      INTO tenant_id_nullable
      FROM information_schema.columns
     WHERE table_schema = target_schema
       AND table_name = 'demo_invites'
       AND column_name = 'tenant_id';

    predicate := format(
        'nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid = %L::uuid',
        target_tenant::text
    );
    IF NOT tenant_id_nullable THEN
        predicate := predicate ||
            ' AND tenant_id = nullif(current_setting(''app.current_tenant_id'', true), '''')::uuid';
    END IF;

    EXECUTE format('ALTER TABLE %I.demo_invites ENABLE ROW LEVEL SECURITY', target_schema);
    EXECUTE format('ALTER TABLE %I.demo_invites FORCE ROW LEVEL SECURITY', target_schema);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I.demo_invites', target_schema);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I.demo_invites USING (%s) WITH CHECK (%s)',
                   target_schema, predicate, predicate);
END
$v67$;
