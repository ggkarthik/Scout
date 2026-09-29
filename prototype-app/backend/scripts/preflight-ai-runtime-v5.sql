\set ON_ERROR_STOP on

-- Run before deploying tenant V5. V5 deliberately refuses to guess how plaintext provider
-- identifiers should be transformed because the tenant-scoped HMAC key is not available to SQL.
DO $runtime_v5_preflight$
DECLARE
    tenant_record record;
    current_version integer;
    populated bigint;
BEGIN
    FOR tenant_record IN
        SELECT schema_name FROM platform.tenants
         WHERE deleted_at IS NULL AND upper(status) NOT IN ('DELETED','PURGED')
    LOOP
        IF to_regclass(format('%I.tenant_schema_history', tenant_record.schema_name)) IS NULL THEN
            CONTINUE;
        END IF;
        EXECUTE format('select coalesce(max(version::integer),0) from %I.tenant_schema_history where success and version ~ ''^[0-9]+$''',
                       tenant_record.schema_name) INTO current_version;
        IF current_version = 4 AND to_regclass(format('%I.ai_agent_executions', tenant_record.schema_name)) IS NOT NULL THEN
            EXECUTE format('select (select count(*) from %I.ai_agent_executions) + '
                         || '(select count(*) from %I.ai_agent_execution_cursors) + '
                         || '(select count(*) from %I.ai_agent_execution_receipts)',
                           tenant_record.schema_name, tenant_record.schema_name, tenant_record.schema_name) INTO populated;
            IF populated > 0 THEN
                RAISE EXCEPTION 'Tenant schema % has % V4 runtime rows. Export/transform them with the tenant runtime HMAC key, or use the supported cleanup procedure before V5.',
                    tenant_record.schema_name, populated;
            END IF;
        END IF;
    END LOOP;
END
$runtime_v5_preflight$;

SELECT 'ai_runtime_v5_preflight_status=verified';
