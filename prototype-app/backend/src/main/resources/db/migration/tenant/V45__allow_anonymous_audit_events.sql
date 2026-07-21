-- Allow pre-authentication/demo audit events to use a null tenant while
-- retaining strict tenant matching for tenant-scoped audit events.
DROP POLICY IF EXISTS tenant_isolation ON audit_events;

CREATE POLICY tenant_isolation ON audit_events
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        OR (
            tenant_id IS NULL
            AND (
                nullif(current_setting('app.current_tenant_id', true), '') IS NULL
                OR current_setting('app.current_tenant_id', true)
                   = '00000000-0000-0000-0000-000000000000'
            )
        )
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid
        OR (
            tenant_id IS NULL
            AND (
                nullif(current_setting('app.current_tenant_id', true), '') IS NULL
                OR current_setting('app.current_tenant_id', true)
                   = '00000000-0000-0000-0000-000000000000'
            )
        )
    );
