-- Production readiness foundation: tenant lifecycle metadata, users,
-- memberships, service accounts, and immutable audit events.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS slug varchar(120),
    ADD COLUMN IF NOT EXISTS status varchar(32) NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN IF NOT EXISTS plan_code varchar(64) NOT NULL DEFAULT 'pilot',
    ADD COLUMN IF NOT EXISTS billing_ref varchar(255),
    ADD COLUMN IF NOT EXISTS suspended_at timestamp(6) with time zone,
    ADD COLUMN IF NOT EXISTS deleted_at timestamp(6) with time zone,
    ADD COLUMN IF NOT EXISTS updated_at timestamp(6) with time zone NOT NULL DEFAULT now();

UPDATE tenants
SET slug = regexp_replace(lower(name), '[^a-z0-9]+', '-', 'g')
WHERE slug IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_tenants_slug ON tenants(slug);
CREATE INDEX IF NOT EXISTS ix_tenants_status ON tenants(status);

CREATE TABLE IF NOT EXISTS app_users (
    id uuid PRIMARY KEY,
    external_subject varchar(255) NOT NULL,
    email varchar(320),
    display_name varchar(255),
    status varchar(32) NOT NULL DEFAULT 'ACTIVE',
    last_seen_at timestamp(6) with time zone,
    created_at timestamp(6) with time zone NOT NULL DEFAULT now(),
    updated_at timestamp(6) with time zone NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_app_users_external_subject ON app_users(external_subject);
CREATE INDEX IF NOT EXISTS ix_app_users_email ON app_users(email);
CREATE INDEX IF NOT EXISTS ix_app_users_status ON app_users(status);

CREATE TABLE IF NOT EXISTS tenant_memberships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    user_id uuid NOT NULL REFERENCES app_users(id),
    role varchar(64) NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'ACTIVE',
    invited_by uuid REFERENCES app_users(id),
    created_at timestamp(6) with time zone NOT NULL DEFAULT now(),
    updated_at timestamp(6) with time zone NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id, role)
);

CREATE INDEX IF NOT EXISTS ix_tenant_memberships_tenant ON tenant_memberships(tenant_id);
CREATE INDEX IF NOT EXISTS ix_tenant_memberships_user ON tenant_memberships(user_id);
CREATE INDEX IF NOT EXISTS ix_tenant_memberships_status ON tenant_memberships(status);

CREATE TABLE IF NOT EXISTS service_accounts (
    id uuid PRIMARY KEY,
    tenant_id uuid REFERENCES tenants(id),
    name varchar(255) NOT NULL,
    key_id varchar(120) NOT NULL,
    role varchar(64) NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'ACTIVE',
    last_used_at timestamp(6) with time zone,
    created_at timestamp(6) with time zone NOT NULL DEFAULT now(),
    updated_at timestamp(6) with time zone NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_service_accounts_key_id ON service_accounts(key_id);
CREATE INDEX IF NOT EXISTS ix_service_accounts_tenant ON service_accounts(tenant_id);
CREATE INDEX IF NOT EXISTS ix_service_accounts_status ON service_accounts(status);

CREATE TABLE IF NOT EXISTS audit_events (
    id uuid PRIMARY KEY,
    occurred_at timestamp(6) with time zone NOT NULL DEFAULT now(),
    tenant_id uuid REFERENCES tenants(id),
    actor_user_id uuid REFERENCES app_users(id),
    actor_subject varchar(255) NOT NULL,
    actor_role varchar(64),
    action varchar(160) NOT NULL,
    target_type varchar(120),
    target_id varchar(255),
    request_id varchar(120),
    source_ip varchar(80),
    outcome varchar(32) NOT NULL DEFAULT 'SUCCESS',
    details_json jsonb
);

CREATE INDEX IF NOT EXISTS ix_audit_events_tenant_time ON audit_events(tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_events_actor_time ON audit_events(actor_subject, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_events_action_time ON audit_events(action, occurred_at DESC);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_tenant ON audit_events;
CREATE POLICY rls_tenant ON audit_events
    USING (
        tenant_id = nullif(current_setting('app.current_tenant_id', TRUE), '')::uuid
        OR tenant_id IS NULL
        OR nullif(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    );
