CREATE TABLE IF NOT EXISTS platform.tenant_user_invites (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    invited_by uuid,
    email varchar(320) NOT NULL,
    display_name varchar(255),
    external_subject varchar(320) NOT NULL,
    role varchar(64) NOT NULL,
    status varchar(32) NOT NULL,
    token varchar(96) NOT NULL,
    provider_message_id varchar(255),
    delivery_detail varchar(500),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    last_sent_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_tenant_user_invites_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_tenant_user_invites_invited_by FOREIGN KEY (invited_by) REFERENCES platform.app_users (id),
    CONSTRAINT uk_tenant_user_invites_token UNIQUE (token)
);

CREATE INDEX IF NOT EXISTS idx_tenant_user_invites_tenant_created
    ON platform.tenant_user_invites (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_tenant_user_invites_tenant_status
    ON platform.tenant_user_invites (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_tenant_user_invites_subject_status
    ON platform.tenant_user_invites (external_subject, status);
