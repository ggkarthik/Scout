CREATE TABLE IF NOT EXISTS platform.personal_finding_queues (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    queue_key varchar(120) NOT NULL,
    title varchar(160) NOT NULL,
    description varchar(500),
    filter_json text NOT NULL,
    display_order integer NOT NULL,
    is_default boolean NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_personal_finding_queues_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_personal_finding_queues_owner FOREIGN KEY (owner_user_id) REFERENCES platform.app_users (id),
    CONSTRAINT uk_personal_finding_queues_owner_key UNIQUE (tenant_id, owner_user_id, queue_key),
    CONSTRAINT uk_personal_finding_queues_owner_title UNIQUE (tenant_id, owner_user_id, title)
);

CREATE UNIQUE INDEX IF NOT EXISTS uk_personal_finding_queues_owner_default
    ON platform.personal_finding_queues (tenant_id, owner_user_id)
    WHERE is_default = true;

CREATE INDEX IF NOT EXISTS idx_personal_finding_queues_owner_order
    ON platform.personal_finding_queues (tenant_id, owner_user_id, display_order, created_at);

CREATE TABLE IF NOT EXISTS platform.finding_queue_preferences (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    default_queue_ref varchar(160) NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_finding_queue_preferences_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_finding_queue_preferences_owner FOREIGN KEY (owner_user_id) REFERENCES platform.app_users (id),
    CONSTRAINT uk_finding_queue_preferences_owner UNIQUE (tenant_id, owner_user_id)
);
