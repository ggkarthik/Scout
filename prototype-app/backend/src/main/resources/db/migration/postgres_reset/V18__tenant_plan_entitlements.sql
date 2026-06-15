CREATE TABLE IF NOT EXISTS platform.plan_definitions (
    code varchar(64) PRIMARY KEY,
    display_name varchar(120) NOT NULL,
    status varchar(32) NOT NULL,
    description varchar(500),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS platform.entitlement_definitions (
    key varchar(120) PRIMARY KEY,
    category varchar(64) NOT NULL,
    value_type varchar(32) NOT NULL,
    description varchar(500),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS platform.plan_entitlements (
    plan_code varchar(64) NOT NULL,
    entitlement_key varchar(120) NOT NULL,
    enabled boolean NOT NULL,
    config_json jsonb,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_plan_entitlements PRIMARY KEY (plan_code, entitlement_key),
    CONSTRAINT fk_plan_entitlements_plan_code FOREIGN KEY (plan_code) REFERENCES platform.plan_definitions (code),
    CONSTRAINT fk_plan_entitlements_entitlement_key FOREIGN KEY (entitlement_key) REFERENCES platform.entitlement_definitions (key)
);

CREATE TABLE IF NOT EXISTS platform.tenant_entitlement_overrides (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    entitlement_key varchar(120) NOT NULL,
    enabled boolean NOT NULL,
    config_json jsonb,
    reason varchar(500),
    expires_at timestamptz,
    created_by uuid,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT fk_tenant_entitlement_overrides_tenant FOREIGN KEY (tenant_id) REFERENCES platform.tenants (id),
    CONSTRAINT fk_tenant_entitlement_overrides_entitlement_key FOREIGN KEY (entitlement_key) REFERENCES platform.entitlement_definitions (key),
    CONSTRAINT fk_tenant_entitlement_overrides_created_by FOREIGN KEY (created_by) REFERENCES platform.app_users (id),
    CONSTRAINT uk_tenant_entitlement_overrides_tenant_key UNIQUE (tenant_id, entitlement_key)
);

CREATE INDEX IF NOT EXISTS idx_tenant_entitlement_overrides_tenant_expires
    ON platform.tenant_entitlement_overrides (tenant_id, expires_at);

CREATE INDEX IF NOT EXISTS idx_tenant_entitlement_overrides_entitlement_key
    ON platform.tenant_entitlement_overrides (entitlement_key);

UPDATE platform.tenants
SET plan_code = CASE
    WHEN plan_code IS NULL OR trim(plan_code) = '' THEN 'PRO'
    WHEN upper(trim(plan_code)) = 'PILOT' THEN 'PRO'
    ELSE upper(trim(plan_code))
END
WHERE plan_code IS NULL
   OR trim(plan_code) = ''
   OR upper(trim(plan_code)) <> plan_code
   OR upper(trim(plan_code)) = 'PILOT';

INSERT INTO platform.plan_definitions (code, display_name, status, description, created_at, updated_at)
VALUES
    ('PRO', 'Pro', 'ACTIVE', 'Commercial Pro plan', now(), now()),
    ('ENTERPRISE', 'Enterprise', 'ACTIVE', 'Commercial Enterprise plan', now(), now()),
    ('DEMO', 'Demo', 'ACTIVE', 'Demo tenant plan', now(), now()),
    ('PILOT', 'Pilot', 'ACTIVE', 'Legacy pilot plan retained for compatibility', now(), now())
ON CONFLICT (code) DO NOTHING;

INSERT INTO platform.entitlement_definitions (key, category, value_type, description, created_at, updated_at)
VALUES
    ('ai.investigation_summary', 'AI', 'BOOLEAN', 'Generate AI investigation summaries', now(), now()),
    ('ai.solution_generation', 'AI', 'BOOLEAN', 'Generate AI remediation solutions', now(), now()),
    ('ai.required_actions', 'AI', 'BOOLEAN', 'Generate AI required actions', now(), now()),
    ('ai.fix_generation', 'AI', 'BOOLEAN', 'Generate AI fix records', now(), now()),
    ('ai.investigation_agent', 'AI', 'BOOLEAN', 'Run AI investigation agent workflows', now(), now()),
    ('ai.upgrade_recommendation', 'AI', 'BOOLEAN', 'Generate AI upgrade recommendations', now(), now())
ON CONFLICT (key) DO NOTHING;

INSERT INTO platform.plan_entitlements (plan_code, entitlement_key, enabled, config_json, created_at, updated_at)
VALUES
    ('PRO', 'ai.investigation_summary', false, NULL, now(), now()),
    ('PRO', 'ai.solution_generation', false, NULL, now(), now()),
    ('PRO', 'ai.required_actions', false, NULL, now(), now()),
    ('PRO', 'ai.fix_generation', false, NULL, now(), now()),
    ('PRO', 'ai.investigation_agent', false, NULL, now(), now()),
    ('PRO', 'ai.upgrade_recommendation', false, NULL, now(), now()),
    ('ENTERPRISE', 'ai.investigation_summary', true, NULL, now(), now()),
    ('ENTERPRISE', 'ai.solution_generation', true, NULL, now(), now()),
    ('ENTERPRISE', 'ai.required_actions', true, NULL, now(), now()),
    ('ENTERPRISE', 'ai.fix_generation', true, NULL, now(), now()),
    ('ENTERPRISE', 'ai.investigation_agent', true, NULL, now(), now()),
    ('ENTERPRISE', 'ai.upgrade_recommendation', true, NULL, now(), now()),
    ('DEMO', 'ai.investigation_summary', false, NULL, now(), now()),
    ('DEMO', 'ai.solution_generation', false, NULL, now(), now()),
    ('DEMO', 'ai.required_actions', false, NULL, now(), now()),
    ('DEMO', 'ai.fix_generation', false, NULL, now(), now()),
    ('DEMO', 'ai.investigation_agent', false, NULL, now(), now()),
    ('DEMO', 'ai.upgrade_recommendation', false, NULL, now(), now()),
    ('PILOT', 'ai.investigation_summary', false, NULL, now(), now()),
    ('PILOT', 'ai.solution_generation', false, NULL, now(), now()),
    ('PILOT', 'ai.required_actions', false, NULL, now(), now()),
    ('PILOT', 'ai.fix_generation', false, NULL, now(), now()),
    ('PILOT', 'ai.investigation_agent', false, NULL, now(), now()),
    ('PILOT', 'ai.upgrade_recommendation', false, NULL, now(), now())
ON CONFLICT (plan_code, entitlement_key) DO NOTHING;
