CREATE TABLE suppression_rules (
    id           UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id    UUID        NOT NULL REFERENCES tenants(id),
    name         TEXT        NOT NULL,
    state        VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
    record_type  VARCHAR(20) NOT NULL DEFAULT 'FINDING',
    conditions_json JSONB    NOT NULL DEFAULT '[]',
    condition_logic VARCHAR(3) NOT NULL DEFAULT 'AND',
    reason       TEXT,
    valid_from   TIMESTAMPTZ,
    valid_to     TIMESTAMPTZ,
    execution_order INT      NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_suppression_rules_tenant ON suppression_rules(tenant_id);
