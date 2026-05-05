ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS demo_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS demo_created_by VARCHAR(255),
    ADD COLUMN IF NOT EXISTS demo_source VARCHAR(64);

CREATE TABLE IF NOT EXISTS demo_requests (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    company VARCHAR(255) NOT NULL,
    role_title VARCHAR(255),
    company_size VARCHAR(80),
    use_case VARCHAR(120),
    notes VARCHAR(2000),
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ,
    decided_by VARCHAR(255),
    rejection_reason VARCHAR(255),
    tenant_id UUID
);

CREATE INDEX IF NOT EXISTS idx_demo_requests_status_requested
    ON demo_requests (status, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_demo_requests_email
    ON demo_requests (lower(email));

CREATE TABLE IF NOT EXISTS demo_invites (
    id UUID PRIMARY KEY,
    token VARCHAR(96) NOT NULL UNIQUE,
    request_id UUID REFERENCES demo_requests(id),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    email VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'SENT',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    last_sent_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_demo_invites_request_created
    ON demo_invites (request_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_demo_invites_tenant
    ON demo_invites (tenant_id);
