CREATE TABLE IF NOT EXISTS platform.plan_definitions (
    code varchar(64) PRIMARY KEY,
    display_name varchar(120) NOT NULL,
    status varchar(32) NOT NULL,
    description varchar(500),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

UPDATE platform.tenants
SET plan_code = CASE
    WHEN plan_code IS NULL OR trim(plan_code) = '' THEN 'ENTERPRISE'
    WHEN upper(trim(plan_code)) = 'PILOT' THEN 'ENTERPRISE'
    ELSE upper(trim(plan_code))
END
WHERE plan_code IS NULL
   OR trim(plan_code) = ''
   OR upper(trim(plan_code)) <> plan_code
   OR upper(trim(plan_code)) = 'PILOT';

INSERT INTO platform.plan_definitions (code, display_name, status, description, created_at, updated_at)
VALUES
    ('PRO', 'Pro', 'ACTIVE', 'Legacy commercial plan label retained for compatibility', now(), now()),
    ('ENTERPRISE', 'Enterprise', 'ACTIVE', 'Default workspace plan label retained for compatibility', now(), now()),
    ('DEMO', 'Demo', 'ACTIVE', 'Demo tenant plan label retained for compatibility', now(), now()),
    ('PILOT', 'Pilot', 'ACTIVE', 'Legacy pilot plan retained for compatibility', now(), now())
ON CONFLICT (code) DO NOTHING;
