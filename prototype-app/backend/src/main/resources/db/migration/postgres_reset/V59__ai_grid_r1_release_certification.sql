-- migration-guard: platform-only
-- Keep every reset-line tenant schema compatible with the generalized host Finding entity before JPA starts.
-- Customer schemas also receive this through tenant V48; these statements are intentionally idempotent.
DO $tenant_findings$
DECLARE
    schema_name text;
BEGIN
    FOR schema_name IN
        SELECT n.nspname
          FROM pg_namespace n
         WHERE (n.nspname = 'tenant_default' OR n.nspname LIKE 'tenant\_%' ESCAPE '\')
           AND to_regclass(format('%I.findings', n.nspname)) IS NOT NULL
         ORDER BY n.nspname
    LOOP
        EXECUTE format('ALTER TABLE %I.findings DROP CONSTRAINT IF EXISTS uk_findings_component_vulnerability', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ALTER COLUMN asset_id DROP NOT NULL', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ALTER COLUMN component_id DROP NOT NULL', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ALTER COLUMN vulnerability_id DROP NOT NULL', schema_name);
        EXECUTE format('ALTER TABLE %I.findings DROP CONSTRAINT IF EXISTS findings_creation_source_check', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ADD CONSTRAINT findings_creation_source_check CHECK (creation_source IN (''MANUAL'',''AUTOMATIC'',''AI_SECURITY''))', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ADD COLUMN IF NOT EXISTS finding_kind varchar(32) NOT NULL DEFAULT ''VULNERABILITY''', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ADD COLUMN IF NOT EXISTS fingerprint varchar(64)', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ADD COLUMN IF NOT EXISTS workflow_class varchar(32)', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ADD COLUMN IF NOT EXISTS title varchar(512)', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ADD COLUMN IF NOT EXISTS policy_id varchar(128)', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ADD COLUMN IF NOT EXISTS policy_version varchar(32)', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ADD COLUMN IF NOT EXISTS reason_code varchar(128)', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ADD COLUMN IF NOT EXISTS assessment_id uuid', schema_name);
        EXECUTE format('ALTER TABLE %I.findings DROP CONSTRAINT IF EXISTS findings_kind_check', schema_name);
        EXECUTE format('ALTER TABLE %I.findings ADD CONSTRAINT findings_kind_check CHECK (finding_kind IN (''VULNERABILITY'',''AI_POSTURE'',''AI_EXPOSURE''))', schema_name);
        EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS uk_findings_component_vulnerability ON %I.findings (component_id, vulnerability_id) WHERE finding_kind = ''VULNERABILITY''', schema_name);
        EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS uk_findings_tenant_fingerprint ON %I.findings (tenant_id, fingerprint) WHERE fingerprint IS NOT NULL', schema_name);
    END LOOP;
END
$tenant_findings$;

CREATE TABLE platform.ai_grid_release_gate_evidence (
    id uuid PRIMARY KEY,
    release_id varchar(32) NOT NULL,
    gate_code varchar(96) NOT NULL,
    status varchar(16) NOT NULL,
    evidence_reference text NOT NULL,
    rationale text NOT NULL,
    valid_until timestamptz NOT NULL,
    recorded_by varchar(255) NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    CHECK (release_id IN ('R0','R1','R2')),
    CHECK (status IN ('PASS','FAIL')),
    CHECK (valid_until > recorded_at)
);

CREATE INDEX idx_ai_grid_release_gate_latest
    ON platform.ai_grid_release_gate_evidence (release_id, gate_code, recorded_at DESC);

CREATE TABLE platform.ai_grid_release_decisions (
    id uuid PRIMARY KEY,
    release_id varchar(32) NOT NULL,
    decision varchar(16) NOT NULL,
    gate_snapshot_json jsonb NOT NULL,
    reason text NOT NULL,
    decided_by varchar(255) NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT now(),
    CHECK (release_id IN ('R0','R1','R2')),
    CHECK (decision IN ('APPROVED','BLOCKED'))
);

CREATE INDEX idx_ai_grid_release_decision_latest
    ON platform.ai_grid_release_decisions (release_id, decided_at DESC);
