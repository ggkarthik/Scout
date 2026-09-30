-- migration-guard: tenant-only

-- GHSA Integration Status per Tenant
CREATE TABLE IF NOT EXISTS tenant_ghsa_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL UNIQUE REFERENCES tenant_id(id) ON DELETE CASCADE,

    is_enabled BOOLEAN DEFAULT FALSE,

    enabled_at TIMESTAMP,
    disabled_at TIMESTAMP,

    auto_create_findings BOOLEAN DEFAULT TRUE,
    auto_correlate_components BOOLEAN DEFAULT TRUE,
    create_finding_for_low_severity BOOLEAN DEFAULT FALSE,

    reason_enabled VARCHAR(255),
    enabled_by_user_id UUID,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ghsa_integration_enabled ON tenant_ghsa_integrations(is_enabled);

-- Repository Component to Advisory Correlation (Tenant-Scoped)
CREATE TABLE IF NOT EXISTS tenant_github_repository_component_advisories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenant_id(id) ON DELETE CASCADE,

    github_source_id UUID NOT NULL REFERENCES github_sbom_sources(id) ON DELETE CASCADE,
    component_id VARCHAR(500) NOT NULL,
    advisory_id UUID NOT NULL,

    is_affected BOOLEAN NOT NULL,
    installed_version VARCHAR(50) NOT NULL,
    is_installed_version_vulnerable BOOLEAN NOT NULL,
    vulnerable_range_reason VARCHAR(255),

    finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
    finding_kind VARCHAR(50) DEFAULT 'AI_GITHUB_ADVISORY',

    recommended_fixed_version VARCHAR(50),
    upgrade_available BOOLEAN,

    discovered_at TIMESTAMP DEFAULT NOW(),
    first_alert_sent_at TIMESTAMP,
    last_alert_sent_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_repo_comp_advisory_source ON tenant_github_repository_component_advisories(tenant_id, github_source_id);
CREATE INDEX idx_repo_comp_advisory_affected ON tenant_github_repository_component_advisories(tenant_id, is_affected) WHERE is_affected = TRUE;
CREATE INDEX idx_repo_comp_advisory_finding ON tenant_github_repository_component_advisories(tenant_id, finding_id) WHERE finding_id IS NOT NULL;

-- GHSA Subscriptions per Tenant
CREATE TABLE IF NOT EXISTS tenant_ghsa_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenant_id(id) ON DELETE CASCADE,

    advisory_id UUID NOT NULL,

    subscription_reason VARCHAR(100),

    is_active BOOLEAN DEFAULT TRUE,
    subscribed_at TIMESTAMP DEFAULT NOW(),
    unsubscribed_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_ghsa_subscription_unique ON tenant_ghsa_subscriptions(tenant_id, advisory_id);
CREATE INDEX idx_ghsa_subscription_active ON tenant_ghsa_subscriptions(tenant_id, is_active);

-- Extend findings table for GHSA correlation
ALTER TABLE findings ADD COLUMN IF NOT EXISTS github_advisory_id UUID;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ghsa_id VARCHAR(20);

CREATE INDEX IF NOT EXISTS idx_findings_ghsa ON findings(tenant_id, ghsa_id) WHERE ghsa_id IS NOT NULL;
