-- migration-guard: platform-only

-- GitHub Security Advisories (GHSA) - Platform Level Cache
-- Shared across all tenants, synced once per hour
-- Current head: V4

CREATE TABLE IF NOT EXISTS public.github_security_advisories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    ghsa_id VARCHAR(20) NOT NULL UNIQUE,
    cve_id VARCHAR(20),

    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(100),

    ecosystem VARCHAR(50) NOT NULL,
    package_name VARCHAR(255) NOT NULL,

    affected_versions_start VARCHAR(50),
    affected_versions_end VARCHAR(50),
    affected_versions_pattern VARCHAR(500),
    fixed_versions TEXT,

    github_advisory_url VARCHAR(500),
    published_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW(),
    withdrawn_at TIMESTAMP,

    first_synced_at TIMESTAMP DEFAULT NOW(),
    last_synced_at TIMESTAMP DEFAULT NOW(),
    is_applicable BOOLEAN DEFAULT TRUE,
    sync_hash VARCHAR(64),

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ghsa_id ON public.github_security_advisories(ghsa_id);
CREATE INDEX idx_ghsa_package ON public.github_security_advisories(ecosystem, package_name);
CREATE INDEX idx_ghsa_cve ON public.github_security_advisories(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX idx_ghsa_applicable ON public.github_security_advisories(is_applicable) WHERE is_applicable = TRUE;

-- Platform GHSA Sync State
CREATE TABLE IF NOT EXISTS public.github_advisory_sync_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    sync_type VARCHAR(50) DEFAULT 'GITHUB_GHSA',

    status VARCHAR(20) DEFAULT 'IDLE',
    last_full_sync_at TIMESTAMP,
    last_incremental_sync_at TIMESTAMP,
    next_scheduled_sync_at TIMESTAMP,

    last_cursor VARCHAR(1000),
    sync_complete BOOLEAN DEFAULT FALSE,

    advisories_synced INT DEFAULT 0,
    advisories_newly_found INT DEFAULT 0,
    advisories_updated INT DEFAULT 0,
    sync_duration_ms INT,

    last_error VARCHAR(1000),
    consecutive_errors INT DEFAULT 0,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_ghsa_sync_type ON public.github_advisory_sync_state(sync_type);
CREATE INDEX idx_ghsa_sync_next ON public.github_advisory_sync_state(next_scheduled_sync_at);

-- Advisory Source Registrations
CREATE TABLE IF NOT EXISTS public.advisory_source_registrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    source_type VARCHAR(50) NOT NULL UNIQUE,
    is_enabled BOOLEAN DEFAULT TRUE,

    source_config JSONB,

    sync_interval_hours INT DEFAULT 1,
    last_sync_at TIMESTAMP,
    next_sync_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO public.advisory_source_registrations (source_type, is_enabled, sync_interval_hours, next_sync_at)
SELECT 'GITHUB_GHSA', TRUE, 1, NOW() + INTERVAL '1 hour'
WHERE NOT EXISTS (SELECT 1 FROM public.advisory_source_registrations WHERE source_type = 'GITHUB_GHSA');
