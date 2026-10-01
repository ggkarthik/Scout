-- migration-guard: platform-only

CREATE TABLE osv_advisories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    osv_id VARCHAR(50) UNIQUE NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,
    package_name VARCHAR(500) NOT NULL,

    summary TEXT NOT NULL,
    details TEXT,
    severity VARCHAR(20),
    cvss_v3_score DECIMAL(3,1),
    cvss_v3_vector VARCHAR(100),

    affected_ranges JSONB NOT NULL,
    published_at TIMESTAMP,
    modified_at TIMESTAMP,
    withdrawn_at TIMESTAMP,

    references JSONB,
    osv_data JSONB NOT NULL,

    source VARCHAR(50) NOT NULL,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    synced_at TIMESTAMP
);

CREATE INDEX idx_osv_ecosystem_package ON osv_advisories(ecosystem, package_name);
CREATE INDEX idx_osv_package_name ON osv_advisories(package_name);
CREATE INDEX idx_osv_modified ON osv_advisories(modified_at DESC);
CREATE INDEX idx_osv_source ON osv_advisories(source);

CREATE TABLE advisory_equivalences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    nvd_cve_id VARCHAR(50),
    ghsa_id VARCHAR(50),
    osv_id VARCHAR(50),

    cwe_ids JSONB,

    equivalence_confidence DECIMAL(3,2),
    equivalence_reason VARCHAR(100),

    discovered_at TIMESTAMP DEFAULT NOW(),
    verified_at TIMESTAMP,
    verified_by_user_id UUID,

    notes TEXT,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_advisory_equivalences_keys
    ON advisory_equivalences(COALESCE(nvd_cve_id, ''), COALESCE(ghsa_id, ''), COALESCE(osv_id, ''));
CREATE INDEX idx_advisory_equivalences_cve ON advisory_equivalences(nvd_cve_id);
CREATE INDEX idx_advisory_equivalences_ghsa ON advisory_equivalences(ghsa_id);
CREATE INDEX idx_advisory_equivalences_osv ON advisory_equivalences(osv_id);
