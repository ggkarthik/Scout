package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.Locale;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SoftwareIdentitySummaryProjectionService {

    private static final int NEAR_EOL_THRESHOLD_DAYS = EolConstants.NEAR_EOL_THRESHOLD_DAYS;

    private final NamedParameterJdbcTemplate jdbcTemplate;

    public SoftwareIdentitySummaryProjectionService(NamedParameterJdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
    public int refreshAll() {
        jdbcTemplate.getJdbcTemplate().update("DELETE FROM software_identity_summary");
        return insertSummaryRows(new MapSqlParameterSource().addValue("nearEolThresholdDays", NEAR_EOL_THRESHOLD_DAYS), "");
    }

    @Transactional
    public int refreshTenant(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return 0;
        }
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("nearEolThresholdDays", NEAR_EOL_THRESHOLD_DAYS);
        jdbcTemplate.update("DELETE FROM software_identity_summary WHERE tenant_id = :tenantId", params);
        return insertSummaryRows(params, " AND ic.tenant_id = :tenantId");
    }

    @Transactional
    public int refreshByNormalizedKey(String normalizedKey) {
        String normalized = normalizeKey(normalizedKey);
        if (normalized == null) {
            return 0;
        }
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("normalizedKey", normalized)
                .addValue("nearEolThresholdDays", NEAR_EOL_THRESHOLD_DAYS);
        jdbcTemplate.update("DELETE FROM software_identity_summary WHERE normalized_key = :normalizedKey", params);
        return insertSummaryRows(params, """
                 AND lower(coalesce(sid.vendor, '')) || '::' || lower(coalesce(sid.product, '')) = :normalizedKey
                """);
    }

    public void ensureTenantProjection(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return;
        }
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("tenantId", tenant.getId());
        Long summaryCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM software_identity_summary WHERE tenant_id = :tenantId",
                params,
                Long.class
        );
        if (summaryCount != null && summaryCount > 0L) {
            return;
        }
        Long activeInventoryCount = jdbcTemplate.queryForObject("""
                SELECT COUNT(*)
                FROM inventory_components
                WHERE tenant_id = :tenantId
                  AND component_status = 'ACTIVE'
                  AND software_identity_id IS NOT NULL
                """, params, Long.class);
        if (activeInventoryCount != null && activeInventoryCount > 0L) {
            refreshTenant(tenant);
        }
    }

    private int insertSummaryRows(MapSqlParameterSource params, String filterClause) {
        return jdbcTemplate.update("""
                INSERT INTO software_identity_summary (
                    tenant_id,
                    software_identity_id,
                    display_name,
                    canonical_key,
                    vendor,
                    product,
                    normalized_key,
                    purl,
                    cpe23,
                    asset_types,
                    ecosystems,
                    source_systems,
                    eol_slug,
                    mapping_confirmed,
                    needs_eol_mapping,
                    asset_count,
                    component_count,
                    version_count,
                    eol_component_count,
                    near_eol_component_count,
                    unknown_eol_component_count,
                    last_observed_at,
                    summary_updated_at
                )
                SELECT
                    aggregated.tenant_id,
                    aggregated.software_identity_id,
                    aggregated.display_name,
                    aggregated.canonical_key,
                    aggregated.vendor,
                    aggregated.product,
                    aggregated.normalized_key,
                    aggregated.purl,
                    aggregated.cpe23,
                    aggregated.asset_types,
                    aggregated.ecosystems,
                    aggregated.source_systems,
                    aggregated.eol_slug,
                    aggregated.mapping_confirmed,
                    CASE
                        WHEN aggregated.eol_slug IS NOT NULL THEN FALSE
                        WHEN nullif(trim(aggregated.cpe23), '') IS NOT NULL THEN TRUE
                        WHEN coalesce(array_length(aggregated.ecosystems, 1), 0) = 0 THEN TRUE
                        WHEN EXISTS (
                            SELECT 1
                            FROM unnest(aggregated.ecosystems) AS ecosystem
                            WHERE ecosystem IS NOT NULL
                              AND lower(ecosystem) NOT IN (
                                  'npm',
                                  'pypi',
                                  'gem',
                                  'cargo',
                                  'nuget',
                                  'composer',
                                  'maven',
                                  'gomod',
                                  'golang',
                                  'go',
                                  'rubygems'
                              )
                        ) THEN TRUE
                        ELSE FALSE
                    END AS needs_eol_mapping,
                    aggregated.asset_count,
                    aggregated.component_count,
                    aggregated.version_count,
                    aggregated.eol_component_count,
                    aggregated.near_eol_component_count,
                    aggregated.unknown_eol_component_count,
                    aggregated.last_observed_at,
                    aggregated.summary_updated_at
                FROM (
                    SELECT
                        ic.tenant_id,
                        sid.id AS software_identity_id,
                        sid.display_name,
                        sid.canonical_key,
                        sid.vendor,
                        sid.product,
                        lower(coalesce(sid.vendor, '')) || '::' || lower(coalesce(sid.product, '')) AS normalized_key,
                        sid.purl,
                        sid.cpe23,
                        array_remove(array_agg(DISTINCT a.type::text), NULL) AS asset_types,
                        array_remove(array_agg(DISTINCT ic.ecosystem), NULL) AS ecosystems,
                        array_remove(array_agg(DISTINCT nullif(lower(coalesce(u.ingestion_source_system, '')), '')), NULL) AS source_systems,
                        COALESCE(mapping.eol_slug, MAX(ic.eol_slug)) AS eol_slug,
                        COALESCE(mapping.confirmed, false) AS mapping_confirmed,
                        COUNT(DISTINCT ic.asset_id) AS asset_count,
                        COUNT(DISTINCT ic.id) AS component_count,
                        COUNT(DISTINCT COALESCE(NULLIF(trim(ic.version), ''), '(unknown)')) AS version_count,
                        COUNT(*) FILTER (WHERE ic.is_eol = true) AS eol_component_count,
                        COUNT(*) FILTER (
                            WHERE ic.is_eol = false
                              AND ic.eol_date IS NOT NULL
                              AND (ic.eol_date - CURRENT_DATE) <= :nearEolThresholdDays
                        ) AS near_eol_component_count,
                        COUNT(*) FILTER (WHERE ic.eol_slug IS NULL) AS unknown_eol_component_count,
                        MAX(ic.last_observed_at) AS last_observed_at,
                        now() AS summary_updated_at
                    FROM inventory_components ic
                    JOIN software_identities sid ON sid.id = ic.software_identity_id
                    JOIN assets a ON a.id = ic.asset_id
                    LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                    LEFT JOIN LATERAL (
                        SELECT m.eol_slug, m.confirmed
                        FROM software_eol_mapping m
                        WHERE m.software_identity_id = sid.id
                           OR (
                               m.software_identity_id IS NULL
                               AND m.normalized_key = lower(coalesce(sid.vendor, '')) || '::' || lower(coalesce(sid.product, ''))
                           )
                        ORDER BY
                            CASE WHEN m.software_identity_id = sid.id THEN 0 ELSE 1 END,
                            CASE WHEN m.confirmed THEN 0 ELSE 1 END,
                            m.updated_at DESC
                        LIMIT 1
                    ) mapping ON true
                    WHERE ic.component_status = 'ACTIVE'
                      AND ic.software_identity_id IS NOT NULL
                    """ + filterClause + """
                    GROUP BY
                        ic.tenant_id,
                        sid.id,
                        sid.display_name,
                        sid.canonical_key,
                        sid.vendor,
                        sid.product,
                        sid.purl,
                        sid.cpe23,
                        mapping.eol_slug,
                        mapping.confirmed
                ) aggregated
                ON CONFLICT (tenant_id, software_identity_id) DO UPDATE SET
                    display_name = EXCLUDED.display_name,
                    canonical_key = EXCLUDED.canonical_key,
                    vendor = EXCLUDED.vendor,
                    product = EXCLUDED.product,
                    normalized_key = EXCLUDED.normalized_key,
                    purl = EXCLUDED.purl,
                    cpe23 = EXCLUDED.cpe23,
                    asset_types = EXCLUDED.asset_types,
                    ecosystems = EXCLUDED.ecosystems,
                    source_systems = EXCLUDED.source_systems,
                    eol_slug = EXCLUDED.eol_slug,
                    mapping_confirmed = EXCLUDED.mapping_confirmed,
                    needs_eol_mapping = EXCLUDED.needs_eol_mapping,
                    asset_count = EXCLUDED.asset_count,
                    component_count = EXCLUDED.component_count,
                    version_count = EXCLUDED.version_count,
                    eol_component_count = EXCLUDED.eol_component_count,
                    near_eol_component_count = EXCLUDED.near_eol_component_count,
                    unknown_eol_component_count = EXCLUDED.unknown_eol_component_count,
                    last_observed_at = EXCLUDED.last_observed_at,
                    summary_updated_at = EXCLUDED.summary_updated_at
                """, params);
    }

    private String normalizeKey(String normalizedKey) {
        if (normalizedKey == null || normalizedKey.isBlank()) {
            return null;
        }
        return normalizedKey.trim().toLowerCase(Locale.ROOT);
    }
}
