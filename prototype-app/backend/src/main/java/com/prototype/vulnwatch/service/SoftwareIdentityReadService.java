package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SoftwareIdentityAssetResponse;
import com.prototype.vulnwatch.dto.SoftwareIdentityDetailResponse;
import com.prototype.vulnwatch.dto.SoftwareIdentityPageResponse;
import com.prototype.vulnwatch.dto.SoftwareIdentitySummaryResponse;
import com.prototype.vulnwatch.dto.SoftwareIdentityVersionResponse;
import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class SoftwareIdentityReadService {

    private static final int MAX_PAGE_SIZE = 200;
    private static final int DETAIL_ASSET_LIMIT = 200;

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final SoftwareIdentitySummaryProjectionService projectionService;

    public SoftwareIdentityReadService(
            NamedParameterJdbcTemplate jdbcTemplate,
            SoftwareIdentitySummaryProjectionService projectionService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.projectionService = projectionService;
    }

    public SoftwareIdentityPageResponse listPage(
            Tenant tenant,
            List<AssetType> assetTypes,
            List<String> sourceSystems,
            List<String> ecosystems,
            String query,
            String lifecycle,
            String mappingState,
            int page,
            int size
    ) {
        requireTenant(tenant);
        projectionService.ensureTenantProjection(tenant);

        int safePage = Math.max(0, page);
        int safeSize = Math.min(MAX_PAGE_SIZE, Math.max(1, size));
        ProjectionFilters filters = buildProjectionFilters(tenant, assetTypes, sourceSystems, ecosystems, query, lifecycle, mappingState);
        MapSqlParameterSource params = filters.params()
                .addValue("limit", safeSize)
                .addValue("offset", (long) safePage * safeSize);

        Long total = jdbcTemplate.queryForObject(countSql(filters.whereClause()), params, Long.class);
        long totalElements = total == null ? 0L : total;
        List<SoftwareIdentityProjectionRow> rows = jdbcTemplate.query(
                summarySql(filters.whereClause()),
                params,
                (rs, rowNum) -> toProjectionRow(rs)
        );

        Map<UUID, ExposureCounts> exposureCounts = loadExposureCounts(tenant.getId(), rows.stream().map(SoftwareIdentityProjectionRow::id).toList());
        List<SoftwareIdentitySummaryResponse> content = rows.stream()
                .map(row -> toSummaryResponse(row, exposureCounts.getOrDefault(row.id(), ExposureCounts.ZERO)))
                .toList();

        return new SoftwareIdentityPageResponse(
                content,
                safePage,
                safeSize,
                totalElements,
                totalElements == 0L ? 0 : (int) Math.ceil((double) totalElements / (double) safeSize)
        );
    }

    public SoftwareIdentityDetailResponse getDetail(Tenant tenant, UUID softwareIdentityId) {
        requireTenant(tenant);
        projectionService.ensureTenantProjection(tenant);

        MapSqlParameterSource summaryParams = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("softwareIdentityId", softwareIdentityId);
        SoftwareIdentityProjectionRow summary = jdbcTemplate.query(
                detailSummarySql(),
                summaryParams,
                rs -> rs.next() ? toProjectionRow(rs) : null
        );
        if (summary == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Software identity not found in active inventory");
        }

        Map<UUID, ExposureCounts> exposureCounts = loadExposureCounts(tenant.getId(), List.of(softwareIdentityId));
        ExposureCounts counts = exposureCounts.getOrDefault(softwareIdentityId, ExposureCounts.ZERO);

        SqlFilters filters = buildIdentityScope(tenant, softwareIdentityId);
        List<SoftwareIdentityVersionResponse> versions = jdbcTemplate.query(
                detailVersionsSql(filters.whereClause()),
                filters.params(),
                (rs, rowNum) -> new SoftwareIdentityVersionResponse(
                        rs.getString("version"),
                        rs.getString("eol_slug"),
                        rs.getString("eol_cycle"),
                        rs.getObject("eol_date", LocalDate.class),
                        rs.getObject("support_end_date", LocalDate.class),
                        rs.getObject("is_eol") == null ? null : rs.getBoolean("is_eol"),
                        rs.getObject("eol_days_remaining") == null ? null : rs.getInt("eol_days_remaining"),
                        rs.getLong("asset_count"),
                        rs.getLong("component_count"),
                        rs.getLong("open_finding_count"),
                        rs.getLong("open_vulnerability_count"),
                        getInstant(rs, "last_observed_at")
                )
        );

        MapSqlParameterSource assetParams = new MapSqlParameterSource()
                .addValues(filters.params().getValues())
                .addValue("assetLimit", DETAIL_ASSET_LIMIT);
        List<SoftwareIdentityAssetResponse> assets = jdbcTemplate.query(
                detailAssetsSql(filters.whereClause()),
                assetParams,
                (rs, rowNum) -> new SoftwareIdentityAssetResponse(
                        getUuid(rs, "asset_id"),
                        rs.getString("asset_name"),
                        rs.getString("asset_identifier"),
                        rs.getString("asset_type"),
                        getUuid(rs, "component_id"),
                        rs.getString("package_name"),
                        rs.getString("ecosystem"),
                        rs.getString("version"),
                        rs.getString("source_system"),
                        rs.getString("eol_slug"),
                        rs.getString("eol_cycle"),
                        rs.getObject("eol_date", LocalDate.class),
                        rs.getObject("is_eol") == null ? null : rs.getBoolean("is_eol"),
                        rs.getObject("eol_days_remaining") == null ? null : rs.getInt("eol_days_remaining"),
                        rs.getLong("open_finding_count"),
                        rs.getLong("open_vulnerability_count"),
                        getInstant(rs, "last_observed_at")
                )
        );

        return new SoftwareIdentityDetailResponse(
                summary.id(),
                summary.displayName(),
                summary.canonicalKey(),
                summary.vendor(),
                summary.product(),
                summary.normalizedKey(),
                summary.purl(),
                summary.cpe23(),
                summary.assetTypes(),
                summary.ecosystems(),
                summary.sourceSystems(),
                summary.eolSlug(),
                summary.mappingConfirmed(),
                summary.needsEolMapping(),
                summary.assetCount(),
                summary.componentCount(),
                summary.versionCount(),
                summary.eolComponentCount(),
                summary.nearEolComponentCount(),
                summary.unknownEolComponentCount(),
                counts.openFindingCount(),
                counts.openVulnerabilityCount(),
                summary.lastObservedAt(),
                versions,
                assets
        );
    }

    private void requireTenant(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tenant is required");
        }
    }

    private SoftwareIdentitySummaryResponse toSummaryResponse(SoftwareIdentityProjectionRow row, ExposureCounts counts) {
        return new SoftwareIdentitySummaryResponse(
                row.id(),
                row.displayName(),
                row.canonicalKey(),
                row.vendor(),
                row.product(),
                row.normalizedKey(),
                row.assetTypes(),
                row.ecosystems(),
                row.sourceSystems(),
                row.eolSlug(),
                row.mappingConfirmed(),
                row.needsEolMapping(),
                row.assetCount(),
                row.componentCount(),
                row.versionCount(),
                row.eolComponentCount(),
                row.nearEolComponentCount(),
                row.unknownEolComponentCount(),
                counts.openFindingCount(),
                counts.openVulnerabilityCount(),
                row.lastObservedAt()
        );
    }

    private SoftwareIdentityProjectionRow toProjectionRow(ResultSet rs) throws SQLException {
        return new SoftwareIdentityProjectionRow(
                getUuid(rs, "software_identity_id"),
                rs.getString("display_name"),
                rs.getString("canonical_key"),
                rs.getString("vendor"),
                rs.getString("product"),
                rs.getString("normalized_key"),
                rs.getString("purl"),
                rs.getString("cpe23"),
                toStringList(rs, "asset_types"),
                toStringList(rs, "ecosystems"),
                toStringList(rs, "source_systems"),
                rs.getString("eol_slug"),
                rs.getBoolean("mapping_confirmed"),
                rs.getBoolean("needs_eol_mapping"),
                rs.getLong("asset_count"),
                rs.getLong("component_count"),
                rs.getLong("version_count"),
                rs.getLong("eol_component_count"),
                rs.getLong("near_eol_component_count"),
                rs.getLong("unknown_eol_component_count"),
                getInstant(rs, "last_observed_at")
        );
    }

    private ProjectionFilters buildProjectionFilters(
            Tenant tenant,
            List<AssetType> assetTypes,
            List<String> sourceSystems,
            List<String> ecosystems,
            String query,
            String lifecycle,
            String mappingState
    ) {
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("tenantId", tenant.getId());
        StringBuilder where = new StringBuilder("""
                WHERE sis.tenant_id = :tenantId
                """);

        List<String> normalizedAssetTypes = assetTypes == null ? List.of() : assetTypes.stream().map(Enum::name).distinct().toList();
        if (!normalizedAssetTypes.isEmpty()) {
            params.addValue("assetTypes", normalizedAssetTypes);
            where.append("""
                     AND EXISTS (
                         SELECT 1
                         FROM unnest(sis.asset_types) asset_type
                         WHERE asset_type IN (:assetTypes)
                     )
                    """);
        }

        List<String> normalizedSourceSystems = normalizeValueList(sourceSystems, this::normalizeExactValue);
        if (!normalizedSourceSystems.isEmpty()) {
            params.addValue("sourceSystems", normalizedSourceSystems);
            where.append("""
                     AND EXISTS (
                         SELECT 1
                         FROM unnest(sis.source_systems) source_system
                         WHERE source_system IN (:sourceSystems)
                     )
                    """);
        }

        List<String> normalizedEcosystems = normalizeValueList(ecosystems, this::normalizeExactValue);
        if (!normalizedEcosystems.isEmpty()) {
            params.addValue("ecosystems", normalizedEcosystems);
            where.append("""
                     AND EXISTS (
                         SELECT 1
                         FROM unnest(sis.ecosystems) ecosystem
                         WHERE ecosystem IN (:ecosystems)
                     )
                    """);
        }

        String queryPattern = buildQueryPattern(query);
        if (queryPattern != null) {
            params.addValue("queryPattern", queryPattern);
            where.append("""
                     AND (
                       lower(coalesce(sis.display_name, '')) LIKE :queryPattern
                       OR lower(coalesce(sis.canonical_key, '')) LIKE :queryPattern
                       OR lower(coalesce(sis.vendor, '')) LIKE :queryPattern
                       OR lower(coalesce(sis.product, '')) LIKE :queryPattern
                       OR lower(coalesce(sis.normalized_key, '')) LIKE :queryPattern
                       OR lower(coalesce(sis.purl, '')) LIKE :queryPattern
                       OR lower(coalesce(sis.cpe23, '')) LIKE :queryPattern
                     )
                    """);
        }

        String normalizedLifecycle = normalizeLifecycle(lifecycle);
        if (normalizedLifecycle != null) {
            where.append(switch (normalizedLifecycle) {
                case "eol" -> """
                         AND sis.eol_component_count > 0
                        """;
                case "near-eol" -> """
                         AND sis.eol_component_count = 0
                         AND sis.near_eol_component_count > 0
                        """;
                case "unknown" -> """
                         AND sis.eol_component_count = 0
                         AND sis.near_eol_component_count = 0
                         AND sis.unknown_eol_component_count > 0
                        """;
                case "supported" -> """
                         AND sis.eol_component_count = 0
                         AND sis.near_eol_component_count = 0
                         AND sis.unknown_eol_component_count = 0
                        """;
                default -> "";
            });
        }

        String normalizedMappingState = normalizeMappingState(mappingState);
        if (normalizedMappingState != null) {
            where.append(switch (normalizedMappingState) {
                case "needs-review" -> """
                         AND sis.needs_eol_mapping = true
                        """;
                case "mapped" -> """
                         AND sis.eol_slug IS NOT NULL
                        """;
                case "manual" -> """
                         AND sis.mapping_confirmed = true
                        """;
                case "automatic" -> """
                         AND sis.eol_slug IS NOT NULL
                         AND sis.mapping_confirmed = false
                        """;
                default -> "";
            });
        }

        return new ProjectionFilters(where.toString(), params);
    }

    private SqlFilters buildIdentityScope(Tenant tenant, UUID softwareIdentityId) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("softwareIdentityId", softwareIdentityId);
        return new SqlFilters("""
                WHERE ic.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND ic.software_identity_id = :softwareIdentityId
                """, params);
    }

    private Map<UUID, ExposureCounts> loadExposureCounts(UUID tenantId, List<UUID> softwareIdentityIds) {
        if (tenantId == null || softwareIdentityIds == null || softwareIdentityIds.isEmpty()) {
            return Map.of();
        }
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("tenantId", tenantId)
                .addValue("softwareIdentityIds", softwareIdentityIds);
        Map<UUID, ExposureCounts> counts = new HashMap<>();
        jdbcTemplate.query("""
                SELECT
                    ic.software_identity_id,
                    COUNT(DISTINCT f.id) AS open_finding_count,
                    COUNT(DISTINCT f.vulnerability_id) AS open_vulnerability_count
                FROM inventory_components ic
                JOIN findings f
                    ON f.component_id = ic.id
                   AND f.tenant_id = :tenantId
                   AND f.status = 'OPEN'
                WHERE ic.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND ic.software_identity_id IN (:softwareIdentityIds)
                GROUP BY ic.software_identity_id
                """, params, (ResultSet rs) -> {
            counts.put(
                    getUuid(rs, "software_identity_id"),
                    new ExposureCounts(
                            rs.getLong("open_finding_count"),
                            rs.getLong("open_vulnerability_count")
                    )
            );
        });
        return counts;
    }

    private String countSql(String whereClause) {
        return """
                SELECT COUNT(*)
                FROM software_identity_summary sis
                """ + whereClause;
    }

    private String summarySql(String whereClause) {
        return """
                SELECT
                    sis.software_identity_id,
                    sis.display_name,
                    sis.canonical_key,
                    sis.vendor,
                    sis.product,
                    sis.normalized_key,
                    sis.purl,
                    sis.cpe23,
                    sis.asset_types,
                    sis.ecosystems,
                    sis.source_systems,
                    sis.eol_slug,
                    sis.mapping_confirmed,
                    sis.needs_eol_mapping,
                    sis.asset_count,
                    sis.component_count,
                    sis.version_count,
                    sis.eol_component_count,
                    sis.near_eol_component_count,
                    sis.unknown_eol_component_count,
                    sis.last_observed_at
                FROM software_identity_summary sis
                """ + whereClause + """
                ORDER BY
                    sis.component_count DESC,
                    sis.display_name ASC NULLS LAST,
                    sis.canonical_key ASC NULLS LAST
                LIMIT :limit OFFSET :offset
                """;
    }

    private String detailSummarySql() {
        return """
                SELECT
                    sis.software_identity_id,
                    sis.display_name,
                    sis.canonical_key,
                    sis.vendor,
                    sis.product,
                    sis.normalized_key,
                    sis.purl,
                    sis.cpe23,
                    sis.asset_types,
                    sis.ecosystems,
                    sis.source_systems,
                    sis.eol_slug,
                    sis.mapping_confirmed,
                    sis.needs_eol_mapping,
                    sis.asset_count,
                    sis.component_count,
                    sis.version_count,
                    sis.eol_component_count,
                    sis.near_eol_component_count,
                    sis.unknown_eol_component_count,
                    sis.last_observed_at
                FROM software_identity_summary sis
                WHERE sis.tenant_id = :tenantId
                  AND sis.software_identity_id = :softwareIdentityId
                """;
    }

    private String filteredComponentsCte(String whereClause) {
        return """
                WITH filtered_components AS (
                    SELECT
                        ic.id AS component_id,
                        ic.software_identity_id,
                        ic.package_name,
                        ic.version,
                        ic.ecosystem,
                        ic.eol_slug,
                        ic.eol_cycle,
                        ic.eol_date,
                        ic.eol_support_end_date,
                        ic.is_eol,
                        ic.last_observed_at,
                        a.id AS asset_id,
                        a.name AS asset_name,
                        a.identifier AS asset_identifier,
                        a.type AS asset_type,
                        lower(coalesce(u.ingestion_source_system, '')) AS source_system
                    FROM inventory_components ic
                    JOIN assets a ON a.id = ic.asset_id
                    LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                """ + whereClause + """
                )
                """;
    }

    private String detailVersionsSql(String whereClause) {
        return filteredComponentsCte(whereClause) + """
                SELECT
                    COALESCE(NULLIF(trim(fc.version), ''), '(unknown)') AS version,
                    MAX(fc.eol_slug) AS eol_slug,
                    MAX(fc.eol_cycle) AS eol_cycle,
                    MAX(fc.eol_date) AS eol_date,
                    MAX(fc.eol_support_end_date) AS support_end_date,
                    BOOL_OR(fc.is_eol = true) AS is_eol,
                    CASE
                        WHEN MAX(fc.eol_date) IS NOT NULL THEN (MAX(fc.eol_date) - CURRENT_DATE)::int
                        ELSE NULL
                    END AS eol_days_remaining,
                    COUNT(DISTINCT fc.asset_id) AS asset_count,
                    COUNT(DISTINCT fc.component_id) AS component_count,
                    COUNT(DISTINCT f.id) AS open_finding_count,
                    COUNT(DISTINCT f.vulnerability_id) AS open_vulnerability_count,
                    MAX(fc.last_observed_at) AS last_observed_at
                FROM filtered_components fc
                LEFT JOIN findings f
                    ON f.component_id = fc.component_id
                   AND f.tenant_id = :tenantId
                   AND f.status = 'OPEN'
                GROUP BY COALESCE(NULLIF(trim(fc.version), ''), '(unknown)')
                ORDER BY
                    COUNT(DISTINCT fc.component_id) DESC,
                    COALESCE(NULLIF(trim(fc.version), ''), '(unknown)') ASC
                """;
    }

    private String detailAssetsSql(String whereClause) {
        return filteredComponentsCte(whereClause) + """
                SELECT
                    fc.asset_id,
                    fc.asset_name,
                    fc.asset_identifier,
                    fc.asset_type,
                    fc.component_id,
                    fc.package_name,
                    fc.ecosystem,
                    fc.version,
                    NULLIF(fc.source_system, '') AS source_system,
                    fc.eol_slug,
                    fc.eol_cycle,
                    fc.eol_date,
                    fc.is_eol,
                    CASE
                        WHEN fc.eol_date IS NOT NULL THEN (fc.eol_date - CURRENT_DATE)::int
                        ELSE NULL
                    END AS eol_days_remaining,
                    COUNT(DISTINCT f.id) AS open_finding_count,
                    COUNT(DISTINCT f.vulnerability_id) AS open_vulnerability_count,
                    fc.last_observed_at
                FROM filtered_components fc
                LEFT JOIN findings f
                    ON f.component_id = fc.component_id
                   AND f.tenant_id = :tenantId
                   AND f.status = 'OPEN'
                GROUP BY
                    fc.asset_id,
                    fc.asset_name,
                    fc.asset_identifier,
                    fc.asset_type,
                    fc.component_id,
                    fc.package_name,
                    fc.ecosystem,
                    fc.version,
                    fc.source_system,
                    fc.eol_slug,
                    fc.eol_cycle,
                    fc.eol_date,
                    fc.is_eol,
                    fc.last_observed_at
                ORDER BY
                    fc.asset_name ASC,
                    fc.package_name ASC,
                    COALESCE(NULLIF(trim(fc.version), ''), '(unknown)') ASC
                LIMIT :assetLimit
                """;
    }

    private UUID getUuid(ResultSet rs, String column) throws SQLException {
        Object value = rs.getObject(column);
        return value instanceof UUID uuid ? uuid : null;
    }

    private Instant getInstant(ResultSet rs, String column) throws SQLException {
        OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return value == null ? null : value.toInstant();
    }

    private List<String> toStringList(ResultSet rs, String column) throws SQLException {
        Array sqlArray = rs.getArray(column);
        if (sqlArray == null) {
            return List.of();
        }
        Object raw = sqlArray.getArray();
        if (!(raw instanceof Object[] values)) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = value.toString().trim();
            if (!text.isEmpty()) {
                result.add(text);
            }
        }
        return result;
    }

    private List<String> normalizeValueList(Collection<String> values, java.util.function.Function<String, String> normalizer) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return values.stream()
                .filter(value -> value != null && !value.isBlank())
                .map(normalizer)
                .distinct()
                .toList();
    }

    private String buildQueryPattern(String query) {
        if (query == null || query.isBlank()) {
            return null;
        }
        return "%" + query.trim().toLowerCase(Locale.ROOT) + "%";
    }

    private String normalizeExactValue(String value) {
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeLifecycle(String lifecycle) {
        if (lifecycle == null || lifecycle.isBlank()) {
            return null;
        }
        return lifecycle.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeMappingState(String mappingState) {
        if (mappingState == null || mappingState.isBlank()) {
            return null;
        }
        return mappingState.trim().toLowerCase(Locale.ROOT);
    }

    private record ProjectionFilters(String whereClause, MapSqlParameterSource params) {
    }

    private record SqlFilters(String whereClause, MapSqlParameterSource params) {
    }

    private record ExposureCounts(long openFindingCount, long openVulnerabilityCount) {
        private static final ExposureCounts ZERO = new ExposureCounts(0L, 0L);
    }

    private record SoftwareIdentityProjectionRow(
            UUID id,
            String displayName,
            String canonicalKey,
            String vendor,
            String product,
            String normalizedKey,
            String purl,
            String cpe23,
            List<String> assetTypes,
            List<String> ecosystems,
            List<String> sourceSystems,
            String eolSlug,
            boolean mappingConfirmed,
            boolean needsEolMapping,
            long assetCount,
            long componentCount,
            long versionCount,
            long eolComponentCount,
            long nearEolComponentCount,
            long unknownEolComponentCount,
            Instant lastObservedAt
    ) {
    }
}
