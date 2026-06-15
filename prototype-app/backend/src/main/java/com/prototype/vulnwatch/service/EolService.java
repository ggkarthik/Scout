package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.EolProductCatalog;
import com.prototype.vulnwatch.domain.SoftwareEolMapping;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.dto.ComponentEolStatusDto;
import com.prototype.vulnwatch.dto.EolMappingConfirmRequest;
import com.prototype.vulnwatch.dto.EolProductCatalogDto;
import com.prototype.vulnwatch.dto.EolReleaseDto;
import com.prototype.vulnwatch.dto.EolSummaryDto;
import com.prototype.vulnwatch.dto.EolUnresolvedMappingDto;
import com.prototype.vulnwatch.dto.PackageAssetDto;
import com.prototype.vulnwatch.dto.PackageEolStatusDto;
import com.prototype.vulnwatch.repo.EolProductCatalogRepository;
import com.prototype.vulnwatch.repo.EolReleaseRepository;
import com.prototype.vulnwatch.repo.SoftwareEolMappingRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import java.time.Instant;
import java.util.HashMap;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Map;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class EolService {

    private static final int NEAR_EOL_THRESHOLD_DAYS = EolConstants.NEAR_EOL_THRESHOLD_DAYS;

    /**
     * Library/package-manager ecosystems that endoflife.date does not track.
     * Excluded from "Unknown" counts and the unresolved review queue so analysts
     * only see actionable gaps — OS packages, runtimes, infrastructure software.
     */
    private static final String LIBRARY_ECOSYSTEMS_SQL =
            "'npm','pypi','gem','cargo','nuget','composer','maven','gomod','golang','go','rubygems'";

    private final EolProductCatalogRepository catalogRepository;
    private final EolReleaseRepository releaseRepository;
    private final SoftwareEolMappingRepository mappingRepository;
    private final SoftwareIdentityRepository identityRepository;
    private final JdbcTemplate jdbcTemplate;
    private final EolRefreshService eolRefreshService;
    private final RequestActorService requestActorService;

    public EolService(
            EolProductCatalogRepository catalogRepository,
            EolReleaseRepository releaseRepository,
            SoftwareEolMappingRepository mappingRepository,
            SoftwareIdentityRepository identityRepository,
            JdbcTemplate jdbcTemplate,
            EolRefreshService eolRefreshService,
            RequestActorService requestActorService) {
        this.catalogRepository = catalogRepository;
        this.releaseRepository = releaseRepository;
        this.mappingRepository = mappingRepository;
        this.identityRepository = identityRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.eolRefreshService = eolRefreshService;
        this.requestActorService = requestActorService;
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    public EolSummaryDto getSummary() {
        String sql = """
                SELECT
                    COUNT(*) FILTER (WHERE is_eol = true)                                                        AS eol_count,
                    COUNT(*) FILTER (WHERE is_eol = false
                                       AND eol_date IS NOT NULL
                                       AND (eol_date - CURRENT_DATE) <= ?)                                       AS near_eol_count,
                    COUNT(*) FILTER (WHERE is_eol = false
                                       AND (eol_date IS NULL OR (eol_date - CURRENT_DATE) > ?))                  AS supported_count,
                    COUNT(*) FILTER (WHERE eol_slug IS NULL
                                       AND (ecosystem IS NULL
                                            OR lower(ecosystem) NOT IN (""" + LIBRARY_ECOSYSTEMS_SQL + """
                                           )))                                                                    AS unknown_count,
                    COUNT(*)                                                                                      AS total_count
                FROM inventory_components
                WHERE component_status = 'ACTIVE'
                """;

        return jdbcTemplate.queryForObject(sql, (rs, rowNum) -> new EolSummaryDto(
                rs.getLong("total_count"),
                rs.getLong("eol_count"),
                rs.getLong("near_eol_count"),
                rs.getLong("supported_count"),
                rs.getLong("unknown_count")
        ), NEAR_EOL_THRESHOLD_DAYS, NEAR_EOL_THRESHOLD_DAYS);
    }

    // -------------------------------------------------------------------------
    // Component EOL statuses (paged)
    // -------------------------------------------------------------------------

    public Page<ComponentEolStatusDto> getComponentStatuses(String filter, int page, int size) {
        String whereClause = buildComponentFilterClause(filter);

        String countSql = """
                SELECT COUNT(*)
                FROM inventory_components ic
                JOIN assets a ON ic.asset_id = a.id
                WHERE ic.component_status = 'ACTIVE'
                """ + whereClause;

        String dataSql = """
                SELECT ic.id, ic.package_name, ic.ecosystem, ic.version,
                       a.name AS asset_name,
                       ic.eol_slug, ic.eol_cycle, ic.eol_date, ic.is_eol, ic.eol_support_end_date,
                       (ic.eol_date - CURRENT_DATE)::int AS eol_days_remaining
                FROM inventory_components ic
                JOIN assets a ON ic.asset_id = a.id
                WHERE ic.component_status = 'ACTIVE'
                """ + whereClause + """

                ORDER BY ic.eol_date ASC NULLS LAST, ic.package_name ASC
                LIMIT ? OFFSET ?
                """;

        Long total = jdbcTemplate.queryForObject(countSql, Long.class);
        if (total == null) {
            total = 0L;
        }

        List<ComponentEolStatusDto> items = jdbcTemplate.query(
                dataSql,
                (rs, rowNum) -> new ComponentEolStatusDto(
                        (java.util.UUID) rs.getObject("id"),
                        rs.getString("package_name"),
                        rs.getString("ecosystem"),
                        rs.getString("version"),
                        rs.getString("asset_name"),
                        rs.getString("eol_slug"),
                        rs.getString("eol_cycle"),
                        rs.getObject("eol_date", java.time.LocalDate.class),
                        rs.getObject("is_eol") != null ? rs.getBoolean("is_eol") : null,
                        rs.getObject("eol_days_remaining") != null ? rs.getInt("eol_days_remaining") : null,
                        rs.getObject("eol_support_end_date", java.time.LocalDate.class)
                ),
                size, (long) page * size);

        return new PageImpl<>(items, PageRequest.of(page, size), total);
    }

    private static final Map<String, String> FILTER_CLAUSE_WHITELIST = Map.of(
            "eol",      " AND ic.is_eol = true",
            "near-eol", " AND ic.is_eol = false AND ic.eol_date IS NOT NULL AND (ic.eol_date - CURRENT_DATE) <= " + NEAR_EOL_THRESHOLD_DAYS,
            "ok",       " AND ic.is_eol = false AND (ic.eol_date IS NULL OR (ic.eol_date - CURRENT_DATE) > " + NEAR_EOL_THRESHOLD_DAYS + ")",
            "unknown",  " AND ic.eol_slug IS NULL AND (ic.ecosystem IS NULL OR lower(ic.ecosystem) NOT IN (" + LIBRARY_ECOSYSTEMS_SQL + "))"
    );

    private String buildComponentFilterClause(String filter) {
        if (filter == null || filter.isBlank()) {
            return "";
        }
        return FILTER_CLAUSE_WHITELIST.getOrDefault(filter.toLowerCase(), "");
    }

    // -------------------------------------------------------------------------
    // Package EOL statuses — grouped by package (one row per package, not per instance)
    // -------------------------------------------------------------------------

    public Page<PackageEolStatusDto> getPackageStatuses(String filter, int page, int size) {
        String whereClause = buildComponentFilterClause(filter);

        String countSql = "SELECT COUNT(*) FROM (" +
                "SELECT 1 FROM inventory_components ic " +
                "WHERE ic.component_status = 'ACTIVE'" + whereClause +
                " GROUP BY ic.package_name, ic.ecosystem, ic.eol_slug, ic.eol_cycle, ic.eol_date, ic.is_eol" +
                ") sub";

        String dataSql = """
                SELECT ic.package_name, ic.ecosystem, ic.eol_slug, ic.eol_cycle,
                       ic.eol_date, ic.is_eol,
                       MIN((ic.eol_date - CURRENT_DATE)::int) AS eol_days_remaining,
                       COUNT(DISTINCT ic.asset_id) AS asset_count
                FROM inventory_components ic
                WHERE ic.component_status = 'ACTIVE'
                """ + whereClause + """

                GROUP BY ic.package_name, ic.ecosystem, ic.eol_slug, ic.eol_cycle, ic.eol_date, ic.is_eol
                ORDER BY ic.eol_date ASC NULLS LAST, ic.package_name ASC
                LIMIT ? OFFSET ?
                """;

        Long total = jdbcTemplate.queryForObject(countSql, Long.class);
        if (total == null) {
            total = 0L;
        }

        List<PackageEolStatusDto> items = jdbcTemplate.query(
                dataSql,
                (rs, rowNum) -> new PackageEolStatusDto(
                        rs.getString("package_name"),
                        rs.getString("ecosystem"),
                        rs.getString("eol_slug"),
                        rs.getString("eol_cycle"),
                        rs.getObject("eol_date", java.time.LocalDate.class),
                        rs.getObject("is_eol") != null ? rs.getBoolean("is_eol") : null,
                        rs.getObject("eol_days_remaining") != null ? rs.getInt("eol_days_remaining") : null,
                        rs.getLong("asset_count")
                ),
                size, (long) page * size);

        return new PageImpl<>(items, PageRequest.of(page, size), total);
    }

    // -------------------------------------------------------------------------
    // Package asset drill-down — assets that have a specific package installed
    // -------------------------------------------------------------------------

    public Page<PackageAssetDto> getPackageAssets(String packageName, String ecosystem, int page, int size) {
        boolean hasEcosystem = ecosystem != null && !ecosystem.isBlank();
        String ecosystemFilter = hasEcosystem ? " AND ic.ecosystem = ?" : "";

        String countSql = "SELECT COUNT(DISTINCT ic.asset_id) FROM inventory_components ic " +
                "WHERE ic.component_status = 'ACTIVE' AND ic.package_name = ?" + ecosystemFilter;

        String dataSql = "SELECT a.name AS asset_name, " +
                "STRING_AGG(DISTINCT ic.version, ', ' ORDER BY ic.version) AS versions " +
                "FROM inventory_components ic " +
                "JOIN assets a ON ic.asset_id = a.id " +
                "WHERE ic.component_status = 'ACTIVE' AND ic.package_name = ?" + ecosystemFilter + " " +
                "GROUP BY a.name " +
                "ORDER BY a.name ASC " +
                "LIMIT ? OFFSET ?";

        Long total;
        if (hasEcosystem) {
            total = jdbcTemplate.queryForObject(countSql, Long.class, packageName, ecosystem);
        } else {
            total = jdbcTemplate.queryForObject(countSql, Long.class, packageName);
        }
        if (total == null) {
            total = 0L;
        }

        List<PackageAssetDto> items;
        if (hasEcosystem) {
            items = jdbcTemplate.query(dataSql,
                    (rs, rowNum) -> new PackageAssetDto(
                            rs.getString("asset_name"),
                            rs.getString("versions")
                    ),
                    packageName, ecosystem, size, (long) page * size);
        } else {
            items = jdbcTemplate.query(dataSql,
                    (rs, rowNum) -> new PackageAssetDto(
                            rs.getString("asset_name"),
                            rs.getString("versions")
                    ),
                    packageName, size, (long) page * size);
        }

        return new PageImpl<>(items, PageRequest.of(page, size), total);
    }

    // -------------------------------------------------------------------------
    // Product catalog
    // -------------------------------------------------------------------------

    public List<EolProductCatalogDto> listProducts() {
        Map<String, Long> releaseCounts = new HashMap<>();
        for (Object[] row : releaseRepository.countReleasesByProductSlug()) {
            if (row.length < 2 || row[0] == null) {
                continue;
            }
            long count = row[1] instanceof Number value ? value.longValue() : 0L;
            releaseCounts.put(row[0].toString(), count);
        }

        return catalogRepository.findAll().stream()
                .sorted(Comparator.comparing(
                        (EolProductCatalog catalog) -> catalog.getDisplayName() == null || catalog.getDisplayName().isBlank()
                                ? catalog.getSlug()
                                : catalog.getDisplayName(),
                        String.CASE_INSENSITIVE_ORDER
                ).thenComparing(EolProductCatalog::getSlug, String.CASE_INSENSITIVE_ORDER))
                .map(catalog -> toCatalogDto(catalog, releaseCounts.getOrDefault(catalog.getSlug(), 0L)))
                .toList();
    }

    public List<EolReleaseDto> listReleases(String slug) {
        return releaseRepository.findByProductSlug(slug).stream()
                .map(r -> new EolReleaseDto(
                        r.getCycle(),
                        r.getReleaseDate(),
                        r.getEolDate(),
                        r.getEolBoolean(),
                        r.getSupportEndDate(),
                        r.getExtendedSupportDate(),
                        r.getSecuritySupportDate(),
                        r.getLatestVersion(),
                        r.getLatestReleaseDate(),
                        r.isLts(),
                        r.isEol(),
                        r.getEoas(),
                        r.getEoes(),
                        r.isDiscontinued(),
                        r.getOfficialSourceUrl(),
                        r.getSupportPhase()
                ))
                .toList();
    }

    // -------------------------------------------------------------------------
    // Mapping management
    // -------------------------------------------------------------------------

    @Transactional
    public void confirmMapping(EolMappingConfirmRequest request) {
        String normalizedKey = normalizeLowercaseValue(request.normalizedKey(), "Normalized key");
        String eolSlug = normalizeLowercaseValue(request.eolSlug(), "EOL slug");
        if (catalogRepository.findBySlug(eolSlug).isEmpty()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Unknown EOL slug: " + eolSlug + ". Refresh the catalog or choose a valid endoflife.date slug."
            );
        }

        Optional<SoftwareEolMapping> existing = mappingRepository.findByNormalizedKey(normalizedKey);
        SoftwareEolMapping mapping = existing.orElseGet(SoftwareEolMapping::new);
        String previousSlug = mapping.getEolSlug();
        mapping.setNormalizedKey(normalizedKey);
        mapping.setEolSlug(eolSlug);
        attachIdentityIfUnique(mapping, normalizedKey);
        mapping.setMatchConfidence("MANUAL");
        mapping.setMatchMethod("MANUAL");
        mapping.setConfirmed(true);
        mapping.setPreviousSlug(previousSlug);
        mapping.setConfirmedBy(requestActorService.currentActor().userId());
        mapping.setConfirmedAt(Instant.now());
        mapping.touch();
        mappingRepository.saveAndFlush(mapping);
        eolRefreshService.refreshConfirmedMapping(normalizedKey);
    }

    private static final String UNRESOLVED_WHERE = """
            WHERE sis.eol_slug IS NULL
              AND (
                  nullif(trim(sis.cpe23), '') IS NOT NULL
                  OR coalesce(array_length(sis.ecosystems, 1), 0) = 0
                  OR EXISTS (
                      SELECT 1
                      FROM unnest(sis.ecosystems) AS ecosystem
                      WHERE ecosystem IS NOT NULL
                        AND lower(ecosystem) NOT IN (
                            'npm','pypi','gem','cargo','nuget','composer','maven',
                            'gomod','golang','go','rubygems'
                        )
                  )
              )
            """;

    public Page<EolUnresolvedMappingDto> listUnresolvedMappings(int page, int size) {
        Long total = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM software_identity_summary sis " + UNRESOLVED_WHERE, Long.class);
        long totalCount = total == null ? 0L : total;

        List<EolUnresolvedMappingDto> content = jdbcTemplate.query("""
                WITH exposure_counts AS (
                    SELECT
                        ic.software_identity_id,
                        COUNT(DISTINCT f.id) AS open_finding_count,
                        COUNT(DISTINCT f.vulnerability_id) AS open_vulnerability_count
                    FROM inventory_components ic
                    LEFT JOIN findings f
                        ON f.component_id = ic.id
                       AND f.status = 'OPEN'
                    WHERE ic.component_status = 'ACTIVE'
                      AND ic.software_identity_id IS NOT NULL
                    GROUP BY ic.software_identity_id
                )
                SELECT
                    sis.software_identity_id,
                    sis.vendor,
                    sis.product,
                    sis.display_name,
                    sis.normalized_key,
                    sis.asset_count,
                    sis.component_count,
                    sis.version_count,
                    COALESCE(ec.open_finding_count, 0) AS open_finding_count,
                    COALESCE(ec.open_vulnerability_count, 0) AS open_vulnerability_count,
                    sis.last_observed_at
                FROM software_identity_summary sis
                LEFT JOIN exposure_counts ec ON ec.software_identity_id = sis.software_identity_id
                WHERE sis.eol_slug IS NULL
                  AND (
                      nullif(trim(sis.cpe23), '') IS NOT NULL
                      OR coalesce(array_length(sis.ecosystems, 1), 0) = 0
                      OR EXISTS (
                          SELECT 1
                          FROM unnest(sis.ecosystems) AS ecosystem
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
                      )
                  )
                ORDER BY
                    COALESCE(ec.open_finding_count, 0) DESC,
                    COALESCE(ec.open_vulnerability_count, 0) DESC,
                    sis.component_count DESC,
                    sis.asset_count DESC,
                    sis.display_name ASC NULLS LAST,
                    sis.canonical_key ASC NULLS LAST
                LIMIT ? OFFSET ?
                """, (rs, rowNum) -> new EolUnresolvedMappingDto(
                (java.util.UUID) rs.getObject("software_identity_id"),
                rs.getString("vendor"),
                rs.getString("product"),
                rs.getString("display_name"),
                rs.getString("normalized_key"),
                rs.getLong("asset_count"),
                rs.getLong("component_count"),
                rs.getLong("version_count"),
                rs.getLong("open_finding_count"),
                rs.getLong("open_vulnerability_count"),
                rs.getTimestamp("last_observed_at") == null ? null : rs.getTimestamp("last_observed_at").toInstant()
        ), size, (long) page * size);

        return new PageImpl<>(content, PageRequest.of(page, size), totalCount);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private EolProductCatalogDto toCatalogDto(EolProductCatalog catalog, long releaseCount) {
        return new EolProductCatalogDto(
                catalog.getSlug(),
                catalog.getDisplayName(),
                catalog.getCpeVendor(),
                catalog.getCpeProduct(),
                catalog.getPurlType(),
                catalog.getPurlNamespace(),
                catalog.getAliasesList(),
                releaseCount,
                catalog.getLastModified(),
                catalog.getLastFetchedAt()
        );
    }

    private void attachIdentityIfUnique(SoftwareEolMapping mapping, String normalizedKey) {
        String[] parts = splitNormalizedKey(normalizedKey);
        if (parts == null) {
            mapping.setSoftwareIdentityId(null);
            return;
        }

        List<SoftwareIdentity> matches = identityRepository.findAllByVendorIgnoreCaseAndProductIgnoreCase(parts[0], parts[1]);
        if (matches.size() == 1) {
            mapping.setSoftwareIdentityId(matches.get(0).getId());
            return;
        }

        mapping.setSoftwareIdentityId(null);
    }

    private String[] splitNormalizedKey(String normalizedKey) {
        if (normalizedKey == null || normalizedKey.isBlank()) {
            return null;
        }
        int separator = normalizedKey.indexOf("::");
        if (separator < 0) {
            return null;
        }
        String vendor = normalizedKey.substring(0, separator).trim().toLowerCase(Locale.ROOT);
        String product = normalizedKey.substring(separator + 2).trim().toLowerCase(Locale.ROOT);
        if (product.isBlank()) {
            return null;
        }
        return new String[]{vendor, product};
    }

    private String normalizeLowercaseValue(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, fieldName + " is required");
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
