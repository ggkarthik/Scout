package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.EolProductCatalog;
import com.prototype.vulnwatch.domain.SoftwareEolMapping;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.dto.ComponentEolStatusDto;
import com.prototype.vulnwatch.dto.EolMappingConfirmRequest;
import com.prototype.vulnwatch.dto.EolProductCatalogDto;
import com.prototype.vulnwatch.dto.EolReleaseDto;
import com.prototype.vulnwatch.dto.EolSummaryDto;
import com.prototype.vulnwatch.repo.EolProductCatalogRepository;
import com.prototype.vulnwatch.repo.EolReleaseRepository;
import com.prototype.vulnwatch.repo.SoftwareEolMappingRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class EolService {

    private static final int NEAR_EOL_THRESHOLD_DAYS = EolConstants.NEAR_EOL_THRESHOLD_DAYS;

    private final EolProductCatalogRepository catalogRepository;
    private final EolReleaseRepository releaseRepository;
    private final SoftwareEolMappingRepository mappingRepository;
    private final SoftwareIdentityRepository identityRepository;
    private final JdbcTemplate jdbcTemplate;

    public EolService(
            EolProductCatalogRepository catalogRepository,
            EolReleaseRepository releaseRepository,
            SoftwareEolMappingRepository mappingRepository,
            SoftwareIdentityRepository identityRepository,
            JdbcTemplate jdbcTemplate) {
        this.catalogRepository = catalogRepository;
        this.releaseRepository = releaseRepository;
        this.mappingRepository = mappingRepository;
        this.identityRepository = identityRepository;
        this.jdbcTemplate = jdbcTemplate;
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
                    COUNT(*) FILTER (WHERE eol_slug IS NULL)                                                     AS unknown_count,
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

    private String buildComponentFilterClause(String filter) {
        if (filter == null || filter.isBlank()) {
            return "";
        }
        return switch (filter.toLowerCase()) {
            case "eol"      -> " AND ic.is_eol = true";
            case "near-eol" -> " AND ic.is_eol = false AND ic.eol_date IS NOT NULL AND (ic.eol_date - CURRENT_DATE) <= " + NEAR_EOL_THRESHOLD_DAYS;
            case "ok"       -> " AND ic.is_eol = false AND (ic.eol_date IS NULL OR (ic.eol_date - CURRENT_DATE) > " + NEAR_EOL_THRESHOLD_DAYS + ")";
            case "unknown"  -> " AND ic.eol_slug IS NULL";
            default         -> "";
        };
    }

    // -------------------------------------------------------------------------
    // Product catalog
    // -------------------------------------------------------------------------

    public List<EolProductCatalogDto> listProducts() {
        return catalogRepository.findAll().stream()
                .map(this::toCatalogDto)
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
        Optional<SoftwareEolMapping> existing = mappingRepository.findByNormalizedKey(request.normalizedKey());
        SoftwareEolMapping mapping = existing.orElseGet(SoftwareEolMapping::new);
        mapping.setNormalizedKey(request.normalizedKey());
        mapping.setEolSlug(request.eolSlug());
        mapping.setMatchConfidence("MANUAL");
        mapping.setMatchMethod("MANUAL");
        mapping.setConfirmed(true);
        mapping.touch();
        mappingRepository.save(mapping);
    }

    public List<SoftwareIdentity> listUnresolvedIdentities() {
        Set<String> resolvedKeys = mappingRepository.findAll().stream()
                .map(SoftwareEolMapping::getNormalizedKey)
                .filter(java.util.Objects::nonNull)
                .collect(java.util.stream.Collectors.toCollection(java.util.HashSet::new));

        return identityRepository.findAll().stream()
                .filter(identity -> {
                    String key = (identity.getVendor() == null ? "" : identity.getVendor().toLowerCase())
                            + "::" + (identity.getProduct() == null ? "" : identity.getProduct().toLowerCase());
                    return !resolvedKeys.contains(key);
                })
                .limit(200)
                .toList();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private EolProductCatalogDto toCatalogDto(EolProductCatalog catalog) {
        return new EolProductCatalogDto(
                catalog.getSlug(),
                catalog.getDisplayName(),
                catalog.getCpeVendor(),
                catalog.getCpeProduct(),
                catalog.getPurlType(),
                catalog.getPurlNamespace()
        );
    }
}
