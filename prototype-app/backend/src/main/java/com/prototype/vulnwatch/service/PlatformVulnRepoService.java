package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.OrgSpecificCveExposureRecordResponse;
import com.prototype.vulnwatch.dto.PlatformVulnRepoPageResponse;
import com.prototype.vulnwatch.dto.VulnRepoDashboardResponse;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelSummarySourceRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PlatformVulnRepoService {

    private static final String EXTERNAL_ID_PREFIX = "CVE-";
    private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");

    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityIntelSummarySourceRepository vulnerabilityIntelSummarySourceRepository;
    private final VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository;
    private final VulnerabilityIntelDescriptionService vulnerabilityIntelDescriptionService;
    private final FindingRepository findingRepository;
    private final NamedParameterJdbcTemplate jdbcTemplate;

    public PlatformVulnRepoService(
            VulnerabilityRepository vulnerabilityRepository,
            VulnerabilityIntelSummarySourceRepository vulnerabilityIntelSummarySourceRepository,
            VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository,
            VulnerabilityIntelDescriptionService vulnerabilityIntelDescriptionService,
            FindingRepository findingRepository,
            NamedParameterJdbcTemplate jdbcTemplate
    ) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.vulnerabilityIntelSummarySourceRepository = vulnerabilityIntelSummarySourceRepository;
        this.vulnerabilityIntelObservationRepository = vulnerabilityIntelObservationRepository;
        this.vulnerabilityIntelDescriptionService = vulnerabilityIntelDescriptionService;
        this.findingRepository = findingRepository;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional(readOnly = true)
    public PlatformVulnRepoPageResponse listVulnerabilities(
            int page,
            int size,
            String query,
            Boolean inKev,
            String severity,
            String source
    ) {
        int safePage = Math.max(0, page);
        int safeSize = Math.min(200, Math.max(1, size));
        String normalizedQueryUpper = hasText(query) ? query.trim().toUpperCase(Locale.ROOT) : null;
        String normalizedSeverity = hasText(severity) ? severity.trim().toUpperCase(Locale.ROOT) : null;
        String normalizedSource = hasText(source) ? source.trim().toLowerCase(Locale.ROOT) : null;
        var pageable = PageRequest.of(safePage, safeSize);

        Page<Vulnerability> vulnerabilityPage = normalizedQueryUpper == null
                ? vulnerabilityRepository.searchVulnerabilityIntelWithoutQuery(
                        EXTERNAL_ID_PREFIX,
                        null,
                        false,
                        null,
                        normalizedSeverity != null,
                        normalizedSeverity == null ? List.of() : List.of(normalizedSeverity),
                        normalizedSource != null,
                        normalizedSource == null ? List.of() : List.of(normalizedSource),
                        false,
                        List.of(),
                        inKev,
                        pageable
                )
                : vulnerabilityRepository.searchVulnerabilityIntel(
                        EXTERNAL_ID_PREFIX,
                        normalizedQueryUpper,
                        null,
                        false,
                        null,
                        normalizedSeverity != null,
                        normalizedSeverity == null ? List.of() : List.of(normalizedSeverity),
                        normalizedSource != null,
                        normalizedSource == null ? List.of() : List.of(normalizedSource),
                        false,
                        List.of(),
                        inKev,
                        pageable
                );

        List<Vulnerability> vulnerabilities = vulnerabilityPage.getContent();
        List<UUID> vulnerabilityIds = vulnerabilities.stream()
                .map(Vulnerability::getId)
                .filter(Objects::nonNull)
                .toList();

        Map<UUID, List<String>> sourcesByVulnerability = new HashMap<>();
        if (!vulnerabilityIds.isEmpty()) {
            vulnerabilityIntelSummarySourceRepository.findByVulnerabilityIdIn(vulnerabilityIds)
                    .forEach(row -> sourcesByVulnerability
                            .computeIfAbsent(row.getVulnerabilityId(), ignored -> new ArrayList<>())
                            .add(row.getSourceSystem()));
        }

        Map<UUID, String> euvdIdByVulnerability = new HashMap<>();
        Map<UUID, String> jvndbIdByVulnerability = new HashMap<>();
        if (!vulnerabilityIds.isEmpty()) {
            vulnerabilityIntelObservationRepository
                    .findFirstSourceRecordIdByVulnerabilityIds(vulnerabilityIds, "euvd")
                    .forEach(row -> euvdIdByVulnerability.put(row.getVulnerabilityId(), row.getSourceRecordId()));
            vulnerabilityIntelObservationRepository
                    .findFirstSourceRecordIdByVulnerabilityIds(vulnerabilityIds, "japan-vulndb")
                    .forEach(row -> jvndbIdByVulnerability.put(row.getVulnerabilityId(), row.getSourceRecordId()));
        }

        Map<UUID, Long> openFindingsByVulnerability = new HashMap<>();
        if (!vulnerabilityIds.isEmpty()) {
            findingRepository.countByVulnerabilityIdsAndStatus(vulnerabilityIds, FindingStatus.OPEN)
                    .forEach(row -> openFindingsByVulnerability.put((UUID) row[0], (Long) row[1]));
        }

        List<OrgSpecificCveExposureRecordResponse> items = vulnerabilities.stream()
                .map(vulnerability -> new OrgSpecificCveExposureRecordResponse(
                        syntheticRecordId(vulnerability),
                        vulnerability.getId(),
                        vulnerability.getExternalId(),
                        firstNonBlank(vulnerability.getTitle(), vulnerability.getExternalId()),
                        vulnerabilityIntelDescriptionService.toDescriptionSnippet(vulnerability.getDescription()),
                        "UNKNOWN",
                        false,
                        "UNKNOWN",
                        null,
                        null,
                        normalizeSeverity(vulnerability.getSeverity()),
                        vulnerability.getCvssScore(),
                        vulnerability.getEpssScore(),
                        vulnerability.isInKev(),
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        openFindingsByVulnerability.getOrDefault(vulnerability.getId(), 0L),
                        null,
                        0L,
                        0L,
                        false,
                        null,
                        null,
                        false,
                        null,
                        null,
                        null,
                        null,
                        normalizeSources(sourcesByVulnerability.get(vulnerability.getId()), vulnerability.isInKev()),
                        euvdIdByVulnerability.get(vulnerability.getId()),
                        jvndbIdByVulnerability.get(vulnerability.getId()),
                        true,
                        normalizeSources(sourcesByVulnerability.get(vulnerability.getId()), vulnerability.isInKev()),
                        List.of()
                ))
                .toList();

        return new PlatformVulnRepoPageResponse(
                items,
                vulnerabilityPage.getNumber(),
                vulnerabilityPage.getSize(),
                vulnerabilityPage.getTotalElements(),
                vulnerabilityPage.getTotalPages()
        );
    }

    @Transactional(readOnly = true)
    public VulnRepoDashboardResponse getDashboard() {
        Instant now = Instant.now();
        Instant weekAgo = now.minus(7, ChronoUnit.DAYS);
        long trackedCount = vulnerabilityRepository.countByExternalIdStartingWith(EXTERNAL_ID_PREFIX);
        long trackedAddedLastWeek = countByUpdatedSince(weekAgo);
        long criticalCount = countBySeverity("CRITICAL");
        long exploitCount = countExploitAvailable();
        int exploitCoveragePercent = trackedCount <= 0L ? 0 : (int) Math.round((double) exploitCount * 100.0d / (double) trackedCount);

        return new VulnRepoDashboardResponse(
                now,
                new VulnRepoDashboardResponse.SummaryCards(
                        trackedCount,
                        trackedAddedLastWeek,
                        trackedCount,
                        trackedAddedLastWeek,
                        0L,
                        0L,
                        0L,
                        0L,
                        criticalCount,
                        exploitCount,
                        exploitCoveragePercent,
                        0L,
                        0L,
                        0L,
                        0L,
                        countKev(),
                        countKevAddedSince(weekAgo),
                        0L,
                        0L
                ),
                loadSeverityBreakdown(),
                new VulnRepoDashboardResponse.ResolutionStatus(0L, 0L, 0L, 0L),
                List.of(),
                List.of(),
                loadRecentAdvisories(),
                List.of()
        );
    }

    private long countByUpdatedSince(Instant start) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from vulnerabilities v
                where v.external_id like :prefix
                  and coalesce(v.updated_at, v.last_modified_at, v.published_at) >= :start
                """,
                new MapSqlParameterSource()
                        .addValue("prefix", EXTERNAL_ID_PREFIX + "%")
                        .addValue("start", Timestamp.from(start)),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countBySeverity(String severity) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from vulnerabilities v
                where v.external_id like :prefix
                  and upper(coalesce(v.severity, 'UNKNOWN')) = :severity
                """,
                new MapSqlParameterSource()
                        .addValue("prefix", EXTERNAL_ID_PREFIX + "%")
                        .addValue("severity", severity),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countExploitAvailable() {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from vulnerabilities v
                where v.external_id like :prefix
                  and (v.in_kev = true or coalesce(v.epss_score, 0) >= 0.9)
                """,
                new MapSqlParameterSource().addValue("prefix", EXTERNAL_ID_PREFIX + "%"),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countKev() {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from vulnerabilities v
                where v.external_id like :prefix
                  and v.in_kev = true
                """,
                new MapSqlParameterSource().addValue("prefix", EXTERNAL_ID_PREFIX + "%"),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countKevAddedSince(Instant start) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from vulnerabilities v
                where v.external_id like :prefix
                  and v.in_kev = true
                  and coalesce(v.updated_at, v.last_modified_at, v.published_at) >= :start
                """,
                new MapSqlParameterSource()
                        .addValue("prefix", EXTERNAL_ID_PREFIX + "%")
                        .addValue("start", Timestamp.from(start)),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private List<VulnRepoDashboardResponse.SeverityBreakdownItem> loadSeverityBreakdown() {
        Map<String, Long> counts = new LinkedHashMap<>();
        SEVERITY_ORDER.forEach(severity -> counts.put(severity, 0L));
        counts.put("UNKNOWN", 0L);

        jdbcTemplate.query(
                """
                select upper(coalesce(v.severity, 'UNKNOWN')) as severity, count(*) as total
                from vulnerabilities v
                where v.external_id like :prefix
                group by upper(coalesce(v.severity, 'UNKNOWN'))
                """,
                new MapSqlParameterSource().addValue("prefix", EXTERNAL_ID_PREFIX + "%"),
                (RowCallbackHandler) rs -> counts.put(rs.getString("severity"), rs.getLong("total"))
        );

        List<VulnRepoDashboardResponse.SeverityBreakdownItem> items = new ArrayList<>();
        counts.forEach((severity, total) -> {
            if (total > 0L || !"UNKNOWN".equals(severity)) {
                items.add(new VulnRepoDashboardResponse.SeverityBreakdownItem(severity, total));
            }
        });
        return items;
    }

    private List<VulnRepoDashboardResponse.RecentAdvisoryItem> loadRecentAdvisories() {
        return jdbcTemplate.query(
                """
                select
                  v.external_id,
                  coalesce(nullif(v.title, ''), nullif(v.description_snippet, ''), v.external_id) as title,
                  coalesce(nullif(v.description_snippet, ''), nullif(v.title, ''), v.external_id) as description_snippet,
                  upper(coalesce(v.severity, 'UNKNOWN')) as severity,
                  upper(cast(v.source as text)) as source,
                  v.published_at,
                  v.last_modified_at
                from vulnerabilities v
                where v.external_id like :prefix
                order by coalesce(v.updated_at, v.last_modified_at, v.published_at) desc, v.external_id asc
                limit 5
                """,
                new MapSqlParameterSource().addValue("prefix", EXTERNAL_ID_PREFIX + "%"),
                (rs, rowNum) -> new VulnRepoDashboardResponse.RecentAdvisoryItem(
                        rs.getString("external_id"),
                        rs.getString("title"),
                        rs.getString("description_snippet"),
                        rs.getString("severity"),
                        rs.getString("source"),
                        rs.getTimestamp("published_at") == null ? null : rs.getTimestamp("published_at").toInstant(),
                        rs.getTimestamp("last_modified_at") == null ? null : rs.getTimestamp("last_modified_at").toInstant()
                )
        );
    }

    private List<String> normalizeSources(List<String> sources, boolean inKev) {
        List<String> normalized = new ArrayList<>();
        if (sources != null) {
            for (String source : sources) {
                if (hasText(source) && normalized.stream().noneMatch(existing -> existing.equalsIgnoreCase(source))) {
                    normalized.add(source);
                }
            }
        }
        if (inKev && normalized.stream().noneMatch(existing -> existing.equalsIgnoreCase("kev"))) {
            normalized.add("kev");
        }
        return normalized;
    }

    private UUID syntheticRecordId(Vulnerability vulnerability) {
        return UUID.nameUUIDFromBytes(("platform::" + vulnerability.getExternalId()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private String normalizeSeverity(String severity) {
        if (!hasText(severity)) {
            return "UNKNOWN";
        }
        return severity.trim().toUpperCase(Locale.ROOT);
    }

    private String firstNonBlank(String primary, String fallback) {
        return hasText(primary) ? primary : fallback;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
