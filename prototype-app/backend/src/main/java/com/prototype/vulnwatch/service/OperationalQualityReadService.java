package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OperationalQualityDomainCountResponse;
import com.prototype.vulnwatch.dto.OperationalQualityDrilldownTargetResponse;
import com.prototype.vulnwatch.dto.OperationalQualityFilterValuesResponse;
import com.prototype.vulnwatch.dto.OperationalQualityIssueDetailResponse;
import com.prototype.vulnwatch.dto.OperationalQualityIssuePageResponse;
import com.prototype.vulnwatch.dto.OperationalQualityIssueResponse;
import com.prototype.vulnwatch.dto.OperationalQualitySampleRecordResponse;
import com.prototype.vulnwatch.dto.OperationalQualitySummaryResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
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
public class OperationalQualityReadService {

    private static final int MAX_PAGE_SIZE = 200;
    private static final List<String> DOMAIN_ORDER = List.of(
            "INGESTION",
            "NORMALIZATION",
            "CORRELATION",
            "VEX",
            "EOL",
            "PROJECTION_FRESHNESS"
    );
    private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");
    private static final TypeReference<Map<String, Object>> EVIDENCE_TYPE = new TypeReference<>() { };

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final QualityIssueProjectionService projectionService;
    private final ObjectMapper objectMapper;

    public OperationalQualityReadService(
            NamedParameterJdbcTemplate jdbcTemplate,
            QualityIssueProjectionService projectionService,
            ObjectMapper objectMapper
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.projectionService = projectionService;
        this.objectMapper = objectMapper;
    }

    public OperationalQualitySummaryResponse getSummary(Tenant tenant) {
        requireTenant(tenant);
        projectionService.ensureTenantProjection(tenant);

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("newIssueThreshold", Timestamp.from(Instant.now().minus(24, ChronoUnit.HOURS)));

        long totalIssues = queryLong("""
                SELECT COUNT(*)
                FROM quality_issue_projection
                WHERE tenant_id = :tenantId
                """, params);
        long criticalIssues = queryLong("""
                SELECT COUNT(*)
                FROM quality_issue_projection
                WHERE tenant_id = :tenantId
                  AND severity = 'CRITICAL'
                """, params);
        long affectsActiveFindingsCount = queryLong("""
                SELECT COUNT(*)
                FROM quality_issue_projection
                WHERE tenant_id = :tenantId
                  AND affects_active_findings = true
                """, params);
        long newIssuesLast24h = queryLong("""
                SELECT COUNT(*)
                FROM quality_issue_projection
                WHERE tenant_id = :tenantId
                  AND first_seen_at >= :newIssueThreshold
                """, params);

        Map<String, Long> countsByDomain = new LinkedHashMap<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList("""
                SELECT domain, COUNT(*) AS issue_count
                FROM quality_issue_projection
                WHERE tenant_id = :tenantId
                GROUP BY domain
                """, params)) {
            countsByDomain.put(String.valueOf(row.get("domain")), ((Number) row.get("issue_count")).longValue());
        }

        List<OperationalQualityDomainCountResponse> domainCounts = DOMAIN_ORDER.stream()
                .map(domain -> new OperationalQualityDomainCountResponse(domain, countsByDomain.getOrDefault(domain, 0L)))
                .toList();

        return new OperationalQualitySummaryResponse(
                Instant.now(),
                totalIssues,
                criticalIssues,
                affectsActiveFindingsCount,
                newIssuesLast24h,
                domainCounts
        );
    }

    public OperationalQualityIssuePageResponse listIssues(
            Tenant tenant,
            String domain,
            String issueType,
            String severity,
            Boolean affectsActiveFindings,
            List<AssetType> assetTypes,
            List<String> sourceSystems,
            List<String> ecosystems,
            String query,
            int page,
            int size
    ) {
        requireTenant(tenant);
        projectionService.ensureTenantProjection(tenant);

        int safePage = Math.max(0, page);
        int safeSize = Math.min(MAX_PAGE_SIZE, Math.max(1, size));
        SqlFilters filters = buildFilters(
                tenant,
                domain,
                issueType,
                severity,
                affectsActiveFindings,
                assetTypes,
                sourceSystems,
                ecosystems,
                query
        );
        MapSqlParameterSource params = filters.params()
                .addValue("limit", safeSize)
                .addValue("offset", (long) safePage * safeSize);

        long totalItems = queryLong(countSql(filters.whereClause()), params);
        List<OperationalQualityIssueResponse> items = jdbcTemplate.query(
                listSql(filters.whereClause()),
                params,
                (rs, rowNum) -> new OperationalQualityIssueResponse(
                        rs.getString("id"),
                        rs.getString("issue_key"),
                        rs.getString("domain"),
                        rs.getString("issue_type"),
                        rs.getString("severity"),
                        rs.getString("reason_code"),
                        rs.getString("title"),
                        rs.getString("source_object_type"),
                        rs.getString("source_object_id"),
                        rs.getString("primary_label"),
                        rs.getString("secondary_label"),
                        rs.getString("asset_type"),
                        rs.getString("source_system"),
                        rs.getString("ecosystem"),
                        rs.getBoolean("affects_active_findings"),
                        rs.getLong("affected_asset_count"),
                        rs.getLong("affected_component_count"),
                        rs.getLong("open_finding_count"),
                        rs.getLong("open_vulnerability_count"),
                        getInstant(rs, "first_seen_at"),
                        getInstant(rs, "last_seen_at")
                )
        );

        return new OperationalQualityIssuePageResponse(
                items,
                safePage,
                safeSize,
                totalItems,
                totalItems == 0L ? 0 : (int) Math.ceil((double) totalItems / (double) safeSize)
        );
    }

    public OperationalQualityIssueDetailResponse getIssueDetail(Tenant tenant, String issueId) {
        requireTenant(tenant);
        projectionService.ensureTenantProjection(tenant);
        if (issueId == null || issueId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Issue id is required");
        }

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("issueId", issueId.trim());
        QualityIssueRow row = jdbcTemplate.query(detailSql(), params, rs -> rs.next() ? toRow(rs) : null);
        if (row == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Quality issue not found");
        }

        String evidenceJson = prettyJson(row.evidenceJson());
        OverrideInfo overrideInfo = resolveOverrideInfo(tenant, row);
        return new OperationalQualityIssueDetailResponse(
                row.id(),
                row.issueKey(),
                row.domain(),
                row.issueType(),
                row.severity(),
                row.reasonCode(),
                row.title(),
                row.sourceObjectType(),
                row.sourceObjectId(),
                row.primaryLabel(),
                row.secondaryLabel(),
                row.assetType(),
                row.sourceSystem(),
                row.ecosystem(),
                row.affectsActiveFindings(),
                row.affectedAssetCount(),
                row.affectedComponentCount(),
                row.openFindingCount(),
                row.openVulnerabilityCount(),
                row.firstSeenAt(),
                row.lastSeenAt(),
                whyThisMatters(row),
                evidenceJson,
                recommendedAction(row),
                buildDrilldownTargets(row),
                buildSampleRecords(row),
                overrideInfo.active(),
                overrideInfo.actor(),
                overrideInfo.at()
        );
    }

    public OperationalQualityFilterValuesResponse listFilterValues(Tenant tenant) {
        requireTenant(tenant);
        projectionService.ensureTenantProjection(tenant);

        MapSqlParameterSource params = new MapSqlParameterSource().addValue("tenantId", tenant.getId());
        List<String> issueTypes = queryDistinctValues("""
                SELECT DISTINCT issue_type
                FROM quality_issue_projection
                WHERE tenant_id = :tenantId
                  AND issue_type IS NOT NULL
                ORDER BY issue_type
                """, params);
        List<String> assetTypes = queryDistinctValues("""
                SELECT DISTINCT asset_type
                FROM quality_issue_projection
                WHERE tenant_id = :tenantId
                  AND asset_type IS NOT NULL
                ORDER BY asset_type
                """, params);
        List<String> sourceSystems = queryDistinctValues("""
                SELECT DISTINCT source_system
                FROM quality_issue_projection
                WHERE tenant_id = :tenantId
                  AND source_system IS NOT NULL
                ORDER BY source_system
                """, params);
        List<String> ecosystems = queryDistinctValues("""
                SELECT DISTINCT ecosystem
                FROM quality_issue_projection
                WHERE tenant_id = :tenantId
                  AND ecosystem IS NOT NULL
                ORDER BY ecosystem
                """, params);

        return new OperationalQualityFilterValuesResponse(
                DOMAIN_ORDER,
                issueTypes,
                SEVERITY_ORDER,
                assetTypes,
                sourceSystems,
                ecosystems
        );
    }

    private SqlFilters buildFilters(
            Tenant tenant,
            String domain,
            String issueType,
            String severity,
            Boolean affectsActiveFindings,
            List<AssetType> assetTypes,
            List<String> sourceSystems,
            List<String> ecosystems,
            String query
    ) {
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("tenantId", tenant.getId());
        StringBuilder where = new StringBuilder("""
                WHERE q.tenant_id = :tenantId
                """);

        String normalizedDomain = normalizeToken(domain);
        if (!normalizedDomain.isBlank()) {
            params.addValue("domain", normalizedDomain);
            where.append(" AND q.domain = :domain");
        }

        String normalizedIssueType = normalizeToken(issueType);
        if (!normalizedIssueType.isBlank()) {
            params.addValue("issueType", normalizedIssueType);
            where.append(" AND q.issue_type = :issueType");
        }

        String normalizedSeverity = normalizeToken(severity);
        if (!normalizedSeverity.isBlank()) {
            params.addValue("severity", normalizedSeverity);
            where.append(" AND q.severity = :severity");
        }

        if (affectsActiveFindings != null) {
            params.addValue("affectsActiveFindings", affectsActiveFindings);
            where.append(" AND q.affects_active_findings = :affectsActiveFindings");
        }

        List<String> normalizedAssetTypes = assetTypes == null
                ? List.of()
                : assetTypes.stream().map(Enum::name).distinct().toList();
        if (!normalizedAssetTypes.isEmpty()) {
            params.addValue("assetTypes", normalizedAssetTypes);
            where.append(" AND q.asset_type IN (:assetTypes)");
        }

        List<String> normalizedSourceSystems = normalizeLowerList(sourceSystems);
        if (!normalizedSourceSystems.isEmpty()) {
            params.addValue("sourceSystems", normalizedSourceSystems);
            where.append(" AND q.source_system IN (:sourceSystems)");
        }

        List<String> normalizedEcosystems = normalizeLowerList(ecosystems);
        if (!normalizedEcosystems.isEmpty()) {
            params.addValue("ecosystems", normalizedEcosystems);
            where.append(" AND q.ecosystem IN (:ecosystems)");
        }

        if (query != null && !query.isBlank()) {
            params.addValue("query", "%" + query.trim().toLowerCase(Locale.ROOT) + "%");
            where.append("""
                     AND (
                         lower(coalesce(q.title, '')) LIKE :query
                         OR lower(coalesce(q.primary_label, '')) LIKE :query
                         OR lower(coalesce(q.secondary_label, '')) LIKE :query
                         OR lower(coalesce(q.issue_type, '')) LIKE :query
                         OR lower(coalesce(q.reason_code, '')) LIKE :query
                         OR lower(coalesce(q.source_system, '')) LIKE :query
                         OR lower(coalesce(q.ecosystem, '')) LIKE :query
                     )
                    """);
        }

        return new SqlFilters(where.toString(), params);
    }

    private String countSql(String whereClause) {
        return """
                SELECT COUNT(*)
                FROM quality_issue_projection q
                """ + whereClause + "\n";
    }

    private String listSql(String whereClause) {
        return """
                SELECT
                    q.id,
                    q.issue_key,
                    q.domain,
                    q.issue_type,
                    q.severity,
                    q.reason_code,
                    q.title,
                    q.source_object_type,
                    q.source_object_id,
                    q.primary_label,
                    q.secondary_label,
                    q.asset_type,
                    q.source_system,
                    q.ecosystem,
                    q.affects_active_findings,
                    q.affected_asset_count,
                    q.affected_component_count,
                    q.open_finding_count,
                    q.open_vulnerability_count,
                    q.first_seen_at,
                    q.last_seen_at
                FROM quality_issue_projection q
                """ + whereClause + "\n" + """
                ORDER BY
                    CASE q.severity
                        WHEN 'CRITICAL' THEN 0
                        WHEN 'HIGH' THEN 1
                        WHEN 'MEDIUM' THEN 2
                        ELSE 3
                    END,
                    q.affects_active_findings DESC,
                    q.last_seen_at DESC,
                    q.title ASC
                LIMIT :limit OFFSET :offset
                """;
    }

    private String detailSql() {
        return """
                SELECT
                    q.id,
                    q.issue_key,
                    q.domain,
                    q.issue_type,
                    q.severity,
                    q.reason_code,
                    q.title,
                    q.source_object_type,
                    q.source_object_id,
                    q.asset_id,
                    q.component_id,
                    q.software_identity_id,
                    q.vulnerability_id,
                    q.sync_run_id,
                    q.primary_label,
                    q.secondary_label,
                    q.asset_type,
                    q.source_system,
                    q.ecosystem,
                    q.affects_active_findings,
                    q.affected_asset_count,
                    q.affected_component_count,
                    q.open_finding_count,
                    q.open_vulnerability_count,
                    q.first_seen_at,
                    q.last_seen_at,
                    cast(q.evidence_json as text) AS evidence_json
                FROM quality_issue_projection q
                WHERE q.tenant_id = :tenantId
                  AND q.id = :issueId
                """;
    }

    private QualityIssueRow toRow(ResultSet rs) throws SQLException {
        return new QualityIssueRow(
                rs.getString("id"),
                rs.getString("issue_key"),
                rs.getString("domain"),
                rs.getString("issue_type"),
                rs.getString("severity"),
                rs.getString("reason_code"),
                rs.getString("title"),
                rs.getString("source_object_type"),
                rs.getString("source_object_id"),
                getUuid(rs, "asset_id"),
                getUuid(rs, "component_id"),
                getUuid(rs, "software_identity_id"),
                getUuid(rs, "vulnerability_id"),
                getUuid(rs, "sync_run_id"),
                rs.getString("primary_label"),
                rs.getString("secondary_label"),
                rs.getString("asset_type"),
                rs.getString("source_system"),
                rs.getString("ecosystem"),
                rs.getBoolean("affects_active_findings"),
                rs.getLong("affected_asset_count"),
                rs.getLong("affected_component_count"),
                rs.getLong("open_finding_count"),
                rs.getLong("open_vulnerability_count"),
                getInstant(rs, "first_seen_at"),
                getInstant(rs, "last_seen_at"),
                rs.getString("evidence_json")
        );
    }

    private String whyThisMatters(QualityIssueRow row) {
        return switch (row.issueType()) {
            case "SOURCE_RUN_FAILED" -> "The latest source run failed, so downstream inventory, vulnerability, or lifecycle views may be stale or incomplete.";
            case "SOURCE_RUN_PARTIAL_FAILURE" -> "The latest source run only completed partially, which means some records landed while others were dropped or failed.";
            case "SOURCE_FEED_STALE" -> "This source has not refreshed recently enough to trust the current downstream views without qualification.";
            case "INGESTED_NO_DOWNSTREAM_RECORDS" -> "The source completed, but it did not create usable downstream records, which usually points to parser, schema, or mapping gaps.";
            case "COMPONENT_MISSING_VERSION", "COMPONENT_MISSING_SOFTWARE_IDENTITY", "HOST_LOW_CONFIDENCE_ALIAS", "HOST_DISCOVERY_MODEL_REVIEW",
                    "VULNERABILITY_TARGET_IDENTITY_UNRESOLVED", "VEX_PRODUCT_KEY_UNRESOLVED" ->
                    "Normalization is incomplete here, so the app cannot confidently reason about correlation, VEX, or lifecycle for the affected records.";
            case "COMPONENT_NO_CORRELATION_CANDIDATES", "COMPONENT_LOW_CONFIDENCE_MATCH", "COMPONENT_FALLBACK_ONLY_CORRELATION" ->
                    "Correlation quality is degraded for this record, which can suppress findings, create noise, or push analysts into low-confidence investigation paths.";
            case "AWAITING_EXACT_VEX", "STALE_VEX_MATCH", "OPEN_FINDING_CONFLICTS_WITH_VEX", "VENDOR_ONLY_VEX_COVERAGE" ->
                    "Vendor applicability evidence and current exposure state are not aligned cleanly, so analyst decisions may be slower or misleading.";
            case "SOFTWARE_IDENTITY_NEEDS_EOL_MAPPING", "SOFTWARE_IDENTITY_UNKNOWN_LIFECYCLE", "SOFTWARE_IDENTITY_CYCLE_UNRESOLVED" ->
                    "Lifecycle truth is incomplete for this software identity, which weakens EOL-based prioritization in matched software and Org CVE views.";
            case "SUMMARY_PROJECTION_STALE", "CROSS_VIEW_COUNT_MISMATCH", "POST_RECOMPUTE_PROJECTION_PENDING", "SOURCE_FRESHNESS_BLOCKING_QUALITY" ->
                    "Projected read models are lagging or disagreeing with canonical data, so users may see inconsistent counts across the app.";
            default -> "This issue represents a data-quality gap that can make downstream views incomplete, stale, or lower confidence.";
        };
    }

    private String recommendedAction(QualityIssueRow row) {
        return switch (row.domain()) {
            case "INGESTION" -> "Open Connect or the Operations ingestion views, inspect the latest run, and rerun the source if the failure is still relevant.";
            case "NORMALIZATION" -> row.assetType() != null && "HOST".equals(row.assetType())
                    ? "Open the Hosts or Inventory workflow to review normalization evidence and resolve the host-side software record."
                    : "Open Inventory or Software Identities to inspect the normalized record and confirm the missing or low-confidence fields.";
            case "CORRELATION" -> "Open Inventory or the owning asset workflow to inspect the software record, then review why the vulnerability match candidates are missing or low confidence.";
            case "VEX" -> "Open Vulnerability Investigation to inspect matched software, current VEX evidence, and any open finding that now conflicts with that evidence.";
            case "EOL" -> "Open Software Identities or the EOL catalog to review the mapped slug and lifecycle coverage before changing any override.";
            case "PROJECTION_FRESHNESS" -> "Open the Operations freshness or read-path views to confirm whether a rebuild, recompute, or stale source is blocking the projection.";
            default -> "Open the owning workflow to inspect the underlying record and confirm whether the issue is still active.";
        };
    }

    private List<OperationalQualityDrilldownTargetResponse> buildDrilldownTargets(QualityIssueRow row) {
        LinkedHashMap<String, String> targets = new LinkedHashMap<>();
        if ("INGESTION".equals(row.domain())) {
            addTarget(targets, "Connect", "/?tab=connect");
            addTarget(targets, "Operations · Ingestion", "/?tab=operations&operationsView=ingestion");
        }
        if ("PROJECTION_FRESHNESS".equals(row.domain())) {
            addTarget(targets, "Operations · Freshness", "/?tab=operations&operationsView=freshness");
            addTarget(targets, "Operations · Read-Path", "/?tab=operations&operationsView=read-path");
        }
        if (row.softwareIdentityId() != null) {
            addTarget(targets, "Software Identities", "/?tab=inventory&inventoryView=software-identities&softwareIdentityId=" + row.softwareIdentityId());
        }
        if ("EOL".equals(row.domain())) {
            addTarget(targets, "EOL Catalog", "/?tab=end-of-life");
        }
        if (row.vulnerabilityId() != null) {
            String externalId = deriveVulnerabilityExternalId(row);
            if (externalId != null && !externalId.isBlank()) {
                addTarget(targets, "Vulnerability Investigation", "/vuln-repo/org-cves/" + encode(externalId));
            }
        }
        if (row.assetId() != null) {
            if ("HOST".equals(row.assetType())) {
                addTarget(targets, "Host Detail", "/?tab=inventory&inventoryView=hosts&hostAssetId=" + row.assetId());
            } else {
                String inventoryView = inventoryViewForAssetType(row.assetType());
                addTarget(targets, "Inventory", "/?tab=inventory&inventoryView=" + inventoryView);
            }
        }
        if ("CORRELATION".equals(row.domain()) || "NORMALIZATION".equals(row.domain())) {
            String inventoryView = inventoryViewForAssetType(row.assetType());
            addTarget(targets, "Inventory Review", "/?tab=inventory&inventoryView=" + inventoryView);
        }
        if (targets.isEmpty()) {
            addTarget(targets, "Operations", "/?tab=operations&operationsView=quality");
        }
        return targets.entrySet().stream()
                .map(entry -> new OperationalQualityDrilldownTargetResponse(entry.getKey(), entry.getValue()))
                .toList();
    }

    private List<OperationalQualitySampleRecordResponse> buildSampleRecords(QualityIssueRow row) {
        List<OperationalQualitySampleRecordResponse> samples = new ArrayList<>();
        if (row.primaryLabel() != null && !row.primaryLabel().isBlank()) {
            samples.add(new OperationalQualitySampleRecordResponse(
                    "Primary object",
                    row.primaryLabel(),
                    blankToNull(row.secondaryLabel())
            ));
        }
        samples.add(new OperationalQualitySampleRecordResponse(
                "Affected scope",
                row.affectedComponentCount() + " components",
                row.affectedAssetCount() + " assets"
        ));
        samples.add(new OperationalQualitySampleRecordResponse(
                "Exposure",
                row.openFindingCount() + " open findings",
                row.openVulnerabilityCount() + " open vulnerabilities"
        ));
        if (row.sourceSystem() != null || row.ecosystem() != null) {
            samples.add(new OperationalQualitySampleRecordResponse(
                    "Source context",
                    blankToDash(row.sourceSystem()),
                    blankToDash(row.ecosystem())
            ));
        }

        Map<String, Object> evidence = parseEvidence(row.evidenceJson());
        evidence.entrySet().stream()
                .filter(entry -> entry.getValue() != null)
                .limit(2)
                .forEach(entry -> samples.add(new OperationalQualitySampleRecordResponse(
                        prettifyToken(entry.getKey()),
                        stringifyValue(entry.getValue()),
                        null
                )));
        return samples.stream().limit(5).toList();
    }

    private OverrideInfo resolveOverrideInfo(Tenant tenant, QualityIssueRow row) {
        if ("NORMALIZATION".equals(row.domain())) {
            OverrideInfo clusterOverride = findClusterNormalizationOverride(tenant, row);
            if (clusterOverride.active()) {
                return clusterOverride;
            }

            OverrideInfo componentOverride = findComponentNormalizationOverride(tenant, row);
            if (componentOverride.active()) {
                return componentOverride;
            }

            return findSoftwareInstanceNormalizationOverride(tenant, row);
        }

        if ("CORRELATION".equals(row.domain())) {
            return findCorrelationOverride(tenant, row);
        }

        return OverrideInfo.inactive();
    }

    private OverrideInfo findClusterNormalizationOverride(Tenant tenant, QualityIssueRow row) {
        String sourceType = normalizeClusterSourceType(row.sourceObjectType());
        if (sourceType == null || row.sourceObjectId() == null || row.sourceObjectId().isBlank()) {
            return OverrideInfo.inactive();
        }

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("sourceType", sourceType)
                .addValue("sourceKey", row.sourceObjectId());

        return jdbcTemplate.query("""
                SELECT confirmed_by, confirmed_at
                FROM software_identity_cluster_link
                WHERE tenant_id = :tenantId
                  AND source_type = :sourceType
                  AND source_key = :sourceKey
                  AND revoked_at IS NULL
                ORDER BY confirmed_at DESC
                LIMIT 1
                """, params, rs -> rs.next()
                ? new OverrideInfo(true, blankToNull(rs.getString("confirmed_by")), getInstant(rs, "confirmed_at"))
                : OverrideInfo.inactive());
    }

    private OverrideInfo findComponentNormalizationOverride(Tenant tenant, QualityIssueRow row) {
        if (row.componentId() == null) {
            return OverrideInfo.inactive();
        }

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("componentId", row.componentId());

        return jdbcTemplate.query("""
                SELECT manual_identity_confirmed_by, manual_identity_confirmed_at
                FROM inventory_components
                WHERE tenant_id = :tenantId
                  AND id = :componentId
                  AND manual_identity_confirmed_at IS NOT NULL
                """, params, rs -> rs.next()
                ? new OverrideInfo(
                        true,
                        blankToNull(rs.getString("manual_identity_confirmed_by")),
                        getInstant(rs, "manual_identity_confirmed_at"))
                : OverrideInfo.inactive());
    }

    private OverrideInfo findSoftwareInstanceNormalizationOverride(Tenant tenant, QualityIssueRow row) {
        if (!"SOFTWARE_INSTANCE".equals(row.sourceObjectType())
                || row.sourceObjectId() == null
                || row.sourceObjectId().isBlank()) {
            return OverrideInfo.inactive();
        }

        UUID softwareInstanceId;
        try {
            softwareInstanceId = UUID.fromString(row.sourceObjectId());
        } catch (IllegalArgumentException ignored) {
            return OverrideInfo.inactive();
        }

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("softwareInstanceId", softwareInstanceId);

        return jdbcTemplate.query("""
                SELECT manual_identity_confirmed_by, manual_identity_confirmed_at
                FROM software_instances
                WHERE tenant_id = :tenantId
                  AND id = :softwareInstanceId
                  AND manual_identity_confirmed_at IS NOT NULL
                """, params, rs -> rs.next()
                ? new OverrideInfo(
                        true,
                        blankToNull(rs.getString("manual_identity_confirmed_by")),
                        getInstant(rs, "manual_identity_confirmed_at"))
                : OverrideInfo.inactive());
    }

    private OverrideInfo findCorrelationOverride(Tenant tenant, QualityIssueRow row) {
        if (row.componentId() == null) {
            return OverrideInfo.inactive();
        }

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("componentId", row.componentId());

        return jdbcTemplate.query("""
                SELECT analyst_updated_by, analyst_updated_at
                FROM component_vulnerability_states
                WHERE tenant_id = :tenantId
                  AND component_id = :componentId
                  AND analyst_updated_at IS NOT NULL
                ORDER BY analyst_updated_at DESC
                LIMIT 1
                """, params, rs -> rs.next()
                ? new OverrideInfo(
                        true,
                        blankToNull(rs.getString("analyst_updated_by")),
                        getInstant(rs, "analyst_updated_at"))
                : OverrideInfo.inactive());
    }

    private String normalizeClusterSourceType(String sourceObjectType) {
        if (sourceObjectType == null || sourceObjectType.isBlank()) {
            return null;
        }
        return switch (sourceObjectType) {
            case "CLUSTER_DISCOVERY_MODEL", "DISCOVERY_MODEL" -> "DISCOVERY_MODEL";
            case "CLUSTER_PACKAGE_PATTERN", "PACKAGE_PATTERN" -> "PACKAGE_PATTERN";
            default -> null;
        };
    }

    private Map<String, Object> parseEvidence(String evidenceJson) {
        if (evidenceJson == null || evidenceJson.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(evidenceJson, EVIDENCE_TYPE);
        } catch (JsonProcessingException ignored) {
            return Map.of();
        }
    }

    private String prettyJson(String rawJson) {
        if (rawJson == null || rawJson.isBlank()) {
            return "{}";
        }
        try {
            Object parsed = objectMapper.readValue(rawJson, Object.class);
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(parsed);
        } catch (JsonProcessingException ignored) {
            return rawJson;
        }
    }

    private String deriveVulnerabilityExternalId(QualityIssueRow row) {
        if (row.primaryLabel() != null && row.primaryLabel().toUpperCase(Locale.ROOT).startsWith("CVE-")) {
            return row.primaryLabel();
        }
        if (row.vulnerabilityId() == null) {
            return null;
        }
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("vulnerabilityId", row.vulnerabilityId());
        return jdbcTemplate.query("""
                SELECT external_id
                FROM vulnerabilities
                WHERE id = :vulnerabilityId
                """, params, rs -> rs.next() ? rs.getString("external_id") : null);
    }

    private List<String> queryDistinctValues(String sql, MapSqlParameterSource params) {
        return jdbcTemplate.query(sql, params, (rs, rowNum) -> rs.getString(1)).stream()
                .filter(value -> value != null && !value.isBlank())
                .distinct()
                .sorted()
                .toList();
    }

    private long queryLong(String sql, MapSqlParameterSource params) {
        Long value = jdbcTemplate.queryForObject(sql, params, Long.class);
        return value == null ? 0L : value;
    }

    private void requireTenant(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tenant is required");
        }
    }

    private Instant getInstant(ResultSet rs, String column) throws SQLException {
        Timestamp timestamp = rs.getTimestamp(column);
        return timestamp == null ? null : timestamp.toInstant();
    }

    private UUID getUuid(ResultSet rs, String column) throws SQLException {
        Object value = rs.getObject(column);
        if (value instanceof UUID uuid) {
            return uuid;
        }
        if (value == null) {
            return null;
        }
        return UUID.fromString(String.valueOf(value));
    }

    private String normalizeToken(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.trim().toUpperCase(Locale.ROOT)
                .replace('/', '_')
                .replace('-', '_')
                .replace(' ', '_');
    }

    private List<String> normalizeLowerList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return values.stream()
                .filter(value -> value != null && !value.isBlank())
                .map(value -> value.trim().toLowerCase(Locale.ROOT))
                .distinct()
                .toList();
    }

    private void addTarget(Map<String, String> targets, String label, String href) {
        if (label == null || label.isBlank() || href == null || href.isBlank()) {
            return;
        }
        targets.putIfAbsent(label, href);
    }

    private String inventoryViewForAssetType(String assetType) {
        if (assetType == null || assetType.isBlank()) {
            return "sbom";
        }
        return switch (assetType) {
            case "HOST" -> "hosts";
            case "CONTAINER_IMAGE" -> "container-images";
            default -> "sbom";
        };
    }

    private String prettifyToken(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String[] parts = value.replace('_', ' ')
                .replace('-', ' ')
                .trim()
                .toLowerCase(Locale.ROOT)
                .split("\\s+");
        List<String> words = new ArrayList<>();
        for (String part : parts) {
            if (part.isBlank()) {
                continue;
            }
            words.add(Character.toUpperCase(part.charAt(0)) + part.substring(1));
        }
        return String.join(" ", words);
    }

    private String stringifyValue(Object value) {
        if (value == null) {
            return "-";
        }
        if (value instanceof List<?> list) {
            return list.stream().map(String::valueOf).limit(5).reduce((left, right) -> left + ", " + right).orElse("-");
        }
        if (value.getClass().isArray()) {
            if (value instanceof Object[] array) {
                return String.join(", ", java.util.Arrays.stream(array).map(String::valueOf).toList());
            }
            return String.valueOf(value);
        }
        return String.valueOf(value);
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private String blankToDash(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private record SqlFilters(
            String whereClause,
            MapSqlParameterSource params
    ) {
    }

    private record OverrideInfo(
            boolean active,
            String actor,
            Instant at
    ) {
        private static OverrideInfo inactive() {
            return new OverrideInfo(false, null, null);
        }
    }

    /** Lightweight projection used by OperationsOverrideController to resolve issue → source IDs. */
    public record IssueSourceIds(
            String sourceObjectType,
            String sourceObjectId,
            UUID componentId
    ) {
    }

    public IssueSourceIds getIssueSourceIds(Tenant tenant, String issueId) {
        requireTenant(tenant);
        if (issueId == null || issueId.isBlank()) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.BAD_REQUEST, "Issue id is required");
        }
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("issueId", issueId.trim());
        QualityIssueRow row = jdbcTemplate.query(detailSql(), params, rs -> rs.next() ? toRow(rs) : null);
        if (row == null) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND, "Quality issue not found");
        }
        return new IssueSourceIds(row.sourceObjectType(), row.sourceObjectId(), row.componentId());
    }

    private record QualityIssueRow(
            String id,
            String issueKey,
            String domain,
            String issueType,
            String severity,
            String reasonCode,
            String title,
            String sourceObjectType,
            String sourceObjectId,
            UUID assetId,
            UUID componentId,
            UUID softwareIdentityId,
            UUID vulnerabilityId,
            UUID syncRunId,
            String primaryLabel,
            String secondaryLabel,
            String assetType,
            String sourceSystem,
            String ecosystem,
            boolean affectsActiveFindings,
            long affectedAssetCount,
            long affectedComponentCount,
            long openFindingCount,
            long openVulnerabilityCount,
            Instant firstSeenAt,
            Instant lastSeenAt,
            String evidenceJson
    ) {
    }
}
