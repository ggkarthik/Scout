package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OperationalQualityProjectionService {

    private static final double LOW_CONFIDENCE_THRESHOLD = 0.65d;
    private static final double LOW_CONFIDENCE_ALIAS_THRESHOLD = HostInventoryReviewEvaluator.LOW_CONFIDENCE_ALIAS_THRESHOLD;
    private static final long SOURCE_STALE_HOURS = 24L;
    private static final long RECENT_WINDOW_DAYS = 7L;
    private static final List<String> CANONICAL_DOMAINS = List.of(
            "INGESTION",
            "NORMALIZATION",
            "CORRELATION",
            "VEX",
            "EOL",
            "PROJECTION_FRESHNESS"
    );

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final TenantRepository tenantRepository;
    private final ObjectMapper objectMapper;

    public OperationalQualityProjectionService(
            NamedParameterJdbcTemplate jdbcTemplate,
            TenantRepository tenantRepository,
            ObjectMapper objectMapper
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.tenantRepository = tenantRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public int refreshAll() {
        int total = 0;
        for (Tenant tenant : tenantRepository.findAllByOrderByCreatedAtAsc()) {
            total += refreshTenant(tenant);
        }
        return total;
    }

    @Transactional
    public int refreshTenant(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return 0;
        }
        UUID tenantId = tenant.getId();
        List<QualityIssueRecord> issues = buildIssuesForTenant(tenantId);
        upsertRows(issues);
        deleteStaleRows(tenantId, issues);
        return issues.size();
    }

    public void ensureTenantProjection(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return;
        }
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("tenantId", tenant.getId());
        Long projectedCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM quality_issue_projection WHERE tenant_id = :tenantId",
                params,
                Long.class
        );
        if (projectedCount != null && projectedCount > 0L) {
            return;
        }
        Long sourceCount = jdbcTemplate.queryForObject("""
                SELECT
                  COALESCE((SELECT COUNT(*) FROM inventory_components WHERE tenant_id = :tenantId), 0)
                  + COALESCE((SELECT COUNT(*) FROM vulnerabilities), 0)
                  + COALESCE((SELECT COUNT(*) FROM sync_runs), 0)
                """, params, Long.class);
        if (sourceCount != null && sourceCount > 0L) {
            refreshTenant(tenant);
        }
    }

    private List<QualityIssueRecord> buildIssuesForTenant(UUID tenantId) {
        LinkedHashMap<String, QualityIssueRecord> issues = new LinkedHashMap<>();

        Set<UUID> missingIdentityComponentIds = new LinkedHashSet<>();
        Set<UUID> noCandidateComponentIds = new LinkedHashSet<>();
        Set<UUID> fallbackOnlyComponentIds = new LinkedHashSet<>();
        Set<UUID> failedSources = new LinkedHashSet<>();
        Set<UUID> vendorOnlyVulnerabilityIds = new LinkedHashSet<>();
        Set<String> conflictedVexPairs = new LinkedHashSet<>();
        Set<UUID> needsEolMappingIdentityIds = new LinkedHashSet<>();

        addIssueRecords(issues, buildSourceRunFailedIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, buildSourceRunPartialFailureIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, buildSourceFeedStaleIssues(tenantId, failedSources), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, buildIngestedNoDownstreamRecordsIssues(tenantId), failedSources, missingIdentityComponentIds);

        List<QualityIssueRecord> missingIdentityIssues = buildComponentMissingSoftwareIdentityIssues(tenantId);
        addIssueRecords(issues, missingIdentityIssues, failedSources, missingIdentityComponentIds);

        addIssueRecords(issues, buildComponentMissingVersionIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, buildHostLowConfidenceAliasIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, buildHostDiscoveryModelReviewIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, buildVulnerabilityTargetIdentityUnresolvedIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, buildVexProductKeyUnresolvedIssues(tenantId), failedSources, missingIdentityComponentIds);

        List<QualityIssueRecord> noCandidateIssues = buildComponentNoCorrelationCandidatesIssues(tenantId, missingIdentityComponentIds);
        addIssueRecords(issues, noCandidateIssues, failedSources, missingIdentityComponentIds);
        noCandidateIssues.stream()
                .map(QualityIssueRecord::componentId)
                .filter(Objects::nonNull)
                .forEach(noCandidateComponentIds::add);

        List<QualityIssueRecord> fallbackOnlyIssues = buildComponentFallbackOnlyCorrelationIssues(
                tenantId,
                missingIdentityComponentIds,
                noCandidateComponentIds
        );
        addIssueRecords(issues, fallbackOnlyIssues, failedSources, missingIdentityComponentIds);
        fallbackOnlyIssues.stream()
                .map(QualityIssueRecord::componentId)
                .filter(Objects::nonNull)
                .forEach(fallbackOnlyComponentIds::add);

        addIssueRecords(
                issues,
                buildComponentLowConfidenceMatchIssues(
                        tenantId,
                        missingIdentityComponentIds,
                        noCandidateComponentIds,
                        fallbackOnlyComponentIds
                ),
                failedSources,
                missingIdentityComponentIds
        );

        List<QualityIssueRecord> vendorOnlyIssues = buildVendorOnlyVexCoverageIssues(tenantId);
        addIssueRecords(issues, vendorOnlyIssues, failedSources, missingIdentityComponentIds);
        vendorOnlyIssues.stream()
                .map(QualityIssueRecord::vulnerabilityId)
                .filter(Objects::nonNull)
                .forEach(vendorOnlyVulnerabilityIds::add);

        List<QualityIssueRecord> vexConflictIssues = buildOpenFindingConflictsWithVexIssues(tenantId);
        addIssueRecords(issues, vexConflictIssues, failedSources, missingIdentityComponentIds);
        vexConflictIssues.stream()
                .map(record -> vexPairKey(record.componentId(), record.vulnerabilityId()))
                .filter(Objects::nonNull)
                .forEach(conflictedVexPairs::add);

        addIssueRecords(
                issues,
                buildAwaitingExactVexIssues(tenantId, vendorOnlyVulnerabilityIds, conflictedVexPairs),
                failedSources,
                missingIdentityComponentIds
        );
        addIssueRecords(issues, buildStaleVexMatchIssues(tenantId), failedSources, missingIdentityComponentIds);

        List<QualityIssueRecord> eolMappingIssues = buildSoftwareIdentityNeedsEolMappingIssues(tenantId);
        addIssueRecords(issues, eolMappingIssues, failedSources, missingIdentityComponentIds);
        eolMappingIssues.stream()
                .map(QualityIssueRecord::softwareIdentityId)
                .filter(Objects::nonNull)
                .forEach(needsEolMappingIdentityIds::add);

        addIssueRecords(
                issues,
                buildSoftwareIdentityUnknownLifecycleIssues(tenantId, needsEolMappingIdentityIds),
                failedSources,
                missingIdentityComponentIds
        );
        addIssueRecords(
                issues,
                buildSoftwareIdentityCycleUnresolvedIssues(tenantId, needsEolMappingIdentityIds),
                failedSources,
                missingIdentityComponentIds
        );

        addIssueRecords(issues, buildSummaryProjectionStaleIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, buildCrossViewCountMismatchIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, buildPostRecomputeProjectionPendingIssues(tenantId), failedSources, missingIdentityComponentIds);

        return new ArrayList<>(issues.values());
    }

    private void addIssueRecords(
            Map<String, QualityIssueRecord> issues,
            Collection<QualityIssueRecord> candidates,
            Set<UUID> ignoredSources,
            Set<UUID> ignoredComponents
    ) {
        if (candidates == null || candidates.isEmpty()) {
            return;
        }
        for (QualityIssueRecord issue : candidates) {
            if (issue == null || issue.issueKey() == null || issue.issueKey().isBlank()) {
                continue;
            }
            issues.putIfAbsent(issue.issueKey(), issue);
        }
    }

    private List<QualityIssueRecord> buildSourceRunFailedIssues(UUID tenantId) {
        String sql = """
                WITH ranked AS (
                    SELECT
                        r.id,
                        r.sync_type,
                        r.status,
                        r.error_message,
                        r.started_at,
                        r.completed_at,
                        r.records_fetched,
                        r.records_inserted,
                        r.records_updated,
                        r.records_failed,
                        ROW_NUMBER() OVER (PARTITION BY lower(r.sync_type) ORDER BY r.started_at DESC) AS rn
                    FROM sync_runs r
                    WHERE r.started_at >= :windowStart
                )
                SELECT *
                FROM ranked
                WHERE rn = 1
                  AND lower(status) = 'failed'
                ORDER BY started_at DESC
                """;
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("windowStart", Timestamp.from(Instant.now().minus(RECENT_WINDOW_DAYS, ChronoUnit.DAYS)));
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql, params);
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            String syncType = stringValue(row.get("sync_type"));
            String sourceSystem = normalizeSource(syncType);
            long fetched = longValue(row.get("records_fetched"));
            long inserted = longValue(row.get("records_inserted"));
            long updated = longValue(row.get("records_updated"));
            long failed = longValue(row.get("records_failed"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("syncType", syncType);
            evidence.put("status", stringValue(row.get("status")));
            evidence.put("errorMessage", stringValue(row.get("error_message")));
            evidence.put("recordsFetched", fetched);
            evidence.put("recordsInserted", inserted);
            evidence.put("recordsUpdated", updated);
            evidence.put("recordsFailed", failed);
            issues.add(issue(
                    tenantId,
                    "INGESTION",
                    "source_run_failed",
                    "sync:" + normalizeForKey(syncType),
                    "HIGH",
                    "latest_run_failed",
                    "Latest source run failed",
                    "SYNC_RUN",
                    stringValue(row.get("id")),
                    null,
                    null,
                    null,
                    null,
                    uuidValue(row.get("id")),
                    null,
                    sourceSystem,
                    null,
                    false,
                    0,
                    0,
                    0,
                    0,
                    instantValue(row.get("started_at")),
                    instantValue(row.get("started_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildSourceRunPartialFailureIssues(UUID tenantId) {
        String sql = """
                WITH ranked AS (
                    SELECT
                        r.id,
                        r.sync_type,
                        r.status,
                        r.error_message,
                        r.started_at,
                        r.completed_at,
                        r.records_fetched,
                        r.records_inserted,
                        r.records_updated,
                        r.records_failed,
                        ROW_NUMBER() OVER (PARTITION BY lower(r.sync_type) ORDER BY r.started_at DESC) AS rn
                    FROM sync_runs r
                    WHERE r.started_at >= :windowStart
                )
                SELECT *
                FROM ranked
                WHERE rn = 1
                  AND lower(status) = 'completed'
                  AND records_failed > 0
                ORDER BY started_at DESC
                """;
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("windowStart", Timestamp.from(Instant.now().minus(RECENT_WINDOW_DAYS, ChronoUnit.DAYS)));
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql, params);
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            String syncType = stringValue(row.get("sync_type"));
            String sourceSystem = normalizeSource(syncType);
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("syncType", syncType);
            evidence.put("recordsFetched", longValue(row.get("records_fetched")));
            evidence.put("recordsInserted", longValue(row.get("records_inserted")));
            evidence.put("recordsUpdated", longValue(row.get("records_updated")));
            evidence.put("recordsFailed", longValue(row.get("records_failed")));
            issues.add(issue(
                    tenantId,
                    "INGESTION",
                    "source_run_partial_failure",
                    "sync-partial:" + normalizeForKey(syncType),
                    "MEDIUM",
                    "run_completed_with_failed_records",
                    "Source run completed with failed records",
                    "SYNC_RUN",
                    stringValue(row.get("id")),
                    null,
                    null,
                    null,
                    null,
                    uuidValue(row.get("id")),
                    null,
                    sourceSystem,
                    null,
                    false,
                    0,
                    0,
                    0,
                    0,
                    instantValue(row.get("started_at")),
                    instantValue(row.get("started_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildSourceFeedStaleIssues(UUID tenantId, Set<UUID> failedSources) {
        String sql = """
                WITH latest_success AS (
                    SELECT
                        lower(r.sync_type) AS source_key,
                        r.sync_type,
                        max(r.started_at) AS last_success_at
                    FROM sync_runs r
                    WHERE lower(r.status) = 'completed'
                    GROUP BY lower(r.sync_type), r.sync_type
                )
                SELECT *
                FROM latest_success
                WHERE last_success_at < :staleCutoff
                ORDER BY last_success_at ASC
                """;
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("staleCutoff", Timestamp.from(Instant.now().minus(SOURCE_STALE_HOURS, ChronoUnit.HOURS)));
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql, params);
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            String syncType = stringValue(row.get("sync_type"));
            String sourceSystem = normalizeSource(syncType);
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("syncType", syncType);
            evidence.put("lastSuccessAt", instantValue(row.get("last_success_at")));
            evidence.put("staleThresholdHours", SOURCE_STALE_HOURS);
            issues.add(issue(
                    tenantId,
                    "INGESTION",
                    "source_feed_stale",
                    "sync-stale:" + normalizeForKey(syncType),
                    isVulnerabilityOrLifecycleSource(syncType) ? "HIGH" : "MEDIUM",
                    "latest_success_older_than_stale_threshold",
                    "Source feed is stale",
                    "SYNC_SOURCE",
                    normalizeForKey(syncType),
                    syncType,
                    "No successful run within the stale threshold",
                    null,
                    null,
                    null,
                    null,
                    sourceSystem,
                    null,
                    false,
                    0,
                    0,
                    0,
                    0,
                    instantValue(row.get("last_success_at")),
                    instantValue(row.get("last_success_at")),
                    evidence
            ));
        }

        String uploadSql = """
                SELECT max(uploaded_at) AS last_success_at
                FROM sbom_uploads
                WHERE status = 'SUCCESS'
                """;
        Instant lastUpload = jdbcTemplate.queryForObject(uploadSql, new MapSqlParameterSource(), (rs, rowNum) -> {
            Timestamp value = rs.getTimestamp("last_success_at");
            return value == null ? null : value.toInstant();
        });
        if (lastUpload != null && lastUpload.isBefore(Instant.now().minus(SOURCE_STALE_HOURS, ChronoUnit.HOURS))) {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("syncType", "SBOM_UPLOAD");
            evidence.put("lastSuccessAt", lastUpload);
            evidence.put("staleThresholdHours", SOURCE_STALE_HOURS);
            issues.add(issue(
                    tenantId,
                    "INGESTION",
                    "source_feed_stale",
                    "sync-stale:sbom_upload",
                    "MEDIUM",
                    "latest_success_older_than_stale_threshold",
                    "SBOM uploads are stale",
                    "SYNC_SOURCE",
                    "sbom_upload",
                    "SBOM Upload",
                    "No successful upload within the stale threshold",
                    null,
                    null,
                    null,
                    null,
                    "sbom_upload",
                    null,
                    false,
                    0,
                    0,
                    0,
                    0,
                    lastUpload,
                    lastUpload,
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildIngestedNoDownstreamRecordsIssues(UUID tenantId) {
        String sql = """
                WITH ranked AS (
                    SELECT
                        r.id,
                        r.sync_type,
                        r.started_at,
                        r.records_fetched,
                        r.records_inserted,
                        r.records_updated,
                        ROW_NUMBER() OVER (PARTITION BY lower(r.sync_type) ORDER BY r.started_at DESC) AS rn
                    FROM sync_runs r
                    WHERE lower(r.status) = 'completed'
                      AND r.started_at >= :windowStart
                      AND r.records_fetched > 0
                      AND r.records_inserted = 0
                      AND r.records_updated = 0
                )
                SELECT *
                FROM ranked
                WHERE rn = 1
                """;
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("windowStart", Timestamp.from(Instant.now().minus(RECENT_WINDOW_DAYS, ChronoUnit.DAYS)));
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql, params);
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            String syncType = stringValue(row.get("sync_type"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("syncType", syncType);
            evidence.put("recordsFetched", longValue(row.get("records_fetched")));
            evidence.put("recordsInserted", longValue(row.get("records_inserted")));
            evidence.put("recordsUpdated", longValue(row.get("records_updated")));
            issues.add(issue(
                    tenantId,
                    "INGESTION",
                    "ingested_no_downstream_records",
                    "sync-zero:" + normalizeForKey(syncType),
                    "MEDIUM",
                    "successful_ingest_without_materialized_records",
                    "Source ingest produced no downstream records",
                    "SYNC_RUN",
                    stringValue(row.get("id")),
                    syncType,
                    "Fetched records but no inserts or updates were materialized",
                    null,
                    null,
                    null,
                    null,
                    uuidValue(row.get("id")),
                    null,
                    normalizeSource(syncType),
                    null,
                    false,
                    0,
                    0,
                    0,
                    0,
                    instantValue(row.get("started_at")),
                    instantValue(row.get("started_at")),
                    evidence
            ));
        }

        String uploadSql = """
                SELECT
                    su.id,
                    su.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    su.uploaded_at,
                    su.component_count,
                    lower(coalesce(su.ingestion_source_system, 'api')) AS source_system
                FROM sbom_uploads su
                JOIN assets a ON a.id = su.asset_id
                WHERE su.status = 'SUCCESS'
                  AND su.uploaded_at >= :windowStart
                  AND coalesce(su.component_count, 0) = 0
                ORDER BY su.uploaded_at DESC
                """;
        List<Map<String, Object>> uploadRows = jdbcTemplate.queryForList(uploadSql, params);
        for (Map<String, Object> row : uploadRows) {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("assetName", stringValue(row.get("asset_name")));
            evidence.put("assetIdentifier", stringValue(row.get("asset_identifier")));
            evidence.put("componentCount", longValue(row.get("component_count")));
            issues.add(issue(
                    tenantId,
                    "INGESTION",
                    "ingested_no_downstream_records",
                    "sbom-zero:" + stringValue(row.get("id")),
                    "MEDIUM",
                    "successful_ingest_without_materialized_records",
                    "SBOM upload produced no materialized components",
                    "SBOM_UPLOAD",
                    stringValue(row.get("id")),
                    stringValue(row.get("asset_name")),
                    stringValue(row.get("asset_identifier")),
                    uuidValue(row.get("asset_id")),
                    null,
                    uuidValue(row.get("id")),
                    null,
                    stringValue(row.get("source_system")),
                    null,
                    false,
                    1,
                    0,
                    0,
                    0,
                    instantValue(row.get("uploaded_at")),
                    instantValue(row.get("uploaded_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildComponentMissingVersionIssues(UUID tenantId) {
        String sql = """
                SELECT
                    ic.id AS component_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.last_observed_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = ic.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count,
                    coalesce((
                        SELECT count(DISTINCT state.vulnerability_id)
                        FROM component_vulnerability_states state
                        WHERE state.component_id = ic.id
                    ), 0) AS open_vulnerability_count
                FROM inventory_components ic
                JOIN assets a ON a.id = ic.asset_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE ic.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND coalesce(nullif(trim(ic.version), ''), nullif(trim(ic.normalized_version), '')) IS NULL
                ORDER BY ic.last_observed_at DESC
                """;
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql, tenantParams(tenantId));
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            long openFindingCount = longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("packageName", stringValue(row.get("package_name")));
            evidence.put("assetName", stringValue(row.get("asset_name")));
            evidence.put("assetIdentifier", stringValue(row.get("asset_identifier")));
            issues.add(issue(
                    tenantId,
                    "NORMALIZATION",
                    "component_missing_version",
                    "component:" + stringValue(row.get("component_id")),
                    severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "missing_component_version",
                    "Inventory component is missing a normalized version",
                    "INVENTORY_COMPONENT",
                    stringValue(row.get("component_id")),
                    stringValue(row.get("package_name")),
                    stringValue(row.get("asset_name")) + " (" + stringValue(row.get("asset_identifier")) + ")",
                    uuidValue(row.get("asset_id")),
                    uuidValue(row.get("component_id")),
                    null,
                    null,
                    stringValue(row.get("asset_type")),
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    1,
                    openFindingCount,
                    openVulnerabilityCount,
                    instantValue(row.get("last_observed_at")),
                    instantValue(row.get("last_observed_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildComponentMissingSoftwareIdentityIssues(UUID tenantId) {
        List<QualityIssueRecord> issues = new ArrayList<>();

        String componentSql = """
                SELECT
                    ic.id AS component_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.last_observed_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = ic.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count,
                    coalesce((
                        SELECT count(DISTINCT state.vulnerability_id)
                        FROM component_vulnerability_states state
                        WHERE state.component_id = ic.id
                    ), 0) AS open_vulnerability_count
                FROM inventory_components ic
                JOIN assets a ON a.id = ic.asset_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE ic.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND ic.software_identity_id IS NULL
                ORDER BY ic.last_observed_at DESC
                """;
        for (Map<String, Object> row : jdbcTemplate.queryForList(componentSql, tenantParams(tenantId))) {
            long openFindingCount = longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("packageName", stringValue(row.get("package_name")));
            evidence.put("assetName", stringValue(row.get("asset_name")));
            evidence.put("assetIdentifier", stringValue(row.get("asset_identifier")));
            issues.add(issue(
                    tenantId,
                    "NORMALIZATION",
                    "component_missing_software_identity",
                    "component:" + stringValue(row.get("component_id")),
                    severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "missing_software_identity",
                    "Inventory component is missing a software identity",
                    "INVENTORY_COMPONENT",
                    stringValue(row.get("component_id")),
                    stringValue(row.get("package_name")),
                    stringValue(row.get("asset_name")) + " (" + stringValue(row.get("asset_identifier")) + ")",
                    uuidValue(row.get("asset_id")),
                    uuidValue(row.get("component_id")),
                    null,
                    null,
                    stringValue(row.get("asset_type")),
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    1,
                    openFindingCount,
                    openVulnerabilityCount,
                    instantValue(row.get("last_observed_at")),
                    instantValue(row.get("last_observed_at")),
                    evidence
            ));
        }

        String softwareSql = """
                SELECT
                    si.id AS software_instance_id,
                    ci.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(si.source_system, 'inventory')) AS source_system,
                    si.display_name,
                    si.last_scanned,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.asset_id = a.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count,
                    coalesce((
                        SELECT count(DISTINCT f.vulnerability_id)
                        FROM findings f
                        WHERE f.asset_id = a.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_vulnerability_count
                FROM software_instances si
                JOIN cis ci ON ci.id = si.ci_id
                JOIN assets a ON a.id = ci.asset_id
                WHERE si.tenant_id = :tenantId
                  AND si.active_install = true
                  AND si.software_identity_id IS NULL
                  AND si.inventory_component_id IS NULL
                ORDER BY si.last_scanned DESC NULLS LAST, si.display_name ASC
                """;
        for (Map<String, Object> row : jdbcTemplate.queryForList(softwareSql, tenantParams(tenantId))) {
            long openFindingCount = longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("displayName", stringValue(row.get("display_name")));
            evidence.put("assetName", stringValue(row.get("asset_name")));
            evidence.put("assetIdentifier", stringValue(row.get("asset_identifier")));
            issues.add(issue(
                    tenantId,
                    "NORMALIZATION",
                    "component_missing_software_identity",
                    "software-instance:" + stringValue(row.get("software_instance_id")),
                    openFindingCount > 0 ? "MEDIUM" : "LOW",
                    "missing_software_identity",
                    "Host software instance is missing a software identity",
                    "SOFTWARE_INSTANCE",
                    stringValue(row.get("software_instance_id")),
                    stringValue(row.get("display_name")),
                    stringValue(row.get("asset_name")) + " (" + stringValue(row.get("asset_identifier")) + ")",
                    uuidValue(row.get("asset_id")),
                    null,
                    null,
                    null,
                    stringValue(row.get("asset_type")),
                    stringValue(row.get("source_system")),
                    null,
                    affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    0,
                    openFindingCount,
                    openVulnerabilityCount,
                    instantValue(row.get("last_scanned")),
                    instantValue(row.get("last_scanned")),
                    evidence
            ));
        }

        return issues;
    }

    private List<QualityIssueRecord> buildHostLowConfidenceAliasIssues(UUID tenantId) {
        String sql = """
                SELECT
                    alias.id AS alias_id,
                    ci.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(alias.source_system) AS source_system,
                    alias.alias_name,
                    alias.confidence,
                    alias.last_seen_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.asset_id = a.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count,
                    coalesce((
                        SELECT count(DISTINCT f.vulnerability_id)
                        FROM findings f
                        WHERE f.asset_id = a.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_vulnerability_count
                FROM ci_aliases alias
                JOIN cis ci ON ci.id = alias.ci_id
                JOIN assets a ON a.id = ci.asset_id
                WHERE alias.tenant_id = :tenantId
                  AND alias.confidence IS NOT NULL
                  AND alias.confidence < :lowConfidence
                ORDER BY alias.last_seen_at DESC
                """;
        MapSqlParameterSource params = tenantParams(tenantId).addValue("lowConfidence", LOW_CONFIDENCE_ALIAS_THRESHOLD);
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, params)) {
            long openFindingCount = longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("aliasName", stringValue(row.get("alias_name")));
            evidence.put("confidence", doubleValue(row.get("confidence")));
            issues.add(issue(
                    tenantId,
                    "NORMALIZATION",
                    "host_low_confidence_alias",
                    "alias:" + stringValue(row.get("alias_id")),
                    openFindingCount > 0 ? "MEDIUM" : "LOW",
                    "ci_alias_confidence_below_threshold",
                    "Host alias confidence is below the approval threshold",
                    "CI_ALIAS",
                    stringValue(row.get("alias_id")),
                    stringValue(row.get("alias_name")),
                    stringValue(row.get("asset_name")) + " (" + stringValue(row.get("asset_identifier")) + ")",
                    uuidValue(row.get("asset_id")),
                    null,
                    null,
                    null,
                    stringValue(row.get("asset_type")),
                    stringValue(row.get("source_system")),
                    null,
                    affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    0,
                    openFindingCount,
                    openVulnerabilityCount,
                    instantValue(row.get("last_seen_at")),
                    instantValue(row.get("last_seen_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildHostDiscoveryModelReviewIssues(UUID tenantId) {
        String sql = """
                SELECT
                    si.id AS software_instance_id,
                    si.inventory_component_id AS component_id,
                    ci.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(si.source_system, 'inventory')) AS source_system,
                    si.display_name,
                    dm.primary_key,
                    dm.normalization_status,
                    dm.approved,
                    dm.low_confidence,
                    si.last_scanned,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE (
                            si.inventory_component_id IS NOT NULL
                            AND f.component_id = si.inventory_component_id
                            AND f.status = 'OPEN'
                        ) OR (
                            si.inventory_component_id IS NULL
                            AND f.asset_id = a.id
                            AND f.status = 'OPEN'
                        )
                    ), 0) AS open_finding_count,
                    coalesce((
                        SELECT count(DISTINCT f.vulnerability_id)
                        FROM findings f
                        WHERE (
                            si.inventory_component_id IS NOT NULL
                            AND f.component_id = si.inventory_component_id
                            AND f.status = 'OPEN'
                        ) OR (
                            si.inventory_component_id IS NULL
                            AND f.asset_id = a.id
                            AND f.status = 'OPEN'
                        )
                    ), 0) AS open_vulnerability_count
                FROM software_instances si
                JOIN cis ci ON ci.id = si.ci_id
                JOIN assets a ON a.id = ci.asset_id
                JOIN discovery_models dm ON dm.id = si.discovery_model_id
                WHERE si.tenant_id = :tenantId
                  AND si.active_install = true
                  AND (
                    dm.low_confidence = true
                    OR dm.approved = false
                    OR (
                        dm.normalization_status IS NOT NULL
                        AND lower(dm.normalization_status) <> 'approved'
                    )
                  )
                ORDER BY si.last_scanned DESC NULLS LAST, si.display_name ASC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, tenantParams(tenantId))) {
            long openFindingCount = longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("displayName", stringValue(row.get("display_name")));
            evidence.put("discoveryModelKey", stringValue(row.get("primary_key")));
            evidence.put("normalizationStatus", stringValue(row.get("normalization_status")));
            evidence.put("approved", boolValue(row.get("approved")));
            evidence.put("lowConfidence", boolValue(row.get("low_confidence")));
            issues.add(issue(
                    tenantId,
                    "NORMALIZATION",
                    "host_discovery_model_review",
                    "software-instance:" + stringValue(row.get("software_instance_id")) + ":discovery-model",
                    severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "discovery_model_requires_review",
                    "Host discovery model normalization needs review",
                    "SOFTWARE_INSTANCE",
                    stringValue(row.get("software_instance_id")),
                    stringValue(row.get("display_name")),
                    stringValue(row.get("asset_name")) + " (" + stringValue(row.get("asset_identifier")) + ")",
                    uuidValue(row.get("asset_id")),
                    uuidValue(row.get("component_id")),
                    null,
                    null,
                    stringValue(row.get("asset_type")),
                    stringValue(row.get("source_system")),
                    null,
                    affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    row.get("component_id") == null ? 0 : 1,
                    openFindingCount,
                    openVulnerabilityCount,
                    instantValue(row.get("last_scanned")),
                    instantValue(row.get("last_scanned")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildVulnerabilityTargetIdentityUnresolvedIssues(UUID tenantId) {
        String sql = """
                SELECT
                    vt.id AS target_id,
                    vt.vulnerability_id,
                    v.external_id,
                    lower(coalesce(vt.source, 'unknown')) AS source_system,
                    vt.ecosystem,
                    vt.package_name,
                    vt.normalized_target_key,
                    vt.updated_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.vulnerability_id = vt.vulnerability_id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM vulnerability_targets vt
                JOIN vulnerabilities v ON v.id = vt.vulnerability_id
                WHERE vt.software_identity_id IS NULL
                  AND vt.target_type IN ('PURL', 'COORD', 'ADVISORY_PACKAGE')
                ORDER BY vt.updated_at DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, tenantParams(tenantId))) {
            long openFindingCount = longValue(row.get("open_finding_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("normalizedTargetKey", stringValue(row.get("normalized_target_key")));
            evidence.put("packageName", stringValue(row.get("package_name")));
            evidence.put("externalId", stringValue(row.get("external_id")));
            issues.add(issue(
                    tenantId,
                    "NORMALIZATION",
                    "vulnerability_target_identity_unresolved",
                    "vuln-target:" + stringValue(row.get("target_id")),
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "vulnerability_target_missing_software_identity",
                    "Vulnerability target could not resolve to a software identity",
                    "VULNERABILITY_TARGET",
                    stringValue(row.get("target_id")),
                    stringValue(row.get("external_id")),
                    stringValue(row.get("package_name")),
                    null,
                    null,
                    null,
                    uuidValue(row.get("vulnerability_id")),
                    null,
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    openFindingCount > 0,
                    0,
                    0,
                    openFindingCount,
                    openFindingCount > 0 ? 1 : 0,
                    instantValue(row.get("updated_at")),
                    instantValue(row.get("updated_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildVexProductKeyUnresolvedIssues(UUID tenantId) {
        String sql = """
                SELECT
                    va.id AS assertion_id,
                    va.vulnerability_id,
                    v.external_id,
                    lower(coalesce(va.source_system, 'unknown')) AS source_system,
                    va.provider,
                    va.ecosystem,
                    va.package_name,
                    va.normalized_product_key,
                    va.updated_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.vulnerability_id = va.vulnerability_id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM vex_assertions va
                JOIN vulnerabilities v ON v.id = va.vulnerability_id
                WHERE va.software_identity_id IS NULL
                  AND trim(coalesce(va.normalized_product_key, '')) <> ''
                ORDER BY va.updated_at DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, tenantParams(tenantId))) {
            long openFindingCount = longValue(row.get("open_finding_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("provider", stringValue(row.get("provider")));
            evidence.put("normalizedProductKey", stringValue(row.get("normalized_product_key")));
            evidence.put("packageName", stringValue(row.get("package_name")));
            issues.add(issue(
                    tenantId,
                    "NORMALIZATION",
                    "vex_product_key_unresolved",
                    "vex-assertion:" + stringValue(row.get("assertion_id")),
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "vex_assertion_missing_software_identity",
                    "VEX product key could not resolve to a software identity",
                    "VEX_ASSERTION",
                    stringValue(row.get("assertion_id")),
                    stringValue(row.get("external_id")),
                    stringValue(row.get("package_name")),
                    null,
                    null,
                    null,
                    uuidValue(row.get("vulnerability_id")),
                    null,
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    openFindingCount > 0,
                    0,
                    0,
                    openFindingCount,
                    openFindingCount > 0 ? 1 : 0,
                    instantValue(row.get("updated_at")),
                    instantValue(row.get("updated_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildComponentNoCorrelationCandidatesIssues(UUID tenantId, Set<UUID> suppressedComponentIds) {
        String sql = """
                SELECT
                    ic.id AS component_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    max(state.last_evaluated_at) AS last_evaluated_at,
                    count(DISTINCT state.vulnerability_id) AS open_vulnerability_count,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = ic.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN assets a ON a.id = ic.asset_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE state.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND lower(coalesce(state.applicability_reason, '')) = 'no_candidates'
                GROUP BY ic.id, ic.asset_id, a.name, a.identifier, a.type, u.ingestion_source_system, ic.ecosystem, ic.package_name, ic.version
                ORDER BY max(state.last_evaluated_at) DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, tenantParams(tenantId))) {
            UUID componentId = uuidValue(row.get("component_id"));
            if (suppressedComponentIds.contains(componentId)) {
                continue;
            }
            long openFindingCount = longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("packageName", stringValue(row.get("package_name")));
            evidence.put("version", stringValue(row.get("version")));
            evidence.put("reason", "no_candidates");
            issues.add(issue(
                    tenantId,
                    "CORRELATION",
                    "component_no_correlation_candidates",
                    "component:" + stringValue(row.get("component_id")) + ":no-candidates",
                    severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "no_correlation_candidates",
                    "Component has no correlation candidates",
                    "INVENTORY_COMPONENT",
                    stringValue(row.get("component_id")),
                    stringValue(row.get("package_name")),
                    stringValue(row.get("asset_name")) + " (" + stringValue(row.get("asset_identifier")) + ")",
                    uuidValue(row.get("asset_id")),
                    componentId,
                    null,
                    null,
                    stringValue(row.get("asset_type")),
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    1,
                    openFindingCount,
                    openVulnerabilityCount,
                    instantValue(row.get("last_evaluated_at")),
                    instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildComponentFallbackOnlyCorrelationIssues(
            UUID tenantId,
            Set<UUID> suppressedComponentIds,
            Set<UUID> noCandidateComponentIds
    ) {
        String sql = """
                SELECT
                    ic.id AS component_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    max(state.last_evaluated_at) AS last_evaluated_at,
                    count(DISTINCT state.vulnerability_id) AS open_vulnerability_count,
                    count(*) FILTER (WHERE lower(coalesce(state.matched_by, '')) like '%fallback%') AS fallback_count,
                    count(*) AS total_state_count,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = ic.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN assets a ON a.id = ic.asset_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE state.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND trim(coalesce(state.matched_by, '')) <> ''
                GROUP BY ic.id, ic.asset_id, a.name, a.identifier, a.type, u.ingestion_source_system, ic.ecosystem, ic.package_name, ic.version
                HAVING count(*) FILTER (WHERE lower(coalesce(state.matched_by, '')) like '%fallback%') = count(*)
                   AND count(*) > 0
                ORDER BY max(state.last_evaluated_at) DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, tenantParams(tenantId))) {
            UUID componentId = uuidValue(row.get("component_id"));
            if (suppressedComponentIds.contains(componentId) || noCandidateComponentIds.contains(componentId)) {
                continue;
            }
            long openFindingCount = longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("packageName", stringValue(row.get("package_name")));
            evidence.put("version", stringValue(row.get("version")));
            evidence.put("fallbackStates", longValue(row.get("fallback_count")));
            evidence.put("totalStates", longValue(row.get("total_state_count")));
            issues.add(issue(
                    tenantId,
                    "CORRELATION",
                    "component_fallback_only_correlation",
                    "component:" + stringValue(row.get("component_id")) + ":fallback-only",
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "all_selected_matches_use_fallback_methods",
                    "Component correlation relies only on fallback matching",
                    "INVENTORY_COMPONENT",
                    stringValue(row.get("component_id")),
                    stringValue(row.get("package_name")),
                    stringValue(row.get("asset_name")) + " (" + stringValue(row.get("asset_identifier")) + ")",
                    uuidValue(row.get("asset_id")),
                    componentId,
                    null,
                    null,
                    stringValue(row.get("asset_type")),
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    1,
                    openFindingCount,
                    openVulnerabilityCount,
                    instantValue(row.get("last_evaluated_at")),
                    instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildComponentLowConfidenceMatchIssues(
            UUID tenantId,
            Set<UUID> suppressedComponentIds,
            Set<UUID> noCandidateComponentIds,
            Set<UUID> fallbackOnlyComponentIds
    ) {
        String sql = """
                SELECT
                    ic.id AS component_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    max(state.last_evaluated_at) AS last_evaluated_at,
                    min(state.confidence_score) AS min_confidence_score,
                    count(DISTINCT state.vulnerability_id) AS open_vulnerability_count,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = ic.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN assets a ON a.id = ic.asset_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE state.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND state.confidence_score IS NOT NULL
                  AND state.confidence_score < :confidenceThreshold
                  AND trim(coalesce(state.matched_by, '')) <> ''
                GROUP BY ic.id, ic.asset_id, a.name, a.identifier, a.type, u.ingestion_source_system, ic.ecosystem, ic.package_name, ic.version
                ORDER BY min(state.confidence_score) ASC, max(state.last_evaluated_at) DESC
                """;
        MapSqlParameterSource params = tenantParams(tenantId).addValue("confidenceThreshold", LOW_CONFIDENCE_THRESHOLD);
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, params)) {
            UUID componentId = uuidValue(row.get("component_id"));
            if (suppressedComponentIds.contains(componentId)
                    || noCandidateComponentIds.contains(componentId)
                    || fallbackOnlyComponentIds.contains(componentId)) {
                continue;
            }
            long openFindingCount = longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("packageName", stringValue(row.get("package_name")));
            evidence.put("version", stringValue(row.get("version")));
            evidence.put("minConfidenceScore", doubleValue(row.get("min_confidence_score")));
            evidence.put("threshold", LOW_CONFIDENCE_THRESHOLD);
            issues.add(issue(
                    tenantId,
                    "CORRELATION",
                    "component_low_confidence_match",
                    "component:" + stringValue(row.get("component_id")) + ":low-confidence",
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "selected_match_confidence_below_threshold",
                    "Component correlation confidence is below the review threshold",
                    "INVENTORY_COMPONENT",
                    stringValue(row.get("component_id")),
                    stringValue(row.get("package_name")),
                    stringValue(row.get("asset_name")) + " (" + stringValue(row.get("asset_identifier")) + ")",
                    uuidValue(row.get("asset_id")),
                    componentId,
                    null,
                    null,
                    stringValue(row.get("asset_type")),
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    1,
                    openFindingCount,
                    openVulnerabilityCount,
                    instantValue(row.get("last_evaluated_at")),
                    instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildVendorOnlyVexCoverageIssues(UUID tenantId) {
        String sql = """
                SELECT
                    state.vulnerability_id,
                    v.external_id,
                    count(DISTINCT state.component_id) AS affected_component_count,
                    count(DISTINCT ic.asset_id) AS affected_asset_count,
                    max(state.last_evaluated_at) AS last_evaluated_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.vulnerability_id = state.vulnerability_id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN vulnerabilities v ON v.id = state.vulnerability_id
                WHERE state.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND state.matched_vex_assertion_id IS NULL
                  AND state.applicability_state IN ('APPLICABLE', 'UNKNOWN')
                  AND EXISTS (
                      SELECT 1
                      FROM vex_assertions va
                      WHERE va.vulnerability_id = state.vulnerability_id
                  )
                GROUP BY state.vulnerability_id, v.external_id
                HAVING count(DISTINCT state.component_id) >= 2
                ORDER BY max(state.last_evaluated_at) DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, tenantParams(tenantId))) {
            long openFindingCount = longValue(row.get("open_finding_count"));
            long affectedComponentCount = longValue(row.get("affected_component_count"));
            long affectedAssetCount = longValue(row.get("affected_asset_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("externalId", stringValue(row.get("external_id")));
            evidence.put("affectedComponentCount", affectedComponentCount);
            evidence.put("affectedAssetCount", affectedAssetCount);
            issues.add(issue(
                    tenantId,
                    "VEX",
                    "vendor_only_vex_coverage",
                    "vulnerability:" + stringValue(row.get("vulnerability_id")) + ":vendor-only-vex",
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "vex_exists_but_no_exact_component_match",
                    "VEX exists only at vendor scope for this vulnerability",
                    "VULNERABILITY",
                    stringValue(row.get("vulnerability_id")),
                    stringValue(row.get("external_id")),
                    affectedComponentCount + " affected components",
                    null,
                    null,
                    null,
                    uuidValue(row.get("vulnerability_id")),
                    null,
                    "vendor_vex",
                    null,
                    openFindingCount > 0,
                    affectedAssetCount,
                    affectedComponentCount,
                    openFindingCount,
                    1,
                    instantValue(row.get("last_evaluated_at")),
                    instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildAwaitingExactVexIssues(
            UUID tenantId,
            Set<UUID> vendorOnlyVulnerabilityIds,
            Set<String> conflictedPairs
    ) {
        String sql = """
                SELECT
                    state.component_id,
                    state.vulnerability_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    v.external_id,
                    state.last_evaluated_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = state.component_id
                          AND f.vulnerability_id = state.vulnerability_id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN assets a ON a.id = ic.asset_id
                JOIN vulnerabilities v ON v.id = state.vulnerability_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE state.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND state.applicability_state = 'APPLICABLE'
                  AND state.matched_vex_assertion_id IS NULL
                  AND lower(coalesce(state.impact_reason, '')) = 'awaiting_vex_assessment'
                ORDER BY state.last_evaluated_at DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, tenantParams(tenantId))) {
            UUID vulnerabilityId = uuidValue(row.get("vulnerability_id"));
            UUID componentId = uuidValue(row.get("component_id"));
            if (vendorOnlyVulnerabilityIds.contains(vulnerabilityId)
                    || conflictedPairs.contains(vexPairKey(componentId, vulnerabilityId))) {
                continue;
            }
            long openFindingCount = longValue(row.get("open_finding_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("externalId", stringValue(row.get("external_id")));
            evidence.put("packageName", stringValue(row.get("package_name")));
            evidence.put("version", stringValue(row.get("version")));
            issues.add(issue(
                    tenantId,
                    "VEX",
                    "awaiting_exact_vex",
                    "state:" + stringValue(row.get("component_id")) + ":" + stringValue(row.get("vulnerability_id")),
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "awaiting_exact_vex_assessment",
                    "Component is awaiting exact VEX evidence",
                    "COMPONENT_VULNERABILITY_STATE",
                    stringValue(row.get("component_id")) + ":" + stringValue(row.get("vulnerability_id")),
                    stringValue(row.get("external_id")),
                    stringValue(row.get("package_name")) + " on " + stringValue(row.get("asset_name")),
                    uuidValue(row.get("asset_id")),
                    componentId,
                    null,
                    vulnerabilityId,
                    null,
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    openFindingCount > 0,
                    1,
                    1,
                    openFindingCount,
                    1,
                    instantValue(row.get("last_evaluated_at")),
                    instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildStaleVexMatchIssues(UUID tenantId) {
        String sql = """
                SELECT
                    state.component_id,
                    state.vulnerability_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    v.external_id,
                    state.vex_provider,
                    state.last_evaluated_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = state.component_id
                          AND f.vulnerability_id = state.vulnerability_id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN assets a ON a.id = ic.asset_id
                JOIN vulnerabilities v ON v.id = state.vulnerability_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE state.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND state.matched_vex_assertion_id IS NOT NULL
                  AND upper(coalesce(state.vex_freshness, '')) = 'STALE'
                ORDER BY state.last_evaluated_at DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, tenantParams(tenantId))) {
            long openFindingCount = longValue(row.get("open_finding_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("externalId", stringValue(row.get("external_id")));
            evidence.put("packageName", stringValue(row.get("package_name")));
            evidence.put("vexProvider", stringValue(row.get("vex_provider")));
            issues.add(issue(
                    tenantId,
                    "VEX",
                    "stale_vex_match",
                    "state:" + stringValue(row.get("component_id")) + ":" + stringValue(row.get("vulnerability_id")) + ":stale-vex",
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "matched_vex_assertion_is_stale",
                    "Component is matched to stale VEX evidence",
                    "COMPONENT_VULNERABILITY_STATE",
                    stringValue(row.get("component_id")) + ":" + stringValue(row.get("vulnerability_id")),
                    stringValue(row.get("external_id")),
                    stringValue(row.get("package_name")) + " on " + stringValue(row.get("asset_name")),
                    uuidValue(row.get("asset_id")),
                    uuidValue(row.get("component_id")),
                    null,
                    uuidValue(row.get("vulnerability_id")),
                    null,
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    openFindingCount > 0,
                    1,
                    1,
                    openFindingCount,
                    1,
                    instantValue(row.get("last_evaluated_at")),
                    instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildOpenFindingConflictsWithVexIssues(UUID tenantId) {
        String sql = """
                SELECT
                    state.component_id,
                    state.vulnerability_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    v.external_id,
                    state.impact_state,
                    state.last_evaluated_at,
                    count(*) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN findings f
                  ON f.component_id = state.component_id
                 AND f.vulnerability_id = state.vulnerability_id
                 AND f.status = 'OPEN'
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN assets a ON a.id = ic.asset_id
                JOIN vulnerabilities v ON v.id = state.vulnerability_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE state.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND state.impact_state IN ('FIXED', 'NOT_IMPACTED')
                GROUP BY
                    state.component_id,
                    state.vulnerability_id,
                    ic.asset_id,
                    a.name,
                    a.identifier,
                    a.type,
                    u.ingestion_source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    v.external_id,
                    state.impact_state,
                    state.last_evaluated_at
                ORDER BY state.last_evaluated_at DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, tenantParams(tenantId))) {
            long openFindingCount = longValue(row.get("open_finding_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("externalId", stringValue(row.get("external_id")));
            evidence.put("packageName", stringValue(row.get("package_name")));
            evidence.put("impactState", stringValue(row.get("impact_state")));
            issues.add(issue(
                    tenantId,
                    "VEX",
                    "open_finding_conflicts_with_vex",
                    "state:" + stringValue(row.get("component_id")) + ":" + stringValue(row.get("vulnerability_id")) + ":finding-conflict",
                    "CRITICAL",
                    "open_finding_conflicts_with_vex_impact_state",
                    "Open finding conflicts with current VEX-driven impact state",
                    "FINDING",
                    stringValue(row.get("component_id")) + ":" + stringValue(row.get("vulnerability_id")),
                    stringValue(row.get("external_id")),
                    stringValue(row.get("package_name")) + " on " + stringValue(row.get("asset_name")),
                    uuidValue(row.get("asset_id")),
                    uuidValue(row.get("component_id")),
                    null,
                    uuidValue(row.get("vulnerability_id")),
                    null,
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    true,
                    1,
                    1,
                    openFindingCount,
                    1,
                    instantValue(row.get("last_evaluated_at")),
                    instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildSoftwareIdentityNeedsEolMappingIssues(UUID tenantId) {
        String sql = """
                WITH exposure AS (
                    SELECT
                        ic.software_identity_id,
                        count(DISTINCT f.id) FILTER (WHERE f.status = 'OPEN') AS open_finding_count,
                        count(DISTINCT state.vulnerability_id) AS open_vulnerability_count
                    FROM inventory_components ic
                    LEFT JOIN findings f ON f.component_id = ic.id
                    LEFT JOIN component_vulnerability_states state ON state.component_id = ic.id
                    WHERE ic.tenant_id = :tenantId
                      AND ic.component_status = 'ACTIVE'
                      AND ic.software_identity_id IS NOT NULL
                    GROUP BY ic.software_identity_id
                )
                SELECT
                    sis.software_identity_id,
                    sis.display_name,
                    sis.eol_slug,
                    sis.asset_count,
                    sis.component_count,
                    sis.version_count,
                    sis.last_observed_at,
                    CASE
                        WHEN coalesce(array_length(sis.asset_types, 1), 0) = 1 THEN sis.asset_types[1]
                        WHEN coalesce(array_length(sis.asset_types, 1), 0) > 1 THEN 'MULTIPLE'
                        ELSE NULL
                    END AS asset_type,
                    CASE
                        WHEN coalesce(array_length(sis.source_systems, 1), 0) = 1 THEN sis.source_systems[1]
                        WHEN coalesce(array_length(sis.source_systems, 1), 0) > 1 THEN 'multiple'
                        ELSE NULL
                    END AS source_system,
                    CASE
                        WHEN coalesce(array_length(sis.ecosystems, 1), 0) = 1 THEN sis.ecosystems[1]
                        WHEN coalesce(array_length(sis.ecosystems, 1), 0) > 1 THEN 'multiple'
                        ELSE NULL
                    END AS ecosystem,
                    coalesce(exposure.open_finding_count, 0) AS open_finding_count,
                    coalesce(exposure.open_vulnerability_count, 0) AS open_vulnerability_count
                FROM software_identity_summary sis
                LEFT JOIN exposure ON exposure.software_identity_id = sis.software_identity_id
                WHERE sis.tenant_id = :tenantId
                  AND sis.needs_eol_mapping = true
                ORDER BY sis.last_observed_at DESC NULLS LAST, sis.display_name ASC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, tenantParams(tenantId))) {
            long openFindingCount = longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = longValue(row.get("open_vulnerability_count"));
            long assetCount = longValue(row.get("asset_count"));
            long componentCount = longValue(row.get("component_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("displayName", stringValue(row.get("display_name")));
            evidence.put("versionCount", longValue(row.get("version_count")));
            issues.add(issue(
                    tenantId,
                    "EOL",
                    "software_identity_needs_eol_mapping",
                    "software-identity:" + stringValue(row.get("software_identity_id")) + ":needs-eol-mapping",
                    severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "missing_eol_slug_mapping",
                    "Software identity needs an EOL mapping",
                    "SOFTWARE_IDENTITY",
                    stringValue(row.get("software_identity_id")),
                    stringValue(row.get("display_name")),
                    "No mapped endoflife.date slug",
                    null,
                    null,
                    uuidValue(row.get("software_identity_id")),
                    null,
                    null,
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    assetCount,
                    componentCount,
                    openFindingCount,
                    openVulnerabilityCount,
                    instantValue(row.get("last_observed_at")),
                    instantValue(row.get("last_observed_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildSoftwareIdentityUnknownLifecycleIssues(UUID tenantId, Set<UUID> suppressedIdentityIds) {
        String sql = """
                WITH exposure AS (
                    SELECT
                        ic.software_identity_id,
                        count(DISTINCT f.id) FILTER (WHERE f.status = 'OPEN') AS open_finding_count,
                        count(DISTINCT state.vulnerability_id) AS open_vulnerability_count
                    FROM inventory_components ic
                    LEFT JOIN findings f ON f.component_id = ic.id
                    LEFT JOIN component_vulnerability_states state ON state.component_id = ic.id
                    WHERE ic.tenant_id = :tenantId
                      AND ic.component_status = 'ACTIVE'
                      AND ic.software_identity_id IS NOT NULL
                    GROUP BY ic.software_identity_id
                )
                SELECT
                    sis.software_identity_id,
                    sis.display_name,
                    sis.eol_slug,
                    sis.asset_count,
                    sis.component_count,
                    sis.unknown_eol_component_count,
                    sis.last_observed_at,
                    CASE
                        WHEN coalesce(array_length(sis.source_systems, 1), 0) = 1 THEN sis.source_systems[1]
                        WHEN coalesce(array_length(sis.source_systems, 1), 0) > 1 THEN 'multiple'
                        ELSE NULL
                    END AS source_system,
                    CASE
                        WHEN coalesce(array_length(sis.ecosystems, 1), 0) = 1 THEN sis.ecosystems[1]
                        WHEN coalesce(array_length(sis.ecosystems, 1), 0) > 1 THEN 'multiple'
                        ELSE NULL
                    END AS ecosystem,
                    coalesce(exposure.open_finding_count, 0) AS open_finding_count,
                    coalesce(exposure.open_vulnerability_count, 0) AS open_vulnerability_count
                FROM software_identity_summary sis
                LEFT JOIN exposure ON exposure.software_identity_id = sis.software_identity_id
                WHERE sis.tenant_id = :tenantId
                  AND sis.needs_eol_mapping = false
                  AND sis.eol_slug IS NOT NULL
                  AND sis.unknown_eol_component_count = sis.component_count
                  AND sis.component_count > 0
                ORDER BY sis.last_observed_at DESC NULLS LAST, sis.display_name ASC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, tenantParams(tenantId))) {
            UUID identityId = uuidValue(row.get("software_identity_id"));
            if (suppressedIdentityIds.contains(identityId)) {
                continue;
            }
            long openFindingCount = longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = longValue(row.get("open_vulnerability_count"));
            long assetCount = longValue(row.get("asset_count"));
            long componentCount = longValue(row.get("component_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("displayName", stringValue(row.get("display_name")));
            evidence.put("eolSlug", stringValue(row.get("eol_slug")));
            evidence.put("unknownEolComponentCount", longValue(row.get("unknown_eol_component_count")));
            issues.add(issue(
                    tenantId,
                    "EOL",
                    "software_identity_unknown_lifecycle",
                    "software-identity:" + stringValue(row.get("software_identity_id")) + ":unknown-lifecycle",
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "mapped_slug_still_resolves_to_unknown_lifecycle",
                    "Software identity lifecycle is still unknown after mapping",
                    "SOFTWARE_IDENTITY",
                    stringValue(row.get("software_identity_id")),
                    stringValue(row.get("display_name")),
                    "Mapped slug: " + stringValue(row.get("eol_slug")),
                    null,
                    null,
                    identityId,
                    null,
                    null,
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    assetCount,
                    componentCount,
                    openFindingCount,
                    openVulnerabilityCount,
                    instantValue(row.get("last_observed_at")),
                    instantValue(row.get("last_observed_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildSoftwareIdentityCycleUnresolvedIssues(UUID tenantId, Set<UUID> suppressedIdentityIds) {
        String sql = """
                WITH exposure AS (
                    SELECT
                        ic.software_identity_id,
                        count(DISTINCT f.id) FILTER (WHERE f.status = 'OPEN') AS open_finding_count,
                        count(DISTINCT state.vulnerability_id) AS open_vulnerability_count
                    FROM inventory_components ic
                    LEFT JOIN findings f ON f.component_id = ic.id
                    LEFT JOIN component_vulnerability_states state ON state.component_id = ic.id
                    WHERE ic.tenant_id = :tenantId
                      AND ic.component_status = 'ACTIVE'
                      AND ic.software_identity_id IS NOT NULL
                    GROUP BY ic.software_identity_id
                )
                SELECT
                    sis.software_identity_id,
                    sis.display_name,
                    sis.eol_slug,
                    sis.asset_count,
                    sis.component_count,
                    sis.unknown_eol_component_count,
                    sis.last_observed_at,
                    CASE
                        WHEN coalesce(array_length(sis.source_systems, 1), 0) = 1 THEN sis.source_systems[1]
                        WHEN coalesce(array_length(sis.source_systems, 1), 0) > 1 THEN 'multiple'
                        ELSE NULL
                    END AS source_system,
                    CASE
                        WHEN coalesce(array_length(sis.ecosystems, 1), 0) = 1 THEN sis.ecosystems[1]
                        WHEN coalesce(array_length(sis.ecosystems, 1), 0) > 1 THEN 'multiple'
                        ELSE NULL
                    END AS ecosystem,
                    coalesce(exposure.open_finding_count, 0) AS open_finding_count,
                    coalesce(exposure.open_vulnerability_count, 0) AS open_vulnerability_count
                FROM software_identity_summary sis
                LEFT JOIN exposure ON exposure.software_identity_id = sis.software_identity_id
                WHERE sis.tenant_id = :tenantId
                  AND sis.needs_eol_mapping = false
                  AND sis.eol_slug IS NOT NULL
                  AND sis.unknown_eol_component_count > 0
                  AND sis.unknown_eol_component_count < sis.component_count
                ORDER BY sis.last_observed_at DESC NULLS LAST, sis.display_name ASC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, tenantParams(tenantId))) {
            UUID identityId = uuidValue(row.get("software_identity_id"));
            if (suppressedIdentityIds.contains(identityId)) {
                continue;
            }
            long openFindingCount = longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = longValue(row.get("open_vulnerability_count"));
            long assetCount = longValue(row.get("asset_count"));
            long componentCount = longValue(row.get("component_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("displayName", stringValue(row.get("display_name")));
            evidence.put("eolSlug", stringValue(row.get("eol_slug")));
            evidence.put("unknownEolComponentCount", longValue(row.get("unknown_eol_component_count")));
            issues.add(issue(
                    tenantId,
                    "EOL",
                    "software_identity_cycle_unresolved",
                    "software-identity:" + stringValue(row.get("software_identity_id")) + ":cycle-unresolved",
                    severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "mapped_slug_has_unresolved_version_cycles",
                    "Software identity has unresolved EOL cycles",
                    "SOFTWARE_IDENTITY",
                    stringValue(row.get("software_identity_id")),
                    stringValue(row.get("display_name")),
                    "Mapped slug: " + stringValue(row.get("eol_slug")),
                    null,
                    null,
                    identityId,
                    null,
                    null,
                    stringValue(row.get("source_system")),
                    stringValue(row.get("ecosystem")),
                    affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    assetCount,
                    componentCount,
                    openFindingCount,
                    openVulnerabilityCount,
                    instantValue(row.get("last_observed_at")),
                    instantValue(row.get("last_observed_at")),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildSummaryProjectionStaleIssues(UUID tenantId) {
        List<QualityIssueRecord> issues = new ArrayList<>();
        MapSqlParameterSource params = tenantParams(tenantId);

        long activeIdentityComponents = queryLong("""
                SELECT COUNT(*)
                FROM inventory_components
                WHERE tenant_id = :tenantId
                  AND component_status = 'ACTIVE'
                  AND software_identity_id IS NOT NULL
                """, params);
        long identitySummaryRows = queryLong("""
                SELECT COUNT(*)
                FROM software_identity_summary
                WHERE tenant_id = :tenantId
                """, params);
        if (activeIdentityComponents > 0 && identitySummaryRows == 0) {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("activeIdentityComponents", activeIdentityComponents);
            evidence.put("summaryRows", identitySummaryRows);
            issues.add(issue(
                    tenantId,
                    "PROJECTION_FRESHNESS",
                    "summary_projection_stale",
                    "projection:software-identity-summary:stale",
                    "HIGH",
                    "software_identity_summary_missing",
                    "Software identity summary projection is stale or missing",
                    "READ_MODEL",
                    "software-identity-summary",
                    "Software Identities",
                    "Summary rows are missing for active inventory",
                    null,
                    null,
                    null,
                    null,
                    null,
                    "projection",
                    null,
                    false,
                    0,
                    activeIdentityComponents,
                    0,
                    0,
                    Instant.now(),
                    Instant.now(),
                    evidence
            ));
        }

        long vulnerabilityCount = queryLong("SELECT COUNT(*) FROM vulnerabilities", new MapSqlParameterSource());
        long vulnerabilitySummaryCount = queryLong("SELECT COUNT(*) FROM vulnerability_intel_summary", new MapSqlParameterSource());
        if (vulnerabilityCount > 0 && vulnerabilitySummaryCount == 0) {
            long openFindingCount = queryLong("""
                    SELECT COUNT(*)
                    FROM findings
                    WHERE tenant_id = :tenantId
                      AND status = 'OPEN'
                    """, params);
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("vulnerabilityCount", vulnerabilityCount);
            evidence.put("summaryRows", vulnerabilitySummaryCount);
            issues.add(issue(
                    tenantId,
                    "PROJECTION_FRESHNESS",
                    "summary_projection_stale",
                    "projection:vulnerability-intel-summary:stale",
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "vulnerability_intel_summary_missing",
                    "Vulnerability intelligence summary projection is stale or missing",
                    "READ_MODEL",
                    "vulnerability-intel-summary",
                    "Vulnerability Intelligence",
                    "Summary rows are missing for tracked vulnerabilities",
                    null,
                    null,
                    null,
                    null,
                    null,
                    "projection",
                    null,
                    openFindingCount > 0,
                    0,
                    0,
                    openFindingCount,
                    0,
                    Instant.now(),
                    Instant.now(),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildCrossViewCountMismatchIssues(UUID tenantId) {
        List<QualityIssueRecord> issues = new ArrayList<>();
        MapSqlParameterSource params = tenantParams(tenantId);

        long activeIdentityComponents = queryLong("""
                SELECT COUNT(*)
                FROM inventory_components
                WHERE tenant_id = :tenantId
                  AND component_status = 'ACTIVE'
                  AND software_identity_id IS NOT NULL
                """, params);
        long projectedIdentityComponents = queryLong("""
                SELECT COALESCE(SUM(component_count), 0)
                FROM software_identity_summary
                WHERE tenant_id = :tenantId
                """, params);
        if (activeIdentityComponents > 0
                && projectedIdentityComponents > 0
                && activeIdentityComponents != projectedIdentityComponents) {
            long openFindingCount = queryLong("""
                    SELECT COUNT(*)
                    FROM findings
                    WHERE tenant_id = :tenantId
                      AND status = 'OPEN'
                    """, params);
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("activeIdentityComponents", activeIdentityComponents);
            evidence.put("projectedIdentityComponents", projectedIdentityComponents);
            issues.add(issue(
                    tenantId,
                    "PROJECTION_FRESHNESS",
                    "cross_view_count_mismatch",
                    "projection:software-identity-summary:mismatch",
                    openFindingCount > 0 ? "CRITICAL" : "HIGH",
                    "software_identity_summary_component_count_mismatch",
                    "Software identity summary count disagrees with active inventory",
                    "READ_MODEL",
                    "software-identity-summary",
                    "Software Identities",
                    activeIdentityComponents + " inventory components vs " + projectedIdentityComponents + " projected",
                    null,
                    null,
                    null,
                    null,
                    null,
                    "projection",
                    null,
                    openFindingCount > 0,
                    0,
                    activeIdentityComponents,
                    openFindingCount,
                    0,
                    Instant.now(),
                    Instant.now(),
                    evidence
            ));
        }

        long vulnerabilityCount = queryLong("SELECT COUNT(*) FROM vulnerabilities", new MapSqlParameterSource());
        long vulnerabilitySummaryCount = queryLong("SELECT COUNT(*) FROM vulnerability_intel_summary", new MapSqlParameterSource());
        if (vulnerabilitySummaryCount > 0 && vulnerabilityCount != vulnerabilitySummaryCount) {
            long openFindingCount = queryLong("""
                    SELECT COUNT(*)
                    FROM findings
                    WHERE tenant_id = :tenantId
                      AND status = 'OPEN'
                    """, params);
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("vulnerabilityCount", vulnerabilityCount);
            evidence.put("summaryRows", vulnerabilitySummaryCount);
            issues.add(issue(
                    tenantId,
                    "PROJECTION_FRESHNESS",
                    "cross_view_count_mismatch",
                    "projection:vulnerability-intel-summary:mismatch",
                    openFindingCount > 0 ? "CRITICAL" : "HIGH",
                    "vulnerability_intel_summary_count_mismatch",
                    "Vulnerability summary count disagrees with tracked vulnerabilities",
                    "READ_MODEL",
                    "vulnerability-intel-summary",
                    "Vulnerability Intelligence",
                    vulnerabilityCount + " vulnerabilities vs " + vulnerabilitySummaryCount + " projected summaries",
                    null,
                    null,
                    null,
                    null,
                    null,
                    "projection",
                    null,
                    openFindingCount > 0,
                    0,
                    0,
                    openFindingCount,
                    0,
                    Instant.now(),
                    Instant.now(),
                    evidence
            ));
        }
        return issues;
    }

    private List<QualityIssueRecord> buildPostRecomputeProjectionPendingIssues(UUID tenantId) {
        String sql = """
                SELECT
                    r.id,
                    r.sync_type,
                    r.status,
                    r.started_at,
                    r.records_fetched,
                    r.records_inserted,
                    r.records_updated
                FROM sync_runs r
                WHERE lower(r.status) IN ('queued', 'running')
                  AND (
                    lower(r.sync_type) LIKE '%recompute%'
                    OR lower(r.sync_type) LIKE '%backfill%'
                    OR lower(r.sync_type) LIKE '%repair%'
                    OR lower(r.sync_type) LIKE '%denormalize%'
                    OR lower(r.sync_type) LIKE '%mapping%'
                  )
                ORDER BY r.started_at DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, new MapSqlParameterSource())) {
            String syncType = stringValue(row.get("sync_type"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("syncType", syncType);
            evidence.put("status", stringValue(row.get("status")));
            evidence.put("recordsFetched", longValue(row.get("records_fetched")));
            evidence.put("recordsInserted", longValue(row.get("records_inserted")));
            evidence.put("recordsUpdated", longValue(row.get("records_updated")));
            issues.add(issue(
                    tenantId,
                    "PROJECTION_FRESHNESS",
                    "post_recompute_projection_pending",
                    "sync-pending:" + stringValue(row.get("id")),
                    "LOW",
                    "projection_refresh_pending_after_recompute",
                    "Recompute-related job is still in progress",
                    "SYNC_RUN",
                    stringValue(row.get("id")),
                    syncType,
                    "Projection updates may still be settling",
                    null,
                    null,
                    null,
                    null,
                    uuidValue(row.get("id")),
                    null,
                    normalizeSource(syncType),
                    null,
                    false,
                    0,
                    0,
                    0,
                    0,
                    instantValue(row.get("started_at")),
                    instantValue(row.get("started_at")),
                    evidence
            ));
        }
        return issues;
    }

    private QualityIssueRecord issue(
            UUID tenantId,
            String domain,
            String issueType,
            String issueKeySuffix,
            String severity,
            String reasonCode,
            String title,
            String sourceObjectType,
            String sourceObjectId,
            String primaryLabel,
            String secondaryLabel,
            UUID assetId,
            UUID componentId,
            UUID syncRunId,
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
            Map<String, Object> evidence
    ) {
        return issue(
                tenantId,
                domain,
                issueType,
                issueKeySuffix,
                severity,
                reasonCode,
                title,
                sourceObjectType,
                sourceObjectId,
                primaryLabel,
                secondaryLabel,
                assetId,
                componentId,
                null,
                null,
                syncRunId,
                assetType,
                sourceSystem,
                ecosystem,
                affectsActiveFindings,
                affectedAssetCount,
                affectedComponentCount,
                openFindingCount,
                openVulnerabilityCount,
                firstSeenAt,
                lastSeenAt,
                evidence
        );
    }

    private QualityIssueRecord issue(
            UUID tenantId,
            String domain,
            String issueType,
            String issueKeySuffix,
            String severity,
            String reasonCode,
            String title,
            String sourceObjectType,
            String sourceObjectId,
            String primaryLabel,
            String secondaryLabel,
            UUID assetId,
            UUID componentId,
            UUID softwareIdentityId,
            UUID vulnerabilityId,
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
            Map<String, Object> evidence
    ) {
        return issue(
                tenantId,
                domain,
                issueType,
                issueKeySuffix,
                severity,
                reasonCode,
                title,
                sourceObjectType,
                sourceObjectId,
                primaryLabel,
                secondaryLabel,
                assetId,
                componentId,
                softwareIdentityId,
                vulnerabilityId,
                null,
                assetType,
                sourceSystem,
                ecosystem,
                affectsActiveFindings,
                affectedAssetCount,
                affectedComponentCount,
                openFindingCount,
                openVulnerabilityCount,
                firstSeenAt,
                lastSeenAt,
                evidence
        );
    }

    private QualityIssueRecord issue(
            UUID tenantId,
            String domain,
            String issueType,
            String issueKeySuffix,
            String severity,
            String reasonCode,
            String title,
            String sourceObjectType,
            String sourceObjectId,
            String primaryLabel,
            String secondaryLabel,
            UUID assetId,
            UUID componentId,
            UUID softwareIdentityId,
            UUID vulnerabilityId,
            UUID syncRunId,
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
            Map<String, Object> evidence
    ) {
        String normalizedDomain = normalizeExact(domain);
        String normalizedIssueType = normalizeExact(issueType);
        String issueKey = normalizedDomain.toLowerCase(Locale.ROOT) + ":" + normalizeForKey(issueKeySuffix);
        String id = tenantId + ":" + issueKey;
        Instant seenAt = firstSeenAt == null ? Instant.now() : firstSeenAt;
        Instant observedAt = lastSeenAt == null ? seenAt : lastSeenAt;
        return new QualityIssueRecord(
                id,
                tenantId,
                issueKey,
                normalizedDomain,
                normalizedIssueType,
                normalizeExact(severity),
                reasonCode,
                sourceObjectType,
                sourceObjectId,
                assetId,
                componentId,
                softwareIdentityId,
                vulnerabilityId,
                syncRunId,
                title,
                primaryLabel,
                secondaryLabel,
                assetType == null ? null : normalizeExact(assetType),
                sourceSystem == null ? null : normalizeSource(sourceSystem),
                ecosystem == null ? null : ecosystem.trim().toLowerCase(Locale.ROOT),
                affectsActiveFindings,
                affectedAssetCount,
                affectedComponentCount,
                openFindingCount,
                openVulnerabilityCount,
                seenAt,
                observedAt,
                Instant.now(),
                toJson(evidence),
                "[]"
        );
    }

    private void upsertRows(List<QualityIssueRecord> issues) {
        if (issues == null || issues.isEmpty()) {
            return;
        }
        String sql = """
                INSERT INTO quality_issue_projection (
                    id,
                    tenant_id,
                    issue_key,
                    domain,
                    issue_type,
                    severity,
                    reason_code,
                    source_object_type,
                    source_object_id,
                    asset_id,
                    component_id,
                    software_identity_id,
                    vulnerability_id,
                    sync_run_id,
                    title,
                    primary_label,
                    secondary_label,
                    asset_type,
                    source_system,
                    ecosystem,
                    affects_active_findings,
                    affected_asset_count,
                    affected_component_count,
                    open_finding_count,
                    open_vulnerability_count,
                    first_seen_at,
                    last_seen_at,
                    last_computed_at,
                    evidence_json,
                    drilldown_json
                )
                VALUES (
                    :id,
                    :tenantId,
                    :issueKey,
                    :domain,
                    :issueType,
                    :severity,
                    :reasonCode,
                    :sourceObjectType,
                    :sourceObjectId,
                    :assetId,
                    :componentId,
                    :softwareIdentityId,
                    :vulnerabilityId,
                    :syncRunId,
                    :title,
                    :primaryLabel,
                    :secondaryLabel,
                    :assetType,
                    :sourceSystem,
                    :ecosystem,
                    :affectsActiveFindings,
                    :affectedAssetCount,
                    :affectedComponentCount,
                    :openFindingCount,
                    :openVulnerabilityCount,
                    :firstSeenAt,
                    :lastSeenAt,
                    :lastComputedAt,
                    cast(:evidenceJson as jsonb),
                    cast(:drilldownJson as jsonb)
                )
                ON CONFLICT (id) DO UPDATE SET
                    id = EXCLUDED.id,
                    tenant_id = EXCLUDED.tenant_id,
                    issue_key = EXCLUDED.issue_key,
                    domain = EXCLUDED.domain,
                    issue_type = EXCLUDED.issue_type,
                    severity = EXCLUDED.severity,
                    reason_code = EXCLUDED.reason_code,
                    source_object_type = EXCLUDED.source_object_type,
                    source_object_id = EXCLUDED.source_object_id,
                    asset_id = EXCLUDED.asset_id,
                    component_id = EXCLUDED.component_id,
                    software_identity_id = EXCLUDED.software_identity_id,
                    vulnerability_id = EXCLUDED.vulnerability_id,
                    sync_run_id = EXCLUDED.sync_run_id,
                    title = EXCLUDED.title,
                    primary_label = EXCLUDED.primary_label,
                    secondary_label = EXCLUDED.secondary_label,
                    asset_type = EXCLUDED.asset_type,
                    source_system = EXCLUDED.source_system,
                    ecosystem = EXCLUDED.ecosystem,
                    affects_active_findings = EXCLUDED.affects_active_findings,
                    affected_asset_count = EXCLUDED.affected_asset_count,
                    affected_component_count = EXCLUDED.affected_component_count,
                    open_finding_count = EXCLUDED.open_finding_count,
                    open_vulnerability_count = EXCLUDED.open_vulnerability_count,
                    first_seen_at = quality_issue_projection.first_seen_at,
                    last_seen_at = EXCLUDED.last_seen_at,
                    last_computed_at = EXCLUDED.last_computed_at,
                    evidence_json = EXCLUDED.evidence_json,
                    drilldown_json = EXCLUDED.drilldown_json
                """;
        MapSqlParameterSource[] batch = issues.stream()
                .map(issue -> new MapSqlParameterSource()
                        .addValue("id", issue.id())
                        .addValue("tenantId", issue.tenantId())
                        .addValue("issueKey", issue.issueKey())
                        .addValue("domain", issue.domain())
                        .addValue("issueType", issue.issueType())
                        .addValue("severity", issue.severity())
                        .addValue("reasonCode", issue.reasonCode())
                        .addValue("sourceObjectType", issue.sourceObjectType())
                        .addValue("sourceObjectId", issue.sourceObjectId())
                        .addValue("assetId", issue.assetId())
                        .addValue("componentId", issue.componentId())
                        .addValue("softwareIdentityId", issue.softwareIdentityId())
                        .addValue("vulnerabilityId", issue.vulnerabilityId())
                        .addValue("syncRunId", issue.syncRunId())
                        .addValue("title", issue.title())
                        .addValue("primaryLabel", issue.primaryLabel())
                        .addValue("secondaryLabel", issue.secondaryLabel())
                        .addValue("assetType", issue.assetType())
                        .addValue("sourceSystem", issue.sourceSystem())
                        .addValue("ecosystem", issue.ecosystem())
                        .addValue("affectsActiveFindings", issue.affectsActiveFindings())
                        .addValue("affectedAssetCount", issue.affectedAssetCount())
                        .addValue("affectedComponentCount", issue.affectedComponentCount())
                        .addValue("openFindingCount", issue.openFindingCount())
                        .addValue("openVulnerabilityCount", issue.openVulnerabilityCount())
                        .addValue("firstSeenAt", Timestamp.from(issue.firstSeenAt()))
                        .addValue("lastSeenAt", Timestamp.from(issue.lastSeenAt()))
                        .addValue("lastComputedAt", Timestamp.from(issue.lastComputedAt()))
                        .addValue("evidenceJson", issue.evidenceJson())
                        .addValue("drilldownJson", issue.drilldownJson()))
                .toArray(MapSqlParameterSource[]::new);
        jdbcTemplate.batchUpdate(sql, batch);
    }

    private void deleteStaleRows(UUID tenantId, List<QualityIssueRecord> issues) {
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("tenantId", tenantId);
        if (issues == null || issues.isEmpty()) {
            jdbcTemplate.update("DELETE FROM quality_issue_projection WHERE tenant_id = :tenantId", params);
            return;
        }
        List<String> issueKeys = issues.stream().map(QualityIssueRecord::issueKey).distinct().toList();
        params.addValue("issueKeys", issueKeys);
        jdbcTemplate.update("""
                DELETE FROM quality_issue_projection
                WHERE tenant_id = :tenantId
                  AND issue_key NOT IN (:issueKeys)
                """, params);
    }

    private MapSqlParameterSource tenantParams(UUID tenantId) {
        return new MapSqlParameterSource().addValue("tenantId", tenantId);
    }

    private long queryLong(String sql, MapSqlParameterSource params) {
        Long value = jdbcTemplate.queryForObject(sql, params, Long.class);
        return value == null ? 0L : value;
    }

    private String severityForExposureIssue(long openFindingCount, long openVulnerabilityCount, String defaultSeverity) {
        if (openFindingCount > 0) {
            return "HIGH";
        }
        if (openVulnerabilityCount > 0) {
            return "MEDIUM";
        }
        return defaultSeverity;
    }

    private boolean affectsActiveFindings(long openFindingCount, long openVulnerabilityCount) {
        return openFindingCount > 0 || openVulnerabilityCount > 0;
    }

    private boolean isVulnerabilityOrLifecycleSource(String syncType) {
        String normalized = normalizeSource(syncType);
        return normalized.contains("vex")
                || normalized.contains("csaf")
                || normalized.contains("nvd")
                || normalized.contains("eol");
    }

    private String normalizeSource(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.trim()
                .toLowerCase(Locale.ROOT)
                .replace(' ', '_')
                .replace('-', '_');
    }

    private String normalizeExact(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
    }

    private String normalizeForKey(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.trim()
                .toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("(^-|-$)", "");
    }

    private String vexPairKey(UUID componentId, UUID vulnerabilityId) {
        if (componentId == null || vulnerabilityId == null) {
            return null;
        }
        return componentId + ":" + vulnerabilityId;
    }

    private String toJson(Map<String, Object> evidence) {
        try {
            return objectMapper.writeValueAsString(evidence == null ? Map.of() : evidence);
        } catch (JsonProcessingException ignored) {
            return "{}";
        }
    }

    private String stringValue(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private UUID uuidValue(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof UUID uuid) {
            return uuid;
        }
        String text = String.valueOf(value).trim();
        if (text.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(text);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private long longValue(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value == null) {
            return 0L;
        }
        try {
            return Long.parseLong(String.valueOf(value));
        } catch (NumberFormatException ignored) {
            return 0L;
        }
    }

    private double doubleValue(Object value) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value == null) {
            return 0d;
        }
        try {
            return Double.parseDouble(String.valueOf(value));
        } catch (NumberFormatException ignored) {
            return 0d;
        }
    }

    private boolean boolValue(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        return value != null && Boolean.parseBoolean(String.valueOf(value));
    }

    private Instant instantValue(Object value) {
        if (value instanceof Instant instant) {
            return instant;
        }
        if (value instanceof Timestamp timestamp) {
            return timestamp.toInstant();
        }
        return null;
    }

    private record QualityIssueRecord(
            String id,
            UUID tenantId,
            String issueKey,
            String domain,
            String issueType,
            String severity,
            String reasonCode,
            String sourceObjectType,
            String sourceObjectId,
            UUID assetId,
            UUID componentId,
            UUID softwareIdentityId,
            UUID vulnerabilityId,
            UUID syncRunId,
            String title,
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
            Instant lastComputedAt,
            String evidenceJson,
            String drilldownJson
    ) {
    }
}
