package com.prototype.vulnwatch.service;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class IngestionQualityIssueBuilder {

    private static final long SOURCE_STALE_HOURS = 24L;
    private static final long RECENT_WINDOW_DAYS = 7L;

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final QualityIssueJdbcSupport support;

    public IngestionQualityIssueBuilder(
            NamedParameterJdbcTemplate jdbcTemplate,
            QualityIssueJdbcSupport support
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.support = support;
    }

    public List<QualityIssueRecord> buildSourceRunFailedIssues(UUID tenantId) {
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
            String syncType = support.stringValue(row.get("sync_type"));
            String sourceSystem = support.normalizeSource(syncType);
            long fetched = support.longValue(row.get("records_fetched"));
            long inserted = support.longValue(row.get("records_inserted"));
            long updated = support.longValue(row.get("records_updated"));
            long failed = support.longValue(row.get("records_failed"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("syncType", syncType);
            evidence.put("status", support.stringValue(row.get("status")));
            evidence.put("errorMessage", support.stringValue(row.get("error_message")));
            evidence.put("recordsFetched", fetched);
            evidence.put("recordsInserted", inserted);
            evidence.put("recordsUpdated", updated);
            evidence.put("recordsFailed", failed);
            issues.add(support.issue(
                    tenantId,
                    "INGESTION",
                    "source_run_failed",
                    "sync:" + support.normalizeForKey(syncType),
                    "HIGH",
                    "latest_run_failed",
                    "Latest source run failed",
                    "SYNC_RUN",
                    support.stringValue(row.get("id")),
                    null,
                    null,
                    null,
                    null,
                    support.uuidValue(row.get("id")),
                    null,
                    sourceSystem,
                    null,
                    false,
                    0,
                    0,
                    0,
                    0,
                    support.instantValue(row.get("started_at")),
                    support.instantValue(row.get("started_at")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildSourceRunPartialFailureIssues(UUID tenantId) {
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
            String syncType = support.stringValue(row.get("sync_type"));
            String sourceSystem = support.normalizeSource(syncType);
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("syncType", syncType);
            evidence.put("recordsFetched", support.longValue(row.get("records_fetched")));
            evidence.put("recordsInserted", support.longValue(row.get("records_inserted")));
            evidence.put("recordsUpdated", support.longValue(row.get("records_updated")));
            evidence.put("recordsFailed", support.longValue(row.get("records_failed")));
            issues.add(support.issue(
                    tenantId,
                    "INGESTION",
                    "source_run_partial_failure",
                    "sync-partial:" + support.normalizeForKey(syncType),
                    "MEDIUM",
                    "run_completed_with_failed_records",
                    "Source run completed with failed records",
                    "SYNC_RUN",
                    support.stringValue(row.get("id")),
                    null,
                    null,
                    null,
                    null,
                    support.uuidValue(row.get("id")),
                    null,
                    sourceSystem,
                    null,
                    false,
                    0,
                    0,
                    0,
                    0,
                    support.instantValue(row.get("started_at")),
                    support.instantValue(row.get("started_at")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildSourceFeedStaleIssues(UUID tenantId, Set<UUID> failedSources) {
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
            String syncType = support.stringValue(row.get("sync_type"));
            String sourceSystem = support.normalizeSource(syncType);
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("syncType", syncType);
            evidence.put("lastSuccessAt", support.instantValue(row.get("last_success_at")));
            evidence.put("staleThresholdHours", SOURCE_STALE_HOURS);
            issues.add(support.issue(
                    tenantId,
                    "INGESTION",
                    "source_feed_stale",
                    "sync-stale:" + support.normalizeForKey(syncType),
                    support.isVulnerabilityOrLifecycleSource(syncType) ? "HIGH" : "MEDIUM",
                    "latest_success_older_than_stale_threshold",
                    "Source feed is stale",
                    "SYNC_SOURCE",
                    support.normalizeForKey(syncType),
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
                    support.instantValue(row.get("last_success_at")),
                    support.instantValue(row.get("last_success_at")),
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
            issues.add(support.issue(
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

    public List<QualityIssueRecord> buildIngestedNoDownstreamRecordsIssues(UUID tenantId) {
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
            String syncType = support.stringValue(row.get("sync_type"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("syncType", syncType);
            evidence.put("recordsFetched", support.longValue(row.get("records_fetched")));
            evidence.put("recordsInserted", support.longValue(row.get("records_inserted")));
            evidence.put("recordsUpdated", support.longValue(row.get("records_updated")));
            issues.add(support.issue(
                    tenantId,
                    "INGESTION",
                    "ingested_no_downstream_records",
                    "sync-zero:" + support.normalizeForKey(syncType),
                    "MEDIUM",
                    "successful_ingest_without_materialized_records",
                    "Source ingest produced no downstream records",
                    "SYNC_RUN",
                    support.stringValue(row.get("id")),
                    syncType,
                    "Fetched records but no inserts or updates were materialized",
                    null,
                    null,
                    support.uuidValue(row.get("id")),
                    null,
                    support.normalizeSource(syncType),
                    null,
                    false,
                    0,
                    0,
                    0,
                    0,
                    support.instantValue(row.get("started_at")),
                    support.instantValue(row.get("started_at")),
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
            evidence.put("assetName", support.stringValue(row.get("asset_name")));
            evidence.put("assetIdentifier", support.stringValue(row.get("asset_identifier")));
            evidence.put("componentCount", support.longValue(row.get("component_count")));
            issues.add(support.issue(
                    tenantId,
                    "INGESTION",
                    "ingested_no_downstream_records",
                    "sbom-zero:" + support.stringValue(row.get("id")),
                    "MEDIUM",
                    "successful_ingest_without_materialized_records",
                    "SBOM upload produced no materialized components",
                    "SBOM_UPLOAD",
                    support.stringValue(row.get("id")),
                    support.stringValue(row.get("asset_name")),
                    support.stringValue(row.get("asset_identifier")),
                    support.uuidValue(row.get("asset_id")),
                    null,
                    support.uuidValue(row.get("id")),
                    null,
                    support.stringValue(row.get("source_system")),
                    null,
                    false,
                    1,
                    0,
                    0,
                    0,
                    support.instantValue(row.get("uploaded_at")),
                    support.instantValue(row.get("uploaded_at")),
                    evidence
            ));
        }
        return issues;
    }
}
