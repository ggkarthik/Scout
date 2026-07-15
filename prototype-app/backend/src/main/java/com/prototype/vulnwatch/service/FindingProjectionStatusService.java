package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.time.Duration;
import java.time.Instant;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class FindingProjectionStatusService {

    private static final String STATUS_KEY = "finding-workspace";

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final FindingProjectionRefreshService findingProjectionRefreshService;
    private final TransactionTemplate readTransactionTemplate;
    private final long staleAfterSeconds;

    public FindingProjectionStatusService(
            NamedParameterJdbcTemplate jdbcTemplate,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            FindingProjectionRefreshService findingProjectionRefreshService,
            PlatformTransactionManager transactionManager,
            @Value("${app.slo.projection-stale-threshold-minutes:15}") long projectionStaleThresholdMinutes
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.findingProjectionRefreshService = findingProjectionRefreshService;
        this.readTransactionTemplate = new TransactionTemplate(transactionManager);
        this.readTransactionTemplate.setReadOnly(true);
        this.readTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.staleAfterSeconds = Math.max(1L, projectionStaleThresholdMinutes) * 60L;
    }

    public FindingListProjectionService.ProjectionStatus getProjectionStatus(Tenant tenant) {
        FindingListProjectionService.ProjectionStatus status = inspectProjectionStatus(tenant);
        if (status.missing()) {
            findingProjectionRefreshService.refreshTenant(tenant);
            return inspectProjectionStatus(tenant);
        }
        return status;
    }

    public FindingListProjectionService.ProjectionStatus inspectProjectionStatus(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return FindingListProjectionService.ProjectionStatus.empty();
        }
        String statusTable = qualifiedTenantTable(tenant, "finding_workspace_projection_status");
        return tenantSchemaExecutionService.run(tenant, () -> {
            FindingListProjectionService.ProjectionStatus status = readTransactionTemplate.execute(transactionStatus -> {
                long currentProjectedCount = findingProjectionRefreshService.countProjectedRows(tenant);
                long sourceFindingCount = findingProjectionRefreshService.countSourceFindings();
                return jdbcTemplate.query("""
                        SELECT last_computed_at, last_rebuild_duration_ms
                        FROM %s
                        WHERE projection_key = :projectionKey
                        """.formatted(statusTable),
                        new MapSqlParameterSource().addValue("projectionKey", STATUS_KEY),
                        rs -> rs.next()
                                ? new FindingListProjectionService.ProjectionStatus(
                                        rs.getTimestamp("last_computed_at").toInstant(),
                                        currentProjectedCount,
                                        sourceFindingCount,
                                        coalesceNullableLong(rs, "last_rebuild_duration_ms"),
                                        buildStaleFlag(
                                                rs.getTimestamp("last_computed_at") == null ? null : rs.getTimestamp("last_computed_at").toInstant(),
                                                currentProjectedCount,
                                                sourceFindingCount
                                        ),
                                        Math.abs(currentProjectedCount - sourceFindingCount)
                                )
                                : FindingListProjectionService.ProjectionStatus.missing(sourceFindingCount)
                );
            });
            return status == null ? FindingListProjectionService.ProjectionStatus.empty() : status;
        });
    }

    private String qualifiedTenantTable(Tenant tenant, String tableName) {
        String schema = tenant == null ? null : tenant.getSchemaName();
        if (schema == null || !schema.matches("[a-z][a-z0-9_]*")) {
            throw new IllegalArgumentException("Invalid tenant schema name");
        }
        return '"' + schema + '"' + "." + '"' + tableName + '"';
    }

    private Long coalesceNullableLong(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    private boolean buildStaleFlag(Instant lastComputedAt, long findingCount, long sourceFindingCount) {
        if (lastComputedAt == null) {
            return true;
        }
        if (findingCount != sourceFindingCount) {
            return true;
        }
        return Duration.between(lastComputedAt, Instant.now()).getSeconds() > staleAfterSeconds;
    }
}
