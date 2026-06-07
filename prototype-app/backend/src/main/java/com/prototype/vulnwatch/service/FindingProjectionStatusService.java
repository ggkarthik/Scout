package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.time.Duration;
import java.time.Instant;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingProjectionStatusService {

    private static final String STATUS_KEY = "finding-workspace";
    private static final long STALE_AFTER_SECONDS = 15 * 60L;

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final FindingProjectionRefreshService findingProjectionRefreshService;

    public FindingProjectionStatusService(
            NamedParameterJdbcTemplate jdbcTemplate,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            FindingProjectionRefreshService findingProjectionRefreshService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.findingProjectionRefreshService = findingProjectionRefreshService;
    }

    @Transactional(readOnly = true)
    public FindingListProjectionService.ProjectionStatus getProjectionStatus(Tenant tenant) {
        FindingListProjectionService.ProjectionStatus status = inspectProjectionStatus(tenant);
        if (status.missing()) {
            findingProjectionRefreshService.refreshTenant(tenant);
            return inspectProjectionStatus(tenant);
        }
        return status;
    }

    @Transactional(readOnly = true)
    public FindingListProjectionService.ProjectionStatus inspectProjectionStatus(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return FindingListProjectionService.ProjectionStatus.empty();
        }
        return tenantSchemaExecutionService.run(tenant, () -> {
            long currentProjectedCount = findingProjectionRefreshService.countProjectedRows();
            long sourceFindingCount = findingProjectionRefreshService.countSourceFindings();
            return jdbcTemplate.query("""
                    SELECT last_computed_at, last_rebuild_duration_ms
                    FROM finding_workspace_projection_status
                    WHERE projection_key = :projectionKey
                    """,
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
        return Duration.between(lastComputedAt, Instant.now()).getSeconds() > STALE_AFTER_SECONDS;
    }
}
