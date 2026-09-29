package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;

class AiGridPolicyPortfolioServiceTest {

    private final NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
    private final TenantSchemaExecutionService tenantExecution = mock(TenantSchemaExecutionService.class);
    private final AiGridPolicyPortfolioService service = new AiGridPolicyPortfolioService(
            jdbc, new ObjectMapper(), mock(AuditEventService.class), tenantExecution);

    @Test
    @SuppressWarnings("unchecked")
    void reportsMissingTenantV2AsNotAssessedInsteadOfFailing() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        UUID epoch = UUID.randomUUID();
        UUID run = UUID.randomUUID();
        when(tenantExecution.run(any(Tenant.class), any(Supplier.class)))
                .thenAnswer(invocation -> invocation.getArgument(1, Supplier.class).get());
        when(jdbc.queryForObject(contains("ai_grid_frameworks"), any(Map.class),
                org.mockito.ArgumentMatchers.eq(Integer.class))).thenReturn(1);
        when(jdbc.query(contains("from ai_grid_policy_readiness"), any(Map.class), any(ResultSetExtractor.class))).thenReturn(run);
        when(jdbc.query(contains("tenant_schema_versions"), any(Map.class), any(ResultSetExtractor.class))).thenReturn(false);
        when(jdbc.query(contains("with latest as"), any(SqlParameterSource.class), any(RowMapper.class))).thenReturn(List.of());
        when(jdbc.queryForObject(contains("where p.release_family is null"), any(Map.class), any(RowMapper.class)))
                .thenReturn(new AiGridPolicyPortfolioService.LegacyCompatibility(21, 21, 13, 0, 8));

        var coverage = service.frameworkCoverage(tenant, "OWASP_AGENTIC_TOP_10", "2026", epoch);

        assertFalse(coverage.tenantSchemaReady());
        assertEquals(List.of("TENANT_SCHEMA_VERSION_UNAVAILABLE"), coverage.blockers());
        verify(jdbc).query(contains("r.selection='PREVIEW'"), any(SqlParameterSource.class), any(RowMapper.class));
        verify(jdbc).query(contains("platform.ai_grid_policy_visible_to_tenant"),
                any(SqlParameterSource.class), any(RowMapper.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void reportsAnExplicitBlockerWhenNoCoverageEpochExists() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        when(tenantExecution.run(any(Tenant.class), any(Supplier.class)))
                .thenAnswer(invocation -> invocation.getArgument(1, Supplier.class).get());
        when(jdbc.queryForObject(contains("ai_grid_frameworks"), any(Map.class),
                org.mockito.ArgumentMatchers.eq(Integer.class))).thenReturn(1);
        when(jdbc.query(contains("select epoch_id"), any(Map.class), any(ResultSetExtractor.class))).thenReturn(null);
        when(jdbc.query(contains("tenant_schema_versions"), any(Map.class), any(ResultSetExtractor.class))).thenReturn(true);
        when(jdbc.query(contains("with latest as"), any(SqlParameterSource.class), any(RowMapper.class))).thenReturn(List.of());
        when(jdbc.queryForObject(contains("where p.release_family is null"), any(Map.class), any(RowMapper.class)))
                .thenReturn(new AiGridPolicyPortfolioService.LegacyCompatibility(21, 21, 13, 0, 8));

        var coverage = service.frameworkCoverage(tenant, "OWASP_AGENTIC_TOP_10", "2026", null);

        assertEquals(List.of("NO_COVERAGE_EPOCH"), coverage.blockers());
    }
}
