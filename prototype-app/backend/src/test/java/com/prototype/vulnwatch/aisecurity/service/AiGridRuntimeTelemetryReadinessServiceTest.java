package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.migration.PackagedMigrationCatalog;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.sql.ResultSet;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;

class AiGridRuntimeTelemetryReadinessServiceTest {

    @Test
    @SuppressWarnings("unchecked")
    void configuredProviderWithNoExecutionsFailsClosed() throws Exception {
        NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
        TenantSchemaExecutionService execution = mock(TenantSchemaExecutionService.class);
        when(execution.run(any(Tenant.class), any(Supplier.class)))
                .thenAnswer(invocation -> invocation.getArgument(1, Supplier.class).get());
        when(jdbc.query(contains("platform.tenant_schema_versions"), anyMap(), any(ResultSetExtractor.class)))
                .thenReturn(PackagedMigrationCatalog.resolve().tenantTarget());
        when(jdbc.query(contains("with configured_sources as"), any(SqlParameterSource.class), any(RowMapper.class)))
                .thenAnswer(invocation -> {
                    RowMapper<AiGridRuntimeTelemetryReadinessService.SourceReadiness> mapper = invocation.getArgument(2);
                    ResultSet rs = mock(ResultSet.class);
                    when(rs.getString("source_id")).thenReturn("AZURE_FOUNDRY_RUNTIME");
                    when(rs.getString("provider")).thenReturn("AZURE_FOUNDRY");
                    when(rs.getString("source_kind")).thenReturn("PROVIDER_CONNECTOR");
                    when(rs.getBoolean("required_for_program_gate")).thenReturn(true);
                    when(rs.getBoolean("configured")).thenReturn(true);
                    when(rs.getLong("executions")).thenReturn(0L);
                    when(rs.getLong("approval_populated")).thenReturn(0L);
                    when(rs.getLong("policy_populated")).thenReturn(0L);
                    return java.util.List.of(mapper.mapRow(rs, 0));
                });
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        var readiness = new AiGridRuntimeTelemetryReadinessService(
                jdbc, execution, new PackagedMigrationCatalog())
                .readiness(tenant);

        assertEquals(true, readiness.available());
        assertFalse(readiness.program2EntryGateMet());
        assertEquals(java.util.List.of("MINIMUM_EXECUTIONS_NOT_MET",
                        "CONSEQUENTIAL_EVENT_SAMPLE_INSUFFICIENT", "APPROVAL_STATE_FILL_BELOW_THRESHOLD",
                        "POLICY_STATE_FILL_BELOW_THRESHOLD", "ACTION_OUTCOME_FILL_BELOW_THRESHOLD",
                        "AGENT_CORRELATION_BELOW_THRESHOLD", "VERSION_SAMPLE_INSUFFICIENT"),
                readiness.providers().get(0).blockers());
    }
}
