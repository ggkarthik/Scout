package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.sql.ResultSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;

class AiGridTenantPolicyDefaultsServiceTest {
    private final NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
    private final TenantSchemaExecutionService tenantExecution = mock(TenantSchemaExecutionService.class);
    private final AuditEventService audit = mock(AuditEventService.class);
    private final Tenant tenant = tenant();
    private final AiGridTenantPolicyDefaultsService service =
            new AiGridTenantPolicyDefaultsService(jdbc, tenantExecution, audit);

    @BeforeEach
    @SuppressWarnings("unchecked")
    void executeInTenantContext() {
        when(tenantExecution.run(any(Tenant.class), any(Supplier.class)))
                .thenAnswer(invocation -> invocation.getArgument(1, Supplier.class).get());
    }

    @Test
    @SuppressWarnings("unchecked")
    void preservesPreviewDefaultAndSelectsOneVersionPerDistribution() throws Exception {
        stubQueries("PREVIEW", null, null);
        when(jdbc.update(anyString(), any(SqlParameterSource.class))).thenReturn(1);

        AiGridTenantPolicyDefaultsService.SynchronizationResult result = service.ensureDefaults(tenant);

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<SqlParameterSource> parameters = ArgumentCaptor.forClass(SqlParameterSource.class);
        verify(jdbc).update(sql.capture(), parameters.capture());
        assertEquals("PREVIEW", parameters.getValue().getValue("selection"));
        assertTrue(sql.getValue().contains("configuration_source = 'PLATFORM_DEFAULT'"));
        assertEquals(1, result.distributedPolicies());
        assertEquals(1, result.insertedPolicies());
        assertEquals(0, result.realignedPolicies());
        verify(audit, never()).recordExplicitActor(any(), anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyString());

        ArgumentCaptor<String> query = ArgumentCaptor.forClass(String.class);
        verify(jdbc, org.mockito.Mockito.times(2)).query(query.capture(), any(Map.class), any(RowMapper.class));
        assertTrue(query.getAllValues().get(0).contains("join lateral"));
        assertTrue(query.getAllValues().get(0).contains("limit 1"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void realignsOnlyPlatformDefaultsAndAuditsTheRestrictiveMove() throws Exception {
        stubQueries("DISABLED", "ENABLED", "PLATFORM_DEFAULT");
        when(jdbc.update(anyString(), any(SqlParameterSource.class))).thenReturn(1);

        AiGridTenantPolicyDefaultsService.SynchronizationResult result = service.ensureDefaults(tenant);

        assertEquals(1, result.realignedPolicies());
        assertEquals(1, result.enabledToDisabledOrPreview());
        verify(jdbc, org.mockito.Mockito.times(2)).update(anyString(), any(SqlParameterSource.class));
        verify(audit).recordExplicitActor(any(), anyString(), anyString(),
                org.mockito.ArgumentMatchers.eq("ai_grid.policy_defaults.backfill_planned"),
                anyString(), anyString(), anyString(), anyString());
        verify(audit).recordExplicitActor(any(), anyString(), anyString(),
                org.mockito.ArgumentMatchers.eq("ai_grid.policy_default.realigned"),
                anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void leavesTenantOverrideSelectionUntouched() throws Exception {
        stubQueries("DISABLED", "ENABLED", "TENANT_OVERRIDE");
        when(jdbc.update(anyString(), any(SqlParameterSource.class))).thenReturn(1);

        AiGridTenantPolicyDefaultsService.SynchronizationResult result = service.ensureDefaults(tenant);

        assertEquals(0, result.realignedPolicies());
        assertEquals(0, result.enabledToDisabledOrPreview());
        verify(jdbc).update(anyString(), any(SqlParameterSource.class));
        verify(audit, never()).recordExplicitActor(any(), anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyString());
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void stubQueries(String platformDefault, String currentSelection,
                             String configurationSource) throws Exception {
        when(jdbc.query(anyString(), any(Map.class), any(RowMapper.class))).thenAnswer(invocation -> {
            String sql = invocation.getArgument(0, String.class);
            RowMapper mapper = invocation.getArgument(2, RowMapper.class);
            ResultSet resultSet = mock(ResultSet.class);
            if (sql.contains("platform.ai_grid_policy_distribution")) {
                when(resultSet.getString("policy_id")).thenReturn("RUNTIME_TEST_POLICY");
                when(resultSet.getString("version")).thenReturn("2.0.0");
                when(resultSet.getString("default_selection")).thenReturn(platformDefault);
                return List.of(mapper.mapRow(resultSet, 0));
            }
            if (currentSelection == null) {
                return List.of();
            }
            when(resultSet.getString("policy_id")).thenReturn("RUNTIME_TEST_POLICY");
            when(resultSet.getString("selection")).thenReturn(currentSelection);
            when(resultSet.getString("configuration_source")).thenReturn(configurationSource);
            return List.of(mapper.mapRow(resultSet, 0));
        });
    }

    private static Tenant tenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        return tenant;
    }
}
