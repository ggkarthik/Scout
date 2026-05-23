package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.FindingResponse;
import com.prototype.vulnwatch.dto.FindingFilterValuesResponse;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class FindingQueryServiceTest {

    @Mock
    private FindingRepository findingRepository;
    @Mock
    private FindingsScoreService findingsScoreService;
    @Mock
    private RiskPolicyService riskPolicyService;
    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Test
    void listAvailableFiltersNormalizesRepositoryValuesAndAppliesPreferredOrdering() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        when(findingRepository.findDistinctSeveritiesByTenant(tenant)).thenReturn(List.of("medium", "critical"));
        when(findingRepository.findDistinctStatusesByTenant(tenant)).thenReturn(List.of(FindingStatus.RESOLVED, FindingStatus.OPEN));
        when(findingRepository.findDistinctDecisionStatesByTenant(tenant)).thenReturn(List.of(
                FindingDecisionState.UNDER_INVESTIGATION,
                FindingDecisionState.AFFECTED
        ));
        when(findingRepository.findDistinctMatchMethodsByTenant(tenant)).thenReturn(List.of("CPE", "package"));
        when(findingRepository.findDistinctVexStatusesByTenant(tenant)).thenReturn(List.of("not_affected"));
        when(findingRepository.findDistinctVexFreshnessByTenant(tenant)).thenReturn(List.of("stale"));
        when(findingRepository.findDistinctVexProvidersByTenant(tenant)).thenReturn(List.of("microsoft"));
        doAnswer(invocation -> invocation.getArgument(1, java.util.function.Supplier.class).get())
                .when(tenantSchemaExecutionService)
                .run(any(Tenant.class), org.mockito.ArgumentMatchers.<java.util.function.Supplier<Object>>any());

        FindingQueryService service = new FindingQueryService(
                findingRepository, new ObjectMapper(), findingsScoreService, riskPolicyService, tenantSchemaExecutionService);

        FindingFilterValuesResponse filters = service.listAvailableFilters(tenant);

        assertEquals(List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"), filters.severities());
        assertEquals(List.of("OPEN", "RESOLVED", "SUPPRESSED", "AUTO_CLOSED"), filters.statuses());
        assertEquals(
                List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "UNDER_INVESTIGATION", "NEEDS_REVIEW"),
                filters.decisionStates()
        );
        assertEquals(List.of("cpe", "package"), filters.matchMethods());
        assertEquals(
                List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "NO_PATCH", "UNDER_INVESTIGATION", "UNKNOWN"),
                filters.vexStatuses()
        );
        assertEquals(List.of("FRESH", "STALE", "UNKNOWN"), filters.vexFreshness());
        assertTrue(filters.vexProviders().contains("microsoft"));
        assertTrue(filters.vexProviders().contains("unknown"));
    }

    @Test
    void toResponseDoesNotFailWhenLegacyFindingAssociationsAreMissing() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId("CVE-2026-1234");
        vulnerability.setSeverity("HIGH");

        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setVulnerability(vulnerability);
        finding.setRiskScore(8.4);
        finding.setConfidenceScore(0.72);
        finding.setMatchedBy("package");
        finding.setStatus(FindingStatus.OPEN);
        finding.setDecisionState(FindingDecisionState.AFFECTED);
        finding.setEvidence("{\"impactReason\":\"reachable\"}");

        when(riskPolicyService.getFindingsScoreConfig(tenant)).thenReturn("{}");
        when(findingsScoreService.compute("{}", finding)).thenThrow(new NullPointerException("missing relations"));

        FindingQueryService service = new FindingQueryService(
                findingRepository, new ObjectMapper(), findingsScoreService, riskPolicyService, tenantSchemaExecutionService);

        FindingResponse response = service.toResponse(finding);

        assertEquals("CVE-2026-1234", response.vulnerabilityId());
        assertEquals("HIGH", response.severity());
        assertEquals(8.4, response.riskScore());
        assertEquals(8.4, response.findingsScore());
        assertEquals("reachable", response.impactReason());
        assertNull(response.componentId());
        assertNull(response.assetName());
        assertNull(response.assetType());
        assertNull(response.source());
    }
}
