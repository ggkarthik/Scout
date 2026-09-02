package com.prototype.vulnwatch.aisecurity.service;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.service.FindingListProjectionService;
import com.prototype.vulnwatch.service.FindingSlaService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.service.RiskPolicyService;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

class AiGridFindingServiceTest {
    private final NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
    private final FindingRepository findings = mock(FindingRepository.class);
    private final FindingWorkflowService workflow = mock(FindingWorkflowService.class);
    private final FindingListProjectionService projections = mock(FindingListProjectionService.class);
    private final AiGridFindingService service = new AiGridFindingService(jdbc, new ObjectMapper(), findings,
            mock(RiskPolicyService.class), mock(FindingSlaService.class), workflow, projections);
    private final Tenant tenant = mock(Tenant.class);

    @Test
    void previewFailureDoesNotCreateAnOwnerFacingFinding() {
        service.reconcile(tenant, result("PREVIEW", "FAIL"));

        verifyNoInteractions(jdbc);
        verify(findings).findByTenantAndFingerprint(tenant, "fingerprint");
        verifyNoInteractions(workflow);
    }

    @Test
    void disabledPolicyAutoClosesAnExistingOwnerFacingFindingWithGovernanceReason() {
        Finding finding = mock(Finding.class);
        when(finding.getStatus()).thenReturn(FindingStatus.OPEN);
        when(findings.findByTenantAndFingerprint(tenant, "fingerprint")).thenReturn(Optional.of(finding));

        service.reconcile(tenant, result("DISABLED", "PASS"));

        verifyNoInteractions(jdbc);
        verify(workflow).autoCloseFinding(org.mockito.ArgumentMatchers.eq(finding),
                org.mockito.ArgumentMatchers.eq(FindingCloseReason.AUTO_POLICY_NOT_OWNER_FACING),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyMap(),
                org.mockito.ArgumentMatchers.any());
        verify(findings).save(finding);
    }

    @Test
    void projectionRefreshIsExplicitlyBatchedOutsideIndividualFindingReconciliation() {
        service.reconcile(tenant, result("PREVIEW", "FAIL"));
        verifyNoInteractions(projections);

        service.refreshProjectionAfterCommit(tenant);

        verify(projections).refreshTenant(tenant);
    }

    @Test
    void policyDeprecationUsesThePlatformDeprecationCloseReason() {
        Finding finding = mock(Finding.class);
        when(findings.findOpenAiFindingsByTenantAndPolicy(tenant, "POLICY")).thenReturn(List.of(finding));

        int closed = service.closeForPolicy(tenant, "POLICY", FindingCloseReason.AUTO_POLICY_PLATFORM_DEPRECATED);

        org.junit.jupiter.api.Assertions.assertEquals(1, closed);
        verify(workflow).autoCloseFinding(org.mockito.ArgumentMatchers.eq(finding),
                org.mockito.ArgumentMatchers.eq(FindingCloseReason.AUTO_POLICY_PLATFORM_DEPRECATED),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyMap(),
                org.mockito.ArgumentMatchers.any());
        verify(findings).saveAll(List.of(finding));
    }

    private AiGridFindingService.AssessmentResult result(String selection, String decision) {
        return new AiGridFindingService.AssessmentResult(UUID.randomUUID(), UUID.randomUUID(),
                "POLICY", "1.0.0", "Policy",
                "HIGH", selection, decision, "REASON", UUID.randomUUID(), "fingerprint", Map.of());
    }
}
