package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class FindingWorkflowFacadeTest {

    @Mock
    private FindingRepository findingRepository;

    @Mock
    private ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;

    @Mock
    private RiskPolicyService riskPolicyService;

    @Mock
    private RiskScoringService riskScoringService;

    @Mock
    private FindingWorkflowService findingWorkflowService;

    @Mock
    private OrgCveRecordService orgCveRecordService;

    @Mock
    private FindingSlaService findingSlaService;

    private FindingWorkflowFacade findingWorkflowFacade;

    @BeforeEach
    void setUp() {
        findingWorkflowFacade = new FindingWorkflowFacade(
                findingRepository,
                componentVulnerabilityStateRepository,
                riskPolicyService,
                riskScoringService,
                findingWorkflowService,
                orgCveRecordService,
                findingSlaService,
                new ObjectMapper()
        );
    }

    @Test
    void suppressFindingsForVulnerabilityBuildsBulkWorkflowRequest() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        Vulnerability vulnerability = mock(Vulnerability.class);
        UUID vulnerabilityId = UUID.randomUUID();
        Finding finding = new Finding();
        List<Finding> findings = List.of(finding);
        Instant expiresAt = Instant.parse("2026-03-27T10:15:30Z");
        when(vulnerability.getId()).thenReturn(vulnerabilityId);

        when(findingRepository.findByTenant_IdAndVulnerability_Id(tenant.getId(), vulnerabilityId))
                .thenReturn(findings);
        when(findingWorkflowService.updateWorkflowBulk(eq(findings), org.mockito.ArgumentMatchers.any()))
                .thenReturn(1);

        int updated = findingWorkflowFacade.suppressFindingsForVulnerability(
                tenant,
                vulnerability,
                "RISK_ACCEPTED",
                "Approved during review",
                "local-analyst",
                expiresAt
        );

        assertEquals(1, updated);
        ArgumentCaptor<FindingWorkflowUpdateRequest> requestCaptor =
                ArgumentCaptor.forClass(FindingWorkflowUpdateRequest.class);
        verify(findingWorkflowService).updateWorkflowBulk(eq(findings), requestCaptor.capture());
        assertEquals("SUPPRESSED", requestCaptor.getValue().status());
        assertEquals("RISK_ACCEPTED: Approved during review", requestCaptor.getValue().suppressionReason());
        assertEquals(expiresAt, requestCaptor.getValue().suppressedUntil());
        assertEquals("local-analyst", requestCaptor.getValue().actor());
    }
}
