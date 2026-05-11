package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class FindingsScoreRecomputeServiceTest {

    @Mock private FindingRepository findingRepository;
    @Mock private RiskPolicyService riskPolicyService;
    @Mock private FindingsScoreService findingsScoreService;
    @Mock private FindingSlaService findingSlaService;

    private FindingsScoreRecomputeService service;

    @BeforeEach
    void setUp() {
        service = new FindingsScoreRecomputeService(
                findingRepository,
                riskPolicyService,
                findingsScoreService,
                findingSlaService
        );
    }

    @Test
    void recomputeAllUpdatesOpenFindingsWithCombinedScore() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("workspace");

        RiskPolicy policy = new RiskPolicy();
        policy.setFindingsScoreConfig("[{\"table\":\"VULNERABILITY\",\"column\":\"severity\",\"values\":[{\"operator\":\"is\",\"value\":\"CRITICAL\",\"weight\":0.5}]}]");

        Vulnerability vuln = new Vulnerability();
        vuln.setSeverity("CRITICAL");
        vuln.setCvssScore(9.5);

        Asset asset = new Asset();
        InventoryComponent comp = new InventoryComponent();

        Finding finding = new Finding();
        finding.setStatus(FindingStatus.OPEN);
        finding.setVulnerability(vuln);
        finding.setAsset(asset);
        finding.setComponent(comp);
        finding.setFirstObservedAt(Instant.now());

        when(riskPolicyService.getOrCreate(tenant)).thenReturn(policy);
        when(findingRepository.findByTenantAndStatusOrderByUpdatedAtDesc(tenant, FindingStatus.OPEN))
                .thenReturn(List.of(finding));
        when(findingsScoreService.computeFromParts(anyString(), any(), any(), any(), isNull()))
                .thenReturn(5.0);
        when(findingSlaService.deriveDueAt(any(), any(Double.class), any(), any())).thenReturn(null);

        int updated = service.recomputeAll(tenant);

        assertEquals(1, updated);
        assertEquals(5.0, finding.getRiskScore(), 0.001);
        verify(findingRepository).saveAll(List.of(finding));
    }

    @Test
    void recomputeAllReturnsZeroWhenNoOpenFindings() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("workspace");

        when(riskPolicyService.getOrCreate(tenant)).thenReturn(new RiskPolicy());
        when(findingRepository.findByTenantAndStatusOrderByUpdatedAtDesc(tenant, FindingStatus.OPEN))
                .thenReturn(List.of());

        int updated = service.recomputeAll(tenant);

        assertEquals(0, updated);
    }

    @Test
    void recomputeAllCapsScoreAt10() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("workspace");

        RiskPolicy policy = new RiskPolicy();
        policy.setFindingsScoreConfig("[{\"table\":\"VULNERABILITY\",\"column\":\"in_kev\",\"values\":[{\"operator\":\"is\",\"value\":\"true\",\"weight\":1.0}]}]");

        Vulnerability vuln = new Vulnerability();
        Asset asset = new Asset();
        InventoryComponent comp = new InventoryComponent();

        Finding finding = new Finding();
        finding.setStatus(FindingStatus.OPEN);
        finding.setVulnerability(vuln);
        finding.setAsset(asset);
        finding.setComponent(comp);
        finding.setFirstObservedAt(Instant.now());

        when(riskPolicyService.getOrCreate(tenant)).thenReturn(policy);
        when(findingRepository.findByTenantAndStatusOrderByUpdatedAtDesc(tenant, FindingStatus.OPEN))
                .thenReturn(List.of(finding));
        when(findingsScoreService.computeFromParts(anyString(), any(), any(), any(), isNull()))
                .thenReturn(10.0);
        when(findingSlaService.deriveDueAt(any(), any(Double.class), any(), any())).thenReturn(null);

        service.recomputeAll(tenant);

        assertEquals(10.0, finding.getRiskScore(), 0.001);
    }
}
