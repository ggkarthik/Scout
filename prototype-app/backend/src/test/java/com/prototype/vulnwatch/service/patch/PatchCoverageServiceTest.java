package com.prototype.vulnwatch.service.patch;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.dto.patch.PatchCoverageMetricsResponse;
import com.prototype.vulnwatch.repo.AssetFixStatusRepository;
import com.prototype.vulnwatch.repo.FixRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PatchCoverageServiceTest {

    @Mock
    private AssetFixStatusRepository assetFixStatusRepository;

    @Mock
    private FixRepository fixRepository;

    private PatchCoverageService coverageService;

    @BeforeEach
    void setUp() {
        coverageService = new PatchCoverageService(assetFixStatusRepository, fixRepository);
    }

    @Test
    void testCalculateCoverageMetricsWithMixedStatuses() {
        // Arrange
        UUID tenantId = UUID.randomUUID();
        UUID fixId1 = UUID.randomUUID();
        UUID fixId2 = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();

        Asset asset = Asset.builder().id(assetId).name("test-asset").build();

        // Create mock asset fix statuses
        AssetFixStatus deployed = AssetFixStatus.builder()
            .fixId(fixId1)
            .asset(asset)
            .deploymentStatus(AssetFixStatus.DeploymentStatus.DEPLOYED)
            .sourceSystem("SCCM")
            .build();

        AssetFixStatus pending = AssetFixStatus.builder()
            .fixId(fixId2)
            .asset(asset)
            .deploymentStatus(AssetFixStatus.DeploymentStatus.PENDING)
            .sourceSystem("SCCM")
            .build();

        AssetFixStatus failed = AssetFixStatus.builder()
            .fixId(fixId1)
            .asset(asset)
            .deploymentStatus(AssetFixStatus.DeploymentStatus.FAILED)
            .sourceSystem("SCCM")
            .build();

        when(assetFixStatusRepository.findByTenantId(tenantId))
            .thenReturn(List.of(deployed, pending, failed));

        Fix fix1 = Fix.builder()
            .id(fixId1)
            .ecosystem("Windows")
            .severity(Fix.Severity.HIGH)
            .sourceSystem("SCCM")
            .build();

        Fix fix2 = Fix.builder()
            .id(fixId2)
            .ecosystem("Windows")
            .severity(Fix.Severity.CRITICAL)
            .sourceSystem("SCCM")
            .build();

        when(fixRepository.findAllById(Set.of(fixId1, fixId2)))
            .thenReturn(List.of(fix1, fix2));

        // Act
        PatchCoverageMetricsResponse metrics = coverageService.calculateCoverageMetrics(tenantId);

        // Assert
        assertEquals(3, metrics.getTotalPatches());
        assertEquals(1, metrics.getDeployedPatches());
        assertEquals(1, metrics.getPendingPatches());
        assertEquals(1, metrics.getFailedPatches());
        assertEquals(33.33, metrics.getDeploymentPercentage(), 0.01);
        assertEquals(3, metrics.getByDeploymentStatus().size());
    }

    @Test
    void testCalculateCoverageMetricsEmpty() {
        // Arrange
        UUID tenantId = UUID.randomUUID();
        when(assetFixStatusRepository.findByTenantId(tenantId))
            .thenReturn(Collections.emptyList());

        // Act
        PatchCoverageMetricsResponse metrics = coverageService.calculateCoverageMetrics(tenantId);

        // Assert
        assertEquals(0, metrics.getTotalPatches());
        assertEquals(0, metrics.getDeployedPatches());
        assertEquals(0.0, metrics.getDeploymentPercentage());
    }

    @Test
    void testCoverageMetricsGroupByEcosystem() {
        // Arrange
        UUID tenantId = UUID.randomUUID();
        UUID fixId1 = UUID.randomUUID();
        UUID fixId2 = UUID.randomUUID();
        UUID assetId1 = UUID.randomUUID();
        UUID assetId2 = UUID.randomUUID();

        Asset asset1 = Asset.builder().id(assetId1).name("win-asset").build();
        Asset asset2 = Asset.builder().id(assetId2).name("linux-asset").build();

        AssetFixStatus status1 = AssetFixStatus.builder()
            .fixId(fixId1)
            .asset(asset1)
            .deploymentStatus(AssetFixStatus.DeploymentStatus.DEPLOYED)
            .sourceSystem("SCCM")
            .build();

        AssetFixStatus status2 = AssetFixStatus.builder()
            .fixId(fixId2)
            .asset(asset2)
            .deploymentStatus(AssetFixStatus.DeploymentStatus.DEPLOYED)
            .sourceSystem("SCCM")
            .build();

        when(assetFixStatusRepository.findByTenantId(tenantId))
            .thenReturn(List.of(status1, status2));

        Fix fix1 = Fix.builder().id(fixId1).ecosystem("Windows").severity(Fix.Severity.HIGH).build();
        Fix fix2 = Fix.builder().id(fixId2).ecosystem("Linux").severity(Fix.Severity.MEDIUM).build();

        when(fixRepository.findAllById(Set.of(fixId1, fixId2)))
            .thenReturn(List.of(fix1, fix2));

        // Act
        PatchCoverageMetricsResponse metrics = coverageService.calculateCoverageMetrics(tenantId);

        // Assert
        assertEquals(2, metrics.getByEcosystem().size());
        assertEquals(1L, metrics.getByEcosystem().get("Windows"));
        assertEquals(1L, metrics.getByEcosystem().get("Linux"));
    }

    @Test
    void testCoverageMetricsGroupBySeverity() {
        // Arrange
        UUID tenantId = UUID.randomUUID();
        UUID fixId1 = UUID.randomUUID();
        UUID fixId2 = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();

        Asset asset = Asset.builder().id(assetId).name("test-asset").build();

        AssetFixStatus status1 = AssetFixStatus.builder()
            .fixId(fixId1)
            .asset(asset)
            .deploymentStatus(AssetFixStatus.DeploymentStatus.DEPLOYED)
            .sourceSystem("SCCM")
            .build();

        AssetFixStatus status2 = AssetFixStatus.builder()
            .fixId(fixId2)
            .asset(asset)
            .deploymentStatus(AssetFixStatus.DeploymentStatus.DEPLOYED)
            .sourceSystem("SCCM")
            .build();

        when(assetFixStatusRepository.findByTenantId(tenantId))
            .thenReturn(List.of(status1, status2));

        Fix fix1 = Fix.builder().id(fixId1).ecosystem("Windows").severity(Fix.Severity.CRITICAL).build();
        Fix fix2 = Fix.builder().id(fixId2).ecosystem("Windows").severity(Fix.Severity.HIGH).build();

        when(fixRepository.findAllById(Set.of(fixId1, fixId2)))
            .thenReturn(List.of(fix1, fix2));

        // Act
        PatchCoverageMetricsResponse metrics = coverageService.calculateCoverageMetrics(tenantId);

        // Assert
        assertEquals(2, metrics.getBySeverity().size());
        assertEquals(1L, metrics.getBySeverity().get("CRITICAL"));
        assertEquals(1L, metrics.getBySeverity().get("HIGH"));
    }

    @Test
    void testCoverageMetricsGroupBySourceSystem() {
        // Arrange
        UUID tenantId = UUID.randomUUID();
        UUID fixId1 = UUID.randomUUID();
        UUID fixId2 = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();

        Asset asset = Asset.builder().id(assetId).name("test-asset").build();

        AssetFixStatus status1 = AssetFixStatus.builder()
            .fixId(fixId1)
            .asset(asset)
            .deploymentStatus(AssetFixStatus.DeploymentStatus.DEPLOYED)
            .sourceSystem("SCCM")
            .build();

        AssetFixStatus status2 = AssetFixStatus.builder()
            .fixId(fixId2)
            .asset(asset)
            .deploymentStatus(AssetFixStatus.DeploymentStatus.PENDING)
            .sourceSystem("BIGFIX")
            .build();

        when(assetFixStatusRepository.findByTenantId(tenantId))
            .thenReturn(List.of(status1, status2));

        Fix fix1 = Fix.builder().id(fixId1).ecosystem("Windows").severity(Fix.Severity.HIGH).build();
        Fix fix2 = Fix.builder().id(fixId2).ecosystem("Windows").severity(Fix.Severity.MEDIUM).build();

        when(fixRepository.findAllById(Set.of(fixId1, fixId2)))
            .thenReturn(List.of(fix1, fix2));

        // Act
        PatchCoverageMetricsResponse metrics = coverageService.calculateCoverageMetrics(tenantId);

        // Assert
        assertEquals(2, metrics.getBySourceSystem().size());
        var sccmMetrics = metrics.getBySourceSystem().stream()
            .filter(s -> "SCCM".equals(s.getSourceSystem()))
            .findFirst();
        assertTrue(sccmMetrics.isPresent());
        assertEquals(1, sccmMetrics.get().getDeployedPatches());
        assertEquals(100.0, sccmMetrics.get().getDeploymentPercentage());
    }
}
