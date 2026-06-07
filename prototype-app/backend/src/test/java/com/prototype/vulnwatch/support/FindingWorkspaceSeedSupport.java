package com.prototype.vulnwatch.support;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingCreationSource;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import org.springframework.test.util.ReflectionTestUtils;

public final class FindingWorkspaceSeedSupport {

    private final AssetRepository assetRepository;
    private final SbomUploadRepository sbomUploadRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final FindingRepository findingRepository;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public FindingWorkspaceSeedSupport(
            AssetRepository assetRepository,
            SbomUploadRepository sbomUploadRepository,
            InventoryComponentRepository inventoryComponentRepository,
            VulnerabilityRepository vulnerabilityRepository,
            FindingRepository findingRepository,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.assetRepository = assetRepository;
        this.sbomUploadRepository = sbomUploadRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.findingRepository = findingRepository;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    public SeededWorkspace seedCriticalWorkspace(Tenant tenant, int totalFindings, int unassignedCount) {
        return tenantSchemaExecutionService.run(tenant, () -> {
            String token = UUID.randomUUID().toString().substring(0, 8);
            Asset asset = new Asset();
            asset.setTenant(tenant);
            asset.setType(AssetType.APPLICATION);
            asset.setName("findings-workspace-scale-host-" + token);
            asset.setIdentifier("app:findings-workspace-scale-host-" + token);
            asset.setSupportGroup("Platform Ops");
            asset.setBusinessCriticality(BusinessCriticality.HIGH);
            asset.setState(AssetState.ACTIVE);
            asset.setLastInventoryAt(Instant.now());
            asset = assetRepository.save(asset);

            SbomUpload upload = new SbomUpload();
            upload.setTenant(tenant);
            upload.setAsset(asset);
            upload.setFormat(SbomFormat.CYCLONEDX);
            upload.setStatus(SbomIngestionStatus.SUCCESS);
            upload.setOriginalFilename("findings-workspace-scale-" + token + ".json");
            upload = sbomUploadRepository.save(upload);

            Vulnerability vulnerability = new Vulnerability();
            vulnerability.setExternalId("CVE-2099-9900-" + token);
            vulnerability.setSource(VulnerabilitySource.NVD);
            vulnerability.setTitle("Workspace Scale Validation");
            vulnerability.setSeverity("CRITICAL");
            vulnerability.setCvssScore(9.8);
            vulnerability.setDescription("Synthetic vulnerability for findings workspace integration coverage.");
            vulnerability.touch();
            vulnerability = vulnerabilityRepository.save(vulnerability);

            Instant base = Instant.parse("2026-06-01T00:00:00Z");
            for (int i = 0; i < totalFindings; i++) {
                String findingToken = String.format(Locale.ROOT, "%03d", i);
                InventoryComponent component = new InventoryComponent();
                component.setTenant(tenant);
                component.setAsset(asset);
                component.setSbomUpload(upload);
                component.setEcosystem("maven");
                component.setPackageName("workspace-seed-" + findingToken);
                component.setVersion("1.0." + findingToken);
                component.setPurl("pkg:maven/com.example/workspace-seed-" + findingToken + "@1.0." + findingToken);
                component.setComponentStatus(InventoryComponentStatus.ACTIVE);
                component = inventoryComponentRepository.save(component);

                Finding finding = new Finding();
                finding.setTenant(tenant);
                finding.setAsset(asset);
                finding.setComponent(component);
                finding.setVulnerability(vulnerability);
                finding.setStatus(FindingStatus.OPEN);
                finding.setDecisionState(FindingDecisionState.AFFECTED);
                finding.setCreationSource(FindingCreationSource.AUTOMATIC);
                finding.setRiskScore(100.0 - i);
                finding.setConfidenceScore(0.95d);
                finding.setMatchedBy("cpe");
                finding.setAssignedTo(i < unassignedCount ? null : "analyst@example.com");
                finding.setAssignedBy("system");
                finding.setDueAt(i < unassignedCount
                        ? base.minusSeconds(86_400L * (i + 1L))
                        : base.plusSeconds(86_400L * ((i % 7) + 1L)));
                finding.setSeverityOverride("CRITICAL");
                finding.setEvidence("{\"source\":\"workspace-seed\"}");
                finding.setOwnerGroup(i < unassignedCount ? "Critical Triage" : "Platform");
                if (i % 5 == 0) {
                    finding.setIncidentId("INC-" + findingToken);
                    finding.setIncidentStatus("In Progress");
                }
                finding.setFirstObservedAt(base.minusSeconds(86_400L * (30L + i)));
                finding.setLastObservedAt(base.minusSeconds(86_400L * (i % 10L)));
                finding = findingRepository.save(finding);
                ReflectionTestUtils.setField(finding, "createdAt", base.minusSeconds(86_400L * (40L + i)));
                ReflectionTestUtils.setField(finding, "updatedAt", base.minusSeconds(60L * i));
                findingRepository.save(finding);
            }

            return new SeededWorkspace(tenant, vulnerability.getExternalId(), totalFindings, unassignedCount);
        });
    }

    public record SeededWorkspace(
            Tenant tenant,
            String vulnerabilityId,
            int totalFindings,
            int unassignedCount
    ) {
    }
}
