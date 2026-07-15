package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.dto.VulnRepoDashboardResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class VulnRepoDashboardServicePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("vuln_repo_dashboard");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private VulnRepoDashboardService vulnRepoDashboardService;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private OrgCveRecordRepository orgCveRecordRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private SbomUploadRepository sbomUploadRepository;

    @Autowired
    private InventoryComponentRepository inventoryComponentRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Test
    void dashboardSummaryCardsRemainConsistentWithSetBasedAggregateQuery() {
        Tenant tenant = tenantService.getDefaultTenant();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
        try {
        Vulnerability kevImpacted = createVulnerability("CVE-2099-5101", "CRITICAL", 0.45, true);
        Vulnerability epssPriority = createVulnerability("CVE-2099-5102", "HIGH", 0.95, false);
        Vulnerability resolved = createVulnerability("CVE-2099-5103", "MEDIUM", 0.10, false);

        createOrgCveRecord(
                tenant, kevImpacted, ApplicabilityState.APPLICABLE, true, ImpactState.IMPACTED,
                3, 2, 2, 2, 0, 0, 0, 0, 0, 0
        );
        createOrgCveRecord(
                tenant, epssPriority, ApplicabilityState.APPLICABLE, false, ImpactState.UNKNOWN,
                2, 2, 1, 0, 0, 0, 0, 1, 0, 0
        );
        createOrgCveRecord(
                tenant, resolved, ApplicabilityState.NOT_APPLICABLE, false, ImpactState.NOT_IMPACTED,
                0, 0, 0, 0, 1, 0, 0, 0, 0, 0
        );

        InventoryComponent openComponent = createComponent(tenant, "dashboard-open");
        InventoryComponent suppressedComponent = createComponent(tenant, "dashboard-suppressed");
        createFinding(tenant, openComponent, kevImpacted, FindingStatus.OPEN, FindingDecisionState.AFFECTED);
        createFinding(tenant, suppressedComponent, resolved, FindingStatus.SUPPRESSED, FindingDecisionState.NOT_AFFECTED);

        VulnRepoDashboardResponse response = vulnRepoDashboardService.get(tenant);

        assertEquals(3L, response.summaryCards().trackedCount());
        assertEquals(3L, response.summaryCards().trackedAddedLastWeek());
        assertEquals(2L, response.summaryCards().applicableCount());
        assertEquals(2L, response.summaryCards().applicableAddedLastWeek());
        assertEquals(2L, response.summaryCards().impactedInvestigationDoneCount());
        assertEquals(1L, response.summaryCards().impactedAddedLastWeek());
        assertEquals(2L, response.summaryCards().remediationCveCount());
        assertEquals(0L, response.summaryCards().needsAttentionCount());
        assertEquals(1L, response.summaryCards().criticalCount());
        assertEquals(2L, response.summaryCards().exploitCount());
        assertEquals(1L, response.summaryCards().impactedCriticalCount());
        assertEquals(1L, response.summaryCards().impactedHighCount());
        assertEquals(0L, response.summaryCards().impactedMediumCount());
        assertEquals(0L, response.summaryCards().impactedLowCount());
        assertEquals(1L, response.summaryCards().impactedKevCount());
        assertEquals(1L, response.summaryCards().kevAddedLastWeek());
        assertEquals(0L, response.summaryCards().criticalUninvestigatedCount());
        assertEquals(0L, response.summaryCards().kevReinvestigationCount());

        assertEquals(2L, response.resolutionStatus().unresolvedCount());
        assertEquals(1L, response.resolutionStatus().resolvedCount());
        assertEquals(0L, response.resolutionStatus().inProgressCount());
        assertEquals(1L, response.resolutionStatus().acceptedRiskCount());
        } finally {
            TenantContext.clear();
        }
    }

    private Vulnerability createVulnerability(String externalId, String severity, double epssScore, boolean inKev) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId(externalId);
        vulnerability.setSource(VulnerabilitySource.NVD);
        vulnerability.setTitle(externalId + " title");
        vulnerability.setDescriptionSnippet(externalId + " description");
        vulnerability.setSeverity(severity);
        vulnerability.setCvssScore("CRITICAL".equals(severity) ? 9.8 : ("HIGH".equals(severity) ? 8.4 : 6.1));
        vulnerability.setEpssScore(epssScore);
        vulnerability.setInKev(inKev);
        vulnerability.setLastModifiedAt(Instant.now());
        return vulnerabilityRepository.save(vulnerability);
    }

    private void createOrgCveRecord(
            Tenant tenant,
            Vulnerability vulnerability,
            ApplicabilityState applicabilityState,
            boolean impacted,
            ImpactState impactState,
            long matchedComponentCount,
            long matchedSoftwareCount,
            long matchedAssetCount,
            long applicableComponentCount,
            long impactedComponentCount,
            long notAffectedComponentCount,
            long fixedComponentCount,
            long noPatchComponentCount,
            long underInvestigationComponentCount,
            long unknownComponentCount
    ) {
        OrgCveRecord record = new OrgCveRecord();
        record.setTenant(tenant);
        record.setVulnerability(vulnerability);
        record.setExternalId(vulnerability.getExternalId());
        record.setSeverity(vulnerability.getSeverity());
        record.setCvssScore(vulnerability.getCvssScore());
        record.setEpssScore(vulnerability.getEpssScore());
        record.setInKev(vulnerability.isInKev());
        record.setApplicabilityState(applicabilityState);
        record.setImpacted(impacted);
        record.setImpactState(impactState);
        record.setImpactReason(impactState.name().toLowerCase());
        record.setMatchedComponentCount(matchedComponentCount);
        record.setMatchedSoftwareCount(matchedSoftwareCount);
        record.setMatchedAssetCount(matchedAssetCount);
        record.setApplicableComponentCount(applicableComponentCount);
        record.setImpactedComponentCount(impactedComponentCount);
        record.setNotAffectedComponentCount(notAffectedComponentCount);
        record.setFixedComponentCount(fixedComponentCount);
        record.setNoPatchComponentCount(noPatchComponentCount);
        record.setUnderInvestigationComponentCount(underInvestigationComponentCount);
        record.setUnknownComponentCount(unknownComponentCount);
        record.setLastEvaluatedAt(Instant.now());
        record.touch();
        orgCveRecordRepository.save(record);
    }

    private InventoryComponent createComponent(Tenant tenant, String suffix) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.HOST);
        asset.setName(suffix);
        asset.setIdentifier("asset:" + suffix);
        asset = assetRepository.save(asset);

        SbomUpload upload = new SbomUpload();
        upload.setTenant(tenant);
        upload.setAsset(asset);
        upload.setFormat(SbomFormat.CYCLONEDX);
        upload.setOriginalFilename(suffix + ".json");
        upload = sbomUploadRepository.save(upload);

        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(upload);
        component.setEcosystem("maven");
        component.setPackageName("dashboard-" + suffix);
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.example/dashboard-" + suffix + "@1.0.0");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        return inventoryComponentRepository.save(component);
    }

    private void createFinding(
            Tenant tenant,
            InventoryComponent component,
            Vulnerability vulnerability,
            FindingStatus status,
            FindingDecisionState decisionState
    ) {
        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setAsset(component.getAsset());
        finding.setComponent(component);
        finding.setVulnerability(vulnerability);
        finding.setStatus(status);
        finding.setDecisionState(decisionState);
        finding.setMatchedBy("cpe-indexed-direct");
        finding.setRiskScore(9.3);
        finding.setConfidenceScore(0.97);
        finding.setEvidence("{\"source\":\"dashboard-test\"}");
        if (status == FindingStatus.SUPPRESSED) {
            finding.setSuppressionReason("Accepted risk");
        }
        findingRepository.save(finding);
    }
}
