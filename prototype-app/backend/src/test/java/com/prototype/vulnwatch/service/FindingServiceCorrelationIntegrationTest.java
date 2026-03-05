package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.CpeDim;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityConstraintType;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.util.CpeUtil;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "spring.datasource.url=jdbc:h2:mem:finding_correlation;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "app.correlation.backfill-targets-on-startup=false"
})
@Transactional
class FindingServiceCorrelationIntegrationTest {

    @Autowired
    private FindingService findingService;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private SbomUploadRepository sbomUploadRepository;

    @Autowired
    private InventoryComponentRepository inventoryComponentRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private VulnerabilityTargetRepository vulnerabilityTargetRepository;

    @Autowired
    private InventoryComponentCpeMappingService inventoryComponentCpeMappingService;

    @Autowired
    private CpeDimensionService cpeDimensionService;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;

    @Autowired
    private SoftwareInventorySyncService softwareInventorySyncService;

    @Autowired
    private OrgCveRecordRepository orgCveRecordRepository;

    @Test
    void cpeIndexedJoinCreatesAffectedFinding() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        TestFixture fixture = createAssetAndComponent(
                tenant,
                "cpe-indexed",
                "maven",
                "log4j-core",
                "2.14.1",
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        );

        Vulnerability vulnerability = createVulnerability("CVE-2099-0001", VulnerabilitySource.NVD, "HIGH", 8.4);
        createCpeTarget(
                vulnerability,
                "nvd",
                "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                "2.0.0",
                "2.17.1",
                null,
                null,
                null
        );

        int active = findingService.recomputeOnSoftwareDelta(tenant.getId(), fixture.component().getId());
        assertEquals(1, active);

        List<Finding> findings = findingRepository.findByComponent(fixture.component());
        assertEquals(1, findings.size());
        Finding finding = findings.get(0);
        assertEquals(FindingStatus.OPEN, finding.getStatus());
        assertEquals(FindingDecisionState.AFFECTED, finding.getDecisionState());
        assertTrue(finding.getMatchedBy().startsWith("cpe-"));
        assertNotNull(finding.getEvidence());
    }

    @Test
    void softwareDeltaRecomputeScopesToChangedComponent() {
        Tenant tenant = tenantService.getDefaultTenant();
        TestFixture left = createAssetAndComponent(
                tenant,
                "left",
                "maven",
                "spring-core",
                "5.3.10",
                "pkg:maven/org.springframework/spring-core@5.3.10",
                "cpe:2.3:a:vmware:spring_framework:5.3.10:*:*:*:*:*:*:*"
        );
        TestFixture right = createAssetAndComponent(
                tenant,
                "right",
                "generic",
                "nginx",
                "1.23.0",
                "pkg:generic/nginx@1.23.0",
                "cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*"
        );

        Vulnerability springVuln = createVulnerability("CVE-2099-0101", VulnerabilitySource.ADVISORY, "HIGH", 8.1);
        Vulnerability nginxVuln = createVulnerability("CVE-2099-0102", VulnerabilitySource.ADVISORY, "HIGH", 8.0);

        createCpeTarget(
                springVuln,
                "advisory",
                "cpe:2.3:a:vmware:spring_framework:5.3.10:*:*:*:*:*:*:*",
                "5.0.0",
                "5.3.30",
                null,
                null,
                null
        );
        createCpeTarget(
                nginxVuln,
                "advisory",
                "cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*",
                "1.20.0",
                "1.24.0",
                null,
                null,
                null
        );

        assertEquals(1, findingService.recomputeOnSoftwareDelta(tenant.getId(), left.component().getId()));
        assertEquals(1, findingService.recomputeOnSoftwareDelta(tenant.getId(), right.component().getId()));
        assertEquals(2, findingRepository.findByTenantOrderByUpdatedAtDesc(tenant).size());

        left.component().setComponentStatus(InventoryComponentStatus.RETIRED);
        inventoryComponentRepository.save(left.component());

        assertEquals(0, findingService.recomputeOnSoftwareDelta(tenant.getId(), left.component().getId()));

        List<Finding> leftFindings = findingRepository.findByComponent(left.component());
        List<Finding> rightFindings = findingRepository.findByComponent(right.component());
        assertEquals(1, leftFindings.size());
        assertEquals(1, rightFindings.size());
        assertEquals(FindingStatus.RESOLVED, leftFindings.get(0).getStatus());
        assertEquals(FindingDecisionState.NOT_AFFECTED, leftFindings.get(0).getDecisionState());
        assertEquals(FindingStatus.OPEN, rightFindings.get(0).getStatus());
    }

    @Test
    void cveDeltaRecomputeScopesToComponentsSharingCpe() {
        Tenant tenant = tenantService.getDefaultTenant();
        TestFixture left = createAssetAndComponent(
                tenant,
                "cve-left",
                "generic",
                "spring-framework",
                "5.3.10",
                "pkg:generic/spring-framework@5.3.10",
                "cpe:2.3:a:vmware:spring_framework:5.3.10:*:*:*:*:*:*:*"
        );
        TestFixture right = createAssetAndComponent(
                tenant,
                "cve-right",
                "generic",
                "nginx",
                "1.23.0",
                "pkg:generic/nginx@1.23.0",
                "cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*"
        );

        Vulnerability vulnerability = createVulnerability("CVE-2099-0103", VulnerabilitySource.NVD, "HIGH", 8.0);
        createCpeTarget(
                vulnerability,
                "nvd",
                "cpe:2.3:a:vmware:spring_framework:5.3.10:*:*:*:*:*:*:*",
                "5.0.0",
                "5.3.30",
                null,
                null,
                null
        );

        assertEquals(1, findingService.recomputeOnSoftwareDelta(tenant.getId(), left.component().getId()));
        assertEquals(0, findingService.recomputeOnSoftwareDelta(tenant.getId(), right.component().getId()));
        assertEquals(1, findingRepository.findByTenantOrderByUpdatedAtDesc(tenant).size());

        VulnerabilityTarget target = vulnerabilityTargetRepository.findAll().stream()
                .filter(row -> row.getVulnerability() != null && vulnerability.getId().equals(row.getVulnerability().getId()))
                .findFirst()
                .orElseThrow();
        target.setVersionEnd("5.2.0");
        vulnerabilityTargetRepository.save(target);

        int impactedComponents = findingService.recomputeOnCveDelta(vulnerability.getId());
        assertEquals(0, impactedComponents);

        List<Finding> leftFindings = findingRepository.findByComponent(left.component());
        List<Finding> rightFindings = findingRepository.findByComponent(right.component());
        assertEquals(1, leftFindings.size());
        assertEquals(FindingStatus.RESOLVED, leftFindings.get(0).getStatus());
        assertEquals(0, rightFindings.size());
    }

    @Test
    void vexOverlayDeltaIsDeterministicAndIdempotent() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        TestFixture fixture = createAssetAndComponent(
                tenant,
                "vex-overlay",
                "maven",
                "commons-codec",
                "1.14.0",
                "pkg:maven/commons-codec/commons-codec@1.14.0",
                "cpe:2.3:a:apache:commons_codec:1.14.0:*:*:*:*:*:*:*"
        );

        Vulnerability vulnerability = createVulnerability("CVE-2099-0201", VulnerabilitySource.ADVISORY, "HIGH", 7.9);
        createCpeTarget(
                vulnerability,
                "advisory",
                "cpe:2.3:a:apache:commons_codec:1.14.0:*:*:*:*:*:*:*",
                "1.0.0",
                "2.0.0",
                null,
                null,
                null
        );

        assertEquals(1, findingService.recomputeOnSoftwareDelta(tenant.getId(), fixture.component().getId()));
        assertEquals(1, findingRepository.findByComponent(fixture.component()).size());

        Instant now = Instant.now();
        createCpeTarget(
                vulnerability,
                "vex-redhat",
                "cpe:2.3:a:apache:commons_codec:1.14.0:*:*:*:*:*:*:*",
                null,
                null,
                "AFFECTED",
                now.minusSeconds(600),
                "redhat"
        );
        createCpeTarget(
                vulnerability,
                "vex-microsoft",
                "cpe:2.3:a:apache:commons_codec:1.14.0:*:*:*:*:*:*:*",
                null,
                null,
                "NOT_AFFECTED",
                now,
                "microsoft"
        );

        int first = findingService.applyVexDeltaForVulnerability(vulnerability.getId(), "vex");
        int second = findingService.applyVexDeltaForVulnerability(vulnerability.getId(), "vex");

        assertEquals(1, first);
        assertEquals(0, second);

        Finding finding = findingRepository.findByComponent(fixture.component()).get(0);
        assertEquals(FindingStatus.RESOLVED, finding.getStatus());
        assertEquals(FindingDecisionState.NOT_AFFECTED, finding.getDecisionState());
    }

    @Test
    void noPatchVexCreatesFindingAndMarksImpactState() {
        Tenant tenant = tenantService.getDefaultTenant();
        TestFixture fixture = createAssetAndComponent(
                tenant,
                "vex-no-patch",
                "maven",
                "commons-compress",
                "1.24.0",
                "pkg:maven/org.apache.commons/commons-compress@1.24.0",
                "cpe:2.3:a:apache:commons_compress:1.24.0:*:*:*:*:*:*:*"
        );

        Vulnerability vulnerability = createVulnerability("CVE-2099-0301", VulnerabilitySource.ADVISORY, "HIGH", 8.1);
        createCpeTarget(
                vulnerability,
                "advisory",
                "cpe:2.3:a:apache:commons_compress:1.24.0:*:*:*:*:*:*:*",
                "1.0.0",
                "2.0.0",
                null,
                null,
                null
        );
        createCpeTarget(
                vulnerability,
                "vex-redhat",
                "cpe:2.3:a:apache:commons_compress:1.24.0:*:*:*:*:*:*:*",
                null,
                null,
                "NO_PATCH",
                Instant.now(),
                "redhat"
        );

        int active = findingService.recomputeOnSoftwareDelta(tenant.getId(), fixture.component().getId());
        assertEquals(1, active);
        assertEquals(1, findingRepository.findByComponent(fixture.component()).size());

        List<ComponentVulnerabilityState> states = componentVulnerabilityStateRepository.findByTenantAndComponent(tenant, fixture.component());
        assertEquals(1, states.size());
        assertEquals(ApplicabilityState.APPLICABLE, states.get(0).getApplicabilityState());
        assertEquals(ImpactState.NO_PATCH, states.get(0).getImpactState());
        assertTrue(states.get(0).isEligibleForFinding());

        OrgCveRecord orgRecord = orgCveRecordRepository
                .findByTenantAndVulnerability_Id(tenant, vulnerability.getId())
                .orElseThrow();
        assertEquals(ApplicabilityState.APPLICABLE, orgRecord.getApplicabilityState());
        assertTrue(orgRecord.isImpacted());
        assertEquals(ImpactState.NO_PATCH, orgRecord.getImpactState());
        assertTrue(orgRecord.getMatchedSoftwareCount() >= 1L);
    }

    @Test
    void vexNotAffectedDoesNotCreateFindingAndTracksState() {
        Tenant tenant = tenantService.getDefaultTenant();
        TestFixture fixture = createAssetAndComponent(
                tenant,
                "vex-not-affected-state",
                "maven",
                "snakeyaml",
                "1.33.0",
                "pkg:maven/org.yaml/snakeyaml@1.33.0",
                "cpe:2.3:a:snakeyaml_project:snakeyaml:1.33.0:*:*:*:*:*:*:*"
        );

        Vulnerability vulnerability = createVulnerability("CVE-2099-0302", VulnerabilitySource.ADVISORY, "HIGH", 8.0);
        createCpeTarget(
                vulnerability,
                "advisory",
                "cpe:2.3:a:snakeyaml_project:snakeyaml:1.33.0:*:*:*:*:*:*:*",
                "1.0.0",
                "2.0.0",
                null,
                null,
                null
        );
        createCpeTarget(
                vulnerability,
                "vex-microsoft",
                "cpe:2.3:a:snakeyaml_project:snakeyaml:1.33.0:*:*:*:*:*:*:*",
                null,
                null,
                "NOT_AFFECTED",
                Instant.now(),
                "microsoft"
        );

        int active = findingService.recomputeOnSoftwareDelta(tenant.getId(), fixture.component().getId());
        assertEquals(0, active);
        assertTrue(findingRepository.findByComponent(fixture.component()).isEmpty());

        List<ComponentVulnerabilityState> states = componentVulnerabilityStateRepository.findByTenantAndComponent(tenant, fixture.component());
        assertEquals(1, states.size());
        assertEquals(ApplicabilityState.NOT_APPLICABLE, states.get(0).getApplicabilityState());
        assertEquals(ImpactState.NOT_IMPACTED, states.get(0).getImpactState());
        assertFalse(states.get(0).isEligibleForFinding());
    }

    @Test
    void unchangedStateDoesNotUpdateAssessmentRowTimestamp() {
        Tenant tenant = tenantService.getDefaultTenant();
        TestFixture fixture = createAssetAndComponent(
                tenant,
                "state-unchanged",
                "maven",
                "jackson-databind",
                "2.15.0",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0",
                "cpe:2.3:a:fasterxml:jackson-databind:2.15.0:*:*:*:*:*:*:*"
        );

        Vulnerability vulnerability = createVulnerability("CVE-2099-0303", VulnerabilitySource.ADVISORY, "HIGH", 8.3);
        createCpeTarget(
                vulnerability,
                "advisory",
                "cpe:2.3:a:fasterxml:jackson-databind:2.15.0:*:*:*:*:*:*:*",
                "2.0.0",
                "2.16.0",
                null,
                null,
                null
        );

        assertEquals(1, findingService.recomputeOnSoftwareDelta(tenant.getId(), fixture.component().getId()));
        ComponentVulnerabilityState first = componentVulnerabilityStateRepository
                .findByTenantAndComponent(tenant, fixture.component())
                .get(0);
        Instant firstUpdatedAt = first.getUpdatedAt();

        assertEquals(1, findingService.recomputeOnSoftwareDelta(tenant.getId(), fixture.component().getId()));
        ComponentVulnerabilityState second = componentVulnerabilityStateRepository
                .findByTenantAndComponent(tenant, fixture.component())
                .get(0);
        assertEquals(firstUpdatedAt, second.getUpdatedAt());
    }

    @Test
    void cveWithoutSoftwareMatchCreatesNotApplicableOrgCveRecord() {
        Tenant tenant = tenantService.getDefaultTenant();

        Vulnerability vulnerability = createVulnerability("CVE-2099-0701", VulnerabilitySource.NVD, "HIGH", 8.0);
        createCpeTarget(
                vulnerability,
                "nvd",
                "cpe:2.3:a:vendor:unmatched_product:1.0.0:*:*:*:*:*:*:*",
                null,
                null,
                null,
                null,
                null
        );

        int impactedComponents = findingService.recomputeOnCveDelta(vulnerability.getId());
        assertEquals(0, impactedComponents);

        OrgCveRecord orgRecord = orgCveRecordRepository
                .findByTenantAndVulnerability_Id(tenant, vulnerability.getId())
                .orElseThrow();
        assertEquals(ApplicabilityState.NOT_APPLICABLE, orgRecord.getApplicabilityState());
        assertFalse(orgRecord.isImpacted());
        assertEquals(ImpactState.NOT_IMPACTED, orgRecord.getImpactState());
        assertEquals(0L, orgRecord.getMatchedSoftwareCount());
    }

    private TestFixture createAssetAndComponent(
            Tenant tenant,
            String suffix,
            String ecosystem,
            String packageName,
            String version,
            String purl,
            String cpe
    ) {
        String token = suffix + "-" + UUID.randomUUID().toString().substring(0, 8);

        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.APPLICATION);
        asset.setName("asset-" + token);
        asset.setIdentifier("app:" + token);
        asset.setBusinessCriticality(BusinessCriticality.MEDIUM);
        asset.setState(com.prototype.vulnwatch.domain.AssetState.ACTIVE);
        asset.setLastInventoryAt(Instant.now());
        asset = assetRepository.save(asset);

        SbomUpload upload = new SbomUpload();
        upload.setTenant(tenant);
        upload.setAsset(asset);
        upload.setFormat(SbomFormat.CYCLONEDX);
        upload.setStatus(SbomIngestionStatus.SUCCESS);
        upload.setOriginalFilename("fixture-" + token + ".json");
        upload = sbomUploadRepository.save(upload);

        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(upload);
        component.setEcosystem(ecosystem.toLowerCase(Locale.ROOT));
        component.setPackageName(packageName.toLowerCase(Locale.ROOT));
        component.setVersion(version);
        component.setPurl(purl);
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        component = inventoryComponentRepository.save(component);

        inventoryComponentCpeMappingService.syncActiveComponentMappings(component, List.of(cpe));
        softwareInventorySyncService.syncFromInventoryDelta(tenant, List.of(component), Instant.now());
        return new TestFixture(asset, component);
    }

    private Vulnerability createVulnerability(String externalId, VulnerabilitySource source, String severity, double cvss) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId(externalId + "-" + UUID.randomUUID().toString().substring(0, 8));
        vulnerability.setSource(source);
        vulnerability.setTitle(externalId);
        vulnerability.setSeverity(severity);
        vulnerability.setCvssScore(cvss);
        vulnerability.setDescription("test");
        vulnerability.touch();
        return vulnerabilityRepository.save(vulnerability);
    }

    private void createCpeTarget(
            Vulnerability vulnerability,
            String source,
            String cpe,
            String versionStart,
            String versionEnd,
            String vexStatus,
            Instant updatedAt,
            String vexProvider
    ) {
        String normalizedCpe = CpeUtil.normalizeCpe23(cpe);
        CpeDim cpeDim = cpeDimensionService.resolveOrCreate(normalizedCpe);

        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setVulnerability(vulnerability);
        target.setTargetType(VulnerabilityTargetType.CPE);
        target.setNormalizedTargetKey(normalizedCpe);
        target.setSource(source);
        target.setCpe(normalizedCpe);
        target.setCpeDim(cpeDim);
        target.setCpeWildcardScore(1);
        target.setVersionScheme(VersionScheme.UNKNOWN);
        target.setConstraintType(
                versionStart == null && versionEnd == null
                        ? VulnerabilityConstraintType.NONE
                        : VulnerabilityConstraintType.RANGE
        );
        target.setVersionStart(versionStart);
        target.setStartInclusive(Boolean.TRUE);
        target.setVersionEnd(versionEnd);
        target.setEndInclusive(Boolean.TRUE);
        target.setKbVersion("test-kb");
        if (vexStatus != null) {
            String publishedAt = (updatedAt == null ? Instant.now() : updatedAt).toString();
            target.setQualifiersJson("{\"vexStatus\":\"" + vexStatus + "\",\"vexProvider\":\""
                    + (vexProvider == null ? "unknown" : vexProvider) + "\",\"vexPublishedAt\":\""
                    + publishedAt + "\"}");
        }
        if (updatedAt != null) {
            ReflectionTestUtils.setField(target, "updatedAt", updatedAt);
        }
        vulnerabilityTargetRepository.save(target);
    }

    private record TestFixture(Asset asset, InventoryComponent component) {
    }
}
