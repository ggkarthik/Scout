package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.CpeDim;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
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
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.util.CpeUtil;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "spring.datasource.url=jdbc:h2:mem:correlation_determinism;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "app.correlation.backfill-targets-on-startup=false"
})
@Transactional
class CorrelationDeterminismIntegrationTest {

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
    private InventoryComponentCpeMappingService inventoryComponentCpeMappingService;

    @Autowired
    private CpeDimensionService cpeDimensionService;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private VulnerabilityTargetRepository vulnerabilityTargetRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void recomputeTwice_producesStableCorrelationFingerprint() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        Asset asset = createAsset(tenant);
        InventoryComponent component = createComponent(tenant, asset);
        inventoryComponentCpeMappingService.syncActiveComponentMappings(
                component,
                List.of("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        );

        Vulnerability vuln = createVulnerability("CVE-2099-4001");
        createCpeTarget(
                vuln,
                "advisory",
                "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                "2.0.0",
                "2.17.1"
        );

        int firstActive = findingService.recomputeOnSoftwareDelta(tenant.getId(), component.getId());
        List<Finding> first = findingRepository.findByAsset(asset);
        assertEquals(1, firstActive);
        assertEquals(1, first.size());

        String firstFingerprint = fingerprint(first);

        int secondActive = findingService.recomputeOnSoftwareDelta(tenant.getId(), component.getId());
        List<Finding> second = findingRepository.findByAsset(asset);
        assertEquals(1, secondActive);
        assertEquals(1, second.size());

        String secondFingerprint = fingerprint(second);
        assertEquals(firstFingerprint, secondFingerprint);

        assertFalse(second.isEmpty());
    }

    private String fingerprint(List<Finding> findings) throws Exception {
        List<String> lines = new ArrayList<>();
        for (Finding finding : findings) {
            JsonNode evidence = objectMapper.readTree(finding.getEvidence());
            JsonNode precedenceTrace = objectMapper.readTree(finding.getPrecedenceTrace());
            lines.add(String.join("|",
                    finding.getAsset().getIdentifier(),
                    finding.getComponent().getPackageName(),
                    finding.getComponent().getVersion(),
                    finding.getVulnerability().getExternalId(),
                    finding.getMatchedBy(),
                    finding.getDecisionState().name(),
                    finding.getStatus().name(),
                    number(finding.getConfidenceScore()),
                    evidence.path("decisionReason").asText(""),
                    evidence.path("applicabilityResult").asText(""),
                    evidence.path("applicabilityReason").asText(""),
                    evidence.path("targetId").asText(""),
                    precedenceTrace.path("reason").asText("")
            ));
        }
        lines.sort(Comparator.naturalOrder());
        return sha256(String.join("\n", lines));
    }

    private Asset createAsset(Tenant tenant) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.APPLICATION);
        asset.setName("determinism-app");
        asset.setIdentifier("app:determinism");
        asset.setBusinessCriticality(BusinessCriticality.MEDIUM);
        asset.setState(com.prototype.vulnwatch.domain.AssetState.ACTIVE);
        asset.setLastInventoryAt(Instant.now());
        return assetRepository.save(asset);
    }

    private InventoryComponent createComponent(Tenant tenant, Asset asset) {
        SbomUpload upload = new SbomUpload();
        upload.setTenant(tenant);
        upload.setAsset(asset);
        upload.setFormat(SbomFormat.CYCLONEDX);
        upload.setStatus(SbomIngestionStatus.SUCCESS);
        upload.setOriginalFilename("determinism.json");
        upload = sbomUploadRepository.save(upload);

        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(upload);
        component.setEcosystem("maven");
        component.setPackageName("log4j-core");
        component.setVersion("2.14.1");
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        return inventoryComponentRepository.save(component);
    }

    private Vulnerability createVulnerability(String idPrefix) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId(idPrefix + "-" + UUID.randomUUID().toString().substring(0, 8));
        vulnerability.setSource(VulnerabilitySource.ADVISORY);
        vulnerability.setTitle(idPrefix);
        vulnerability.setDescription("determinism");
        vulnerability.setSeverity("CRITICAL");
        vulnerability.setCvssScore(9.8);
        vulnerability.touch();
        return vulnerabilityRepository.save(vulnerability);
    }

    private void createCpeTarget(
            Vulnerability vulnerability,
            String source,
            String cpe,
            String versionStart,
            String versionEnd
    ) {
        String normalized = CpeUtil.normalizeCpe23(cpe);
        CpeDim dim = cpeDimensionService.resolveOrCreate(normalized);

        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setVulnerability(vulnerability);
        target.setTargetType(VulnerabilityTargetType.CPE);
        target.setNormalizedTargetKey(normalized);
        target.setSource(source);
        target.setCpe(normalized);
        target.setCpeDim(dim);
        target.setCpeWildcardScore(1);
        target.setVersionScheme(VersionScheme.UNKNOWN);
        target.setConstraintType(VulnerabilityConstraintType.RANGE);
        target.setVersionStart(versionStart);
        target.setStartInclusive(Boolean.TRUE);
        target.setVersionEnd(versionEnd);
        target.setEndInclusive(Boolean.TRUE);
        target.setKbVersion("determinism-kb");
        vulnerabilityTargetRepository.save(target);
    }

    private String number(double value) {
        BigDecimal rounded = BigDecimal.valueOf(value).setScale(6, RoundingMode.HALF_UP);
        return rounded.stripTrailingZeros().toPlainString();
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                builder.append(String.format(Locale.ROOT, "%02x", b));
            }
            return builder.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to compute SHA-256", e);
        }
    }
}
