package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityConstraintType;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FindingEvidenceServiceTest {

    private final ObjectMapper objectMapper = JsonMapper.builder().findAndAddModules().build();
    private final FindingEvidenceService service = new FindingEvidenceService(objectMapper);

    @Test
    void buildEvidenceContainsDeterministicDecisionAndTargetContext() throws Exception {
        InventoryComponent component = component("2.14.1");
        Vulnerability vulnerability = vulnerability("CVE-2024-12345");
        VulnerabilityTarget target = target(vulnerability);

        ApplicabilityDecisionService.ApplicabilityDecision applicability =
                new ApplicabilityDecisionService.ApplicabilityDecision(
                        ApplicabilityDecisionService.ApplicabilityResult.TRUE,
                        "within_constraints",
                        Map.of("finalReason", "within_constraints"));

        PrecedenceResolverService.CandidateDecision selected = new PrecedenceResolverService.CandidateDecision(
                target,
                "purl-exact+version",
                1,
                0.93,
                Map.of("base", 0.90, "boosts", 0.03, "penalties", 0.0, "cap", 0.98),
                applicability
        );

        PrecedenceResolverService.PrecedenceResolution resolution = new PrecedenceResolverService.PrecedenceResolution(
                PrecedenceResolverService.FinalState.AFFECTED,
                selected,
                "highest_precedence_affected",
                List.of(Map.of("source", "nvd", "priority", 2)),
                List.of(Map.of("matchedBy", "purl-exact+version", "applicabilityResult", "TRUE")),
                Map.of("engine", "source-precedence-v2", "reason", "highest_precedence_affected")
        );

        String raw = service.buildEvidence(component, vulnerability, target, selected, resolution, riskScoreOutcome(9.2));
        JsonNode payload = objectMapper.readTree(raw);

        assertEquals("purl-exact+version", payload.path("matchedBy").asText());
        assertEquals("AFFECTED", payload.path("decisionState").asText());
        assertEquals("highest_precedence_affected", payload.path("decisionReason").asText());
        assertEquals("TRUE", payload.path("applicabilityResult").asText());
        assertEquals("within_constraints", payload.path("applicabilityReason").asText());
        assertEquals("MAVEN", payload.path("targetVersionScheme").asText());
        assertEquals("RANGE", payload.path("targetConstraintType").asText());
        assertEquals("2.0.0", payload.path("targetVersionStart").asText());
        assertEquals("2.17.0", payload.path("targetVersionEnd").asText());
        assertEquals("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", payload.path("componentPurl").asText());
        assertEquals("CVE-2024-12345", payload.path("vulnerabilityId").asText());
        assertTrue(payload.path("sourcePrecedence").isArray());
        assertEquals("nvd", payload.path("sourcePrecedence").get(0).path("source").asText());
        assertTrue(payload.path("confidenceBreakdown").has("base"));
        assertEquals(9.2, payload.path("riskScore").asDouble());
        assertTrue(payload.path("riskBreakdown").isObject());
    }

    @Test
    void buildEvidenceUsesMissingDecisionDefaultsWhenApplicabilityAbsent() throws Exception {
        InventoryComponent component = component("1.0.0");
        Vulnerability vulnerability = vulnerability("ADV-1");
        VulnerabilityTarget target = target(vulnerability);

        PrecedenceResolverService.CandidateDecision selected = new PrecedenceResolverService.CandidateDecision(
                target,
                "coords-exact+version",
                2,
                0.75,
                Map.of("base", 0.75),
                null
        );

        PrecedenceResolverService.PrecedenceResolution resolution = new PrecedenceResolverService.PrecedenceResolution(
                PrecedenceResolverService.FinalState.UNKNOWN,
                selected,
                "no_decisive_candidate",
                List.of(),
                List.of(),
                Map.of("reason", "no_decisive_candidate")
        );

        String raw = service.buildEvidence(component, vulnerability, target, selected, resolution, riskScoreOutcome(4.1));
        JsonNode payload = objectMapper.readTree(raw);

        assertEquals("UNKNOWN", payload.path("applicabilityResult").asText());
        assertEquals("missing_decision", payload.path("applicabilityReason").asText());
        assertEquals("UNKNOWN", payload.path("decisionState").asText());
    }

    private RiskScoringService.RiskScoreOutcome riskScoreOutcome(double score) {
        return new RiskScoringService.RiskScoreOutcome(
                score,
                Map.of("finalScore", score),
                Map.of("selectedApplicabilityReason", "within_constraints", "staleSignalCount", 0)
        );
    }

    private InventoryComponent component(String version) {
        Asset asset = new Asset();
        asset.setName("payments-api");
        asset.setIdentifier("asset-1");

        InventoryComponent component = new InventoryComponent();
        component.setAsset(asset);
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@" + version);
        component.setPackageName("org.apache.logging.log4j:log4j-core");
        component.setEcosystem("maven");
        component.setVersion(version);
        component.setComponentDigest("sha256:abc");
        return component;
    }

    private Vulnerability vulnerability(String externalId) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId(externalId);
        vulnerability.setSeverity("CRITICAL");
        vulnerability.setTitle(externalId);
        return vulnerability;
    }

    private VulnerabilityTarget target(Vulnerability vulnerability) {
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setVulnerability(vulnerability);
        target.setSource("nvd");
        target.setTargetType(VulnerabilityTargetType.PURL);
        target.setNormalizedTargetKey("pkg:maven/org.apache.logging.log4j/log4j-core");
        target.setVersionScheme(VersionScheme.MAVEN);
        target.setConstraintType(VulnerabilityConstraintType.RANGE);
        target.setVersionStart("2.0.0");
        target.setStartInclusive(true);
        target.setVersionEnd("2.17.0");
        target.setEndInclusive(false);
        target.setKbVersion("test-kb-v1");
        return target;
    }
}
