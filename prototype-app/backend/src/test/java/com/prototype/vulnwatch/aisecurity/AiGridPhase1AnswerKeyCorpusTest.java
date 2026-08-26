package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Contract test that holds the shipped answer-key corpus honest at CI time. It does not run the
 * engine (that requires platform-run-bound evidence — see the corpus certificationRequirement),
 * but it proves the labels themselves never expect a PASS on missing/stale/capability/proxy
 * evidence, that every policy has the full scenario matrix, and that digests are internally
 * consistent. This closes the "answer keys assert nothing" gap for the declarative layer.
 */
class AiGridPhase1AnswerKeyCorpusTest {

    private static final String RESOURCE = "ai-grid/certification/agcf-phase-1-answer-key-corpus.json";
    private static final Set<String> SCENARIOS = Set.of(
            "SECURE", "INSECURE", "MISSING_EVIDENCE", "STALE_EVIDENCE", "CAPABILITY_FAILURE", "PROXY_VS_VERIFIED");
    private static final Set<String> NON_DECISIVE = Set.of(
            "MISSING_EVIDENCE", "STALE_EVIDENCE", "CAPABILITY_FAILURE", "PROXY_VS_VERIFIED");

    private static JsonNode corpus;

    @BeforeAll
    static void load() throws Exception {
        try (InputStream in = AiGridPhase1AnswerKeyCorpusTest.class.getClassLoader().getResourceAsStream(RESOURCE)) {
            assertNotNull(in, "answer-key corpus must be on the classpath: " + RESOURCE);
            corpus = new ObjectMapper().readTree(in);
        }
    }

    @Test
    void corpusIsCompleteAtSeventySixPoliciesTimesSixScenarios() {
        assertEquals(76, corpus.path("policyCount").asInt());
        assertEquals(6, corpus.path("casesPerPolicy").asInt());
        assertEquals(456, corpus.path("caseCount").asInt());
        assertEquals(456, corpus.path("cases").size(), "declared caseCount must equal the actual number of cases");
        assertEquals(76, corpus.path("policies").size());

        Map<String, Set<String>> scenariosByPolicy = new HashMap<>();
        for (JsonNode c : corpus.path("cases")) {
            scenariosByPolicy.computeIfAbsent(c.path("policyId").asText(), ignored -> new HashSet<>())
                    .add(c.path("scenario").asText());
        }
        assertEquals(76, scenariosByPolicy.size(), "every policy must appear in the corpus");
        scenariosByPolicy.forEach((policyId, scenarios) ->
                assertEquals(SCENARIOS, scenarios, policyId + " must carry the full scenario matrix exactly once each"));
    }

    @Test
    void noAnswerKeyEverExpectsPassOnAbsentStaleOrUnprovenEvidence() {
        for (JsonNode c : corpus.path("cases")) {
            String scenario = c.path("scenario").asText();
            String decision = c.path("expectedDecision").asText();
            boolean finding = c.path("expectedFinding").asBoolean();
            String applicability = c.path("expectedApplicability").asText();
            String key = c.path("caseKey").asText();

            assertEquals("APPLICABLE", applicability, key + " applicability");
            switch (scenario) {
                case "SECURE" -> { assertEquals("PASS", decision, key); assertFalse(finding, key); }
                case "INSECURE" -> { assertEquals("FAIL", decision, key); assertTrue(finding, key); }
                default -> {
                    // The core safety invariant: missing/stale/capability/proxy evidence is NO_DECISION, never PASS.
                    assertTrue(NON_DECISIVE.contains(scenario), key + " unexpected scenario " + scenario);
                    assertEquals("NO_DECISION", decision, key + " must be NO_DECISION, never PASS");
                    assertFalse(finding, key + " must not raise a finding without decisive evidence");
                }
            }
        }
    }

    @Test
    void digestsAreInternallyConsistent() {
        assertEquals(64, corpus.path("sourceManifestDigest").asText().length(), "manifest digest is a sha-256 hex");

        Map<String, String> packageDigestByPolicy = new HashMap<>();
        Map<String, String> catalogDigestByPolicy = new HashMap<>();
        for (JsonNode p : corpus.path("policies")) {
            String packageDigest = p.path("packageDigest").asText();
            String catalogDigest = p.path("catalogDigest").asText();
            assertEquals(64, packageDigest.length(), "package digest is a sha-256 hex");
            assertEquals(64, catalogDigest.length(), "catalog digest is a sha-256 hex");
            packageDigestByPolicy.put(p.path("policyId").asText(), packageDigest);
            catalogDigestByPolicy.put(p.path("policyId").asText(), catalogDigest);
        }

        Set<String> policyIds = packageDigestByPolicy.keySet();
        for (JsonNode c : corpus.path("cases")) {
            String policyId = c.path("policyId").asText();
            assertTrue(policyIds.contains(policyId), "case references unknown policy " + policyId);
            assertEquals(packageDigestByPolicy.get(policyId), c.path("packageDigest").asText(),
                    "case package digest must match its policy entry for " + c.path("caseKey").asText());
            assertEquals(catalogDigestByPolicy.get(policyId), c.path("catalogDigest").asText(),
                    "case catalog digest must match its policy entry for " + c.path("caseKey").asText());
        }
        List<String> providers = List.of("AWS", "AZURE", "MULTI_CLOUD");
        long known = corpus.path("policies").findValuesAsText("provider").stream().filter(providers::contains).count();
        assertEquals(76, known, "every policy entry must declare a known provider");
    }
}
