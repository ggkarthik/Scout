package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AiHarmMetadataTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private AiGridFactProducer.FactInput input(String provider, Map<String,Object> attrs) {
        return new AiGridFactProducer.FactInput(provider, "FAMILY", "AI_COMPONENT", "KIND", mapper.valueToTree(attrs), null, null, Instant.now());
    }
    @Test void iamPatternsPreserveExplicitFalseWithoutClaimingEffectiveAccess() {
        var facts = new AwsAiGridFactProducer().produce(input("AWS", Map.of("iamWildcardResources", true,
                "iamPassRole", false, "iamNotAction", true, "iamNotResource", false,
                "permissionBoundaryAttached", false, "crossAccountTrust", true, "trustConditionsPresent", false)));
        assertEquals(7, facts.size());
        assertFalse(facts.stream().anyMatch(f -> f.factKey().contains("effective")));
        assertTrue(facts.stream().anyMatch(f -> f.factKey().equals("identity.pass_role_pattern_observed") && !f.value().asBoolean()));
        assertTrue(new AwsAiGridFactProducer().produce(input("AWS", Map.of())).isEmpty());
    }
    @Test void copilotFactsAreProviderIsolatedAndUnknownTypesRemainCoverageGaps() {
        var producer = new CopilotAiGridFactProducer();
        assertTrue(producer.produce(input("AZURE", Map.of("componentType", "SKILL"))).isEmpty());
        var facts = producer.produce(input("MICROSOFT_COPILOT", Map.of("componentType", "UNKNOWN", "version", "v1", "sourceType", "COPILOT_STUDIO")));
        assertEquals("UNKNOWN", facts.stream().filter(f -> f.factKey().equals("copilot.component_type_observed")).findFirst().orElseThrow().state());
        assertFalse(producer.produce(input("MICROSOFT_COPILOT", Map.of("componentType", "BOT_VARIABLE"))).stream()
                .anyMatch(f -> f.factKey().contains("memory") || f.factKey().contains("handoff")));
    }
    @Test void azureUnknownAuthIsNotAnonymousAndDigestsStayInternal() {
        var fact = new AzureAiGridFactProducer().produce(input("AZURE", Map.of("configuredAuthType", "UNKNOWN"))).get(0);
        assertEquals("mcp.configured_auth_type", fact.factKey());
        assertEquals("UNKNOWN", fact.state());
        assertFalse(AiSecurityFieldContract.responseSafe(Map.of("promptDigest", "internal", "toolDefinitionDigest", "internal")).containsKey("promptDigest"));
    }
    @Test void guardrailDetachmentRequiresCompleteVersionBinding() {
        String approved = snapshot(Map.of("guardrailAttached", true, "guardrailId", "g1", "guardrailVersion", "1"), true);
        assertEquals(AiSecurityDigestBaselineService.Outcome.UNCHANGED, AiGuardrailBaselineComparison.compare(approved, approved));
        assertEquals(AiSecurityDigestBaselineService.Outcome.CONTROL_WEAKENED,
                AiGuardrailBaselineComparison.compare(approved, snapshot(Map.of("guardrailAttached", false), true)));
        assertEquals(AiSecurityDigestBaselineService.Outcome.CONFIGURATION_UNKNOWN,
                AiGuardrailBaselineComparison.compare(approved, snapshot(Map.of("guardrailAttached", false), false)));
        assertEquals(AiSecurityDigestBaselineService.Outcome.CONTROL_CONFIGURATION_CHANGED_REVIEW_REQUIRED,
                AiGuardrailBaselineComparison.compare(approved, snapshot(Map.of("guardrailAttached", true, "guardrailId", "g2", "guardrailVersion", "1"), true)));
        assertEquals(AiSecurityDigestBaselineService.Outcome.CONFIGURATION_UNKNOWN,
                AiGuardrailBaselineComparison.compare(approved, snapshot(Map.of("guardrailAttached", true, "guardrailId", "g1"), true)));
        assertNull(AiGuardrailBaselineComparison.snapshot("MICROSOFT_COPILOT", "MICROSOFT_COPILOT", Map.of("promptDigest", "x"), true));
    }
    @Test void controlStrengthComparisonDoesNotUseCountsAndRequiresComparableVersions() {
        String before = filters("1", "HIGH"), after = filters("1", "LOW");
        assertEquals(AiSecurityDigestBaselineService.Outcome.CONTROL_WEAKENED, AiGuardrailBaselineComparison.compare(before, after));
        assertEquals(AiSecurityDigestBaselineService.Outcome.CONFIGURATION_UNKNOWN, AiGuardrailBaselineComparison.compare(before, filters("2", "LOW")));
        assertEquals(AiSecurityDigestBaselineService.Outcome.CONFIGURATION_UNKNOWN, AiGuardrailBaselineComparison.compare(before,
                AiGuardrailBaselineComparison.snapshot("AWS", "AWS_BEDROCK_GUARDRAIL", Map.of("version", "1", "contentFilterCount", 0), true)));
    }
    @Test void azureChangedReferenceIsReviewOnlyAndUnknownBindingsStayUnknown() {
        String before = AiGuardrailBaselineComparison.snapshot("AZURE", "AZURE_FOUNDRY_DEPLOYMENTS", Map.of("raiPolicyName", "policy-one", "modelVersion", "1"), true);
        String after = AiGuardrailBaselineComparison.snapshot("AZURE", "AZURE_FOUNDRY_DEPLOYMENTS", Map.of("raiPolicyName", "policy-two", "modelVersion", "1"), true);
        assertEquals(AiSecurityDigestBaselineService.Outcome.CONTROL_CONFIGURATION_CHANGED_REVIEW_REQUIRED, AiGuardrailBaselineComparison.compare(before, after));
        assertEquals(AiSecurityDigestBaselineService.Outcome.CONFIGURATION_UNKNOWN, AiGuardrailBaselineComparison.compare(before, before));
        assertEquals(AiSecurityDigestBaselineService.Outcome.CONFIGURATION_UNKNOWN, AiGuardrailBaselineComparison.compare(before,
                AiGuardrailBaselineComparison.snapshot("AZURE", "AZURE_FOUNDRY_DEPLOYMENTS", Map.of("raiPolicyName", "policy-two"), true)));
    }
    private String filters(String version, String strength) {
        return AiGuardrailBaselineComparison.snapshot("AWS", "AWS_BEDROCK_GUARDRAIL", Map.of("version", version, "contentFilterCount", 1,
                "contentFilters", java.util.List.of(Map.of("type", "HATE", "inputStrength", strength, "outputStrength", strength, "inputEnabled", true, "outputEnabled", true))), true);
    }
    private String snapshot(Map<String,Object> attrs, boolean complete) {
        return AiGuardrailBaselineComparison.snapshot("AWS", "AWS_BEDROCK_AGENT", attrs, complete);
    }
}
