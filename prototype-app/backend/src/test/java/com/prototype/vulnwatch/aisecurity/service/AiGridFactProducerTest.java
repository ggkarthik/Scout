package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AiGridFactProducerTest {
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void awsProducerEmitsOnlyOwnedDirectProviderEvidence() throws Exception {
        var input = new AiGridFactProducer.FactInput("AWS", "BEDROCK_AGENTS", "AI_AGENT", "BEDROCK_AGENT",
                mapper.readTree("{\"guardrailAttached\":false,\"guardrailMinimumStrength\":\"LOW\",\"localAuthEnabled\":true}"), null, null, Instant.now());

        Map<String, AiGridFactProducer.ProducedFact> facts = new AwsAiGridFactProducer().produce(input).stream()
                .collect(java.util.stream.Collectors.toMap(AiGridFactProducer.ProducedFact::factKey, value -> value));

        assertFalse(facts.get("bedrock.agent.guardrail_attached_configured").value().asBoolean());
        assertEquals("LOW", facts.get("bedrock.guardrail.minimum_strength_configured").value().asText());
        assertEquals("KNOWN", facts.get("bedrock.agent.guardrail_attached_configured").state());
        assertEquals("DIRECT_PROVIDER_ATTRIBUTE", facts.get("bedrock.agent.guardrail_attached_configured").confidenceMethod());
        assertFalse(facts.containsKey("identity.local_auth_enabled_configured"));
    }

    @Test
    void unknownSensitivityIsExplicitEvidenceNotAFalseNegative() {
        var input = new AiGridFactProducer.FactInput("AZURE", "AZURE_PURVIEW", "DATA_STORE", "AZURE_SEARCH_INDEX",
                mapper.createObjectNode(), "UNKNOWN", "AZURE_PURVIEW", Instant.now());

        var fact = new CommonAiGridFactProducer(mapper).produce(input).stream()
                .filter(value -> value.factKey().equals("data.source_sensitivity")).findFirst().orElseThrow();

        assertEquals("UNKNOWN", fact.state());
        assertEquals("UNKNOWN", fact.value().asText());
        assertTrue(fact.derivationInputs().contains("attributes.piiScanStatus"));
    }

    @Test
    void producerPreservesConnectorStatusAndConfiguredCountsAsTypedFacts() throws Exception {
        var input = new AiGridFactProducer.FactInput("AWS", "BEDROCK_GUARDRAILS", "AI_GUARDRAIL", "AWS_BEDROCK_GUARDRAIL",
                mapper.readTree("{\"status\":\"FAILED\",\"contentFilterCount\":0}"), null, null, Instant.now());

        Map<String, AiGridFactProducer.ProducedFact> facts = new AwsAiGridFactProducer().produce(input).stream()
                .collect(java.util.stream.Collectors.toMap(AiGridFactProducer.ProducedFact::factKey, value -> value));

        assertEquals("FAILED", facts.get("resource.status_observed").value().asText());
        assertEquals(0, facts.get("guardrail.content_filter_count_configured").value().intValue());
        assertEquals("CONFIGURATION", facts.get("resource.status_observed").evidenceClass());
    }

    @Test
    void azureOwnerTagUsesAnExplicitPresenceFact() throws Exception {
        var input = new AiGridFactProducer.FactInput("AZURE", "AZURE_AI_ACCOUNTS", "AI_SERVICE", "AZURE_AI_ACCOUNTS",
                mapper.readTree("{\"tags\":{\"Owner\":\"security-team\"}}"), null, null, Instant.now());
        var fact = new AzureAiGridFactProducer().produce(input).stream()
                .filter(value -> value.factKey().equals("owner.owner_tag_present_configured")).findFirst().orElseThrow();

        assertTrue(fact.value().asBoolean());
    }

    @Test
    void awsProducerNormalizesRemainingGuardrailModelAndNetworkContracts() throws Exception {
        var input = new AiGridFactProducer.FactInput("AWS", "BEDROCK_GUARDRAILS", "AI_GUARDRAIL", "AWS_BEDROCK_GUARDRAIL",
                mapper.readTree("""
                        {"piiEntityCount":0,"contextualGroundingFilterCount":1,"deniedTopicCount":2,
                         "updatedAt":"2026-01-01T00:00:00Z","kmsKeyArn":"arn:aws:kms:region:account:key/id",
                         "foundationModel":"amazon.nova-pro-v1:0","vpcId":"vpc-123","instanceType":"ml.t3.medium"}
                        """), null, null, Instant.now());
        Map<String, AiGridFactProducer.ProducedFact> facts = new AwsAiGridFactProducer().produce(input).stream()
                .collect(java.util.stream.Collectors.toMap(AiGridFactProducer.ProducedFact::factKey, value -> value));

        assertEquals(0, facts.get("guardrail.pii_entity_count_configured").value().intValue());
        assertEquals("amazon.nova-pro-v1:0", facts.get("model.foundation_identifier_configured").value().asText());
        assertEquals("vpc-123", facts.get("network.vpc_id_configured").value().asText());
        assertTrue(facts.get("data.customer_managed_key_configured").value().asBoolean());
    }

    @Test
    void azureProducerNormalizesAllowlistAndRbacContracts() throws Exception {
        var input = new AiGridFactProducer.FactInput("AZURE", "AZURE_RBAC_GLOBAL", "IDENTITY", "AZURE_RBAC_GLOBAL",
                mapper.readTree("""
                        {"raiPolicyMode":"Default","modelPublisher":"Microsoft","toolType":"function",
                         "assignmentScope":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/a",
                         "principalType":"ServicePrincipal","conditionVersion":"2.0",
                         "tags":{"environment":"prod","criticality":"high"}}
                        """), null, null, Instant.now());
        Map<String, AiGridFactProducer.ProducedFact> facts = new AzureAiGridFactProducer().produce(input).stream()
                .collect(java.util.stream.Collectors.toMap(AiGridFactProducer.ProducedFact::factKey, value -> value));

        assertEquals("Default", facts.get("guardrail.rai_mode_configured").value().asText());
        assertEquals("ServicePrincipal", facts.get("identity.principal_type_configured").value().asText());
        assertTrue(facts.get("resource.required_tags_present_configured").value().asBoolean());
    }
}
