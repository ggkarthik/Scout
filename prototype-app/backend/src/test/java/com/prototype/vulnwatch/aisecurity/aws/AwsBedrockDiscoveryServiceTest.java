package com.prototype.vulnwatch.aisecurity.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.bedrock.model.GetGuardrailResponse;
import software.amazon.awssdk.services.bedrock.model.GuardrailContentFilter;
import software.amazon.awssdk.services.bedrock.model.GuardrailContentFilterType;
import software.amazon.awssdk.services.bedrock.model.GuardrailContentPolicy;
import software.amazon.awssdk.services.bedrock.model.GuardrailContextualGroundingAction;
import software.amazon.awssdk.services.bedrock.model.GuardrailContextualGroundingFilter;
import software.amazon.awssdk.services.bedrock.model.GuardrailContextualGroundingFilterType;
import software.amazon.awssdk.services.bedrock.model.GuardrailContextualGroundingPolicy;
import software.amazon.awssdk.services.bedrock.model.GuardrailFilterStrength;
import software.amazon.awssdk.services.bedrock.model.GuardrailManagedWords;
import software.amazon.awssdk.services.bedrock.model.GuardrailManagedWordsType;
import software.amazon.awssdk.services.bedrock.model.GuardrailPiiEntity;
import software.amazon.awssdk.services.bedrock.model.GuardrailPiiEntityType;
import software.amazon.awssdk.services.bedrock.model.GuardrailRegex;
import software.amazon.awssdk.services.bedrock.model.GuardrailSensitiveInformationAction;
import software.amazon.awssdk.services.bedrock.model.GuardrailSensitiveInformationPolicy;
import software.amazon.awssdk.services.bedrock.model.GuardrailStatus;
import software.amazon.awssdk.services.bedrock.model.GuardrailTopic;
import software.amazon.awssdk.services.bedrock.model.GuardrailTopicAction;
import software.amazon.awssdk.services.bedrock.model.GuardrailTopicPolicy;
import software.amazon.awssdk.services.bedrock.model.GuardrailTopicType;
import software.amazon.awssdk.services.bedrock.model.GuardrailWord;
import software.amazon.awssdk.services.bedrock.model.GuardrailWordPolicy;

/** Covers guardrailAttributes(...) — the AWS Bedrock GetGuardrail response mapper that populates
 *  the Observed Facts panel on the AI asset detail page. None of the constructor dependencies are
 *  touched by this pure mapping method, so they're passed as null rather than mocked. */
class AwsBedrockDiscoveryServiceTest {

    private final AwsBedrockDiscoveryService service = new AwsBedrockDiscoveryService(
            null, null, null, new ObjectMapper(), null, null, null, null, null, false);

    @Test
    void capturesBoundedStructuralGuardrailConfigurationWithoutFreeFormMessages() {
        GetGuardrailResponse detail = GetGuardrailResponse.builder()
                .name("search-rerank-guardrail-free-tier")
                .description("Blocks sensitive topics in the free-tier search assistant")
                .status(GuardrailStatus.READY)
                .version("DRAFT")
                .createdAt(Instant.parse("2026-08-09T21:26:18Z"))
                .updatedAt(Instant.parse("2026-08-11T15:12:33Z"))
                .kmsKeyArn("arn:aws:kms:us-east-1:919221584905:key/example")
                .blockedInputMessaging("I can't help with that request.")
                .blockedOutputsMessaging("I can't share that response.")
                .contentPolicy(GuardrailContentPolicy.builder()
                        .filters(GuardrailContentFilter.builder()
                                .type(GuardrailContentFilterType.HATE)
                                .inputStrength(GuardrailFilterStrength.HIGH)
                                .outputStrength(GuardrailFilterStrength.HIGH)
                                .inputEnabled(true)
                                .outputEnabled(true)
                                .build())
                        .build())
                .topicPolicy(GuardrailTopicPolicy.builder()
                        .topics(GuardrailTopic.builder()
                                .name("Investment advice")
                                .type(GuardrailTopicType.DENY)
                                .inputAction(GuardrailTopicAction.BLOCK)
                                .outputAction(GuardrailTopicAction.BLOCK)
                                .build())
                        .build())
                .wordPolicy(GuardrailWordPolicy.builder()
                        .words(GuardrailWord.builder().text("competitor-brand").build())
                        .managedWordLists(GuardrailManagedWords.builder()
                                .type(GuardrailManagedWordsType.PROFANITY)
                                .build())
                        .build())
                .sensitiveInformationPolicy(GuardrailSensitiveInformationPolicy.builder()
                        .piiEntities(GuardrailPiiEntity.builder()
                                .type(GuardrailPiiEntityType.EMAIL)
                                .inputAction(GuardrailSensitiveInformationAction.ANONYMIZE)
                                .outputAction(GuardrailSensitiveInformationAction.ANONYMIZE)
                                .build())
                        .regexes(GuardrailRegex.builder()
                                .name("internal-ticket-id")
                                .pattern("TICKET-\\d+")
                                .action(GuardrailSensitiveInformationAction.BLOCK)
                                .build())
                        .build())
                .contextualGroundingPolicy(GuardrailContextualGroundingPolicy.builder()
                        .filters(GuardrailContextualGroundingFilter.builder()
                                .type(GuardrailContextualGroundingFilterType.GROUNDING)
                                .threshold(0.85)
                                .action(GuardrailContextualGroundingAction.BLOCK)
                                .build())
                        .build())
                .build();

        Map<String, Object> attributes = service.guardrailAttributes(detail, "HIGH");

        assertEquals("READY", attributes.get("status"));
        assertEquals("HIGH", attributes.get("minimumStrength"));
        assertFalse(attributes.containsKey("description"));
        assertEquals("DRAFT", attributes.get("version"));
        assertEquals("arn:aws:kms:us-east-1:919221584905:key/example", attributes.get("kmsKeyArn"));
        assertFalse(attributes.containsKey("blockedInputMessaging"));
        assertFalse(attributes.containsKey("blockedOutputsMessaging"));
        assertTrue(((String) attributes.get("createdAt")).startsWith("2026-08-09"));
        assertTrue(((String) attributes.get("updatedAt")).startsWith("2026-08-11"));

        assertEquals(1, attributes.get("contentFilterCount"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> contentFilters = (List<Map<String, Object>>) attributes.get("contentFilters");
        assertEquals("HATE", contentFilters.get(0).get("type"));
        assertEquals("HIGH", contentFilters.get(0).get("inputStrength"));
        assertEquals("HIGH", contentFilters.get(0).get("outputStrength"));

        assertEquals(1, attributes.get("deniedTopicCount"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> deniedTopics = (List<Map<String, Object>>) attributes.get("deniedTopics");
        assertEquals("Investment advice", deniedTopics.get(0).get("name"));
        assertEquals("BLOCK", deniedTopics.get(0).get("inputAction"));

        assertEquals(1, attributes.get("customWordFilterCount"));
        assertEquals(true, attributes.get("profanityFilterEnabled"));

        assertEquals(1, attributes.get("piiEntityCount"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> piiEntities = (List<Map<String, Object>>) attributes.get("piiEntities");
        assertEquals("EMAIL", piiEntities.get(0).get("type"));
        assertEquals("ANONYMIZE", piiEntities.get(0).get("inputAction"));
        assertEquals(1, attributes.get("sensitiveRegexCount"));

        assertEquals(1, attributes.get("contextualGroundingFilterCount"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> groundingFilters = (List<Map<String, Object>>) attributes.get("contextualGroundingFilters");
        assertEquals("GROUNDING", groundingFilters.get(0).get("type"));
        assertEquals(0.85, groundingFilters.get(0).get("threshold"));
        assertEquals("BLOCK", groundingFilters.get(0).get("action"));
    }

    @Test
    void recordsZeroCountsForUnsetPoliciesAndSkipsNullNestedFields() {
        // A minimal guardrail with no topic/word/PII/grounding policy configured, and a content
        // filter missing its per-direction action fields (older guardrails may predate them) —
        // must not throw NPE. Authoritative zero counts and an empty KMS identifier are retained
        // so absence evaluates as insecure instead of being mistaken for missing evidence.
        GetGuardrailResponse detail = GetGuardrailResponse.builder()
                .name("minimal-guardrail")
                .status(GuardrailStatus.READY)
                .contentPolicy(GuardrailContentPolicy.builder()
                        .filters(GuardrailContentFilter.builder()
                                .type(GuardrailContentFilterType.HATE)
                                .inputStrength(GuardrailFilterStrength.NONE)
                                .outputStrength(GuardrailFilterStrength.NONE)
                                .build())
                        .build())
                .build();

        Map<String, Object> attributes = service.guardrailAttributes(detail, "NONE");

        assertEquals("READY", attributes.get("status"));
        assertFalse(attributes.containsKey("description"));
        assertEquals("", attributes.get("kmsKeyArn"));
        assertEquals(0, attributes.get("deniedTopicCount"));
        assertEquals(0, attributes.get("piiEntityCount"));
        assertEquals(0, attributes.get("contextualGroundingFilterCount"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> contentFilters = (List<Map<String, Object>>) attributes.get("contentFilters");
        Map<String, Object> filter = contentFilters.get(0);
        assertEquals("HATE", filter.get("type"));
        // inputEnabled/outputEnabled were never set on the builder above (null) — entryMap must
        // drop them rather than let Map.of()'s null-value NPE take down the whole discovery scope.
        assertFalse(filter.containsKey("inputEnabled"));
        assertFalse(filter.containsKey("outputEnabled"));
        assertNull(filter.get("missingKeyIsNull"));
    }
}
