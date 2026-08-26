package com.prototype.vulnwatch.aisecurity.policy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.Map;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class AiGridPredicateEngineTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final AiGridPredicateEngine engine = new AiGridPredicateEngine();

    @Test
    void evaluatesTheR0GuardrailPredicateFromExactFacts() throws Exception {
        JsonNode predicate = mapper.readTree("""
                {"all":[
                  {"fact":"bedrock.agent.guardrail_attached_configured","eq":true},
                  {"fact":"bedrock.guardrail.minimum_strength_configured","in":["NONE","LOW"]}
                ]}
                """);
        Map<String, JsonNode> weak = new LinkedHashMap<>();
        weak.put("bedrock.agent.guardrail_attached_configured", mapper.valueToTree(true));
        weak.put("bedrock.guardrail.minimum_strength_configured", mapper.valueToTree("LOW"));
        assertTrue(engine.evaluate(predicate, weak));
        weak.put("bedrock.guardrail.minimum_strength_configured", mapper.valueToTree("HIGH"));
        assertFalse(engine.evaluate(predicate, weak));
    }

    @Test
    void proxyFactCannotSubstituteForARequiredVerifiedFactKey() throws Exception {
        JsonNode verified = mapper.readTree("""
                {"fact":"network.internet_reachability_verified","eq":true}
                """);
        assertFalse(engine.evaluate(verified, Map.of(
                "network.public_access_configured", mapper.valueToTree(true))));
    }

    @Test
    void rejectsExecutableOrUnboundedShapes() throws Exception {
        assertThrows(IllegalArgumentException.class,
                () -> engine.validate(mapper.readTree("{\"script\":\"Runtime.exec()\"}")));
        JsonNode nested = mapper.readTree("{\"not\":{\"not\":{\"not\":{\"not\":{\"not\":{\"not\":{\"not\":{\"not\":{\"fact\":\"x\",\"eq\":true}}}}}}}}}");
        assertThrows(IllegalArgumentException.class, () -> engine.validate(nested));
    }

    @Test
    void supportsParameterizedAllowlistsAndCollectionAndAgePredicates() throws Exception {
        JsonNode allowlist = mapper.readTree("{\"not\":{\"fact\":\"model\",\"in\":{\"parameter\":\"approved\"}}}");
        assertTrue(engine.evaluate(allowlist, Map.of("model", mapper.valueToTree("unapproved")), Map.of("approved", java.util.List.of("approved"))));
        assertFalse(engine.evaluate(allowlist, Map.of("model", mapper.valueToTree("approved")), Map.of("approved", java.util.List.of("approved"))));
        assertTrue(engine.evaluate(mapper.readTree("{\"fact\":\"tools\",\"non_empty\":true}"), Map.of("tools", mapper.readTree("[\"code\"]"))));
        assertTrue(engine.evaluate(mapper.readTree("{\"fact\":\"tools\",\"count_gte\":2}"), Map.of("tools", mapper.readTree("[\"code\",\"search\"]"))));
        assertTrue(engine.evaluate(mapper.readTree("{\"fact\":\"privateEndpointCount\",\"count_eq\":0}"), Map.of("privateEndpointCount", mapper.valueToTree(0))));
        assertTrue(engine.evaluate(mapper.readTree("{\"fact\":\"observed\",\"age_gt_seconds\":1}"), Map.of("observed", mapper.valueToTree(Instant.now().minusSeconds(5).toString()))));
    }
}
