package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;

final class AiGridFactProducerSupport {
    private AiGridFactProducerSupport() {}

    static void copy(AiGridFactProducer.FactInput input, String attribute, String factKey,
                     List<AiGridFactProducer.ProducedFact> output) {
        JsonNode value = input.attributes().get(attribute);
        if (value != null && !value.isNull()) output.add(known(factKey, value, attribute));
    }

    static AiGridFactProducer.ProducedFact known(String factKey, JsonNode value, String attribute) {
        return new AiGridFactProducer.ProducedFact(factKey, value, "KNOWN", "PROVIDER_OBSERVED",
                "CONFIGURATION", attribute, 1.0, "DIRECT_PROVIDER_ATTRIBUTE", "1.0.0",
                List.of("attributes." + attribute), "1.0.0");
    }

    static AiGridFactProducer.ProducedFact unknown(String factKey, String attribute) {
        return new AiGridFactProducer.ProducedFact(factKey, null, "UNKNOWN", "PROVIDER_OBSERVED",
                "CONFIGURATION", attribute, null, "DIRECT_PROVIDER_ATTRIBUTE", "1.0.0",
                List.of("attributes." + attribute), "1.0.0");
    }

    static AiGridFactProducer.ProducedFact unknown(String factKey, JsonNode value, String attribute) {
        return new AiGridFactProducer.ProducedFact(factKey, value, "UNKNOWN", "PROVIDER_OBSERVED",
                "CONFIGURATION", attribute, null, "DIRECT_PROVIDER_ATTRIBUTE", "1.0.0",
                List.of("attributes." + attribute), "1.0.0");
    }

    static List<AiGridFactProducer.ProducedFact> facts() { return new ArrayList<>(); }

    static JsonNode value(ObjectMapper mapper, Object value) { return mapper.valueToTree(value); }
}
