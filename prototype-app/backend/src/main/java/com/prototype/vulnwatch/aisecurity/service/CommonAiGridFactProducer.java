package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.springframework.stereotype.Component;

/** Cross-provider facts derived from already persisted sanitized inventory evidence. */
@Component
public class CommonAiGridFactProducer implements AiGridFactProducer {
    private final ObjectMapper mapper;

    public CommonAiGridFactProducer(ObjectMapper mapper) { this.mapper = mapper; }

    @Override
    public List<ProducedFact> produce(FactInput input) {
        List<ProducedFact> facts = AiGridFactProducerSupport.facts();
        if (input.piiScanStatus() != null && !"NOT_APPLICABLE".equals(input.piiScanStatus())) {
            JsonNode sensitivity = mapper.valueToTree(sensitivityState(input.piiScanStatus()));
            facts.add("UNKNOWN".equals(input.piiScanStatus())
                    ? AiGridFactProducerSupport.unknown("data.source_sensitivity", sensitivity, "piiScanStatus")
                    : AiGridFactProducerSupport.known("data.source_sensitivity", sensitivity, "piiScanStatus"));
        }
        if ("SCANNED_PII_FOUND".equals(input.piiScanStatus())) {
            facts.add(AiGridFactProducerSupport.known("data.sensitivity_confirmed", mapper.valueToTree(true), "piiScanStatus"));
        }
        if (input.piiSource() != null && !input.piiSource().isBlank()) {
            facts.add(AiGridFactProducerSupport.known("data.sensitivity_source", mapper.valueToTree(input.piiSource()), "piiSource"));
        }
        JsonNode tags = input.attributes().get("tags");
        if (tags != null && tags.isObject() && !tags.isEmpty()) {
            facts.add(AiGridFactProducerSupport.known("owner.tag_candidate", tags, "tags"));
        }
        return List.copyOf(facts);
    }

    private String sensitivityState(String piiScanStatus) {
        return switch (piiScanStatus) {
            case "SCANNED_PII_FOUND" -> "SENSITIVE_CONFIRMED";
            case "SCANNED_CLEAN" -> "NO_SENSITIVE_SIGNAL";
            case "NOT_SCANNED" -> "NOT_SCANNED";
            default -> "UNKNOWN";
        };
    }
}
