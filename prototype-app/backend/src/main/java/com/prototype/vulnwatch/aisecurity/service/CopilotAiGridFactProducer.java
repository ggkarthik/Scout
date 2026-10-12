package com.prototype.vulnwatch.aisecurity.service;

import java.util.List;
import org.springframework.stereotype.Component;

/** Copilot Studio inventory observations; component kinds do not prove runtime capabilities. */
@Component
public class CopilotAiGridFactProducer implements AiGridFactProducer {
    @Override
    public List<ProducedFact> produce(FactInput input) {
        if (!"MICROSOFT_COPILOT".equalsIgnoreCase(input.provider())) return List.of();
        List<ProducedFact> facts = AiGridFactProducerSupport.facts();
        copy(input, "status", "copilot.status_observed", facts);
        copy(input, "version", "copilot.version_observed", facts);
        AiGridFactProducerSupport.copy(input, "sourceType", "copilot.source_type_observed", facts);
        copy(input, "componentType", "copilot.component_type_observed", facts);
        return List.copyOf(facts);
    }
    private void copy(FactInput input, String field, String fact, List<ProducedFact> facts) {
        if (input.attributes().hasNonNull(field) && (input.attributes().path(field).asText().isBlank()
                || "UNKNOWN".equalsIgnoreCase(input.attributes().path(field).asText()))) {
            facts.add(AiGridFactProducerSupport.unknown(fact, field));
        } else AiGridFactProducerSupport.copy(input, field, fact, facts);
    }
}
