package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;

/** Provider-owned normalization contract for immutable AI Grid snapshot facts. */
public interface AiGridFactProducer {
    List<ProducedFact> produce(FactInput input);

    record FactInput(String provider, String resourceFamily, String artifactType, String nativeKind,
                     JsonNode attributes, String piiScanStatus, String piiSource, Instant observedAt) {}

    record ProducedFact(String factKey, JsonNode value, String state, String provenance,
                        String evidenceClass, String sourceAttribute, Double confidence,
                        String confidenceMethod, String confidenceMethodVersion,
                        List<String> derivationInputs, String schemaVersion) {}
}
