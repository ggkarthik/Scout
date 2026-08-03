package com.prototype.vulnwatch.aisecurity.azure;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Optional;

/** Conservative, configuration-only interpretation of an Azure RAI policy body. */
final class AzureRaiPolicyAnalyzer {

    Analysis analyze(JsonNode properties) {
        JsonNode filters = properties == null ? null : properties.path("contentFilters");
        if (filters == null || !filters.isArray() || filters.isEmpty()) {
            return new Analysis(0, 0, Optional.empty());
        }
        int unsafe = 0;
        for (JsonNode filter : filters) {
            JsonNode enabled = filter.get("enabled");
            JsonNode blocking = filter.get("blocking");
            if (enabled == null || !enabled.isBoolean() || blocking == null || !blocking.isBoolean()) {
                return new Analysis(filters.size(), unsafe, Optional.empty());
            }
            if (!enabled.asBoolean() || !blocking.asBoolean()) {
                unsafe++;
            }
        }
        return new Analysis(filters.size(), unsafe, Optional.of(unsafe > 0));
    }

    record Analysis(int filterCount, int nonBlockingFilterCount, Optional<Boolean> nonBlockingFilterObserved) {}
}
