package com.prototype.vulnwatch.aisecurity.azure;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class AzureRaiPolicyAnalyzerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AzureRaiPolicyAnalyzer analyzer = new AzureRaiPolicyAnalyzer();

    @Test
    void decidesSafeOnlyWhenEveryReturnedFilterHasExplicitBooleans() throws Exception {
        var analysis = analyzer.analyze(objectMapper.readTree("""
                {"contentFilters":[
                  {"name":"Hate","source":"Prompt","enabled":true,"blocking":true},
                  {"name":"Hate","source":"Completion","enabled":true,"blocking":true}
                ]}
                """));

        assertEquals(2, analysis.filterCount());
        assertEquals(Boolean.FALSE, analysis.nonBlockingFilterObserved().orElseThrow());
    }

    @Test
    void detectsExplicitDisabledAndNonBlockingEntries() throws Exception {
        var analysis = analyzer.analyze(objectMapper.readTree("""
                {"contentFilters":[
                  {"name":"Jailbreak","source":"Prompt","enabled":false,"blocking":true},
                  {"name":"Violence","source":"Completion","enabled":true,"blocking":false}
                ]}
                """));

        assertEquals(2, analysis.nonBlockingFilterCount());
        assertEquals(Boolean.TRUE, analysis.nonBlockingFilterObserved().orElseThrow());
    }

    @Test
    void refusesToDecideForEmptyOrStructurallyIncompleteEvidence() throws Exception {
        assertTrue(analyzer.analyze(objectMapper.readTree("{}"))
                .nonBlockingFilterObserved().isEmpty());
        assertTrue(analyzer.analyze(objectMapper.readTree("""
                {"contentFilters":[{"name":"Hate","enabled":true}]}
                """))
                .nonBlockingFilterObserved().isEmpty());
    }
}
