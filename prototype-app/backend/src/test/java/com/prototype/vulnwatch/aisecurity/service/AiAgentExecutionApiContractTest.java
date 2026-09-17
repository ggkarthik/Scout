package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class AiAgentExecutionApiContractTest {
    @Test
    void executionResponseExposesCorrelationWithoutProviderExecutionIdentity() {
        Set<String> fields = Arrays.stream(AiAgentExecutionApiService.ExecutionResponse.class.getRecordComponents())
                .map(component -> component.getName())
                .collect(Collectors.toSet());

        assertTrue(fields.contains("agentVersionArtifactId"));
        assertTrue(fields.contains("correlationStatus"));
        assertTrue(fields.contains("correlationDiagnostic"));
        assertFalse(fields.contains("providerExecutionId"));
        assertFalse(fields.contains("providerExecutionDigest"));
    }
}
