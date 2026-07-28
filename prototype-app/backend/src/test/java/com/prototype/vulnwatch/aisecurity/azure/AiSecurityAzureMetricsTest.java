package com.prototype.vulnwatch.aisecurity.azure;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class AiSecurityAzureMetricsTest {

    @Test
    void clampsMetricLabelsToBoundedCatalogues() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        AiSecurityAzureMetrics metrics = new AiSecurityAzureMetrics(registry);

        metrics.recordAdmission("tenant-123");
        metrics.recordRun("completed");
        metrics.recordScope("attacker-controlled-family", "COMPLETE");
        metrics.recordCredentialEvent("created");
        metrics.recordRunDuration(Duration.ofSeconds(2));

        assertEquals(1.0, registry.counter("ai.security.azure.admission", "outcome", "unknown").count());
        assertEquals(1.0, registry.counter("ai.security.azure.discovery.runs", "outcome", "completed").count());
        assertEquals(1.0, registry.counter(
                "ai.security.azure.scopes", "family", "unknown", "status", "complete").count());
        assertEquals(1.0, registry.counter("ai.security.azure.credentials", "event", "created").count());
        assertEquals(1, registry.timer("ai.security.azure.discovery.duration").count());
    }
}
