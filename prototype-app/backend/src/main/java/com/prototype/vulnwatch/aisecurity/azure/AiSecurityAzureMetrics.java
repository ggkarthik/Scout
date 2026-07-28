package com.prototype.vulnwatch.aisecurity.azure;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import java.time.Duration;
import java.util.Locale;
import java.util.Set;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

@Component
public class AiSecurityAzureMetrics {

    private static final Set<String> ADMISSION_OUTCOMES = Set.of(
            "granted", "global_timeout", "subscription_timeout", "interrupted", "invalid");
    private static final Set<String> RUN_OUTCOMES = Set.of("completed", "failed", "disabled");
    private static final Set<String> CREDENTIAL_EVENTS = Set.of(
            "created", "test_succeeded", "test_failed", "rotated", "rotation_failed",
            "revoked", "expired", "expiry_warning");
    private static final Set<String> SCOPE_STATUSES = Set.of("complete", "partial", "failed", "unsupported");

    private final MeterRegistry registry;

    public AiSecurityAzureMetrics(ObjectProvider<MeterRegistry> registryProvider) {
        this.registry = registryProvider.getIfAvailable();
    }

    AiSecurityAzureMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    public void recordAdmission(String outcome) {
        increment("ai.security.azure.admission", "outcome", bounded(outcome, ADMISSION_OUTCOMES));
    }

    public void recordRun(String outcome) {
        increment("ai.security.azure.discovery.runs", "outcome", bounded(outcome, RUN_OUTCOMES));
    }

    public void recordRunDuration(Duration duration) {
        if (registry != null && duration != null && !duration.isNegative()) {
            registry.timer("ai.security.azure.discovery.duration").record(duration);
        }
    }

    public void recordScope(String family, String status) {
        if (registry == null) {
            return;
        }
        registry.counter(
                "ai.security.azure.scopes",
                Tags.of(
                        "family", familyTag(family),
                        "status", bounded(status, SCOPE_STATUSES)))
                .increment();
    }

    public void recordCredentialEvent(String event) {
        increment("ai.security.azure.credentials", "event", bounded(event, CREDENTIAL_EVENTS));
    }

    private void increment(String name, String tag, String value) {
        if (registry != null) {
            registry.counter(name, tag, value).increment();
        }
    }

    private String familyTag(String family) {
        if (family == null) {
            return "unknown";
        }
        String normalized = family.trim().toUpperCase(Locale.ROOT);
        return AiSecurityAzureConnectorService.RESOURCE_FAMILIES.contains(normalized)
                ? normalized.toLowerCase(Locale.ROOT)
                : "unknown";
    }

    private String bounded(String value, Set<String> allowed) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        return allowed.contains(normalized) ? normalized : "unknown";
    }
}
