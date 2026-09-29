package com.prototype.vulnwatch.aisecurity.policy;

import java.util.List;
import java.util.Map;

/** Typed projections of policy data owned by the governed database catalog. */
public final class AiSecurityPolicyDefinition {
    private AiSecurityPolicyDefinition() {}

    public record PolicyDefinition(
            String id,
            String version,
            String name,
            String severity,
            List<String> artifactTypes,
            List<String> requiredResourceFamilies,
            String description,
            String remediation,
            Map<String, String> controlMappings
    ) {}

    public record PolicyParameterSpec(
            String key,
            String label,
            String type,
            List<String> options,
            String defaultValue,
            String helpText
    ) {}
}
