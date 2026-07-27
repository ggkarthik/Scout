package com.prototype.vulnwatch.aisecurity.policy;

import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

@Component
public class AiSecurityResourceFamilyCatalogue {

    public static final String VERSION = "1.0";

    private static final Map<String, ScopeSemantics> FAMILIES = Map.of(
            "BEDROCK_AGENTS", ScopeSemantics.REGIONAL,
            "BEDROCK_KNOWLEDGE_BASES", ScopeSemantics.REGIONAL,
            "BEDROCK_GUARDRAILS", ScopeSemantics.REGIONAL,
            "BEDROCK_INVOCATION_LOGGING", ScopeSemantics.REGIONAL,
            "LAMBDA_URLS", ScopeSemantics.REGIONAL,
            "S3_EXPOSURE", ScopeSemantics.REGIONAL,
            "IAM_GLOBAL", ScopeSemantics.ACCOUNT_GLOBAL
    );

    public Optional<String> requiredRegion(String resourceFamily, String artifactRegion) {
        ScopeSemantics semantics = FAMILIES.get(resourceFamily);
        if (semantics == null) {
            return Optional.empty();
        }
        return Optional.of(semantics == ScopeSemantics.ACCOUNT_GLOBAL ? "GLOBAL" : artifactRegion);
    }

    public boolean isKnown(String resourceFamily) {
        return FAMILIES.containsKey(resourceFamily);
    }

    enum ScopeSemantics {
        ACCOUNT_GLOBAL,
        REGIONAL
    }
}
