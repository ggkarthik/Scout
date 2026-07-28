package com.prototype.vulnwatch.aisecurity.policy;

import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

@Component
public class AiSecurityResourceFamilyCatalogue {

    public static final String VERSION = "1.2";

    private static final Map<String, ScopeSemantics> FAMILIES = Map.ofEntries(
            Map.entry("BEDROCK_AGENTS", ScopeSemantics.REGIONAL),
            Map.entry("BEDROCK_KNOWLEDGE_BASES", ScopeSemantics.REGIONAL),
            Map.entry("BEDROCK_GUARDRAILS", ScopeSemantics.REGIONAL),
            Map.entry("BEDROCK_INVOCATION_LOGGING", ScopeSemantics.REGIONAL),
            Map.entry("LAMBDA_URLS", ScopeSemantics.REGIONAL),
            Map.entry("S3_EXPOSURE", ScopeSemantics.REGIONAL),
            Map.entry("IAM_GLOBAL", ScopeSemantics.ACCOUNT_GLOBAL),
            Map.entry("AZURE_AI_ACCOUNTS", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_FOUNDRY_PROJECTS", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_FOUNDRY_DEPLOYMENTS", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_FOUNDRY_AGENTS", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_FOUNDRY_AGENT_TOOLS", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_ML_WORKSPACES", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_ML_MODELS", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_ML_ENDPOINTS", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_ML_DEPLOYMENTS", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_ML_COMPUTE", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_ML_JOBS", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_ML_PIPELINES", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_SEARCH_SERVICES", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_SEARCH_INDEXES", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_SEARCH_SKILLSETS", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_SEARCH_INDEXERS", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_SEARCH_DATA_SOURCES", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_BOT_SERVICES", ScopeSemantics.ACCOUNT_GLOBAL),
            Map.entry("AZURE_BOT_CHANNELS", ScopeSemantics.ACCOUNT_GLOBAL),
            Map.entry("AZURE_BOT_IDENTITIES", ScopeSemantics.ACCOUNT_GLOBAL),
            Map.entry("AZURE_DIAGNOSTIC_SETTINGS", ScopeSemantics.REGIONAL),
            Map.entry("AZURE_RBAC_GLOBAL", ScopeSemantics.ACCOUNT_GLOBAL));

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
