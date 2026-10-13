package com.prototype.vulnwatch.aisecurity.service;

import java.util.Set;

/** Inventory role only: does not change security types, eligibility or system membership. */
public final class AiAgentInventoryClassification {
    public static final Set<String> AGENT_KINDS = Set.of("AWS_BEDROCK_AGENT", "AWS_AGENTCORE_RUNTIME",
            "AZURE_FOUNDRY_AGENTS", "AZURE_CLASSIC_FOUNDRY_AGENTS", "MICROSOFT_COPILOT");
    public static final Set<String> VERSION_KINDS = Set.of("AWS_BEDROCK_AGENT_VERSION",
            "AWS_AGENTCORE_RUNTIME_VERSION", "AZURE_FOUNDRY_AGENT_VERSION", "AZURE_FOUNDRY_AGENT_VERSIONS",
            "AZURE_CLASSIC_FOUNDRY_AGENT_VERSIONS", "MICROSOFT_COPILOT_VERSION");
    private AiAgentInventoryClassification() { }
    public static boolean isAgent(String kind) { return AGENT_KINDS.contains(kind); }
    public static String agentSql(String alias) {
        return alias + ".native_kind in (" + AGENT_KINDS.stream().sorted()
                .map(kind -> "'" + kind + "'").collect(java.util.stream.Collectors.joining(",")) + ")";
    }
    public static String versionSql(String alias) {
        return "(" + alias + ".artifact_type = 'AI_AGENT_VERSION' or " + alias + ".native_kind in ("
                + VERSION_KINDS.stream().sorted().map(kind -> "'" + kind + "'")
                .collect(java.util.stream.Collectors.joining(",")) + "))";
    }
}
