package com.prototype.vulnwatch.aisecurity.service;

import java.util.Set;
import java.util.Locale;

/** Canonical AI Grid vocabulary shared by collectors, graph derivation and API validation. */
public final class AiSecurityTaxonomy {
    public static final String AI_AGENT_VERSION = "AI_AGENT_VERSION";
    public static final String AI_PROMPT = "AI_PROMPT";
    public static final String AI_TOOL = "AI_TOOL";
    public static final String AI_COMPONENT = "AI_COMPONENT";

    public static final String VERSION_OF = "VERSION_OF";
    public static final String ACTIVE_VERSION = "ACTIVE_VERSION";
    public static final String USES_PROMPT = "USES_PROMPT";
    public static final String HAS_COMPONENT = "HAS_COMPONENT";
    public static final String EXECUTED_AS = "EXECUTED_AS";
    public static final String PARTICIPATED_IN = "PARTICIPATED_IN";

    /** Explicit inventory categories. New categories must be added here deliberately. */
    public static final Set<String> EXPLICIT_ARTIFACT_TYPES = Set.of(
            "AI_AGENT", "AI_AGENT_VERSION", "AI_PROMPT", "AI_TOOL", "AI_COMPONENT", "AI_MODEL",
            "AI_GUARDRAIL", "MCP_GATEWAY", "MCP_TARGET", "MCP_SERVER", "KNOWLEDGE_BASE",
            "DATA_SOURCE", "DATA_STORE", "SEARCH_INDEX", "OTHER_AI_ARTIFACT");

    /** These edges describe lineage/definition, not system membership. */
    public static final Set<String> NON_MEMBERSHIP_RELATIONSHIPS = Set.of(
            VERSION_OF, ACTIVE_VERSION, USES_PROMPT, HAS_COMPONENT);

    private AiSecurityTaxonomy() { }

    public static boolean isExplicitArtifactType(String value) {
        return value != null && EXPLICIT_ARTIFACT_TYPES.contains(value.toUpperCase(Locale.ROOT));
    }
}
