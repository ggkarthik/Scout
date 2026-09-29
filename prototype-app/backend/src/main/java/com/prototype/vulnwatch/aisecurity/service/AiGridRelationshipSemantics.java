package com.prototype.vulnwatch.aisecurity.service;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Canonical relationship and native-kind semantics for the AI Grid.
 *
 * <p>Collectors, system derivation, R2 correlation and API validation must consume this
 * registry instead of maintaining local edge lists. Direction is significant: for example,
 * {@code VERSION_OF} is useful lineage but is not outward membership traversal.</p>
 */
public final class AiGridRelationshipSemantics {

    public enum SemanticClass {
        TRAVERSAL,
        SYSTEM_MEMBERSHIP,
        ROOT_DISQUALIFYING,
        VERSION_ROUTING,
        TOOL_IMPLEMENTATION,
        RUNTIME_OVERLAY,
        DATA_ACCESS,
        IDENTITY_ACCESS,
        MCP_CONSEQUENCE
    }

    public enum AttachmentContract {
        ROOT,
        REQUIRED,
        OPTIONAL
    }

    private static final Map<String, Set<SemanticClass>> RELATIONSHIPS = relationships();
    private static final Map<String, AttachmentContract> NATIVE_KIND_ATTACHMENTS = attachments();

    public static final Set<String> ALLOWED_RELATIONSHIPS = Set.copyOf(RELATIONSHIPS.keySet());
    public static final Set<String> SYSTEM_MEMBERSHIP_RELATIONSHIPS = byClass(SemanticClass.SYSTEM_MEMBERSHIP);
    public static final Set<String> ROOT_DISQUALIFYING_RELATIONSHIPS = byClass(SemanticClass.ROOT_DISQUALIFYING);
    public static final Set<String> VERSION_ROUTING_RELATIONSHIPS = byClass(SemanticClass.VERSION_ROUTING);
    public static final Set<String> TOOL_IMPLEMENTATION_RELATIONSHIPS = byClass(SemanticClass.TOOL_IMPLEMENTATION);
    public static final Set<String> RUNTIME_OVERLAY_RELATIONSHIPS = byClass(SemanticClass.RUNTIME_OVERLAY);
    public static final Set<String> DATA_ACCESS_RELATIONSHIPS = byClass(SemanticClass.DATA_ACCESS);
    public static final Set<String> IDENTITY_ACCESS_RELATIONSHIPS = byClass(SemanticClass.IDENTITY_ACCESS);
    public static final Set<String> MCP_CONSEQUENCE_RELATIONSHIPS = byClass(SemanticClass.MCP_CONSEQUENCE);

    private AiGridRelationshipSemantics() {
    }

    public static boolean has(String relationshipType, SemanticClass semanticClass) {
        if (relationshipType == null) return false;
        return RELATIONSHIPS.getOrDefault(relationshipType.toUpperCase(Locale.ROOT), Set.of())
                .contains(semanticClass);
    }

    public static AttachmentContract attachmentContract(String artifactType, String nativeKind) {
        return attachmentContract(artifactType, nativeKind, Map.of());
    }

    public static AttachmentContract attachmentContract(String artifactType, String nativeKind,
                                                         Map<String, ?> attributes) {
        String normalizedType = normalize(artifactType);
        String normalizedKind = normalize(nativeKind);
        if ("AI_AGENT".equals(normalizedType)) return AttachmentContract.ROOT;
        if ("AWS_AGENTCORE_RUNTIME".equals(normalizedKind)) {
            return Boolean.TRUE.equals(attributes == null ? null : attributes.get("agentCoreRootQualified"))
                    ? AttachmentContract.ROOT : AttachmentContract.REQUIRED;
        }
        AttachmentContract explicit = NATIVE_KIND_ATTACHMENTS.get(normalizedKind);
        if (explicit != null) return explicit;
        if (Set.of("AI_AGENT_VERSION", "AI_COMPONENT").contains(normalizedType)) {
            return AttachmentContract.REQUIRED;
        }
        return AttachmentContract.OPTIONAL;
    }

    public static boolean rootEligible(String artifactType, String nativeKind) {
        return attachmentContract(artifactType, nativeKind) == AttachmentContract.ROOT;
    }

    public static boolean rootEligible(String artifactType, String nativeKind, Map<String, ?> attributes) {
        return attachmentContract(artifactType, nativeKind, attributes) == AttachmentContract.ROOT;
    }

    private static Set<String> byClass(SemanticClass semanticClass) {
        return RELATIONSHIPS.entrySet().stream()
                .filter(entry -> entry.getValue().contains(semanticClass))
                .map(Map.Entry::getKey)
                .collect(Collectors.toUnmodifiableSet());
    }

    private static Map<String, Set<SemanticClass>> relationships() {
        Map<String, Set<SemanticClass>> values = new LinkedHashMap<>();
        membership(values, "HAS_COMPONENT", SemanticClass.VERSION_ROUTING);
        membership(values, "SERVES_VERSION", SemanticClass.VERSION_ROUTING);
        lineage(values, "VERSION_OF");
        lineage(values, "ACTIVE_VERSION", SemanticClass.VERSION_ROUTING);
        membership(values, "USES_MODEL");
        membership(values, "USES_PROMPT");
        membership(values, "USES_TOOL", SemanticClass.TOOL_IMPLEMENTATION);
        membership(values, "IMPLEMENTED_BY", SemanticClass.TOOL_IMPLEMENTATION);
        membership(values, "USES_GUARDRAIL");
        membership(values, "USES_KNOWLEDGE_BASE", SemanticClass.DATA_ACCESS);
        membership(values, "USES_DATA_SOURCE", SemanticClass.DATA_ACCESS);
        membership(values, "BACKED_BY_DATA_STORE", SemanticClass.DATA_ACCESS);
        membership(values, "USES_SEARCH_INDEX", SemanticClass.DATA_ACCESS);
        membership(values, "READS_FROM_S3", SemanticClass.DATA_ACCESS);
        membership(values, "READS_FROM_STORAGE_ACCOUNT", SemanticClass.DATA_ACCESS);
        membership(values, "ASSUMES_ROLE", SemanticClass.IDENTITY_ACCESS);
        membership(values, "USES_EXECUTION_ROLE", SemanticClass.IDENTITY_ACCESS);
        membership(values, "USES_MANAGED_IDENTITY", SemanticClass.IDENTITY_ACCESS);
        membership(values, "HAS_ROLE_ASSIGNMENT", SemanticClass.IDENTITY_ACCESS);
        membership(values, "USES_KEY_VAULT_KEY", SemanticClass.IDENTITY_ACCESS);
        membership(values, "EXPOSES_MCP", SemanticClass.MCP_CONSEQUENCE);
        membership(values, "CONNECTS_TO_MCP", SemanticClass.MCP_CONSEQUENCE);
        membership(values, "CONTAINS_MCP_TARGET", SemanticClass.MCP_CONSEQUENCE);
        membership(values, "ROUTES_TO", SemanticClass.MCP_CONSEQUENCE);
        membership(values, "SUPERVISES_AGENT");
        membership(values, "CONTAINS_PROJECT");
        membership(values, "DEPLOYS_MODEL");
        membership(values, "CONTAINS_RESOURCE");
        membership(values, "HAS_DEPLOYMENT", SemanticClass.VERSION_ROUTING);
        membership(values, "RUNS_PIPELINE");
        membership(values, "HAS_CHANNEL");
        membership(values, "USES_NETWORK");
        membership(values, "USES_ENDPOINT_CONFIGURATION");
        membership(values, "PRODUCES_MODEL");
        membership(values, "USES_DATA_CONNECTION", SemanticClass.DATA_ACCESS);
        membership(values, "HAS_PRIVATE_ENDPOINT");
        membership(values, "LOGS_TO");
        membership(values, "CONTAINS");

        lineage(values, "EXECUTED_AS", SemanticClass.RUNTIME_OVERLAY);
        lineage(values, "PARTICIPATED_IN", SemanticClass.RUNTIME_OVERLAY);
        return Map.copyOf(values);
    }

    private static void membership(Map<String, Set<SemanticClass>> values, String relationship,
                                   SemanticClass... additional) {
        EnumSet<SemanticClass> classes = EnumSet.of(
                SemanticClass.TRAVERSAL,
                SemanticClass.SYSTEM_MEMBERSHIP,
                SemanticClass.ROOT_DISQUALIFYING);
        for (SemanticClass semanticClass : additional) classes.add(semanticClass);
        values.put(relationship, Set.copyOf(classes));
    }

    private static void lineage(Map<String, Set<SemanticClass>> values, String relationship,
                                SemanticClass... additional) {
        EnumSet<SemanticClass> classes = EnumSet.of(SemanticClass.TRAVERSAL);
        for (SemanticClass semanticClass : additional) classes.add(semanticClass);
        values.put(relationship, Set.copyOf(classes));
    }

    private static Map<String, AttachmentContract> attachments() {
        Map<String, AttachmentContract> values = new LinkedHashMap<>();

        // AgentCore runtimes become roots only when their observation carries the evidence-qualified
        // root marker. Without it they remain required inventory and surface an association gap.
        values.put("AWS_AGENTCORE_RUNTIME", AttachmentContract.REQUIRED);
        values.put("AWS_AGENTCORE_RUNTIME_VERSION", AttachmentContract.REQUIRED);
        values.put("AWS_AGENTCORE_RUNTIME_ENDPOINT", AttachmentContract.REQUIRED);
        values.put("AWS_AGENTCORE_WORKLOAD_IDENTITY", AttachmentContract.REQUIRED);

        for (String required : Set.of(
                "AWS_BEDROCK_AGENT_VERSION", "AWS_BEDROCK_AGENT_ALIAS", "AWS_BEDROCK_ACTION_GROUP",
                "AWS_IAM_ROLE", "AWS_LAMBDA_FUNCTION",
                "AZURE_FOUNDRY_AGENT_VERSION", "AZURE_FOUNDRY_AGENT_VERSIONS",
                "AZURE_CLASSIC_FOUNDRY_AGENT_VERSIONS", "AZURE_FOUNDRY_AGENT_TOOLS",
                "AZURE_CLASSIC_FOUNDRY_AGENT_TOOLS",
                "MICROSOFT_COPILOT_VERSION", "MICROSOFT_COPILOT_COMPONENT")) {
            values.put(required, AttachmentContract.REQUIRED);
        }
        return Map.copyOf(values);
    }

    public static Set<String> registeredAttachmentNativeKinds() {
        return NATIVE_KIND_ATTACHMENTS.keySet();
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }
}
