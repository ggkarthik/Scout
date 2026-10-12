package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Map;
import java.util.Set;

/** Versioned, bounded control configuration comparison. No counts establish weaker protection. */
public final class AiGuardrailBaselineComparison {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private AiGuardrailBaselineComparison() { }

    public static String snapshot(String provider, String kind, Map<String, Object> attributes, boolean complete) {
        if (provider == null || kind == null || attributes == null || !Set.of("AWS", "AZURE").contains(provider)) return null;
        if ("AWS".equals(provider) && !Set.of("AWS_BEDROCK_AGENT", "AWS_BEDROCK_GUARDRAIL").contains(kind)) return null;
        if ("AZURE".equals(provider) && !Set.of("AZURE_FOUNDRY_DEPLOYMENTS", "AZURE_RAI_POLICIES").contains(kind)) return null;
        JsonNode source = MAPPER.valueToTree(attributes);
        ObjectNode result = MAPPER.createObjectNode();
        result.put("schemaVersion", 1).put("provider", provider).put("nativeKind", kind).put("complete", complete);
        String[] fields;
        if ("AWS_BEDROCK_AGENT".equals(kind) && source.has("guardrailAttached")) {
            fields = new String[]{"guardrailAttached", "guardrailId", "guardrailVersion"};
        } else if ("AWS_BEDROCK_GUARDRAIL".equals(kind) && source.has("contentFilterCount")) {
            fields = new String[]{"version", "contentFilters", "deniedTopics", "piiEntities", "contextualGroundingFilters"};
        } else if ("AZURE_FOUNDRY_DEPLOYMENTS".equals(kind) && source.has("raiPolicyName")) {
            fields = new String[]{"raiPolicyName", "modelVersion"};
        } else if (source.has("raiFilterEvidenceComplete")) {
            fields = new String[]{"raiFilterEvidenceComplete", "raiNonBlockingFilterObserved", "raiPolicyMode", "raiBasePolicyName"};
            // Retained aggregate RAI summaries do not bind individual controls to a policy version.
            result.put("complete", false);
        } else return null;
        for (String field : fields) if (source.has(field)) result.set(field, source.get(field));
        return result.toString();
    }

    static AiSecurityDigestBaselineService.Outcome compare(String approved, String current) {
        if (approved == null || current == null) return unknown();
        try {
            JsonNode before = MAPPER.readTree(approved), after = MAPPER.readTree(current);
            if (before == null || after == null) return unknown();
            if (!before.path("complete").asBoolean() || !after.path("complete").asBoolean()
                    || before.path("schemaVersion").asInt() != 1 || after.path("schemaVersion").asInt() != 1
                    || !before.path("provider").equals(after.path("provider"))
                    || !before.path("nativeKind").equals(after.path("nativeKind"))) return unknown();
            if (before.has("guardrailAttached") && after.has("guardrailAttached")) {
                if (!before.path("guardrailAttached").isBoolean() || !after.path("guardrailAttached").isBoolean()) return unknown();
                if (before.path("guardrailAttached").asBoolean()
                        && before.path("guardrailVersion").asText("").isBlank()) return unknown();
                if (before.path("guardrailAttached").asBoolean() && !after.path("guardrailAttached").asBoolean()) {
                    return AiSecurityDigestBaselineService.Outcome.CONTROL_WEAKENED;
                }
                if (after.path("guardrailAttached").asBoolean()
                        && after.path("guardrailVersion").asText("").isBlank()) return unknown();
            } else if (before.has("raiPolicyName")) {
                // A reference change can be reported for review, but cannot prove detachment or weakening.
                if (before.path("raiPolicyName").asText("").isBlank() || after.path("raiPolicyName").asText("").isBlank()
                        || before.path("modelVersion").asText("").isBlank()
                        || !before.path("modelVersion").equals(after.path("modelVersion"))) return unknown();
                return !before.path("raiPolicyName").equals(after.path("raiPolicyName"))
                        ? AiSecurityDigestBaselineService.Outcome.CONTROL_CONFIGURATION_CHANGED_REVIEW_REQUIRED : unknown();
            } else {
                if (before.path("version").asText("").isBlank()
                        || !before.path("version").equals(after.path("version"))) return unknown();
                if (!completeFilters(before.path("contentFilters")) || !completeFilters(after.path("contentFilters"))) return unknown();
                for (String field : java.util.List.of("deniedTopics", "piiEntities", "contextualGroundingFilters")) {
                    if (before.has(field) && !after.has(field)) return unknown();
                }
                boolean weakened = false;
                for (JsonNode filter : before.path("contentFilters")) {
                    JsonNode match = null;
                    for (JsonNode candidate : after.path("contentFilters")) {
                        if (filter.path("type").equals(candidate.path("type"))) { match = candidate; break; }
                    }
                    if (match == null) return unknown();
                    for (String direction : new String[]{"input", "output"}) {
                        String strength = direction + "Strength", enabled = direction + "Enabled";
                        int oldRank = rank(filter.path(strength).asText()), newRank = rank(match.path(strength).asText());
                        if (oldRank < 0 || newRank < 0 || !filter.path(enabled).isBoolean() || !match.path(enabled).isBoolean()) return unknown();
                        if (filter.path(enabled).asBoolean()
                                && (!match.path(enabled).asBoolean() || newRank < oldRank)) {
                            weakened = true;
                        }
                    }
                }
                if (weakened) return AiSecurityDigestBaselineService.Outcome.CONTROL_WEAKENED;
            }
            return before.equals(after) ? AiSecurityDigestBaselineService.Outcome.UNCHANGED
                    : AiSecurityDigestBaselineService.Outcome.CONTROL_CONFIGURATION_CHANGED_REVIEW_REQUIRED;
        } catch (java.io.IOException error) { return unknown(); }
    }
    private static boolean completeFilters(JsonNode filters) {
        if (!filters.isArray()) return false;
        Set<String> types = new java.util.HashSet<>();
        for (JsonNode filter : filters) {
            String type = filter.path("type").asText("");
            if (type.isBlank() || !types.add(type)) return false;
            for (String direction : java.util.List.of("input", "output")) {
                if (rank(filter.path(direction + "Strength").asText()) < 0
                        || !filter.path(direction + "Enabled").isBoolean()) return false;
            }
        }
        return true;
    }

    static java.util.List<String> changedFields(String approved, String current) {
        if (approved == null || current == null) return java.util.List.of();
        try {
            JsonNode before = MAPPER.readTree(approved), after = MAPPER.readTree(current);
            if (before == null || after == null) return java.util.List.of();
            return java.util.List.of("guardrailAttached", "guardrailId", "guardrailVersion", "version", "contentFilters",
                    "deniedTopics", "piiEntities", "contextualGroundingFilters", "raiPolicyName", "modelVersion", "raiPolicyMode", "raiBasePolicyName")
                    .stream().filter(field -> !before.path(field).equals(after.path(field))).toList();
        } catch (java.io.IOException error) { return java.util.List.of(); }
    }

    private static int rank(String value) {
        return switch (value) { case "NONE" -> 0; case "LOW" -> 1; case "MEDIUM" -> 2; case "HIGH" -> 3; default -> -1; };
    }
    private static AiSecurityDigestBaselineService.Outcome unknown() {
        return AiSecurityDigestBaselineService.Outcome.CONFIGURATION_UNKNOWN;
    }
}
