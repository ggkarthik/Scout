package com.prototype.vulnwatch.aisecurity.policy;

import java.util.List;
import java.util.Locale;

/**
 * Pure decision of whether a policy applies to a given artifact once tenant scope
 * (mode + rule conditions) and any per-artifact override are known. No I/O, no Spring.
 */
public final class AiSecurityPolicyScopeMatcher {

    private AiSecurityPolicyScopeMatcher() {
    }

    public static final String MODE_ALL = "ALL";
    public static final String MODE_MATCH_RULES = "MATCH_RULES";
    public static final String MODE_CUSTOM_LIST = "CUSTOM_LIST";

    public static final String OVERRIDE_INCLUDED = "INCLUDED";
    public static final String OVERRIDE_EXCLUDED = "EXCLUDED";

    public record ScopeCondition(String field, String operator, String value) {
    }

    public record ScopeConfig(String mode, String conditionLogic, List<ScopeCondition> conditions) {
        public static ScopeConfig all() {
            return new ScopeConfig(MODE_ALL, "AND", List.of());
        }
    }

    public record ArtifactScopeFacts(
            String provider, String region, String accountId, String artifactType, String nativeKind, String name) {
    }

    public static boolean isInScope(ScopeConfig scope, ArtifactScopeFacts artifact, String override) {
        if (OVERRIDE_EXCLUDED.equals(override)) {
            return false;
        }
        if (OVERRIDE_INCLUDED.equals(override)) {
            return true;
        }
        String mode = scope == null ? MODE_ALL : scope.mode();
        return switch (mode == null ? MODE_ALL : mode) {
            case MODE_ALL -> true;
            case MODE_MATCH_RULES -> matchesRules(scope, artifact);
            case MODE_CUSTOM_LIST -> false;
            default -> true;
        };
    }

    public static boolean matchesRules(ScopeConfig scope, ArtifactScopeFacts artifact) {
        List<ScopeCondition> conditions = scope.conditions();
        if (conditions.isEmpty()) {
            return false;
        }
        boolean requireAll = !"OR".equalsIgnoreCase(scope.conditionLogic());
        for (ScopeCondition condition : conditions) {
            boolean matched = matches(condition, artifact);
            if (requireAll && !matched) {
                return false;
            }
            if (!requireAll && matched) {
                return true;
            }
        }
        return requireAll;
    }

    private static boolean matches(ScopeCondition condition, ArtifactScopeFacts artifact) {
        String actual = fieldValue(condition.field(), artifact);
        String expected = condition.value() == null ? "" : condition.value();
        if (actual == null) {
            actual = "";
        }
        return switch (condition.operator() == null ? "" : condition.operator().toUpperCase(Locale.ROOT)) {
            case "EQUALS" -> actual.equalsIgnoreCase(expected);
            case "NOT_EQUALS" -> !actual.equalsIgnoreCase(expected);
            case "CONTAINS" -> actual.toLowerCase(Locale.ROOT).contains(expected.toLowerCase(Locale.ROOT));
            case "NOT_CONTAINS" -> !actual.toLowerCase(Locale.ROOT).contains(expected.toLowerCase(Locale.ROOT));
            default -> false;
        };
    }

    private static String fieldValue(String field, ArtifactScopeFacts artifact) {
        return switch (field == null ? "" : field.toUpperCase(Locale.ROOT)) {
            case "PROVIDER" -> artifact.provider();
            case "REGION" -> artifact.region();
            case "ACCOUNT_ID" -> artifact.accountId();
            case "ARTIFACT_TYPE" -> artifact.artifactType();
            case "NATIVE_KIND" -> artifact.nativeKind();
            case "NAME" -> artifact.name();
            default -> null;
        };
    }
}
