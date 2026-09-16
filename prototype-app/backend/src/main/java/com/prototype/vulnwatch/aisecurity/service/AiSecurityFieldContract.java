package com.prototype.vulnwatch.aisecurity.service;

import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Independent storage/response/filter policy for metadata fields. */
public final class AiSecurityFieldContract {
    public enum Tier { STORAGE_ALLOWED, RESPONSE_ALLOWED, FILTER_ALLOWED }

    private static final Set<String> STORAGE_ONLY = Set.of(
            "promptDigest", "toolDefinitionDigest", "digestAlgorithm", "digestKeyVersion");
    private static final Set<String> FILTERABLE = Set.of(
            "sourceType", "sensitivity", "publicContentAccess", "configuredAuthType", "inboundAuthType",
            "outboundAuthType", "endpointExposure", "status", "environment", "provider", "artifactType",
            "nativeKind", "accountId", "region");
    private static final Set<String> NEVER_ALLOWED = Set.of(
            "prompt", "promptBody", "messages", "transcript", "toolArguments", "toolResults", "schema",
            "requestBody", "responseBody", "authorization", "headers", "token", "secret", "password");

    private AiSecurityFieldContract() { }

    public static boolean allows(String field, Tier tier) {
        if (field == null) return false;
        String normalized = field.toLowerCase(Locale.ROOT);
        if (NEVER_ALLOWED.stream().anyMatch(normalized::contains)) return false;
        if (STORAGE_ONLY.contains(field)) return tier == Tier.STORAGE_ALLOWED;
        if (tier == Tier.FILTER_ALLOWED) return FILTERABLE.contains(field);
        return true;
    }

    public static Map<String, Object> responseSafe(Map<String, Object> attributes) {
        return filter(attributes, Tier.RESPONSE_ALLOWED);
    }

    public static Map<String, Object> storageSafe(Map<String, Object> attributes) {
        return filter(attributes, Tier.STORAGE_ALLOWED);
    }

    private static Map<String, Object> filter(Map<String, Object> attributes, Tier tier) {
        Map<String, Object> clean = new LinkedHashMap<>();
        if (attributes == null) return clean;
        attributes.forEach((key, value) -> {
            if (!allows(key, tier)) return;
            clean.put(key, filterValue(value, tier));
        });
        return clean;
    }

    private static Object filterValue(Object value, Tier tier) {
        if (value instanceof Map<?, ?> nested) {
            Map<String, Object> child = new LinkedHashMap<>();
            nested.forEach((nestedKey, nestedValue) -> {
                String key = String.valueOf(nestedKey);
                if (allows(key, tier)) child.put(key, filterValue(nestedValue, tier));
            });
            return child;
        }
        if (value instanceof List<?> list) {
            List<Object> child = new ArrayList<>();
            list.forEach(item -> child.add(filterValue(item, tier)));
            return child;
        }
        return value;
    }
}
