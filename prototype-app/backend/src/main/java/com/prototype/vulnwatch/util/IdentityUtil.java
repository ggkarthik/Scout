package com.prototype.vulnwatch.util;

import java.util.Locale;

public final class IdentityUtil {

    private IdentityUtil() {
    }

    public static String normalize(String value) {
        if (value == null) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    public static String normalizePurl(String purl) {
        if (purl == null || purl.isBlank()) {
            return "";
        }
        return purl.trim().toLowerCase(Locale.ROOT);
    }

    public static String normalizeRepoUrl(String repoUrl) {
        String normalized = normalize(repoUrl);
        if (normalized.endsWith(".git")) {
            normalized = normalized.substring(0, normalized.length() - 4);
        }
        if (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    public static String coordKey(String ecosystem, String namespace, String packageName) {
        return normalize(ecosystem) + ":" + normalize(namespace) + ":" + normalize(packageName);
    }

    public static String coordKey(String ecosystem, String packageName) {
        return coordKey(ecosystem, "", packageName);
    }

    public static String canonicalIdentityKey(String ecosystem, String namespace, String packageName) {
        return "pkg:" + coordKey(ecosystem, namespace, packageName);
    }
}
