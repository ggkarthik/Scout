package com.prototype.vulnwatch.util;

public final class PurlUtil {
    private PurlUtil() {
    }

    public record ParsedPurl(
            String ecosystem,
            String packageName,
            String namespace,
            String version,
            String full
    ) {
    }

    public static ParsedPurl parse(String purl) {
        if (purl == null || purl.isBlank() || !purl.startsWith("pkg:")) {
            return new ParsedPurl("unknown", "unknown", "", "0", purl == null ? "" : purl);
        }

        String withoutPrefix = purl.substring(4);
        int queryIndex = withoutPrefix.indexOf('?');
        if (queryIndex >= 0) {
            withoutPrefix = withoutPrefix.substring(0, queryIndex);
        }

        String[] parts = withoutPrefix.split("@", 2);
        String left = parts[0].trim();
        String version = parts.length > 1 ? parts[1] : "0";

        String[] pathParts = left.split("/");
        String ecosystem = pathParts.length > 0 ? pathParts[0].toLowerCase() : "unknown";
        String packageName = pathParts.length > 0 ? pathParts[pathParts.length - 1].toLowerCase() : "unknown";
        String namespace = "";
        if (pathParts.length > 2) {
            namespace = pathParts[pathParts.length - 2].toLowerCase();
        }

        return new ParsedPurl(ecosystem, packageName, namespace, version, purl);
    }
}
