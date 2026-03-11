package com.prototype.vulnwatch.util;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

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
            return new ParsedPurl("unknown", "unknown", "", null, purl == null ? "" : purl);
        }

        String withoutPrefix = purl.substring(4);

        // BLG-001: Strip qualifiers (?...) and subpath (#...) per PURL spec.
        // The spec structure is: pkg:type/namespace/name@version?qualifiers#subpath
        // Both delimiters are optional but must be stripped before parsing name and version.
        // Previously only '?' was stripped, leaving '#subpath' appended to the version string.
        int queryIndex = withoutPrefix.indexOf('?');
        int hashIndex = withoutPrefix.indexOf('#');
        int stripIndex = -1;
        if (queryIndex >= 0 && hashIndex >= 0) {
            stripIndex = Math.min(queryIndex, hashIndex);
        } else if (queryIndex >= 0) {
            stripIndex = queryIndex;
        } else if (hashIndex >= 0) {
            stripIndex = hashIndex;
        }
        if (stripIndex >= 0) {
            withoutPrefix = withoutPrefix.substring(0, stripIndex);
        }

        String[] parts = withoutPrefix.split("@", 2);
        String left = parts[0].trim();
        // BLG-001: missing version is null, not "0". A default of "0" causes false version
        // matches when components without a version are compared against vulnerability ranges.
        String version = (parts.length > 1 && !parts[1].isBlank()) ? parts[1] : null;

        String[] pathParts = left.split("/");
        String ecosystem = pathParts.length > 0 ? pathParts[0].toLowerCase() : "unknown";
        // BLG-001: percent-decode name and namespace so that encoded characters such as
        // %40 (@ sign in scoped npm packages) are resolved to their canonical forms.
        String packageName = pathParts.length > 0
                ? percentDecode(pathParts[pathParts.length - 1].toLowerCase())
                : "unknown";
        String namespace = "";
        if (pathParts.length > 2) {
            namespace = percentDecode(pathParts[pathParts.length - 2].toLowerCase());
        }

        return new ParsedPurl(ecosystem, packageName, namespace, version, purl);
    }

    private static String percentDecode(String value) {
        if (value == null || !value.contains("%")) {
            return value;
        }
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            return value;
        }
    }
}
