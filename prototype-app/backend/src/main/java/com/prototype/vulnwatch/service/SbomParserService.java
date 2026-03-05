package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.dto.ParsedComponent;
import com.prototype.vulnwatch.util.CpeUtil;
import com.prototype.vulnwatch.util.PurlUtil;
import java.io.IOException;
import java.util.Locale;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Service;

@Service
public class SbomParserService {

    private final ObjectMapper objectMapper;

    public SbomParserService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public SbomFormat detectFormat(byte[] content) throws IOException {
        JsonNode root = normalizeRoot(objectMapper.readTree(content));
        if (root.has("bomFormat") || root.has("components")) {
            return SbomFormat.CYCLONEDX;
        }
        if (root.has("spdxVersion") || root.has("packages")) {
            return SbomFormat.SPDX;
        }
        return SbomFormat.UNKNOWN;
    }

    public List<ParsedComponent> parse(byte[] content) throws IOException {
        JsonNode root = normalizeRoot(objectMapper.readTree(content));
        if (root.has("components")) {
            return parseCycloneDx(root);
        }
        if (root.has("packages")) {
            return parseSpdx(root);
        }
        return List.of();
    }

    private List<ParsedComponent> parseCycloneDx(JsonNode root) {
        List<ParsedComponent> components = new ArrayList<>();
        for (JsonNode component : root.path("components")) {
            String purl = component.path("purl").asText("");
            String name = component.path("name").asText("unknown");
            String version = component.path("version").asText("0");
            PurlUtil.ParsedPurl parsed = PurlUtil.parse(purl);
            String ecosystem = parsed.ecosystem();
            String packageName = parsed.packageName();
            String resolvedVersion = parsed.version().equals("0") ? version : parsed.version();
            if (packageName.equals("unknown")) {
                packageName = name.toLowerCase();
            }
            if (ecosystem.equals("unknown")) {
                ecosystem = "generic";
            }
            String resolvedPurl = purl.isBlank()
                    ? "pkg:" + ecosystem + "/" + packageName + "@" + resolvedVersion
                    : purl;
            String digest = firstNonBlank(
                    extractDigestFromCycloneDxComponent(component),
                    extractDigestFromPurl(resolvedPurl),
                    extractDigestFromBomRef(component.path("bom-ref").asText(""))
            );
            List<String> cpes = augmentCpesWithPurlDerivation(
                    extractCpesFromCycloneDxComponent(component),
                    resolvedPurl,
                    packageName
            );
            components.add(new ParsedComponent(
                    ecosystem,
                    packageName,
                    resolvedVersion,
                    resolvedPurl,
                    digest,
                    cpes
            ));
        }
        return components;
    }

    private List<ParsedComponent> parseSpdx(JsonNode root) {
        List<ParsedComponent> components = new ArrayList<>();
        for (JsonNode pkg : root.path("packages")) {
            String name = pkg.path("name").asText("unknown").toLowerCase();
            String version = pkg.path("versionInfo").asText("0");
            String purl = extractPurlFromSpdx(pkg);
            PurlUtil.ParsedPurl parsed = PurlUtil.parse(purl);
            String ecosystem = parsed.ecosystem();
            String packageName = parsed.packageName();
            if (packageName.equals("unknown")) {
                packageName = name;
            }
            if (ecosystem.equals("unknown")) {
                ecosystem = "generic";
            }
            String resolvedPurl = purl.isBlank()
                    ? "pkg:" + ecosystem + "/" + packageName + "@" + version
                    : purl;
            String digest = firstNonBlank(
                    extractDigestFromSpdxPackage(pkg),
                    extractDigestFromPurl(resolvedPurl)
            );
            List<String> cpes = augmentCpesWithPurlDerivation(
                    extractCpesFromSpdxPackage(pkg),
                    resolvedPurl,
                    packageName
            );
            components.add(new ParsedComponent(
                    ecosystem,
                    packageName,
                    version,
                    resolvedPurl,
                    digest,
                    cpes
            ));
        }
        return components;
    }

    private List<String> augmentCpesWithPurlDerivation(List<String> explicitCpes, String purl, String fallbackPackageName) {
        Set<String> cpes = new LinkedHashSet<>();
        if (explicitCpes != null) {
            cpes.addAll(explicitCpes);
        }
        maybeAddCpe(cpes, deriveCpeFromPurl(purl, fallbackPackageName));
        return new ArrayList<>(cpes);
    }

    private String extractPurlFromSpdx(JsonNode pkg) {
        for (JsonNode ref : pkg.path("externalRefs")) {
            String type = ref.path("referenceType").asText("");
            if ("purl".equalsIgnoreCase(type) || "PACKAGE-MANAGER".equalsIgnoreCase(type)) {
                String locator = ref.path("referenceLocator").asText("");
                if (locator.startsWith("pkg:")) {
                    return locator;
                }
            }
        }
        return "";
    }

    private List<String> extractCpesFromCycloneDxComponent(JsonNode component) {
        Set<String> cpes = new LinkedHashSet<>();
        maybeAddCpe(cpes, component.path("cpe").asText(""));
        maybeAddCpe(cpes, component.path("bom-ref").asText(""));

        JsonNode properties = component.path("properties");
        if (properties.isArray()) {
            for (JsonNode property : properties) {
                String name = property.path("name").asText("");
                if (name == null || name.isBlank()) {
                    continue;
                }
                String normalizedName = name.trim().toLowerCase(Locale.ROOT);
                if (!normalizedName.contains("cpe")) {
                    continue;
                }
                maybeAddCpe(cpes, property.path("value").asText(""));
            }
        }
        return new ArrayList<>(cpes);
    }

    private List<String> extractCpesFromSpdxPackage(JsonNode pkg) {
        Set<String> cpes = new LinkedHashSet<>();
        JsonNode refs = pkg.path("externalRefs");
        if (!refs.isArray()) {
            return List.of();
        }
        for (JsonNode ref : refs) {
            String type = ref.path("referenceType").asText("");
            if (type == null || type.isBlank()) {
                continue;
            }
            String normalizedType = type.trim().toLowerCase(Locale.ROOT);
            if (!normalizedType.contains("cpe")) {
                continue;
            }
            maybeAddCpe(cpes, ref.path("referenceLocator").asText(""));
        }
        return new ArrayList<>(cpes);
    }

    private void maybeAddCpe(Set<String> cpes, String rawCpe) {
        String normalized = CpeUtil.normalizeCpe23(rawCpe);
        if (normalized != null) {
            cpes.add(normalized);
        }
    }

    private String deriveCpeFromPurl(String purl, String fallbackPackageName) {
        PurlUtil.ParsedPurl parsed = PurlUtil.parse(purl);
        String ecosystem = parsed.ecosystem() == null ? "" : parsed.ecosystem().trim().toLowerCase(Locale.ROOT);
        if (ecosystem.isBlank() || "unknown".equals(ecosystem)) {
            return null;
        }

        String product = sanitizeCpeToken(parsed.packageName());
        if (!hasText(product) || "unknown".equals(product)) {
            product = sanitizeCpeToken(fallbackPackageName);
        }
        if (!hasText(product) || "unknown".equals(product)) {
            return null;
        }

        String vendor = sanitizeCpeToken(parsed.namespace());
        if (!hasText(vendor) || "unknown".equals(vendor)) {
            vendor = product;
        }

        return "cpe:2.3:a:" + vendor + ":" + product + ":*:*:*:*:*:*:*:*";
    }

    private String sanitizeCpeToken(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim()
                .toLowerCase(Locale.ROOT)
                .replace(" ", "_")
                .replaceAll("[^a-z0-9._-]", "_");
        return normalized.isBlank() ? null : normalized;
    }

    private JsonNode normalizeRoot(JsonNode root) {
        JsonNode nestedSbom = root.path("sbom");
        if (nestedSbom.isObject()) {
            return nestedSbom;
        }
        return root;
    }

    private String extractDigestFromCycloneDxComponent(JsonNode component) {
        JsonNode hashes = component.path("hashes");
        if (!hashes.isArray()) {
            return null;
        }
        for (JsonNode hash : hashes) {
            String algorithm = hash.path("alg").asText("");
            String content = hash.path("content").asText("");
            String normalized = normalizeDigest(algorithm, content);
            if (normalized != null) {
                return normalized;
            }
        }
        return null;
    }

    private String extractDigestFromSpdxPackage(JsonNode pkg) {
        JsonNode checksums = pkg.path("checksums");
        if (!checksums.isArray()) {
            return null;
        }
        for (JsonNode checksum : checksums) {
            String algorithm = checksum.path("algorithm").asText("");
            String value = checksum.path("checksumValue").asText("");
            String normalized = normalizeDigest(algorithm, value);
            if (normalized != null) {
                return normalized;
            }
        }
        return null;
    }

    private String extractDigestFromPurl(String purl) {
        if (purl == null || purl.isBlank()) {
            return null;
        }
        int queryStart = purl.indexOf('?');
        if (queryStart < 0 || queryStart + 1 >= purl.length()) {
            return null;
        }
        String query = purl.substring(queryStart + 1);
        int fragment = query.indexOf('#');
        if (fragment >= 0) {
            query = query.substring(0, fragment);
        }
        for (String token : query.split("&")) {
            int equals = token.indexOf('=');
            if (equals <= 0 || equals + 1 >= token.length()) {
                continue;
            }
            String key = token.substring(0, equals).toLowerCase(Locale.ROOT);
            String value = token.substring(equals + 1);
            if ("checksum".equals(key) || "digest".equals(key)) {
                String normalized = normalizeDigestToken(value);
                if (normalized != null) {
                    return normalized;
                }
            }
        }
        return null;
    }

    private String extractDigestFromBomRef(String bomRef) {
        if (bomRef == null || bomRef.isBlank()) {
            return null;
        }
        String candidate = bomRef.trim().toLowerCase(Locale.ROOT);
        int idx = candidate.indexOf("sha256:");
        if (idx < 0) {
            return null;
        }
        return normalizeDigestToken(candidate.substring(idx));
    }

    private String normalizeDigest(String algorithm, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String alg = algorithm == null ? "" : algorithm.trim().toLowerCase(Locale.ROOT).replace("-", "");
        String digestValue = value.trim().toLowerCase(Locale.ROOT);
        if (digestValue.contains(":")) {
            return normalizeDigestToken(digestValue);
        }
        if ("sha256".equals(alg)) {
            return normalizeDigestToken("sha256:" + digestValue);
        }
        return null;
    }

    private String normalizeDigestToken(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        String normalized = token.trim().toLowerCase(Locale.ROOT);
        if (!normalized.startsWith("sha256:")) {
            if (normalized.startsWith("sha-256:")) {
                normalized = "sha256:" + normalized.substring("sha-256:".length());
            } else {
                return null;
            }
        }
        String digestValue = normalized.substring("sha256:".length()).trim();
        if (digestValue.length() != 64) {
            return null;
        }
        for (int i = 0; i < digestValue.length(); i++) {
            char ch = digestValue.charAt(i);
            boolean hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
            if (!hex) {
                return null;
            }
        }
        return "sha256:" + digestValue;
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
