package com.prototype.vulnwatch.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class CpeUtil {

    private static final int ATTR_START_INDEX = 2;
    private static final int ATTR_COUNT = 11;

    private CpeUtil() {
    }

    public record ParsedCpe(
            String part,
            String vendor,
            String product,
            String version,
            String update,
            String edition,
            String language,
            String swEdition,
            String targetSw,
            String targetHw,
            String other
    ) {
    }

    public static ParsedCpe parse(String cpe) {
        if (cpe == null || cpe.isBlank()) {
            return empty();
        }

        String normalized = normalizeCpe23(cpe);
        if (normalized == null) {
            return empty();
        }

        String[] parts = normalized.split(":", -1);
        if (parts.length < ATTR_START_INDEX + ATTR_COUNT) {
            return empty();
        }

        // cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<lang>:<swEdition>:<targetSw>:<targetHw>:<other>
        String part = normalizeParsedToken(parts[2]);
        String vendor = normalizeParsedToken(parts[3]);
        String product = normalizeParsedToken(parts[4]);
        String version = normalizeParsedToken(parts[5]);
        String update = normalizeParsedToken(parts[6]);
        String edition = normalizeParsedToken(parts[7]);
        String language = normalizeParsedToken(parts[8]);
        String swEdition = normalizeParsedToken(parts[9]);
        String targetSw = normalizeParsedToken(parts[10]);
        String targetHw = normalizeParsedToken(parts[11]);
        String other = normalizeParsedToken(parts[12]);
        return new ParsedCpe(
                part,
                vendor,
                product,
                version,
                update,
                edition,
                language,
                swEdition,
                targetSw,
                targetHw,
                other);
    }

    public static String normalizeCpe23(String rawCpe) {
        if (rawCpe == null || rawCpe.isBlank()) {
            return null;
        }
        String trimmed = rawCpe.trim().toLowerCase(Locale.ROOT);
        if (!trimmed.startsWith("cpe:2.3:")) {
            return null;
        }
        String[] rawParts = trimmed.split(":", -1);
        if (rawParts.length < ATTR_START_INDEX + ATTR_COUNT) {
            return null;
        }

        List<String> normalizedTokens = new ArrayList<>(ATTR_COUNT);
        for (int i = 0; i < ATTR_COUNT; i++) {
            normalizedTokens.add(normalizeCanonicalToken(rawParts[ATTR_START_INDEX + i]));
        }

        return "cpe:2.3:" + String.join(":", normalizedTokens);
    }

    public static String buildCpeKey(ParsedCpe cpe) {
        if (cpe == null) {
            return "";
        }
        StringBuilder key = new StringBuilder();
        key.append(safeToken(cpe.part()));
        key.append('|').append(safeToken(cpe.vendor()));
        key.append('|').append(safeToken(cpe.product()));

        if (!safeToken(cpe.targetSw()).isBlank()) {
            key.append("|sw=").append(safeToken(cpe.targetSw()));
        }
        if (!safeToken(cpe.targetHw()).isBlank()) {
            key.append("|hw=").append(safeToken(cpe.targetHw()));
        }
        if (!safeToken(cpe.other()).isBlank()) {
            key.append("|other=").append(safeToken(cpe.other()));
        }
        return key.toString();
    }

    private static ParsedCpe empty() {
        return new ParsedCpe("", "", "", "", "", "", "", "", "", "", "");
    }

    private static String normalizeParsedToken(String value) {
        if (value == null) {
            return "";
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank() || "*".equals(normalized) || "-".equals(normalized)) {
            return "";
        }
        return normalized;
    }

    private static String normalizeCanonicalToken(String value) {
        if (value == null) {
            return "*";
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank() || "-".equals(normalized)) {
            return "*";
        }
        return normalized;
    }

    private static String safeToken(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
