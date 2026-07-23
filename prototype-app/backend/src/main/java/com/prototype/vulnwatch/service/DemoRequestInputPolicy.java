package com.prototype.vulnwatch.service;

import java.text.Normalizer;
import java.util.Set;
import org.springframework.http.HttpStatus;

public final class DemoRequestInputPolicy {

    private static final Set<String> COMPANY_SIZES = Set.of("1-100", "101-1000", "1001-5000", "5000+");
    private static final Set<String> USE_CASES = Set.of(
            "SBOM validation",
            "Vulnerability prioritization",
            "Finding workflow",
            "Executive reporting"
    );

    private DemoRequestInputPolicy() {
    }

    public static String requiredSingleLine(String value, String field) {
        String normalized = normalize(value);
        if (normalized == null || normalized.isBlank()) {
            throw invalid(field, field + " is required");
        }
        rejectUnsafe(normalized, field, false);
        return normalized;
    }

    public static String optionalSingleLine(String value, String field) {
        String normalized = normalize(value);
        if (normalized == null || normalized.isBlank()) {
            return null;
        }
        rejectUnsafe(normalized, field, false);
        return normalized;
    }

    public static String optionalNotes(String value) {
        String normalized = normalize(value);
        if (normalized == null || normalized.isBlank()) {
            return null;
        }
        rejectUnsafe(normalized, "notes", true);
        return normalized;
    }

    public static String companySize(String value) {
        String normalized = optionalSingleLine(value, "companySize");
        if (normalized != null && !COMPANY_SIZES.contains(normalized)) {
            throw invalid("companySize", "Select a valid company size");
        }
        return normalized;
    }

    public static String useCase(String value) {
        String normalized = optionalSingleLine(value, "useCase");
        if (normalized != null && !USE_CASES.contains(normalized)) {
            throw invalid("useCase", "Select a valid primary use case");
        }
        return normalized;
    }

    private static String normalize(String value) {
        return value == null ? null : Normalizer.normalize(value, Normalizer.Form.NFKC).trim();
    }

    private static void rejectUnsafe(String value, String field, boolean allowNotesWhitespace) {
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            boolean permittedWhitespace = allowNotesWhitespace && (codePoint == '\n' || codePoint == '\r' || codePoint == '\t');
            boolean bidiControl = (codePoint >= 0x202A && codePoint <= 0x202E)
                    || (codePoint >= 0x2066 && codePoint <= 0x2069)
                    || codePoint == 0x200E || codePoint == 0x200F;
            if ((!permittedWhitespace && Character.isISOControl(codePoint)) || bidiControl) {
                throw invalid(field, field + " contains unsupported control characters");
            }
            offset += Character.charCount(codePoint);
        }
    }

    private static DemoAccessException invalid(String field, String message) {
        return new DemoAccessException("INVALID_" + field.toUpperCase(), message, HttpStatus.BAD_REQUEST);
    }
}
