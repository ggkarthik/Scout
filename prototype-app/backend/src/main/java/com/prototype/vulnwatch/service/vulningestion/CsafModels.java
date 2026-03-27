package com.prototype.vulnwatch.service.vulningestion;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

enum CsafProvider {
    MICROSOFT("microsoft", "Microsoft"),
    REDHAT("redhat", "Red Hat");

    private final String providerKey;
    private final String displayName;

    CsafProvider(String providerKey, String displayName) {
        this.providerKey = providerKey;
        this.displayName = displayName;
    }

    public String providerKey() {
        return providerKey;
    }

    public String displayName() {
        return displayName;
    }
}

record CsafIngestionCounters(int inserted, int updated, Set<UUID> vulnerabilityIds) {
}

record CsafDocumentFetchResult(
        boolean success,
        String body,
        int attempts,
        String failureCategory,
        String failureMessage
) {
    static CsafDocumentFetchResult success(String body, int attempts) {
        return new CsafDocumentFetchResult(true, body, attempts, null, null);
    }

    static CsafDocumentFetchResult failure(int attempts, String failureCategory, String failureMessage) {
        return new CsafDocumentFetchResult(false, null, attempts, failureCategory, failureMessage);
    }
}

final class CsafRunDiagnostics {
    private final String provider;
    private final Map<String, Integer> failureCategories = new LinkedHashMap<>();
    private int documentsAttempted;
    private int documentsProcessed;
    private int documentsFailed;
    private int retries;
    private int canonicalRecords;
    private int canonicalCompleteRecords;
    private int cvssPresent;
    private int referencesPresent;

    CsafRunDiagnostics(String provider) {
        this.provider = provider;
    }

    void markDocumentAttempt() {
        documentsAttempted++;
    }

    void markDocumentSuccess(int attempts) {
        documentsProcessed++;
        if (attempts > 1) {
            retries += attempts - 1;
        }
    }

    void markDocumentFailure(String category, int attempts) {
        documentsFailed++;
        if (attempts > 1) {
            retries += attempts - 1;
        }
        String key = hasText(category) ? category : "UNKNOWN_ERROR";
        failureCategories.merge(key, 1, Integer::sum);
    }

    void observeCanonicalRecord(
            String cveId,
            String sourceSystem,
            String sourceRecordId,
            String severity,
            Double cvss,
            String referencesJson,
            Instant publishedAt,
            Instant lastModifiedAt
    ) {
        canonicalRecords++;
        boolean complete = hasText(cveId)
                && hasText(sourceSystem)
                && hasText(sourceRecordId)
                && hasText(severity)
                && hasText(referencesJson)
                && publishedAt != null
                && lastModifiedAt != null;
        if (complete) {
            canonicalCompleteRecords++;
        }
        if (cvss != null) {
            cvssPresent++;
        }
        if (hasText(referencesJson) && !"[]".equals(referencesJson.trim())) {
            referencesPresent++;
        }
    }

    String summaryLine() {
        double normalizationSuccessRate = canonicalRecords == 0
                ? 1.0
                : (double) canonicalCompleteRecords / (double) canonicalRecords;
        return "provider=" + provider
                + " documentsAttempted=" + documentsAttempted
                + " documentsProcessed=" + documentsProcessed
                + " documentsFailed=" + documentsFailed
                + " retries=" + retries
                + " canonicalRecords=" + canonicalRecords
                + " canonicalCompleteRecords=" + canonicalCompleteRecords
                + " normalizationSuccessRate=" + String.format(Locale.ROOT, "%.4f", normalizationSuccessRate)
                + " cvssPresent=" + cvssPresent
                + " referencesPresent=" + referencesPresent
                + " failureCategories=" + failureCategories;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}

record GhsaIngestionCounters(int inserted, int updated) {
}

record ParsedGhsaRange(
        String versionExact,
        String versionStart,
        Boolean startInclusive,
        String versionEnd,
        Boolean endInclusive,
        String introduced,
        String fixed
) {
}

record CsafDistributionSet(
        String advisoriesDistributionUrl,
        String vexDistributionUrl
) {
}

record CsafDocumentRef(
        String url,
        boolean vexProfile
) {
}

record CsafProductRef(
        String productId,
        String name,
        String cpe,
        String purl
) {
}

record ParsedPurl(
        String type,
        String namespace,
        String name,
        String version
) {
    static final ParsedPurl EMPTY = new ParsedPurl("", "", "", "");
}
