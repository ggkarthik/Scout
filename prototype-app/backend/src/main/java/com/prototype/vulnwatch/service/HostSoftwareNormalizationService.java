package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.util.IdentityUtil;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

@Service
public class HostSoftwareNormalizationService {

    private static final Pattern DATE_VERSION_PATTERN = Pattern.compile("\\b(20\\d{2})[-_/]?(\\d{2})[-_/]?(\\d{2})\\b");
    private static final Pattern DOTTED_VERSION_PATTERN = Pattern.compile("\\b\\d+(?:[._-]\\d+){0,6}\\b");
    private static final Pattern MSI_CODE_PATTERN = Pattern.compile("\\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\\}?");

    private static final Set<String> PRODUCT_STOP_WORDS = Set.of(
            "corporation",
            "corp",
            "company",
            "inc",
            "llc",
            "ltd",
            "limited",
            "gmbh",
            "edition",
            "enterprise",
            "professional",
            "standard",
            "community",
            "language",
            "english",
            "x64",
            "x86",
            "amd64",
            "64bit",
            "64_bit",
            "32bit",
            "32_bit"
    );

    private static final Set<String> UNKNOWN_NORMALIZED_VALUES = Set.of(
            "unknown",
            "unknown_product",
            "unknown_vendor",
            "unmatched",
            "no_match",
            "no-match",
            "not_matched",
            "not-matched",
            "unmapped",
            "unclassified",
            "uncategorized",
            "none",
            "na",
            "n_a",
            "n-a",
            "n/a",
            "other",
            "generic",
            "not_normalized",
            "not-normalized"
    );

    private static final Map<String, String> VENDOR_ALIASES = vendorAliases();

    public NormalizedHostSoftware normalize(
            String displayName,
            String publisher,
            String version,
            String preferredNormalizedProduct,
            String preferredNormalizedPublisher,
            String preferredNormalizedVersion,
            String versionEvidence
    ) {
        String normalizedPublisher = hasMeaningfulNormalizedValue(preferredNormalizedPublisher)
                ? slug(preferredNormalizedPublisher)
                : normalizeVendor(publisher);
        String normalizedProduct = hasMeaningfulNormalizedValue(preferredNormalizedProduct)
                ? slug(preferredNormalizedProduct)
                : normalizeProduct(displayName, normalizedPublisher);
        String normalizedVersion = hasMeaningfulNormalizedValue(preferredNormalizedVersion)
                ? preferredNormalizedVersion.trim()
                : normalizeVersion(version);

        if (!hasText(normalizedPublisher)) {
            normalizedPublisher = "unknown";
        }
        if (!hasText(normalizedProduct)) {
            normalizedProduct = "unknown";
        }

        String normalizedKey = normalizedPublisher + ":" + normalizedProduct;
        String purl = buildGenericPurl(normalizedPublisher, normalizedProduct, normalizedVersion);
        String normalizedEvidence = normalizeEvidence(versionEvidence);

        return new NormalizedHostSoftware(
                IdentityUtil.normalize(displayName),
                IdentityUtil.normalize(publisher),
                version == null ? null : version.trim(),
                normalizedPublisher,
                normalizedProduct,
                normalizedVersion,
                normalizedKey,
                purl,
                normalizedEvidence,
                !hasText(normalizedVersion)
        );
    }

    public String normalizeVendor(String publisher) {
        String normalized = slug(publisher);
        if (!hasText(normalized)) {
            return "";
        }
        return VENDOR_ALIASES.getOrDefault(normalized, normalized);
    }

    public String normalizeProduct(String displayName, String normalizedPublisher) {
        String text = displayName == null ? "" : displayName.trim().toLowerCase(Locale.ROOT);
        if (text.isBlank()) {
            return "";
        }
        if (hasText(normalizedPublisher)) {
            String publisherPhrase = normalizedPublisher.replace('_', ' ');
            if (text.startsWith(publisherPhrase + " ")) {
                text = text.substring(publisherPhrase.length()).trim();
            }
        }
        text = text.replaceAll("\\([^)]*\\)", " ");
        text = text.replaceAll("(?i)\\b\\d+(?:[._-]\\d+){1,6}\\b", " ");
        text = text.replaceAll("(?i)\\b(x64|x86|amd64|64-bit|32-bit|en-us|multi-language|multilingual)\\b", " ");
        text = text.replaceAll("[^a-z0-9]+", " ");
        StringBuilder builder = new StringBuilder();
        for (String token : text.split("\\s+")) {
            String normalizedToken = slug(token);
            if (!hasText(normalizedToken) || PRODUCT_STOP_WORDS.contains(normalizedToken)) {
                continue;
            }
            if (builder.length() > 0) {
                builder.append('_');
            }
            builder.append(normalizedToken);
        }
        if (builder.length() == 0) {
            return slug(displayName);
        }
        return builder.toString();
    }

    public String normalizeVersion(String rawVersion) {
        if (!hasText(rawVersion)) {
            return null;
        }
        String candidate = rawVersion.trim();
        Matcher dateMatcher = DATE_VERSION_PATTERN.matcher(candidate);
        if (dateMatcher.find()) {
            return dateMatcher.group(1) + "." + dateMatcher.group(2) + "." + dateMatcher.group(3);
        }
        Matcher dottedMatcher = DOTTED_VERSION_PATTERN.matcher(candidate);
        if (dottedMatcher.find()) {
            return dottedMatcher.group().replace('_', '.').replace('-', '.');
        }
        return null;
    }

    public String normalizeEvidence(String versionEvidence) {
        if (!hasText(versionEvidence)) {
            return null;
        }
        Matcher msiMatcher = MSI_CODE_PATTERN.matcher(versionEvidence);
        if (msiMatcher.find()) {
            return msiMatcher.group().toLowerCase(Locale.ROOT);
        }
        return versionEvidence.trim();
    }

    private String buildGenericPurl(String vendor, String product, String version) {
        StringBuilder builder = new StringBuilder("pkg:generic/");
        builder.append(hasText(vendor) ? vendor : "unknown");
        builder.append("/");
        builder.append(hasText(product) ? product : "unknown");
        if (hasText(version)) {
            builder.append("@").append(version);
        }
        return builder.toString();
    }

    private String slug(String value) {
        if (value == null) {
            return "";
        }
        String slug = value.trim().toLowerCase(Locale.ROOT)
                .replace('&', ' ')
                .replaceAll("[^a-z0-9]+", "_")
                .replaceAll("_+", "_")
                .replaceAll("^_+|_+$", "");
        return slug;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private boolean hasMeaningfulNormalizedValue(String value) {
        if (!hasText(value)) {
            return false;
        }
        String normalized = slug(value);
        return hasText(normalized) && !UNKNOWN_NORMALIZED_VALUES.contains(normalized);
    }

    private static Map<String, String> vendorAliases() {
        Map<String, String> aliases = new LinkedHashMap<>();
        aliases.put("microsoft_corporation", "microsoft");
        aliases.put("microsoft_corp", "microsoft");
        aliases.put("oracle_corporation", "oracle");
        aliases.put("oracle_america_inc", "oracle");
        aliases.put("vmware_inc", "vmware");
        aliases.put("international_business_machines", "ibm");
        aliases.put("ibm_corporation", "ibm");
        aliases.put("red_hat_inc", "redhat");
        aliases.put("red_hat", "redhat");
        aliases.put("google_llc", "google");
        return Map.copyOf(aliases);
    }

    public record NormalizedHostSoftware(
            String rawDisplayName,
            String rawPublisher,
            String rawVersion,
            String normalizedPublisher,
            String normalizedProduct,
            String normalizedVersion,
            String normalizedKey,
            String purl,
            String normalizedEvidence,
            boolean needsReview
    ) {
    }
}
