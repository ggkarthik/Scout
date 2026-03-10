package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.util.VersionUtil;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class ApplicabilityDecisionService {

    private static final int DEFAULT_VEX_NOT_AFFECTED_FRESHNESS_DAYS = 30;
    private static final int DEFAULT_VEX_FIXED_FRESHNESS_DAYS = 30;

    private final ObjectMapper objectMapper;

    @Value("${app.features.vex-policy-enabled:true}")
    private boolean vexPolicyEnabled = true;

    @Value("${app.vex.no-date-assume-fresh:false}")
    private boolean vexNoDateAssumeFresh = false;

    public ApplicabilityDecisionService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public enum ApplicabilityResult {
        TRUE,
        FALSE,
        UNKNOWN
    }

    public record ApplicabilityDecision(
            ApplicabilityResult result,
            String reason,
            Map<String, Object> trace
    ) {
        public boolean isAffected() {
            return result == ApplicabilityResult.TRUE;
        }
    }

    private record ComparisonOutcome(
            boolean known,
            int value,
            String error
    ) {
    }

    public ApplicabilityDecision evaluate(InventoryComponent component, VulnerabilityTarget target) {
        return evaluate(component, target, null);
    }

    public ApplicabilityDecision evaluate(InventoryComponent component, VulnerabilityTarget target, RiskPolicy policy) {
        Map<String, Object> trace = new LinkedHashMap<>();
        List<Map<String, Object>> checks = new ArrayList<>();
        trace.put("componentVersion", component.getVersion());
        trace.put("targetId", target.getId());
        trace.put("versionScheme", target.getVersionScheme() == null ? VersionScheme.UNKNOWN.name() : target.getVersionScheme().name());
        trace.put("constraintType", target.getConstraintType() == null ? "NONE" : target.getConstraintType().name());
        trace.put("versionExact", target.getVersionExact());
        trace.put("versionStart", target.getVersionStart());
        trace.put("startInclusive", target.getStartInclusive());
        trace.put("versionEnd", target.getVersionEnd());
        trace.put("endInclusive", target.getEndInclusive());
        trace.put("introduced", target.getIntroduced());
        trace.put("fixed", target.getFixed());
        trace.put("checks", checks);

        VexSignal vexSignal = resolveVexSignal(target);
        if (vexPolicyEnabled && vexSignal.hasStatus()) {
            String normalized = vexSignal.status().trim().toUpperCase(Locale.ROOT);
            String trustTier = vexSignal.trustTier().trim().toUpperCase(Locale.ROOT);
            VexFreshness freshness = evaluateVexFreshness(normalized, vexSignal.publishedAt(), vexSignal.lastSeenAt(), policy);
            boolean trustedForSuppression = isTrustedForSuppression(trustTier);
            boolean suppressionEligible = trustedForSuppression && freshness.fresh();

            trace.put("vexStatus", normalized);
            trace.put("vexProvider", vexSignal.provider());
            trace.put("vexTrustTier", trustTier);
            trace.put("vexPublishedAt", vexSignal.publishedAt() == null ? null : vexSignal.publishedAt().toString());
            trace.put("vexLastSeenAt", vexSignal.lastSeenAt() == null ? null : vexSignal.lastSeenAt().toString());
            trace.put("vexFreshnessDays", freshness.freshnessDays());
            trace.put("vexAssertionAgeDays", freshness.assertionAgeDays());
            trace.put("vexFreshnessOutcome", freshness.outcome());
            trace.put("vexSuppressionEligible", suppressionEligible);

            if (normalized.contains("NOT_AFFECTED")) {
                if (!suppressionEligible) {
                    trace.put("finalReason", "vex_not_affected_stale_or_untrusted");
                    return new ApplicabilityDecision(ApplicabilityResult.UNKNOWN, "vex_not_affected_stale_or_untrusted", trace);
                }
                trace.put("finalReason", "vex_not_affected");
                return new ApplicabilityDecision(ApplicabilityResult.FALSE, "vex_not_affected", trace);
            }
            if (normalized.contains("FIXED")) {
                if (!suppressionEligible) {
                    trace.put("finalReason", "vex_fixed_stale_or_untrusted");
                    return new ApplicabilityDecision(ApplicabilityResult.UNKNOWN, "vex_fixed_stale_or_untrusted", trace);
                }
                trace.put("finalReason", "vex_fixed");
                return new ApplicabilityDecision(ApplicabilityResult.FALSE, "vex_fixed", trace);
            }
            if (normalized.contains("UNDER_INVESTIGATION")) {
                trace.put("finalReason", "vex_under_investigation");
                return new ApplicabilityDecision(ApplicabilityResult.UNKNOWN, "vex_under_investigation", trace);
            }
            if (normalized.contains("NO_PATCH")) {
                // Vendor acknowledges no fix exists; component is affected regardless of version.
                trace.put("finalReason", "vex_no_patch");
                return new ApplicabilityDecision(ApplicabilityResult.TRUE, "vex_no_patch", trace);
            }
            if (normalized.contains("AFFECTED")) {
                trace.put("finalReason", "vex_known_affected");
                return new ApplicabilityDecision(ApplicabilityResult.TRUE, "vex_known_affected", trace);
            }
        }

        String componentVersion = component.getVersion();
        if (componentVersion == null || componentVersion.isBlank()) {
            trace.put("finalReason", "VERSION_UNKNOWN");
            return new ApplicabilityDecision(ApplicabilityResult.UNKNOWN, "VERSION_UNKNOWN", trace);
        }

        VersionScheme scheme = target.getVersionScheme() == null ? VersionScheme.UNKNOWN : target.getVersionScheme();

        if (hasText(target.getVersionExact())) {
            ComparisonOutcome exact = compare(componentVersion, target.getVersionExact(), scheme, "exact", checks);
            if (!exact.known()) {
                trace.put("finalReason", "exact_compare_error");
                return new ApplicabilityDecision(ApplicabilityResult.UNKNOWN, "exact_compare_error", trace);
            }
            if (exact.value() != 0) {
                trace.put("finalReason", "exact_version_mismatch");
                return new ApplicabilityDecision(ApplicabilityResult.FALSE, "exact_version_mismatch", trace);
            }
            trace.put("finalReason", "exact_version_match");
            return new ApplicabilityDecision(ApplicabilityResult.TRUE, "exact_version_match", trace);
        }

        if (hasText(target.getIntroduced())) {
            ComparisonOutcome introduced = compare(componentVersion, target.getIntroduced(), scheme, "introduced", checks);
            if (!introduced.known()) {
                trace.put("finalReason", "introduced_compare_error");
                return new ApplicabilityDecision(ApplicabilityResult.UNKNOWN, "introduced_compare_error", trace);
            }
            if (introduced.value() < 0) {
                trace.put("finalReason", "below_introduced");
                return new ApplicabilityDecision(ApplicabilityResult.FALSE, "below_introduced", trace);
            }
        }

        if (hasText(target.getFixed())) {
            ComparisonOutcome fixed = compare(componentVersion, target.getFixed(), scheme, "fixed", checks);
            if (!fixed.known()) {
                trace.put("finalReason", "fixed_compare_error");
                return new ApplicabilityDecision(ApplicabilityResult.UNKNOWN, "fixed_compare_error", trace);
            }
            if (fixed.value() >= 0) {
                trace.put("finalReason", "at_or_above_fixed");
                return new ApplicabilityDecision(ApplicabilityResult.FALSE, "at_or_above_fixed", trace);
            }
        }

        if (hasText(target.getVersionStart())) {
            ComparisonOutcome start = compare(componentVersion, target.getVersionStart(), scheme, "range_start", checks);
            if (!start.known()) {
                trace.put("finalReason", "range_start_compare_error");
                return new ApplicabilityDecision(ApplicabilityResult.UNKNOWN, "range_start_compare_error", trace);
            }
            boolean startInclusive = target.getStartInclusive() == null || target.getStartInclusive();
            if (startInclusive && start.value() < 0) {
                trace.put("finalReason", "below_start_inclusive");
                return new ApplicabilityDecision(ApplicabilityResult.FALSE, "below_start_inclusive", trace);
            }
            if (!startInclusive && start.value() <= 0) {
                trace.put("finalReason", "at_or_below_start_exclusive");
                return new ApplicabilityDecision(ApplicabilityResult.FALSE, "at_or_below_start_exclusive", trace);
            }
        }

        if (hasText(target.getVersionEnd())) {
            ComparisonOutcome end = compare(componentVersion, target.getVersionEnd(), scheme, "range_end", checks);
            if (!end.known()) {
                trace.put("finalReason", "range_end_compare_error");
                return new ApplicabilityDecision(ApplicabilityResult.UNKNOWN, "range_end_compare_error", trace);
            }
            boolean endInclusive = target.getEndInclusive() == null || target.getEndInclusive();
            if (endInclusive && end.value() > 0) {
                trace.put("finalReason", "above_end_inclusive");
                return new ApplicabilityDecision(ApplicabilityResult.FALSE, "above_end_inclusive", trace);
            }
            if (!endInclusive && end.value() >= 0) {
                trace.put("finalReason", "at_or_above_end_exclusive");
                return new ApplicabilityDecision(ApplicabilityResult.FALSE, "at_or_above_end_exclusive", trace);
            }
        }

        trace.put("finalReason", "within_constraints");
        return new ApplicabilityDecision(ApplicabilityResult.TRUE, "within_constraints", trace);
    }

    private ComparisonOutcome compare(
            String left,
            String right,
            VersionScheme scheme,
            String label,
            List<Map<String, Object>> checks
    ) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("check", label);
        entry.put("left", left);
        entry.put("right", right);
        entry.put("scheme", scheme.name());
        try {
            int value = VersionUtil.compare(left, right, scheme);
            entry.put("result", value);
            checks.add(entry);
            return new ComparisonOutcome(true, value, null);
        } catch (RuntimeException e) {
            entry.put("error", e.getMessage());
            checks.add(entry);
            return new ComparisonOutcome(false, 0, e.getMessage());
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private VexSignal resolveVexSignal(VulnerabilityTarget target) {
        String status = null;
        String provider = null;
        String trustTier = null;
        Instant publishedAt = null;
        Instant lastSeenAt = null;

        if (target == null) {
            return VexSignal.empty();
        }

        if (hasText(target.getQualifiersJson())) {
            try {
                JsonNode node = objectMapper.readTree(target.getQualifiersJson());
                String rawStatus = node.path("vexStatus").asText("");
                if (hasText(rawStatus)) {
                    status = rawStatus;
                }
                String rawProvider = node.path("vexProvider").asText("");
                if (hasText(rawProvider)) {
                    provider = rawProvider.trim().toLowerCase(Locale.ROOT);
                }
                String rawTrustTier = node.path("vexTrustTier").asText("");
                if (hasText(rawTrustTier)) {
                    trustTier = rawTrustTier.trim().toUpperCase(Locale.ROOT);
                }
                publishedAt = parseInstant(node.path("vexPublishedAt").asText(""));
                lastSeenAt = parseInstant(node.path("vexLastSeenAt").asText(""));
            } catch (Exception ignored) {
                // ignore malformed qualifiers payload
            }
        }

        String inferredProvider = inferProvider(target.getSource());
        if (!hasText(provider)) {
            provider = inferredProvider;
        }
        if (!hasText(trustTier)) {
            trustTier = inferTrustTier(provider, target.getSource());
        }

        if (hasText(target.getSource()) && target.getSource().toLowerCase().contains("vex")) {
            // Legacy VEX records without explicit status are treated conservatively.
            if (!hasText(status)) {
                status = "UNDER_INVESTIGATION";
            }
        }
        return new VexSignal(status, provider, trustTier, publishedAt, lastSeenAt);
    }

    private Instant parseInstant(String value) {
        if (!hasText(value)) {
            return null;
        }
        try {
            return Instant.parse(value.trim());
        } catch (Exception ignored) {
            return null;
        }
    }

    private String inferProvider(String source) {
        if (!hasText(source)) {
            return "unknown";
        }
        String normalized = source.trim().toLowerCase(Locale.ROOT);
        if (normalized.contains("microsoft") || normalized.contains("msrc")) {
            return "microsoft";
        }
        if (normalized.contains("redhat") || normalized.contains("red-hat")) {
            return "redhat";
        }
        if (normalized.startsWith("vex-")) {
            return normalized.substring("vex-".length());
        }
        if (normalized.startsWith("csaf-")) {
            return normalized.substring("csaf-".length());
        }
        return "unknown";
    }

    private String inferTrustTier(String provider, String source) {
        String normalizedProvider = hasText(provider) ? provider.trim().toLowerCase(Locale.ROOT) : "unknown";
        if ("microsoft".equals(normalizedProvider) || "redhat".equals(normalizedProvider)) {
            return "HIGH";
        }
        if (hasText(source)) {
            String normalizedSource = source.trim().toLowerCase(Locale.ROOT);
            // vex-* sources and csaf-* sources with explicit product status both qualify as VEX signals.
            if (normalizedSource.contains("vex") || normalizedSource.startsWith("csaf-")) {
                return "MEDIUM";
            }
        }
        return "UNKNOWN";
    }

    private VexFreshness evaluateVexFreshness(
            String normalizedStatus,
            Instant publishedAt,
            Instant lastSeenAt,
            RiskPolicy policy
    ) {
        int freshnessDays = freshnessDaysForStatus(normalizedStatus, policy);
        Instant reference = publishedAt != null ? publishedAt : lastSeenAt;
        if (reference == null) {
            boolean fresh = vexNoDateAssumeFresh;
            return new VexFreshness(
                    fresh,
                    null,
                    freshnessDays,
                    fresh ? "NO_DATE_ASSUME_FRESH" : "NO_DATE_TREAT_AS_STALE"
            );
        }
        long ageDays = Math.max(0L, Duration.between(reference, Instant.now()).toDays());
        boolean fresh = ageDays <= freshnessDays;
        return new VexFreshness(fresh, ageDays, freshnessDays, fresh ? "FRESH" : "STALE");
    }

    private int freshnessDaysForStatus(String normalizedStatus, RiskPolicy policy) {
        if (normalizedStatus != null && normalizedStatus.contains("FIXED")) {
            // VEX FIX #3: FIXED status is permanent - once vendor confirms a fix, it doesn't "un-fix"
            // Return Integer.MAX_VALUE to effectively make FIXED statements never expire
            return Integer.MAX_VALUE;
        }
        return policy == null ? DEFAULT_VEX_NOT_AFFECTED_FRESHNESS_DAYS : Math.max(1, policy.getVexNotAffectedFreshnessDays());
    }

    private boolean isTrustedForSuppression(String trustTier) {
        if (!hasText(trustTier)) {
            return false;
        }
        String normalized = trustTier.trim().toUpperCase(Locale.ROOT);
        return "HIGH".equals(normalized) || "MEDIUM".equals(normalized);
    }

    private record VexSignal(
            String status,
            String provider,
            String trustTier,
            Instant publishedAt,
            Instant lastSeenAt
    ) {
        static VexSignal empty() {
            return new VexSignal(null, "unknown", "UNKNOWN", null, null);
        }

        boolean hasStatus() {
            return status != null && !status.isBlank();
        }
    }

    private record VexFreshness(
            boolean fresh,
            Long assertionAgeDays,
            int freshnessDays,
            String outcome
    ) {
    }
}
