package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.RiskPolicy;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class VexPolicyService {

    private static final int DEFAULT_VEX_NOT_AFFECTED_FRESHNESS_DAYS = 30;

    @Value("${app.vex.no-date-assume-fresh:false}")
    private boolean vexNoDateAssumeFresh = false;

    public VexFreshness evaluateFreshness(
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

    public boolean isTrustedForSuppression(String trustTier) {
        if (!hasText(trustTier)) {
            return false;
        }
        String normalized = trustTier.trim().toUpperCase(Locale.ROOT);
        return "HIGH".equals(normalized) || "MEDIUM".equals(normalized);
    }

    public String inferProvider(String source) {
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

    public String inferTrustTier(String provider, String source) {
        String normalizedProvider = hasText(provider) ? provider.trim().toLowerCase(Locale.ROOT) : "unknown";
        if ("microsoft".equals(normalizedProvider) || "redhat".equals(normalizedProvider)) {
            return "HIGH";
        }
        if (hasText(source)) {
            String normalizedSource = source.trim().toLowerCase(Locale.ROOT);
            if (normalizedSource.contains("vex") || normalizedSource.startsWith("csaf-")) {
                return "MEDIUM";
            }
        }
        return "UNKNOWN";
    }

    private int freshnessDaysForStatus(String normalizedStatus, RiskPolicy policy) {
        if (normalizedStatus != null && normalizedStatus.contains("FIXED")) {
            return Integer.MAX_VALUE;
        }
        return DEFAULT_VEX_NOT_AFFECTED_FRESHNESS_DAYS;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    public record VexFreshness(
            boolean fresh,
            Long assertionAgeDays,
            int freshnessDays,
            String outcome
    ) {
    }
}
