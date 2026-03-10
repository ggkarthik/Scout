package com.prototype.vulnwatch.util;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility for parsing and deriving information from CVSS vector strings.
 *
 * This utility allows deriving fields that were removed from the Vulnerability entity:
 * - attackVector, attackComplexity, privilegesRequired, userInteraction, scope
 * - exploitabilityScore, impactScore, cvssVersion
 *
 * CVSS Vector Format:
 * CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
 *
 * Metrics:
 * - AV: Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)
 * - AC: Attack Complexity (L=Low, H=High)
 * - PR: Privileges Required (N=None, L=Low, H=High)
 * - UI: User Interaction (N=None, R=Required)
 * - S: Scope (U=Unchanged, C=Changed)
 * - C: Confidentiality Impact (N=None, L=Low, H=High)
 * - I: Integrity Impact (N=None, L=Low, H=High)
 * - A: Availability Impact (N=None, L=Low, H=High)
 */
public class CvssUtil {

    private static final Pattern CVSS_VERSION_PATTERN = Pattern.compile("^CVSS:([0-9.]+)/");
    private static final Pattern CVSS_METRIC_PATTERN = Pattern.compile("([A-Z]+):([A-Z]+)");

    /**
     * Parsed CVSS metrics from a vector string
     */
    public record CvssMetrics(
            String version,
            String attackVector,
            String attackComplexity,
            String privilegesRequired,
            String userInteraction,
            String scope,
            String confidentialityImpact,
            String integrityImpact,
            String availabilityImpact,
            Map<String, String> allMetrics
    ) {
    }

    /**
     * Parses a CVSS vector string into structured metrics.
     *
     * @param cvssVector CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
     * @return Parsed metrics, or null if vector is invalid
     */
    public static CvssMetrics parse(String cvssVector) {
        if (cvssVector == null || cvssVector.isBlank()) {
            return null;
        }

        String normalized = cvssVector.trim().toUpperCase(Locale.ROOT);

        // Extract version
        String version = extractVersion(normalized);
        if (version == null) {
            return null;
        }

        // Parse all metrics
        Map<String, String> metrics = new HashMap<>();
        Matcher matcher = CVSS_METRIC_PATTERN.matcher(normalized);
        while (matcher.find()) {
            String key = matcher.group(1);
            String value = matcher.group(2);
            metrics.put(key, value);
        }

        return new CvssMetrics(
                version,
                expandAttackVector(metrics.get("AV")),
                expandAttackComplexity(metrics.get("AC")),
                expandPrivilegesRequired(metrics.get("PR")),
                expandUserInteraction(metrics.get("UI")),
                expandScope(metrics.get("S")),
                expandImpact(metrics.get("C")),
                expandImpact(metrics.get("I")),
                expandImpact(metrics.get("A")),
                metrics
        );
    }

    /**
     * Extracts CVSS version from vector string.
     *
     * @param cvssVector CVSS vector string
     * @return Version string (e.g., "3.1", "3.0", "2.0"), or null if not found
     */
    public static String extractVersion(String cvssVector) {
        if (cvssVector == null || cvssVector.isBlank()) {
            return null;
        }

        Matcher matcher = CVSS_VERSION_PATTERN.matcher(cvssVector.toUpperCase(Locale.ROOT));
        if (matcher.find()) {
            return matcher.group(1);
        }

        // Legacy CVSS 2.0 vectors may not have version prefix
        if (cvssVector.contains("AV:") && !cvssVector.startsWith("CVSS:")) {
            return "2.0";
        }

        return null;
    }

    /**
     * Checks if a CVSS vector is CVSS v3.x
     */
    public static boolean isCvss3(String cvssVector) {
        String version = extractVersion(cvssVector);
        return version != null && version.startsWith("3");
    }

    /**
     * Checks if a CVSS vector is CVSS v2.x
     */
    public static boolean isCvss2(String cvssVector) {
        String version = extractVersion(cvssVector);
        return version != null && version.startsWith("2");
    }

    /**
     * Calculates exploitability subscore from CVSS v3 metrics.
     * This is a simplified approximation - for exact calculation, use full CVSS library.
     *
     * @param metrics Parsed CVSS metrics
     * @return Exploitability score (0.0 - 10.0), or null if cannot calculate
     */
    public static Double calculateExploitabilityScore(CvssMetrics metrics) {
        if (metrics == null || !metrics.version.startsWith("3")) {
            return null;
        }

        // Simplified formula (actual CVSS calculation is more complex)
        double avScore = getAttackVectorScore(metrics.allMetrics.get("AV"));
        double acScore = getAttackComplexityScore(metrics.allMetrics.get("AC"));
        double prScore = getPrivilegesRequiredScore(metrics.allMetrics.get("PR"), metrics.allMetrics.get("S"));
        double uiScore = getUserInteractionScore(metrics.allMetrics.get("UI"));

        // Exploitability = 8.22 × AttackVector × AttackComplexity × PrivilegesRequired × UserInteraction
        return 8.22 * avScore * acScore * prScore * uiScore;
    }

    /**
     * Calculates impact subscore from CVSS v3 metrics.
     * This is a simplified approximation - for exact calculation, use full CVSS library.
     *
     * @param metrics Parsed CVSS metrics
     * @return Impact score (0.0 - 10.0), or null if cannot calculate
     */
    public static Double calculateImpactScore(CvssMetrics metrics) {
        if (metrics == null || !metrics.version.startsWith("3")) {
            return null;
        }

        // Simplified formula
        double cScore = getImpactScore(metrics.allMetrics.get("C"));
        double iScore = getImpactScore(metrics.allMetrics.get("I"));
        double aScore = getImpactScore(metrics.allMetrics.get("A"));

        boolean scopeChanged = "C".equals(metrics.allMetrics.get("S"));

        // ISCBase = 1 - [(1 - ImpactConf) × (1 - ImpactInteg) × (1 - ImpactAvail)]
        double iscBase = 1 - ((1 - cScore) * (1 - iScore) * (1 - aScore));

        if (scopeChanged) {
            return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
        } else {
            return 6.42 * iscBase;
        }
    }

    // ========== PRIVATE HELPERS ==========

    private static String expandAttackVector(String av) {
        if (av == null) return null;
        return switch (av) {
            case "N" -> "NETWORK";
            case "A" -> "ADJACENT_NETWORK";
            case "L" -> "LOCAL";
            case "P" -> "PHYSICAL";
            default -> av;
        };
    }

    private static String expandAttackComplexity(String ac) {
        if (ac == null) return null;
        return switch (ac) {
            case "L" -> "LOW";
            case "H" -> "HIGH";
            default -> ac;
        };
    }

    private static String expandPrivilegesRequired(String pr) {
        if (pr == null) return null;
        return switch (pr) {
            case "N" -> "NONE";
            case "L" -> "LOW";
            case "H" -> "HIGH";
            default -> pr;
        };
    }

    private static String expandUserInteraction(String ui) {
        if (ui == null) return null;
        return switch (ui) {
            case "N" -> "NONE";
            case "R" -> "REQUIRED";
            default -> ui;
        };
    }

    private static String expandScope(String s) {
        if (s == null) return null;
        return switch (s) {
            case "U" -> "UNCHANGED";
            case "C" -> "CHANGED";
            default -> s;
        };
    }

    private static String expandImpact(String impact) {
        if (impact == null) return null;
        return switch (impact) {
            case "N" -> "NONE";
            case "L" -> "LOW";
            case "H" -> "HIGH";
            default -> impact;
        };
    }

    private static double getAttackVectorScore(String av) {
        if (av == null) return 0.0;
        return switch (av) {
            case "N" -> 0.85;
            case "A" -> 0.62;
            case "L" -> 0.55;
            case "P" -> 0.2;
            default -> 0.0;
        };
    }

    private static double getAttackComplexityScore(String ac) {
        if (ac == null) return 0.0;
        return switch (ac) {
            case "L" -> 0.77;
            case "H" -> 0.44;
            default -> 0.0;
        };
    }

    private static double getPrivilegesRequiredScore(String pr, String scope) {
        if (pr == null) return 0.0;
        boolean scopeChanged = "C".equals(scope);
        return switch (pr) {
            case "N" -> 0.85;
            case "L" -> scopeChanged ? 0.68 : 0.62;
            case "H" -> scopeChanged ? 0.50 : 0.27;
            default -> 0.0;
        };
    }

    private static double getUserInteractionScore(String ui) {
        if (ui == null) return 0.0;
        return switch (ui) {
            case "N" -> 0.85;
            case "R" -> 0.62;
            default -> 0.0;
        };
    }

    private static double getImpactScore(String impact) {
        if (impact == null) return 0.0;
        return switch (impact) {
            case "H" -> 0.56;
            case "L" -> 0.22;
            case "N" -> 0.0;
            default -> 0.0;
        };
    }
}
