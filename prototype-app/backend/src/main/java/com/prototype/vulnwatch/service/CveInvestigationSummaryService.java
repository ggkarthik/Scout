package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.CveInvestigationSummaryRequest;
import com.prototype.vulnwatch.dto.CveInvestigationSummaryResponse;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import org.springframework.stereotype.Service;

@Service
public class CveInvestigationSummaryService {

    public CveInvestigationSummaryResponse generateSummary(
            String cveId,
            Map<String, Object> payload
    ) {
        SummaryFields summary = summaryFields(cveId, asMap(payload.get("summary")));
        List<AssetFields> affectedAssets = affectedAssets(asList(payload.get("affectedAssets")));
        List<FalsePositiveFields> falsePositiveRows = falsePositiveRows(asList(payload.get("falsePositiveRows")));
        List<EolFields> eolRows = eolRows(asList(payload.get("eolRows")));

        int totalAffected = affectedAssets.size();
        int externalFacing = (int) affectedAssets.stream().filter(AssetFields::externalFacing).count();
        int internalAssets = Math.max(0, totalAffected - externalFacing);
        int falsePositiveAssets = falsePositiveRows.stream()
                .filter(FalsePositiveFields::falsePositive)
                .map(FalsePositiveFields::assetsNotImpacted)
                .filter(Objects::nonNull)
                .mapToInt(Integer::intValue)
                .sum();
        int truePositiveAssets = Math.max(0, totalAffected - falsePositiveAssets);
        int unpatchedVulnerable = summary.patchAvailable() ? 0 : truePositiveAssets;
        int eolCount = (int) eolRows.stream().filter(this::isLifecycleAtRisk).count();
        int criticalAssetCount = (int) affectedAssets.stream().filter(AssetFields::critical).count();
        Map<String, Integer> osCounts = buildOsCountsFromFields(affectedAssets);
        Map<String, Integer> softwareCounts = buildSoftwareCountsFromFields(affectedAssets);

        CveInvestigationSummaryResponse.RiskAnalysis riskAnalysis =
                buildRiskAnalysis(summary, externalFacing, criticalAssetCount, unpatchedVulnerable, eolCount);

        CveInvestigationSummaryResponse.ImpactAnalysis impactAnalysis =
                new CveInvestigationSummaryResponse.ImpactAnalysis(
                        externalFacing,
                        internalAssets,
                        falsePositiveAssets > 0
                                ? falsePositiveAssets + " assets were cleared by vendor advisory or VEX evidence."
                                : "No vendor-confirmed false positives were identified in the current evidence set.",
                        eolCount > 0
                                ? eolCount + " software rows are at or near end of life and increase remediation urgency."
                                : "No end-of-life exposure was identified in the currently assessed software set.",
                        summary.patchAvailable()
                                ? "Patch guidance is available"
                                + (summary.patchVersions() != null && !summary.patchVersions().isBlank()
                                ? " (" + summary.patchVersions() + ")."
                                : ".")
                                : "No validated patch was found for the currently exposed assets."
                );

        List<String> keyFindings = buildKeyFindings(
                summary,
                totalAffected,
                externalFacing,
                criticalAssetCount,
                falsePositiveAssets,
                eolCount,
                osCounts,
                softwareCounts
        );

        List<CveInvestigationSummaryResponse.RemediationAction> remediationPlan =
                buildRemediationPlan(summary, externalFacing, criticalAssetCount, unpatchedVulnerable, eolCount);

        CveInvestigationSummaryResponse.MetricsSummary metrics =
                new CveInvestigationSummaryResponse.MetricsSummary(
                        totalAffected,
                        truePositiveAssets,
                        falsePositiveAssets,
                        externalFacing,
                        unpatchedVulnerable,
                        eolCount
                );

        String executiveSummary = buildExecutiveSummary(summary, riskAnalysis, totalAffected, externalFacing, truePositiveAssets, falsePositiveAssets, eolCount);

        return new CveInvestigationSummaryResponse(
                Instant.now(),
                executiveSummary,
                riskAnalysis,
                impactAnalysis,
                remediationPlan,
                keyFindings,
                metrics,
                null
        );
    }

    public CveInvestigationSummaryResponse generateSummary(
            String cveId,
            CveInvestigationSummaryRequest request
    ) {
        int totalAffected = request.affectedAssets().size();
        int externalFacing = (int) request.affectedAssets().stream()
                .filter(asset -> Boolean.TRUE.equals(asset.externalFacing()))
                .count();
        int internalAssets = Math.max(0, totalAffected - externalFacing);
        int falsePositiveAssets = request.falsePositiveRows().stream()
                .filter(row -> Boolean.TRUE.equals(row.falsePositive()))
                .map(CveInvestigationSummaryRequest.FalsePositiveRow::assetsNotImpacted)
                .filter(Objects::nonNull)
                .mapToInt(Integer::intValue)
                .sum();
        int truePositiveAssets = Math.max(0, totalAffected - falsePositiveAssets);
        int unpatchedVulnerable = Boolean.TRUE.equals(request.summary().patchAvailable()) ? 0 : truePositiveAssets;
        int eolCount = (int) request.eolRows().stream()
                .filter(this::isLifecycleAtRisk)
                .count();
        int criticalAssetCount = (int) request.affectedAssets().stream()
                .filter(asset -> Boolean.TRUE.equals(asset.critical()))
                .count();
        Map<String, Integer> osCounts = buildOsCounts(request.affectedAssets());
        Map<String, Integer> softwareCounts = buildSoftwareCounts(request.affectedAssets());

        CveInvestigationSummaryResponse.RiskAnalysis riskAnalysis =
                buildRiskAnalysis(request, externalFacing, criticalAssetCount, unpatchedVulnerable, eolCount);

        CveInvestigationSummaryResponse.ImpactAnalysis impactAnalysis =
                new CveInvestigationSummaryResponse.ImpactAnalysis(
                        externalFacing,
                        internalAssets,
                        falsePositiveAssets > 0
                                ? falsePositiveAssets + " assets were cleared by vendor advisory or VEX evidence."
                                : "No vendor-confirmed false positives were identified in the current evidence set.",
                        eolCount > 0
                                ? eolCount + " software rows are at or near end of life and increase remediation urgency."
                                : "No end-of-life exposure was identified in the currently assessed software set.",
                        Boolean.TRUE.equals(request.summary().patchAvailable())
                                ? "Patch guidance is available"
                                + (request.summary().patchVersions() != null && !request.summary().patchVersions().isBlank()
                                ? " (" + request.summary().patchVersions() + ")."
                                : ".")
                                : "No validated patch was found for the currently exposed assets."
                );

        List<String> keyFindings = buildKeyFindings(
                request,
                externalFacing,
                criticalAssetCount,
                falsePositiveAssets,
                eolCount,
                osCounts,
                softwareCounts
        );

        List<CveInvestigationSummaryResponse.RemediationAction> remediationPlan =
                buildRemediationPlan(request, externalFacing, criticalAssetCount, unpatchedVulnerable, eolCount);

        CveInvestigationSummaryResponse.MetricsSummary metrics =
                new CveInvestigationSummaryResponse.MetricsSummary(
                        totalAffected,
                        truePositiveAssets,
                        falsePositiveAssets,
                        externalFacing,
                        unpatchedVulnerable,
                        eolCount
                );

        String executiveSummary = buildExecutiveSummary(request, riskAnalysis, externalFacing, truePositiveAssets, falsePositiveAssets, eolCount);

        return new CveInvestigationSummaryResponse(
                Instant.now(),
                executiveSummary,
                riskAnalysis,
                impactAnalysis,
                remediationPlan,
                keyFindings,
                metrics,
                null
        );
    }

    private CveInvestigationSummaryResponse.RiskAnalysis buildRiskAnalysis(
            SummaryFields summary,
            int externalFacing,
            int criticalAssetCount,
            int unpatchedVulnerable,
            int eolCount
    ) {
        int score = severityBaseScore(summary.severity());
        if (summary.exploitAvailable()) score += 12;
        if (summary.inKev()) score += 12;
        score += Math.min(15, externalFacing * 4);
        score += Math.min(12, criticalAssetCount * 2);
        if (unpatchedVulnerable > 0) score += 10;
        if (eolCount > 0) score += 8;
        score = Math.max(5, Math.min(99, score));

        String level = score >= 85 ? "Critical" : score >= 70 ? "High" : score >= 45 ? "Medium" : "Low";
        String rationale = "%s severity with %d externally exposed assets, %d critical assets, %d unpatched vulnerable assets, and %d end-of-life software risks."
                .formatted(level, externalFacing, criticalAssetCount, unpatchedVulnerable, eolCount);

        return new CveInvestigationSummaryResponse.RiskAnalysis(level, score, rationale);
    }

    private CveInvestigationSummaryResponse.RiskAnalysis buildRiskAnalysis(
            CveInvestigationSummaryRequest request,
            int externalFacing,
            int criticalAssetCount,
            int unpatchedVulnerable,
            int eolCount
    ) {
        int score = severityBaseScore(request.summary().severity());
        if (Boolean.TRUE.equals(request.summary().exploitAvailable())) score += 12;
        if (Boolean.TRUE.equals(request.summary().inKev())) score += 12;
        score += Math.min(15, externalFacing * 4);
        score += Math.min(12, criticalAssetCount * 2);
        if (unpatchedVulnerable > 0) score += 10;
        if (eolCount > 0) score += 8;
        score = Math.max(5, Math.min(99, score));

        String level = score >= 85 ? "Critical" : score >= 70 ? "High" : score >= 45 ? "Medium" : "Low";
        String rationale = "%s severity with %d externally exposed assets, %d critical assets, %d unpatched vulnerable assets, and %d end-of-life software risks."
                .formatted(level, externalFacing, criticalAssetCount, unpatchedVulnerable, eolCount);

        return new CveInvestigationSummaryResponse.RiskAnalysis(level, score, rationale);
    }

    private List<String> buildKeyFindings(
            SummaryFields summary,
            int totalAffected,
            int externalFacing,
            int criticalAssetCount,
            int falsePositiveAssets,
            int eolCount,
            Map<String, Integer> osCounts,
            Map<String, Integer> softwareCounts
    ) {
        List<String> findings = new ArrayList<>();
        findings.add(summary.cveId() + " affects " + totalAffected
                + " assets across " + Math.max(softwareCounts.size(), 1) + " software families.");
        if (externalFacing > 0) {
            findings.add(externalFacing + " affected assets are externally facing and should be prioritized for containment.");
        }
        if (criticalAssetCount > 0) {
            findings.add(criticalAssetCount + " affected assets are marked critical by the current investigation evidence.");
        }
        if (falsePositiveAssets > 0) {
            findings.add(falsePositiveAssets + " assets were identified as not impacted through vendor advisory or VEX evidence.");
        }
        if (eolCount > 0) {
            findings.add(eolCount + " software entries are at or near end of life, increasing long-term remediation risk.");
        }
        if (!osCounts.isEmpty()) {
            String dominantOs = osCounts.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(entry -> entry.getKey() + " (" + entry.getValue() + ")")
                    .orElse("Unknown");
            findings.add("The largest affected operating system cohort is " + dominantOs + ".");
        }
        return findings;
    }

    private List<String> buildKeyFindings(
            CveInvestigationSummaryRequest request,
            int externalFacing,
            int criticalAssetCount,
            int falsePositiveAssets,
            int eolCount,
            Map<String, Integer> osCounts,
            Map<String, Integer> softwareCounts
    ) {
        List<String> findings = new ArrayList<>();
        findings.add(request.summary().cveId() + " affects " + request.affectedAssets().size()
                + " assets across " + Math.max(softwareCounts.size(), 1) + " software families.");
        if (externalFacing > 0) {
            findings.add(externalFacing + " affected assets are externally facing and should be prioritized for containment.");
        }
        if (criticalAssetCount > 0) {
            findings.add(criticalAssetCount + " affected assets are marked critical by the current investigation evidence.");
        }
        if (falsePositiveAssets > 0) {
            findings.add(falsePositiveAssets + " assets were identified as not impacted through vendor advisory or VEX evidence.");
        }
        if (eolCount > 0) {
            findings.add(eolCount + " software entries are at or near end of life, increasing long-term remediation risk.");
        }
        if (!osCounts.isEmpty()) {
            String dominantOs = osCounts.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(entry -> entry.getKey() + " (" + entry.getValue() + ")")
                    .orElse("Unknown");
            findings.add("The largest affected operating system cohort is " + dominantOs + ".");
        }
        return findings;
    }

    private List<CveInvestigationSummaryResponse.RemediationAction> buildRemediationPlan(
            SummaryFields summary,
            int externalFacing,
            int criticalAssetCount,
            int unpatchedVulnerable,
            int eolCount
    ) {
        List<CveInvestigationSummaryResponse.RemediationAction> actions = new ArrayList<>();
        int priority = 1;

        if (externalFacing > 0) {
            actions.add(new CveInvestigationSummaryResponse.RemediationAction(
                    priority++,
                    "P1",
                    "Contain external-facing exposure",
                    "Isolate or harden externally exposed assets first, starting with internet-facing systems carrying the affected software footprint.",
                    "Network / Platform",
                    "Immediate",
                    "containment"
            ));
        }

        if (summary.patchAvailable()) {
            actions.add(new CveInvestigationSummaryResponse.RemediationAction(
                    priority++,
                    "P1",
                    "Deploy vendor patch baseline",
                    "Roll out the vendor-recommended patch level"
                            + (summary.patchVersions() != null && !summary.patchVersions().isBlank()
                            ? " (" + summary.patchVersions() + ")"
                            : "")
                            + " to all impacted assets after validating business-critical systems.",
                    "Endpoint / Platform",
                    "Short-term",
                    "patch"
            ));
        } else {
            actions.add(new CveInvestigationSummaryResponse.RemediationAction(
                    priority++,
                    "P1",
                    "Apply compensating controls",
                    "No authoritative patch is available. Reduce exploitability with segmentation, service restriction, and temporary configuration changes.",
                    "Platform / Security Ops",
                    "Immediate",
                    "mitigation"
            ));
        }

        if (criticalAssetCount > 0) {
            actions.add(new CveInvestigationSummaryResponse.RemediationAction(
                    priority++,
                    "P2",
                    "Prioritize critical asset owners",
                    "Coordinate remediation in owner order for critical assets first to compress exposure reduction on high-value systems.",
                    "Asset Owners",
                    "Short-term",
                    "coordination"
            ));
        }

        if (eolCount > 0) {
            actions.add(new CveInvestigationSummaryResponse.RemediationAction(
                    priority++,
                    "P2",
                    "Upgrade end-of-life software",
                    "Replace unsupported or near-EOL software versions with supported releases to remove repeated future exposure and patch lag.",
                    "Platform Engineering",
                    "Medium-term",
                    "upgrade"
            ));
        }

        if (unpatchedVulnerable > 0) {
            actions.add(new CveInvestigationSummaryResponse.RemediationAction(
                    priority++,
                    "P3",
                    "Validate remediation coverage",
                    "Track unpatched vulnerable assets until patch deployment, compensating control rollout, or explicit vendor clearance is complete.",
                    "Security Operations",
                    "Long-term",
                    "validation"
            ));
        }

        return actions.stream()
                .sorted(Comparator.comparingInt(CveInvestigationSummaryResponse.RemediationAction::priority))
                .toList();
    }

    private List<CveInvestigationSummaryResponse.RemediationAction> buildRemediationPlan(
            CveInvestigationSummaryRequest request,
            int externalFacing,
            int criticalAssetCount,
            int unpatchedVulnerable,
            int eolCount
    ) {
        List<CveInvestigationSummaryResponse.RemediationAction> actions = new ArrayList<>();
        int priority = 1;

        if (externalFacing > 0) {
            actions.add(new CveInvestigationSummaryResponse.RemediationAction(
                    priority++,
                    "P1",
                    "Contain external-facing exposure",
                    "Isolate or harden externally exposed assets first, starting with internet-facing systems carrying the affected software footprint.",
                    "Network / Platform",
                    "Immediate",
                    "containment"
            ));
        }

        if (Boolean.TRUE.equals(request.summary().patchAvailable())) {
            actions.add(new CveInvestigationSummaryResponse.RemediationAction(
                    priority++,
                    "P1",
                    "Deploy vendor patch baseline",
                    "Roll out the vendor-recommended patch level"
                            + (request.summary().patchVersions() != null && !request.summary().patchVersions().isBlank()
                            ? " (" + request.summary().patchVersions() + ")"
                            : "")
                            + " to all impacted assets after validating business-critical systems.",
                    "Endpoint / Platform",
                    "Short-term",
                    "patch"
            ));
        } else {
            actions.add(new CveInvestigationSummaryResponse.RemediationAction(
                    priority++,
                    "P1",
                    "Apply compensating controls",
                    "No authoritative patch is available. Reduce exploitability with segmentation, service restriction, and temporary configuration changes.",
                    "Platform / Security Ops",
                    "Immediate",
                    "mitigation"
            ));
        }

        if (criticalAssetCount > 0) {
            actions.add(new CveInvestigationSummaryResponse.RemediationAction(
                    priority++,
                    "P2",
                    "Prioritize critical asset owners",
                    "Coordinate remediation in owner order for critical assets first to compress exposure reduction on high-value systems.",
                    "Asset Owners",
                    "Short-term",
                    "coordination"
            ));
        }

        if (eolCount > 0) {
            actions.add(new CveInvestigationSummaryResponse.RemediationAction(
                    priority++,
                    "P2",
                    "Upgrade end-of-life software",
                    "Replace unsupported or near-EOL software versions with supported releases to remove repeated future exposure and patch lag.",
                    "Platform Engineering",
                    "Medium-term",
                    "upgrade"
            ));
        }

        if (unpatchedVulnerable > 0) {
            actions.add(new CveInvestigationSummaryResponse.RemediationAction(
                    priority++,
                    "P3",
                    "Validate remediation coverage",
                    "Track unpatched vulnerable assets until patch deployment, compensating control rollout, or explicit vendor clearance is complete.",
                    "Security Operations",
                    "Long-term",
                    "validation"
            ));
        }

        return actions.stream()
                .sorted(Comparator.comparingInt(CveInvestigationSummaryResponse.RemediationAction::priority))
                .toList();
    }

    private String buildExecutiveSummary(
            SummaryFields summary,
            CveInvestigationSummaryResponse.RiskAnalysis riskAnalysis,
            int totalAffected,
            int externalFacing,
            int truePositiveAssets,
            int falsePositiveAssets,
            int eolCount
    ) {
        return (
                "%s is currently assessed as %s risk. The investigation identified %d impacted assets, including %d external-facing systems. "
                        + "%d assets remain true positives after vendor-advisory review, while %d assets were cleared as false positives. "
                        + "%d software rows carry end-of-life risk, and the recommended remediation path is to prioritize containment, patching, and lifecycle upgrades in that order."
        ).formatted(
                        summary.cveId(),
                        riskAnalysis.level().toLowerCase(Locale.ROOT),
                        totalAffected,
                        externalFacing,
                        truePositiveAssets,
                        falsePositiveAssets,
                        eolCount
                );
    }

    private String buildExecutiveSummary(
            CveInvestigationSummaryRequest request,
            CveInvestigationSummaryResponse.RiskAnalysis riskAnalysis,
            int externalFacing,
            int truePositiveAssets,
            int falsePositiveAssets,
            int eolCount
    ) {
        return (
                "%s is currently assessed as %s risk. The investigation identified %d impacted assets, including %d external-facing systems. "
                        + "%d assets remain true positives after vendor-advisory review, while %d assets were cleared as false positives. "
                        + "%d software rows carry end-of-life risk, and the recommended remediation path is to prioritize containment, patching, and lifecycle upgrades in that order."
        ).formatted(
                        request.summary().cveId(),
                        riskAnalysis.level().toLowerCase(Locale.ROOT),
                        request.affectedAssets().size(),
                        externalFacing,
                        truePositiveAssets,
                        falsePositiveAssets,
                        eolCount
                );
    }

    private Map<String, Integer> buildOsCountsFromFields(List<AssetFields> assets) {
        Map<String, Integer> counts = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        assets.stream()
                .map(AssetFields::os)
                .filter(os -> os != null && !os.isBlank())
                .forEach(os -> counts.merge(os, 1, Integer::sum));
        return counts;
    }

    private Map<String, Integer> buildSoftwareCountsFromFields(List<AssetFields> assets) {
        Map<String, Integer> counts = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        assets.forEach(asset -> asset.matchedSoftware().forEach(sw -> counts.merge(sw.software(), 1, Integer::sum)));
        return counts;
    }

    private Map<String, Integer> buildOsCounts(List<CveInvestigationSummaryRequest.AffectedAsset> assets) {
        Map<String, Integer> counts = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        assets.stream()
                .map(CveInvestigationSummaryRequest.AffectedAsset::os)
                .filter(os -> os != null && !os.isBlank())
                .forEach(os -> counts.merge(os, 1, Integer::sum));
        return counts;
    }

    private Map<String, Integer> buildSoftwareCounts(List<CveInvestigationSummaryRequest.AffectedAsset> assets) {
        Map<String, Integer> counts = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        assets.forEach(asset -> asset.matchedSoftware().forEach(sw -> counts.merge(sw.software(), 1, Integer::sum)));
        return counts;
    }

    private boolean isLifecycleAtRisk(CveInvestigationSummaryRequest.EolRow row) {
        String lifecycle = row.lifecycle() == null ? "" : row.lifecycle().toUpperCase(Locale.ROOT);
        return lifecycle.contains("END OF LIFE") || lifecycle.contains("NEAR END OF LIFE") || lifecycle.contains("NEAR END");
    }

    private boolean isLifecycleAtRisk(EolFields row) {
        String lifecycle = row.lifecycle() == null ? "" : row.lifecycle().toUpperCase(Locale.ROOT);
        return lifecycle.contains("END OF LIFE") || lifecycle.contains("NEAR END OF LIFE") || lifecycle.contains("NEAR END");
    }

    private int severityBaseScore(String severity) {
        if (severity == null) return 35;
        return switch (severity.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 72;
            case "HIGH" -> 60;
            case "MEDIUM" -> 42;
            case "LOW" -> 24;
            default -> 35;
        };
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> asMap(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Collections.emptyMap();
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> asList(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Object entry : list) {
            if (entry instanceof Map<?, ?> map) {
                rows.add((Map<String, Object>) map);
            }
        }
        return rows;
    }

    private String asString(Object value) {
        if (value == null) return null;
        if (value instanceof String str) return str;
        return String.valueOf(value);
    }

    private boolean asBoolean(Object value) {
        if (value instanceof Boolean bool) return bool;
        if (value instanceof String str) return Boolean.parseBoolean(str);
        return false;
    }

    private Integer asInteger(Object value) {
        if (value instanceof Number number) return number.intValue();
        if (value instanceof String str && !str.isBlank()) {
            try {
                return Integer.parseInt(str);
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private SummaryFields summaryFields(String cveId, Map<String, Object> raw) {
        return new SummaryFields(
                asString(raw.getOrDefault("cveId", cveId)),
                asString(raw.get("severity")),
                asBoolean(raw.get("inKev")),
                asBoolean(raw.get("exploitAvailable")),
                asBoolean(raw.get("patchAvailable")),
                asString(raw.get("patchVersions"))
        );
    }

    private List<AssetFields> affectedAssets(List<Map<String, Object>> rows) {
        return rows.stream()
                .map(row -> new AssetFields(
                        asString(row.get("os")),
                        asBoolean(row.get("externalFacing")),
                        asBoolean(row.get("critical")),
                        asList(row.get("matchedSoftware")).stream()
                                .map(sw -> new SoftwareFields(asString(sw.get("software")), asString(sw.get("version"))))
                                .toList()
                ))
                .toList();
    }

    private List<FalsePositiveFields> falsePositiveRows(List<Map<String, Object>> rows) {
        return rows.stream()
                .map(row -> new FalsePositiveFields(
                        asBoolean(row.get("falsePositive")),
                        asInteger(row.get("assetsNotImpacted"))
                ))
                .toList();
    }

    private List<EolFields> eolRows(List<Map<String, Object>> rows) {
        return rows.stream()
                .map(row -> new EolFields(asString(row.get("lifecycle"))))
                .toList();
    }

    private record SummaryFields(
            String cveId,
            String severity,
            boolean inKev,
            boolean exploitAvailable,
            boolean patchAvailable,
            String patchVersions
    ) {}

    private record AssetFields(
            String os,
            boolean externalFacing,
            boolean critical,
            List<SoftwareFields> matchedSoftware
    ) {}

    private record SoftwareFields(
            String software,
            String version
    ) {}

    private record FalsePositiveFields(
            boolean falsePositive,
            Integer assetsNotImpacted
    ) {}

    private record EolFields(
            String lifecycle
    ) {}
}
