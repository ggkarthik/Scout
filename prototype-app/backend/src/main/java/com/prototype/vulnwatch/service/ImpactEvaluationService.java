package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import java.time.Instant;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class ImpactEvaluationService {

    private static final Set<ImpactState> FINDING_ELIGIBLE_IMPACT_STATES = Set.of(ImpactState.IMPACTED, ImpactState.NO_PATCH);

    public record VexOverlayOutcome(
            boolean applied,
            PrecedenceResolverService.FinalState finalState,
            String status,
            String provider,
            String freshness,
            String source,
            UUID assertionId,
            UUID targetId,
            Instant targetUpdatedAt,
            String reason
    ) {
        public static VexOverlayOutcome none() {
            return new VexOverlayOutcome(
                    false,
                    PrecedenceResolverService.FinalState.AFFECTED,
                    null,
                    "unknown",
                    "UNKNOWN",
                    null,
                    null,
                    null,
                    null,
                    "none"
            );
        }
    }

    public record ImpactAssessment(
            ApplicabilityState applicabilityState,
            String applicabilityReason,
            String applicabilityReasonDetail,
            ImpactState impactState,
            String impactReason,
            String impactReasonDetail,
            boolean findingEligible,
            FindingDecisionState findingDecisionState
    ) {
    }

    public ImpactAssessment evaluate(
            PrecedenceResolverService.PrecedenceResolution resolution,
            PrecedenceResolverService.CandidateDecision selected,
            VexOverlayOutcome vexOverlay
    ) {
        ApplicabilityState applicabilityState = resolveApplicabilityState(resolution, selected);
        String applicabilityReason = resolveApplicabilityReason(resolution, selected);
        String applicabilityReasonDetail = describeApplicability(applicabilityState, applicabilityReason, selected, resolution);

        ImpactState impactState;
        String impactReason;
        if (applicabilityState == ApplicabilityState.NOT_APPLICABLE) {
            impactState = ImpactState.NOT_IMPACTED;
            impactReason = "no_supported_match_in_software_inventory";
        } else if (applicabilityState == ApplicabilityState.UNKNOWN) {
            impactState = ImpactState.UNKNOWN;
            impactReason = "applicability_unknown";
        } else if (vexOverlay != null && vexOverlay.applied()) {
            String normalizedStatus = normalizeStatus(vexOverlay.status());
            if ("NO_PATCH".equals(normalizedStatus)) {
                impactState = ImpactState.NO_PATCH;
                impactReason = "vex_no_patch";
            } else if ("FIXED".equals(normalizedStatus)) {
                impactState = ImpactState.FIXED;
                impactReason = "vex_fixed";
            } else if ("NOT_AFFECTED".equals(normalizedStatus)
                    || vexOverlay.finalState() == PrecedenceResolverService.FinalState.NOT_AFFECTED) {
                impactState = ImpactState.NOT_IMPACTED;
                impactReason = "vex_not_affected";
            } else if ("UNDER_INVESTIGATION".equals(normalizedStatus)
                    || vexOverlay.finalState() == PrecedenceResolverService.FinalState.UNKNOWN) {
                impactState = ImpactState.UNDER_INVESTIGATION;
                impactReason = "vex_under_investigation";
            } else if ("AFFECTED".equals(normalizedStatus)) {
                impactState = ImpactState.IMPACTED;
                impactReason = "vex_affected";
            } else {
                impactState = ImpactState.UNKNOWN;
                impactReason = "awaiting_vex_assessment";
            }
        } else {
            impactState = ImpactState.UNKNOWN;
            impactReason = "awaiting_vex_assessment";
        }

        return new ImpactAssessment(
                applicabilityState,
                applicabilityReason,
                applicabilityReasonDetail,
                impactState,
                impactReason,
                describeImpact(impactState, impactReason, selected, vexOverlay),
                FINDING_ELIGIBLE_IMPACT_STATES.contains(impactState),
                toFindingDecisionState(impactState)
        );
    }

    public String normalizeStatus(String value) {
        if (!hasText(value)) {
            return "UNKNOWN";
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        if (normalized.contains("NO_PATCH")
                || normalized.contains("NO_FIX")
                || normalized.contains("WONT_FIX")
                || normalized.contains("WON'T_FIX")
                || normalized.contains("UNFIXABLE")) {
            return "NO_PATCH";
        }
        if (normalized.contains("NOT_AFFECTED")) {
            return "NOT_AFFECTED";
        }
        if (normalized.contains("UNDER_INVESTIGATION")) {
            return "UNDER_INVESTIGATION";
        }
        if (normalized.contains("FIXED")) {
            return "FIXED";
        }
        if (normalized.contains("AFFECTED")) {
            return "AFFECTED";
        }
        return "UNKNOWN";
    }

    public String normalizeProvider(String value) {
        if (!hasText(value)) {
            return "unknown";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    public String normalizeFreshness(String value) {
        if (!hasText(value)) {
            return "UNKNOWN";
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        if ("NO_DATE_ASSUME_FRESH".equals(normalized)) {
            return "UNKNOWN";
        }
        if (normalized.contains("STALE")) {
            return "STALE";
        }
        if (normalized.contains("FRESH")) {
            return "FRESH";
        }
        return "UNKNOWN";
    }

    private ApplicabilityState resolveApplicabilityState(
            PrecedenceResolverService.PrecedenceResolution resolution,
            PrecedenceResolverService.CandidateDecision selected
    ) {
        if (resolution != null) {
            if (resolution.finalState() == PrecedenceResolverService.FinalState.AFFECTED) {
                return ApplicabilityState.APPLICABLE;
            }
            if (resolution.finalState() == PrecedenceResolverService.FinalState.NOT_AFFECTED) {
                return ApplicabilityState.NOT_APPLICABLE;
            }
        }
        if (selected != null && selected.applicabilityDecision() != null) {
            return switch (selected.applicabilityDecision().result()) {
                case TRUE -> ApplicabilityState.APPLICABLE;
                case FALSE -> ApplicabilityState.NOT_APPLICABLE;
                case UNKNOWN -> ApplicabilityState.UNKNOWN;
            };
        }
        return ApplicabilityState.UNKNOWN;
    }

    private String resolveApplicabilityReason(
            PrecedenceResolverService.PrecedenceResolution resolution,
            PrecedenceResolverService.CandidateDecision selected
    ) {
        if (selected != null && selected.applicabilityDecision() != null && hasText(selected.applicabilityDecision().reason())) {
            return selected.applicabilityDecision().reason();
        }
        if (resolution != null && hasText(resolution.reason())) {
            return resolution.reason();
        }
        return "unknown";
    }

    private String describeApplicability(
            ApplicabilityState applicabilityState,
            String reason,
            PrecedenceResolverService.CandidateDecision selected,
            PrecedenceResolverService.PrecedenceResolution resolution
    ) {
        VulnerabilityTarget target = selected == null ? null : selected.target();
        String versionScope = versionScope(target);
        String componentVersion = selected != null && selected.applicabilityDecision() != null && selected.applicabilityDecision().trace() != null
                ? stringValue(selected.applicabilityDecision().trace().get("componentVersion"))
                : null;
        return switch (applicabilityState) {
            case APPLICABLE -> hasText(versionScope)
                    ? "Installed software version " + defaultText(componentVersion, "unknown")
                    + " matches the vulnerable scope " + versionScope + "."
                    : "Installed software and version matched a vulnerability target in inventory correlation.";
            case NOT_APPLICABLE -> {
                if (hasText(reason) && reason.contains("VERSION_UNKNOWN")) {
                    yield "Installed software was matched, but the asset version is missing so applicability cannot be proven.";
                }
                if (hasText(versionScope)) {
                    yield "Installed version " + defaultText(componentVersion, "unknown")
                            + " is outside the vulnerable scope " + versionScope + ".";
                }
                yield "No supported software and version correlation was found for this asset.";
            }
            case UNKNOWN -> resolution != null && "no_candidates".equals(resolution.reason())
                    ? "No correlation candidates were available for this asset software combination."
                    : "Inventory correlation found partial evidence, but the applicable software/version could not be resolved confidently.";
        };
    }

    private String describeImpact(
            ImpactState impactState,
            String impactReason,
            PrecedenceResolverService.CandidateDecision selected,
            VexOverlayOutcome vexOverlay
    ) {
        String provider = vexOverlay == null ? "vendor" : defaultText(vexOverlay.provider(), "vendor");
        String versionScope = versionScope(selected == null ? null : selected.target());
        return switch (impactState) {
            case IMPACTED -> "Exact VEX evidence from " + provider
                    + " confirms the installed software/version is affected"
                    + (hasText(versionScope) ? " within " + versionScope : "") + ".";
            case NO_PATCH -> "Exact VEX evidence from " + provider
                    + " confirms the installed software/version is affected and no patch is available.";
            case FIXED -> "Exact VEX evidence from " + provider
                    + " marks this software/version as fixed"
                    + (hasText(versionScope) ? " relative to " + versionScope : "") + ".";
            case NOT_IMPACTED -> "no_supported_match_in_software_inventory".equals(impactReason)
                    ? "Installed software/version correlation does not place this asset within the affected scope."
                    : "Exact VEX evidence from " + provider
                    + " marks the installed software/version as not affected.";
            case UNDER_INVESTIGATION -> "VEX evidence exists, but the vendor still marks this software/version as under investigation.";
            case UNKNOWN -> "awaiting_vex_assessment".equals(impactReason)
                    ? "The component is applicable, but no exact VEX statement matched this asset software version."
                    : "Impact could not be resolved with exact VEX evidence for this asset software version.";
        };
    }

    private FindingDecisionState toFindingDecisionState(ImpactState impactState) {
        return switch (impactState) {
            case IMPACTED, NO_PATCH -> FindingDecisionState.AFFECTED;
            case FIXED -> FindingDecisionState.FIXED;
            case NOT_IMPACTED -> FindingDecisionState.NOT_AFFECTED;
            case UNDER_INVESTIGATION, UNKNOWN -> FindingDecisionState.UNDER_INVESTIGATION;
        };
    }

    private String versionScope(VulnerabilityTarget target) {
        if (target == null) {
            return null;
        }
        if (hasText(target.getVersionExact())) {
            return "version " + target.getVersionExact().trim();
        }
        StringBuilder builder = new StringBuilder();
        if (hasText(target.getIntroduced())) {
            builder.append("introduced ").append(target.getIntroduced().trim());
        }
        if (hasText(target.getFixed())) {
            if (builder.length() > 0) {
                builder.append(", ");
            }
            builder.append("fixed before ").append(target.getFixed().trim());
        }
        if (hasText(target.getVersionStart())) {
            if (builder.length() > 0) {
                builder.append(", ");
            }
            builder.append(Boolean.FALSE.equals(target.getStartInclusive()) ? ">" : ">=").append(target.getVersionStart().trim());
        }
        if (hasText(target.getVersionEnd())) {
            if (builder.length() > 0) {
                builder.append(", ");
            }
            builder.append(Boolean.FALSE.equals(target.getEndInclusive()) ? "<" : "<=").append(target.getVersionEnd().trim());
        }
        return builder.length() == 0 ? null : builder.toString();
    }

    private String stringValue(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    private String defaultText(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
