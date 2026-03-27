package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityConfigExpr;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.repo.VulnerabilityConfigExprRepository;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class FindingCorrelationAnalysisService {

    @Value("${app.correlation.non-cpe-create-min-confidence:0.68}")
    private double nonCpeCreateMinConfidence;

    private final VulnerabilityConfigExprRepository vulnerabilityConfigExprRepository;
    private final ApplicabilityDecisionService applicabilityDecisionService;
    private final NvdConfigurationDecisionService nvdConfigurationDecisionService;
    private final PrecedenceResolverService precedenceResolverService;

    public FindingCorrelationAnalysisService(
            VulnerabilityConfigExprRepository vulnerabilityConfigExprRepository,
            ApplicabilityDecisionService applicabilityDecisionService,
            NvdConfigurationDecisionService nvdConfigurationDecisionService,
            PrecedenceResolverService precedenceResolverService
    ) {
        this.vulnerabilityConfigExprRepository = vulnerabilityConfigExprRepository;
        this.applicabilityDecisionService = applicabilityDecisionService;
        this.nvdConfigurationDecisionService = nvdConfigurationDecisionService;
        this.precedenceResolverService = precedenceResolverService;
    }

    public Map<UUID, List<PrecedenceResolverService.CandidateDecision>> buildCandidateDecisionsByVulnerability(
            InventoryComponent component,
            List<CorrelationCandidateService.CandidateMatch> candidates,
            RiskPolicy policy
    ) {
        Map<UUID, List<PrecedenceResolverService.CandidateDecision>> candidateDecisionsByVulnerability = new HashMap<>();
        Map<UUID, List<VulnerabilityConfigExpr>> nvdTreeByVulnerability = nvdExpressionsByVulnerability(candidates);
        for (CorrelationCandidateService.CandidateMatch candidate : candidates) {
            VulnerabilityTarget target = candidate.target();
            UUID vulnerabilityId = target.getVulnerability().getId();
            ApplicabilityDecisionService.ApplicabilityDecision applicabilityDecision =
                    applicabilityDecisionService.evaluateCorrelation(component, target, policy);
            applicabilityDecision = applyNvdConfigurationDecision(
                    component,
                    target,
                    applicabilityDecision,
                    nvdTreeByVulnerability.getOrDefault(vulnerabilityId, List.of())
            );
            Map<String, Double> confidenceBreakdown = new LinkedHashMap<>(candidate.confidenceBreakdown());
            double confidence = applyApplicabilityPenalty(confidenceBreakdown, candidate.confidence(), applicabilityDecision);
            PrecedenceResolverService.CandidateDecision decision = new PrecedenceResolverService.CandidateDecision(
                    target,
                    candidate.matchedBy(),
                    candidate.rank(),
                    confidence,
                    confidenceBreakdown,
                    applicabilityDecision
            );
            candidateDecisionsByVulnerability
                    .computeIfAbsent(vulnerabilityId, ignored -> new ArrayList<>())
                    .add(decision);
        }
        return candidateDecisionsByVulnerability;
    }

    public PrecedenceResolverService.CandidateDecision selectAutomaticFindingCandidate(
            PrecedenceResolverService.PrecedenceResolution resolution,
            List<PrecedenceResolverService.CandidateDecision> decisions
    ) {
        if (resolution == null || decisions == null || decisions.isEmpty()) {
            return null;
        }
        PrecedenceResolverService.CandidateDecision primary = resolution.primary();
        if (primary == null
                || primary.target() == null
                || primary.applicabilityDecision() == null
                || !primary.applicabilityDecision().isAffected()) {
            return null;
        }
        if (isFindingCreationEligible(primary)) {
            return primary;
        }

        int sourcePriority = precedenceResolverService.sourcePriority(primary.target().getSource());
        return decisions.stream()
                .filter(Objects::nonNull)
                .filter(candidate -> candidate.target() != null)
                .filter(candidate -> candidate.applicabilityDecision() != null && candidate.applicabilityDecision().isAffected())
                .filter(this::isFindingCreationEligible)
                .filter(candidate -> precedenceResolverService.sourcePriority(candidate.target().getSource()) == sourcePriority)
                .sorted(Comparator
                        .comparingInt(PrecedenceResolverService.CandidateDecision::rank)
                        .thenComparing(Comparator.comparingDouble(PrecedenceResolverService.CandidateDecision::confidence).reversed())
                        .thenComparing(candidate -> candidate.target().getId(), Comparator.nullsLast(Comparator.naturalOrder())))
                .findFirst()
                .orElse(null);
    }

    public String categorizeNotApplicableReason(String applicabilityReason, String precedenceReason, String source) {
        String reason = applicabilityReason == null ? "" : applicabilityReason.trim().toLowerCase(Locale.ROOT);
        String precedence = precedenceReason == null ? "" : precedenceReason.trim().toLowerCase(Locale.ROOT);
        String normalizedSource = source == null ? "" : source.trim().toLowerCase(Locale.ROOT);

        if (reason.contains("stale_or_untrusted")) {
            return "VEX Stale Or Untrusted";
        }
        if (reason.contains("vex_not_affected")) {
            return "VEX Not Affected";
        }
        if (reason.contains("vex_fixed")) {
            return "VEX Fixed";
        }
        if (reason.contains("nvd_config_override_not_affected")) {
            return "NVD Configuration Not Affected";
        }
        if (reason.contains("exact_version_mismatch")
                || reason.contains("below_introduced")
                || reason.contains("at_or_above_fixed")
                || reason.contains("below_start")
                || reason.contains("above_end")
                || reason.contains("mismatch")) {
            return "Version Outside Affected Range";
        }
        if (precedence.contains("highest_precedence_not_affected")
                && (normalizedSource.contains("csaf")
                || normalizedSource.contains("advisory")
                || normalizedSource.contains("ghsa"))) {
            return "Vendor Advisory Not Affected";
        }
        return "Correlation Not Affected";
    }

    private Map<UUID, List<VulnerabilityConfigExpr>> nvdExpressionsByVulnerability(
            List<CorrelationCandidateService.CandidateMatch> candidates
    ) {
        Set<Vulnerability> vulnerabilities = candidates.stream()
                .map(CorrelationCandidateService.CandidateMatch::target)
                .filter(target -> target.getSource() != null && target.getSource().toLowerCase(Locale.ROOT).contains("nvd"))
                .map(VulnerabilityTarget::getVulnerability)
                .collect(Collectors.toSet());
        if (vulnerabilities.isEmpty()) {
            return Map.of();
        }
        List<VulnerabilityConfigExpr> rows = vulnerabilityConfigExprRepository.findByVulnerabilityInAndSource(vulnerabilities, "nvd");
        Map<UUID, List<VulnerabilityConfigExpr>> grouped = new HashMap<>();
        for (VulnerabilityConfigExpr row : rows) {
            if (row.getVulnerability() == null || row.getVulnerability().getId() == null) {
                continue;
            }
            grouped.computeIfAbsent(row.getVulnerability().getId(), ignored -> new ArrayList<>()).add(row);
        }
        return grouped;
    }

    private ApplicabilityDecisionService.ApplicabilityDecision applyNvdConfigurationDecision(
            InventoryComponent component,
            VulnerabilityTarget target,
            ApplicabilityDecisionService.ApplicabilityDecision current,
            List<VulnerabilityConfigExpr> nvdExpressions
    ) {
        if (target.getSource() == null || !target.getSource().toLowerCase(Locale.ROOT).contains("nvd")) {
            return current;
        }

        ApplicabilityDecisionService.ApplicabilityDecision treeDecision = nvdConfigurationDecisionService.evaluate(component, nvdExpressions);
        Map<String, Object> mergedTrace = new LinkedHashMap<>();
        mergedTrace.put("baseApplicability", current.trace());
        mergedTrace.put("nvdConfiguration", treeDecision.trace());

        if (treeDecision.result() == ApplicabilityDecisionService.ApplicabilityResult.FALSE) {
            return new ApplicabilityDecisionService.ApplicabilityDecision(
                    ApplicabilityDecisionService.ApplicabilityResult.FALSE,
                    "nvd_config_override_not_affected",
                    mergedTrace
            );
        }
        if (current.result() == ApplicabilityDecisionService.ApplicabilityResult.FALSE) {
            return current;
        }
        if (treeDecision.result() == ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN) {
            return new ApplicabilityDecisionService.ApplicabilityDecision(
                    ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN,
                    "nvd_config_unknown",
                    mergedTrace
            );
        }
        return new ApplicabilityDecisionService.ApplicabilityDecision(
                current.result(),
                current.reason(),
                mergedTrace
        );
    }

    private double applyApplicabilityPenalty(
            Map<String, Double> confidenceBreakdown,
            double currentConfidence,
            ApplicabilityDecisionService.ApplicabilityDecision applicabilityDecision
    ) {
        double penalty = 0.0;
        if (applicabilityDecision.result() == ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN
                && applicabilityDecision.reason() != null
                && (applicabilityDecision.reason().contains("compare_error")
                || applicabilityDecision.reason().contains("nvd_config_unknown"))) {
            penalty = 0.12;
        }
        confidenceBreakdown.put("applicabilityPenalty", penalty);
        return Math.max(0.05, Math.min(0.99, currentConfidence - penalty));
    }

    private boolean isCpeMatchMethod(String matchedBy) {
        if (!hasText(matchedBy)) {
            return false;
        }
        return matchedBy.trim().toLowerCase(Locale.ROOT).startsWith("cpe-");
    }

    private boolean isFindingCreationEligible(PrecedenceResolverService.CandidateDecision decision) {
        if (decision == null || !hasText(decision.matchedBy())) {
            return false;
        }
        return isFindingCreationEligible(decision.matchedBy(), decision.confidence());
    }

    private boolean isFindingCreationEligible(String matchedBy, Double confidenceScore) {
        if (!hasText(matchedBy)) {
            return false;
        }
        if (isCpeMatchMethod(matchedBy)) {
            return true;
        }
        if (!isSupportedNonCpeMatch(matchedBy)) {
            return false;
        }
        return (confidenceScore == null ? 0.0 : confidenceScore) >= nonCpeCreateMinConfidence;
    }

    private boolean isSupportedNonCpeMatch(String matchedBy) {
        String normalized = matchedBy == null ? "" : matchedBy.trim().toLowerCase(Locale.ROOT);
        return normalized.startsWith("identity-")
                || normalized.startsWith("purl-")
                || normalized.startsWith("coord-")
                || normalized.startsWith("advisory-pkg-");
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
