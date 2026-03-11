package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.VexAssertion;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.repo.VexAssertionRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class VexAssertionMatchService {

    private final VexAssertionRepository vexAssertionRepository;
    private final ApplicabilityDecisionService applicabilityDecisionService;
    private final VexPolicyService vexPolicyService;
    private final ImpactEvaluationService impactEvaluationService;
    private final PrecedenceResolverService precedenceResolverService;

    public VexAssertionMatchService(
            VexAssertionRepository vexAssertionRepository,
            ApplicabilityDecisionService applicabilityDecisionService,
            VexPolicyService vexPolicyService,
            ImpactEvaluationService impactEvaluationService,
            PrecedenceResolverService precedenceResolverService
    ) {
        this.vexAssertionRepository = vexAssertionRepository;
        this.applicabilityDecisionService = applicabilityDecisionService;
        this.vexPolicyService = vexPolicyService;
        this.impactEvaluationService = impactEvaluationService;
        this.precedenceResolverService = precedenceResolverService;
    }

    public ImpactEvaluationService.VexOverlayOutcome resolve(
            InventoryComponent component,
            UUID vulnerabilityId,
            String sourceKey,
            List<CorrelationCandidateService.CandidateMatch> candidateMatches,
            RiskPolicy policy
    ) {
        if (component == null || component.getId() == null || vulnerabilityId == null
                || candidateMatches == null || candidateMatches.isEmpty()) {
            return ImpactEvaluationService.VexOverlayOutcome.none();
        }

        Map<UUID, List<VexAssertion>> assertionsByTargetId = loadAssertionsByTarget(candidateMatches, vulnerabilityId, sourceKey);
        if (assertionsByTargetId.isEmpty()) {
            return ImpactEvaluationService.VexOverlayOutcome.none();
        }

        List<ResolvedAssertion> exactMatches = new ArrayList<>();
        for (CorrelationCandidateService.CandidateMatch candidate : candidateMatches) {
            VulnerabilityTarget target = candidate.target();
            if (target == null
                    || target.getId() == null
                    || target.getVulnerability() == null
                    || !vulnerabilityId.equals(target.getVulnerability().getId())) {
                continue;
            }

            List<VexAssertion> assertions = assertionsByTargetId.getOrDefault(target.getId(), List.of());
            if (assertions.isEmpty()) {
                continue;
            }

            ApplicabilityDecisionService.ApplicabilityDecision correlationDecision =
                    applicabilityDecisionService.evaluateCorrelation(component, target, policy);
            if (correlationDecision.result() != ApplicabilityDecisionService.ApplicabilityResult.TRUE) {
                continue;
            }

            for (VexAssertion assertion : assertions) {
                exactMatches.add(resolveAssertion(assertion, target, candidate, correlationDecision, policy));
            }
        }

        if (exactMatches.isEmpty()) {
            return ImpactEvaluationService.VexOverlayOutcome.none();
        }

        exactMatches.sort(bestMatchComparator());
        int bestSourcePriority = precedenceResolverService.sourcePriority(exactMatches.get(0).assertion().getSourceSystem());
        int bestRank = exactMatches.get(0).candidate().rank();
        List<ResolvedAssertion> topTier = exactMatches.stream()
                .filter(match -> precedenceResolverService.sourcePriority(match.assertion().getSourceSystem()) == bestSourcePriority)
                .filter(match -> match.candidate().rank() == bestRank)
                .toList();

        Set<String> decisiveStatuses = new LinkedHashSet<>();
        for (ResolvedAssertion match : topTier) {
            if (!"UNKNOWN".equals(match.effectiveStatus())) {
                decisiveStatuses.add(match.effectiveStatus());
            }
        }
        if (decisiveStatuses.size() > 1) {
            ResolvedAssertion anchor = topTier.get(0);
            return new ImpactEvaluationService.VexOverlayOutcome(
                    true,
                    PrecedenceResolverService.FinalState.UNKNOWN,
                    "UNKNOWN",
                    anchor.provider(),
                    anchor.freshness(),
                    anchor.assertion().getSourceSystem(),
                    anchor.assertion().getId(),
                    anchor.target().getId(),
                    anchor.targetUpdatedAt(),
                    "conflicting_exact_vex_assertions"
            );
        }

        ResolvedAssertion best = topTier.stream()
                .filter(match -> !"UNKNOWN".equals(match.effectiveStatus()))
                .findFirst()
                .orElse(topTier.get(0));

        return new ImpactEvaluationService.VexOverlayOutcome(
                true,
                finalStateFor(best.effectiveStatus()),
                best.effectiveStatus(),
                best.provider(),
                best.freshness(),
                best.assertion().getSourceSystem(),
                best.assertion().getId(),
                best.target().getId(),
                best.targetUpdatedAt(),
                best.reason()
        );
    }

    private Map<UUID, List<VexAssertion>> loadAssertionsByTarget(
            List<CorrelationCandidateService.CandidateMatch> candidateMatches,
            UUID vulnerabilityId,
            String sourceKey
    ) {
        Set<UUID> targetIds = new LinkedHashSet<>();
        for (CorrelationCandidateService.CandidateMatch candidate : candidateMatches) {
            VulnerabilityTarget target = candidate.target();
            if (target == null
                    || target.getId() == null
                    || target.getVulnerability() == null
                    || !vulnerabilityId.equals(target.getVulnerability().getId())) {
                continue;
            }
            targetIds.add(target.getId());
        }
        if (targetIds.isEmpty()) {
            return Map.of();
        }

        String sourceFilter = sourceKey == null ? "" : sourceKey.trim().toLowerCase(Locale.ROOT);
        Map<UUID, List<VexAssertion>> assertionsByTargetId = new LinkedHashMap<>();
        for (VexAssertion assertion : vexAssertionRepository.findByTarget_IdIn(targetIds)) {
            if (!sourceFilter.isEmpty()
                    && (assertion.getSourceSystem() == null
                    || !assertion.getSourceSystem().toLowerCase(Locale.ROOT).contains(sourceFilter))) {
                continue;
            }
            if (assertion.getTarget() == null || assertion.getTarget().getId() == null) {
                continue;
            }
            assertionsByTargetId.computeIfAbsent(assertion.getTarget().getId(), ignored -> new ArrayList<>()).add(assertion);
        }
        return assertionsByTargetId;
    }

    private ResolvedAssertion resolveAssertion(
            VexAssertion assertion,
            VulnerabilityTarget target,
            CorrelationCandidateService.CandidateMatch candidate,
            ApplicabilityDecisionService.ApplicabilityDecision correlationDecision,
            RiskPolicy policy
    ) {
        String normalizedStatus = impactEvaluationService.normalizeStatus(assertion.getStatus());
        VexPolicyService.VexFreshness freshnessEvaluation = vexPolicyService.evaluateFreshness(
                normalizedStatus,
                assertion.getPublishedAt(),
                assertion.getLastSeenAt(),
                policy
        );
        String freshness = impactEvaluationService.normalizeFreshness(freshnessEvaluation.outcome());
        boolean trustedForSuppression = vexPolicyService.isTrustedForSuppression(assertion.getTrustTier());
        String effectiveStatus = normalizedStatus;
        String reason = "exact_vex_match";

        if ("NOT_AFFECTED".equals(normalizedStatus) || "FIXED".equals(normalizedStatus)) {
            if (!trustedForSuppression || !freshnessEvaluation.fresh()) {
                effectiveStatus = "UNKNOWN";
                reason = "FIXED".equals(normalizedStatus)
                        ? "vex_fixed_stale_or_untrusted"
                        : "vex_not_affected_stale_or_untrusted";
            }
        } else if ("UNKNOWN".equals(normalizedStatus)) {
            reason = "unknown_vex_status";
        } else if ("UNDER_INVESTIGATION".equals(normalizedStatus)) {
            reason = "vex_under_investigation";
        } else if ("NO_PATCH".equals(normalizedStatus)) {
            reason = "vex_no_patch";
        } else if ("AFFECTED".equals(normalizedStatus)) {
            reason = "vex_affected";
        }

        return new ResolvedAssertion(
                assertion,
                target,
                candidate,
                correlationDecision,
                effectiveStatus,
                impactEvaluationService.normalizeProvider(assertion.getProvider()),
                freshness,
                reason,
                target.getUpdatedAt()
        );
    }

    private Comparator<ResolvedAssertion> bestMatchComparator() {
        return Comparator
                .comparingInt((ResolvedAssertion match) -> precedenceResolverService.sourcePriority(match.assertion().getSourceSystem()))
                .thenComparingInt(match -> match.candidate().rank())
                .thenComparingInt(match -> "UNKNOWN".equals(match.effectiveStatus()) ? 1 : 0)
                .thenComparing(Comparator.comparingDouble((ResolvedAssertion match) -> match.candidate().confidence()).reversed())
                .thenComparing((ResolvedAssertion match) -> match.assertion().getUpdatedAt(), Comparator.nullsLast(Comparator.reverseOrder()))
                .thenComparing(match -> match.assertion().getId(), Comparator.nullsLast(Comparator.naturalOrder()));
    }

    private PrecedenceResolverService.FinalState finalStateFor(String status) {
        return switch (status) {
            case "NOT_AFFECTED", "FIXED" -> PrecedenceResolverService.FinalState.NOT_AFFECTED;
            case "AFFECTED", "NO_PATCH" -> PrecedenceResolverService.FinalState.AFFECTED;
            default -> PrecedenceResolverService.FinalState.UNKNOWN;
        };
    }

    private record ResolvedAssertion(
            VexAssertion assertion,
            VulnerabilityTarget target,
            CorrelationCandidateService.CandidateMatch candidate,
            ApplicabilityDecisionService.ApplicabilityDecision correlationDecision,
            String effectiveStatus,
            String provider,
            String freshness,
            String reason,
            Instant targetUpdatedAt
    ) {
    }
}
