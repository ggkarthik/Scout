package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

@Service
public class PrecedenceResolverService {

    public enum FinalState {
        AFFECTED,
        NOT_AFFECTED,
        UNKNOWN
    }

    public record CandidateDecision(
            VulnerabilityTarget target,
            String matchedBy,
            int rank,
            double confidence,
            Map<String, Double> confidenceBreakdown,
            ApplicabilityDecisionService.ApplicabilityDecision applicabilityDecision
    ) {
    }

    public record PrecedenceResolution(
            FinalState finalState,
            CandidateDecision primary,
            String reason,
            List<Map<String, Object>> sourcePrecedence,
            List<Map<String, Object>> considered,
            Map<String, Object> precedenceTrace
    ) {
    }

    public PrecedenceResolution resolve(List<CandidateDecision> decisions) {
        if (decisions == null || decisions.isEmpty()) {
            return new PrecedenceResolution(
                    FinalState.UNKNOWN,
                    null,
                    "no_candidates",
                    List.of(),
                    List.of(),
                    Map.of("finalReason", "no_candidates"));
        }

        List<CandidateDecision> sorted = decisions.stream()
                .filter(Objects::nonNull)
                .sorted(priorityComparator())
                .toList();

        List<Map<String, Object>> sourcePrecedence = sourcePrecedence(sorted);
        List<Map<String, Object>> considered = considered(sorted);
        List<Integer> priorityLevels = sorted.stream()
                .map(candidate -> sourceProfile(candidate.target().getSource()).priority())
                .distinct()
                .sorted()
                .toList();

        List<Map<String, Object>> priorityEvaluation = new ArrayList<>();
        for (Integer level : priorityLevels) {
            List<CandidateDecision> tier = sorted.stream()
                    .filter(candidate -> sourceProfile(candidate.target().getSource()).priority() == level)
                    .toList();
            CandidateDecision bestTrue = firstByResult(tier, ApplicabilityDecisionService.ApplicabilityResult.TRUE);
            CandidateDecision bestFalse = firstByResult(tier, ApplicabilityDecisionService.ApplicabilityResult.FALSE);
            CandidateDecision bestUnknown = firstByResult(tier, ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN);
            SourceProfile tierProfile = tier.isEmpty() ? sourceProfile("unknown") : sourceProfile(tier.get(0).target().getSource());
            boolean bestFalseEligible = isNotAffectedEligibleForTier(bestFalse, tierProfile);

            Map<String, Object> tierTrace = new LinkedHashMap<>();
            tierTrace.put("priority", level);
            tierTrace.put("sourceClass", tierProfile.sourceClass());
            tierTrace.put("notAffectedOverrides", tierProfile.notAffectedOverrides());
            tierTrace.put("affectedCandidate", candidateId(bestTrue));
            tierTrace.put("notAffectedCandidate", candidateId(bestFalse));
            tierTrace.put("notAffectedCandidateEligible", bestFalseEligible);
            tierTrace.put("unknownCandidate", candidateId(bestUnknown));
            priorityEvaluation.add(tierTrace);

            if (bestFalseEligible && tierProfile.notAffectedOverrides()) {
                return new PrecedenceResolution(
                        FinalState.NOT_AFFECTED,
                        bestFalse,
                        "authoritative_source_not_affected_override",
                        sourcePrecedence,
                        considered,
                        buildTrace("authoritative_source_not_affected_override", priorityEvaluation)
                );
            }

            if (bestTrue != null) {
                return new PrecedenceResolution(
                        FinalState.AFFECTED,
                        bestTrue,
                        "highest_precedence_affected",
                        sourcePrecedence,
                        considered,
                        buildTrace("highest_precedence_affected", priorityEvaluation)
                );
            }

            if (bestFalseEligible) {
                return new PrecedenceResolution(
                        FinalState.NOT_AFFECTED,
                        bestFalse,
                        "highest_precedence_not_affected",
                        sourcePrecedence,
                        considered,
                        buildTrace("highest_precedence_not_affected", priorityEvaluation)
                );
            }
        }

        CandidateDecision bestUnknown = firstByResult(sorted, ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN);
        if (bestUnknown != null) {
            return new PrecedenceResolution(
                    FinalState.UNKNOWN,
                    bestUnknown,
                    "no_decisive_candidate",
                    sourcePrecedence,
                    considered,
                    buildTrace("no_decisive_candidate", priorityEvaluation)
            );
        }

        return new PrecedenceResolution(
                FinalState.UNKNOWN,
                null,
                "no_candidate_after_filter",
                sourcePrecedence,
                considered,
                buildTrace("no_candidate_after_filter", priorityEvaluation));
    }

    private CandidateDecision firstByResult(
            List<CandidateDecision> sorted,
            ApplicabilityDecisionService.ApplicabilityResult result
    ) {
        return sorted.stream()
                .filter(candidate -> candidate.applicabilityDecision() != null && candidate.applicabilityDecision().result() == result)
                .findFirst()
                .orElse(null);
    }

    private List<Map<String, Object>> sourcePrecedence(List<CandidateDecision> sorted) {
        Map<String, Integer> sourceOrder = sorted.stream()
                .map(candidate -> normalizeSource(candidate.target().getSource()))
                .distinct()
                .collect(Collectors.toMap(
                        source -> source,
                        source -> sourceProfile(source).priority(),
                        (left, right) -> left,
                        LinkedHashMap::new
                ));

        List<Map<String, Object>> entries = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : sourceOrder.entrySet()) {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("source", entry.getKey());
            payload.put("priority", entry.getValue());
            entries.add(payload);
        }
        return entries;
    }

    private List<Map<String, Object>> considered(List<CandidateDecision> sorted) {
        List<Map<String, Object>> entries = new ArrayList<>();
        for (CandidateDecision candidate : sorted) {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("targetId", candidate.target().getId());
            payload.put("targetSource", candidate.target().getSource());
            payload.put("matchedBy", candidate.matchedBy());
            payload.put("rank", candidate.rank());
            payload.put("confidence", candidate.confidence());
            payload.put("applicabilityResult",
                    candidate.applicabilityDecision() == null ? ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN.name()
                            : candidate.applicabilityDecision().result().name());
            payload.put("applicabilityReason",
                    candidate.applicabilityDecision() == null ? "missing_decision" : candidate.applicabilityDecision().reason());
            entries.add(payload);
        }
        return entries;
    }

    private Comparator<CandidateDecision> priorityComparator() {
        return Comparator
                .comparingInt((CandidateDecision candidate) -> sourcePriority(candidate.target().getSource()))
                .thenComparingInt(CandidateDecision::rank)
                .thenComparing(Comparator.comparingDouble(CandidateDecision::confidence).reversed())
                .thenComparing(candidate -> candidate.target().getId());
    }

    int sourcePriority(String source) {
        return sourceProfile(source).priority();
    }

    private SourceProfile sourceProfile(String source) {
        String normalized = normalizeSource(source);
        if (normalized.contains("vex")) {
            return new SourceProfile(0, "vendor-vex", true);
        }
        if (normalized.contains("csaf") || normalized.contains("advisory") || normalized.contains("ghsa")) {
            return new SourceProfile(1, "vendor-advisory", false);
        }
        if (normalized.contains("nvd")) {
            return new SourceProfile(2, "nvd", false);
        }
        if (normalized.contains("kev")) {
            return new SourceProfile(3, "kev", false);
        }
        return new SourceProfile(4, "other", false);
    }

    private String normalizeSource(String source) {
        if (source == null || source.isBlank()) {
            return "unknown";
        }
        return source.trim().toLowerCase(Locale.ROOT);
    }

    private Map<String, Object> buildTrace(String reason, List<Map<String, Object>> priorityEvaluation) {
        Map<String, Object> trace = new LinkedHashMap<>();
        trace.put("engine", "source-precedence-v2");
        trace.put("reason", reason);
        trace.put("priorityEvaluation", priorityEvaluation);
        return trace;
    }

    private boolean isNotAffectedEligibleForTier(CandidateDecision candidate, SourceProfile tierProfile) {
        if (candidate == null || candidate.applicabilityDecision() == null) {
            return false;
        }
        if (!tierProfile.notAffectedOverrides()) {
            return true;
        }
        String reason = candidate.applicabilityDecision().reason();
        if (reason == null || reason.isBlank()) {
            return false;
        }
        String normalizedReason = reason.trim().toLowerCase(Locale.ROOT);
        if (normalizedReason.contains("stale_or_untrusted")) {
            return false;
        }
        return normalizedReason.contains("vex_not_affected") || normalizedReason.contains("vex_fixed");
    }

    private String candidateId(CandidateDecision candidate) {
        if (candidate == null || candidate.target() == null || candidate.target().getId() == null) {
            return null;
        }
        return candidate.target().getId().toString();
    }

    private record SourceProfile(int priority, String sourceClass, boolean notAffectedOverrides) {
    }
}
