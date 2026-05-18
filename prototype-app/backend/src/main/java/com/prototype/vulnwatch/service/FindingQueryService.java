package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.FindingFilterValuesResponse;
import com.prototype.vulnwatch.dto.FindingPageResponse;
import com.prototype.vulnwatch.dto.FindingResponse;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingQueryService {

    private final FindingRepository findingRepository;
    private final ObjectMapper objectMapper;
    private final FindingsScoreService findingsScoreService;
    private final RiskPolicyService riskPolicyService;

    public FindingQueryService(
            FindingRepository findingRepository,
            ObjectMapper objectMapper,
            FindingsScoreService findingsScoreService,
            RiskPolicyService riskPolicyService
    ) {
        this.findingRepository = findingRepository;
        this.objectMapper = objectMapper;
        this.findingsScoreService = findingsScoreService;
        this.riskPolicyService = riskPolicyService;
    }

    @Transactional(readOnly = true)
    public FindingPageResponse listByTenantPage(
            Tenant tenant,
            int page,
            int size,
            List<String> severity,
            List<String> status,
            List<String> decisionState,
            List<String> matchMethod,
            List<String> vexStatus,
            List<String> vexFreshness,
            List<String> vexProvider,
            Double minConfidence,
            String vulnerabilityId,
            String packageName,
            String ecosystem
    ) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(200, size));
        Pageable pageable = PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.DESC, "updatedAt"));

        Specification<Finding> specification = byFilter(
                tenant,
                severity,
                status,
                decisionState,
                matchMethod,
                vexStatus,
                vexFreshness,
                vexProvider,
                minConfidence,
                vulnerabilityId,
                packageName,
                ecosystem
        );
        Page<Finding> findings = findingRepository.findAll(specification, pageable);
        return new FindingPageResponse(
                findings.getContent().stream().map(this::toResponse).toList(),
                findings.getNumber(),
                findings.getSize(),
                findings.getTotalElements(),
                findings.getTotalPages()
        );
    }

    @Transactional(readOnly = true)
    public List<Finding> listEntitiesByTenantFilter(
            Tenant tenant,
            List<String> severity,
            List<String> status,
            List<String> decisionState,
            List<String> matchMethod,
            List<String> vexStatus,
            List<String> vexFreshness,
            List<String> vexProvider,
            Double minConfidence,
            String vulnerabilityId,
            String packageName,
            String ecosystem
    ) {
        Specification<Finding> specification = byFilter(
                tenant,
                severity,
                status,
                decisionState,
                matchMethod,
                vexStatus,
                vexFreshness,
                vexProvider,
                minConfidence,
                vulnerabilityId,
                packageName,
                ecosystem
        );
        return findingRepository.findAll(specification, Sort.by(Sort.Direction.DESC, "updatedAt"));
    }

    @Transactional(readOnly = true)
    public List<Finding> listEntitiesByTenantAndIds(Tenant tenant, List<UUID> findingIds) {
        if (findingIds == null || findingIds.isEmpty()) {
            return List.of();
        }
        return findingRepository.findAllById(findingIds).stream()
                .filter(finding -> finding.getTenant() != null
                        && finding.getTenant().getId() != null
                        && finding.getTenant().getId().equals(tenant.getId()))
                .toList();
    }

    @Transactional(readOnly = true)
    public List<FindingResponse> listByTenant(Tenant tenant) {
        return findingRepository.findByTenantOrderByUpdatedAtDesc(tenant).stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public FindingFilterValuesResponse listAvailableFilters(Tenant tenant) {
        LinkedHashSet<String> severities = new LinkedHashSet<>();
        findingRepository.findDistinctSeveritiesByTenant(tenant).stream()
                .filter(this::hasText)
                .map(value -> value.trim().toUpperCase(Locale.ROOT))
                .forEach(severities::add);
        severities.addAll(List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"));

        LinkedHashSet<String> statuses = new LinkedHashSet<>();
        findingRepository.findDistinctStatusesByTenant(tenant).stream()
                .filter(Objects::nonNull)
                .map(Enum::name)
                .forEach(statuses::add);
        for (FindingStatus status : FindingStatus.values()) {
            statuses.add(status.name());
        }

        LinkedHashSet<String> decisionStates = new LinkedHashSet<>();
        findingRepository.findDistinctDecisionStatesByTenant(tenant).stream()
                .filter(Objects::nonNull)
                .map(Enum::name)
                .forEach(decisionStates::add);
        for (FindingDecisionState decisionState : FindingDecisionState.values()) {
            decisionStates.add(decisionState.name());
        }

        LinkedHashSet<String> matchMethods = new LinkedHashSet<>();
        findingRepository.findDistinctMatchMethodsByTenant(tenant).stream()
                .filter(this::hasText)
                .map(value -> value.trim().toLowerCase(Locale.ROOT))
                .forEach(matchMethods::add);

        LinkedHashSet<String> vexStatuses = new LinkedHashSet<>();
        findingRepository.findDistinctVexStatusesByTenant(tenant).stream()
                .filter(this::hasText)
                .map(value -> value.trim().toUpperCase(Locale.ROOT))
                .forEach(vexStatuses::add);
        vexStatuses.addAll(List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "NO_PATCH", "UNDER_INVESTIGATION", "UNKNOWN"));

        LinkedHashSet<String> vexFreshness = new LinkedHashSet<>();
        findingRepository.findDistinctVexFreshnessByTenant(tenant).stream()
                .filter(this::hasText)
                .map(value -> value.trim().toUpperCase(Locale.ROOT))
                .forEach(vexFreshness::add);
        vexFreshness.addAll(List.of("FRESH", "STALE", "UNKNOWN"));

        LinkedHashSet<String> vexProviders = new LinkedHashSet<>();
        findingRepository.findDistinctVexProvidersByTenant(tenant).stream()
                .filter(this::hasText)
                .map(value -> value.trim().toLowerCase(Locale.ROOT))
                .forEach(vexProviders::add);
        vexProviders.add("unknown");

        return new FindingFilterValuesResponse(
                sortByPreferredOrder(severities, List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")),
                sortByPreferredOrder(statuses, List.of("OPEN", "RESOLVED", "SUPPRESSED", "AUTO_CLOSED")),
                sortByPreferredOrder(
                        decisionStates,
                        List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "UNDER_INVESTIGATION", "NEEDS_REVIEW")
                ),
                matchMethods.stream().sorted().toList(),
                sortByPreferredOrder(vexStatuses, List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "NO_PATCH", "UNDER_INVESTIGATION", "UNKNOWN")),
                sortByPreferredOrder(vexFreshness, List.of("FRESH", "STALE", "UNKNOWN")),
                vexProviders.stream().sorted().toList()
        );
    }

    @Transactional(readOnly = true)
    public List<FindingResponse> listLatestByTenant(Tenant tenant, int limit) {
        Pageable pageable = PageRequest.of(0, Math.max(1, Math.min(200, limit)), Sort.by(Sort.Direction.DESC, "updatedAt"));
        return findingRepository.findByTenantOrderByUpdatedAtDesc(tenant, pageable).getContent().stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public long countOpen(Tenant tenant) {
        return findingRepository.countByTenantAndStatus(tenant, FindingStatus.OPEN);
    }

    @Transactional(readOnly = true)
    public long countCritical(Tenant tenant) {
        return findingRepository.countByTenantAndStatusAndRiskScoreGreaterThanEqual(tenant, FindingStatus.OPEN, 9.0);
    }

    public FindingResponse toResponse(Finding finding) {
        Vulnerability vulnerability = finding.getVulnerability();
        InventoryComponent component = finding.getComponent();
        Map<String, Object> evidencePayload = readEvidencePayload(finding.getEvidence());

        String scoreConfig = riskPolicyService.getFindingsScoreConfig(finding.getTenant());
        double findingsScore = findingsScoreService.compute(scoreConfig, finding);

        return new FindingResponse(
                finding.getId(),
                finding.getDisplayId(),
                component.getId(),
                finding.getAsset().getName(),
                finding.getAsset().getIdentifier(),
                finding.getAsset().getType().name(),
                component.getPackageName(),
                component.getVersion(),
                vulnerability.getExternalId(),
                vulnerability.getSource().name(),
                finding.getSeverityOverride() != null ? finding.getSeverityOverride() : vulnerability.getSeverity(),
                vulnerability.isInKev(),
                vulnerability.getEpssScore(),
                finding.getRiskScore(),
                finding.getConfidenceScore(),
                finding.getMatchedBy(),
                finding.getAssignedTo(),
                finding.getDueAt(),
                finding.getSuppressionReason(),
                finding.getSuppressedUntil(),
                finding.getEvidence(),
                finding.getPrecedenceTrace(),
                finding.getVexStatus(),
                finding.getVexProvider(),
                finding.getVexFreshness(),
                finding.getMatchedVexAssertionId(),
                traceString(evidencePayload, "impactReason"),
                finding.getFirstObservedAt(),
                finding.getLastObservedAt(),
                finding.getDecisionState(),
                finding.getStatus(),
                finding.getUpdatedAt(),
                component.getEolSlug(),
                component.getEolCycle(),
                component.getEolDate(),
                component.getIsEol(),
                component.getEolDate() != null
                        ? (int) ChronoUnit.DAYS.between(LocalDate.now(), component.getEolDate())
                        : null,
                finding.getIncidentId(),
                finding.getIncidentStatus(),
                findingsScore,
                finding.getSuppressedByRuleId(),
                finding.getSuppressedByRuleName(),
                finding.getOwnerGroup());
    }

    private Specification<Finding> byTenant(Tenant tenant) {
        return (root, query, cb) -> cb.equal(root.get("tenant"), tenant);
    }

    private Specification<Finding> byFilter(
            Tenant tenant,
            List<String> severity,
            List<String> status,
            List<String> decisionState,
            List<String> matchMethod,
            List<String> vexStatus,
            List<String> vexFreshness,
            List<String> vexProvider,
            Double minConfidence,
            String vulnerabilityId,
            String packageName,
            String ecosystem
    ) {
        return byTenant(tenant)
                .and(bySeverity(severity))
                .and(byStatus(status))
                .and(byDecisionState(decisionState))
                .and(byMatchMethod(matchMethod))
                .and(byVexStatus(vexStatus))
                .and(byVexFreshness(vexFreshness))
                .and(byVexProvider(vexProvider))
                .and(byMinConfidence(minConfidence))
                .and(byVulnerabilityId(vulnerabilityId))
                .and(byPackageName(packageName))
                .and(byEcosystem(ecosystem));
    }

    private Specification<Finding> bySeverity(List<String> severities) {
        Set<String> normalized = normalizeFilterValues(severities);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<String> upper = normalized.stream().map(String::toUpperCase).collect(Collectors.toSet());
        return (root, query, cb) -> {
            jakarta.persistence.criteria.Expression<String> override =
                    cb.upper(root.<String>get("severityOverride"));
            jakarta.persistence.criteria.Expression<String> vulnSev =
                    cb.upper(root.join("vulnerability").get("severity"));
            jakarta.persistence.criteria.Expression<String> effective = cb.coalesce(override, vulnSev);
            return effective.in(upper);
        };
    }

    private Specification<Finding> byStatus(List<String> statuses) {
        Set<String> normalized = normalizeFilterValues(statuses);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<FindingStatus> findingStatuses = new HashSet<>();
        for (String value : normalized) {
            try {
                findingStatuses.add(FindingStatus.valueOf(value.toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException ignored) {
                // Ignore unknown status values and proceed with valid tokens.
            }
        }
        if (findingStatuses.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> root.get("status").in(findingStatuses);
    }

    private Specification<Finding> byDecisionState(List<String> decisionStates) {
        Set<String> normalized = normalizeFilterValues(decisionStates);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<FindingDecisionState> states = new HashSet<>();
        for (String value : normalized) {
            try {
                states.add(FindingDecisionState.valueOf(value.toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException ignored) {
                // Ignore unknown values and continue with valid tokens.
            }
        }
        if (states.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> root.get("decisionState").in(states);
    }

    private Specification<Finding> byMatchMethod(List<String> matchMethods) {
        Set<String> normalized = normalizeFilterValues(matchMethods);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<String> lower = normalized.stream().map(value -> value.toLowerCase(Locale.ROOT)).collect(Collectors.toSet());
        return (root, query, cb) -> cb.lower(root.get("matchedBy")).in(lower);
    }

    private Specification<Finding> byVexStatus(List<String> vexStatuses) {
        Set<String> normalized = normalizeUpperFilterValues(vexStatuses);
        if (normalized.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (normalized.contains("UNKNOWN")) {
                predicates.add(cb.isNull(root.get("vexStatus")));
            }
            predicates.add(cb.upper(root.get("vexStatus")).in(normalized));
            return cb.or(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };
    }

    private Specification<Finding> byVexFreshness(List<String> vexFreshness) {
        Set<String> normalized = normalizeUpperFilterValues(vexFreshness);
        if (normalized.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (normalized.contains("UNKNOWN")) {
                predicates.add(cb.isNull(root.get("vexFreshness")));
            }
            predicates.add(cb.upper(root.get("vexFreshness")).in(normalized));
            return cb.or(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };
    }

    private Specification<Finding> byVexProvider(List<String> vexProviders) {
        Set<String> normalized = normalizeLowerFilterValues(vexProviders);
        if (normalized.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (normalized.contains("unknown")) {
                predicates.add(cb.isNull(root.get("vexProvider")));
            }
            predicates.add(cb.lower(root.get("vexProvider")).in(normalized));
            return cb.or(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };
    }

    private Specification<Finding> byMinConfidence(Double minConfidence) {
        if (minConfidence == null) {
            return null;
        }
        return (root, query, cb) -> cb.greaterThanOrEqualTo(root.get("confidenceScore"), minConfidence);
    }

    private Specification<Finding> byVulnerabilityId(String vulnerabilityId) {
        if (!hasText(vulnerabilityId)) {
            return null;
        }
        String expected = vulnerabilityId.trim().toUpperCase(Locale.ROOT);
        return (root, query, cb) -> cb.equal(
                cb.upper(root.join("vulnerability").get("externalId")),
                expected
        );
    }

    private Specification<Finding> byPackageName(String packageName) {
        if (!hasText(packageName)) {
            return null;
        }
        String expected = packageName.trim().toLowerCase(Locale.ROOT);
        return (root, query, cb) -> cb.equal(
                cb.lower(root.join("component").get("packageName")),
                expected
        );
    }

    private Specification<Finding> byEcosystem(String ecosystem) {
        if (!hasText(ecosystem)) {
            return null;
        }
        String expected = ecosystem.trim().toLowerCase(Locale.ROOT);
        return (root, query, cb) -> cb.equal(
                cb.lower(root.join("component").get("ecosystem")),
                expected
        );
    }

    private Map<String, Object> readEvidencePayload(String evidence) {
        if (!hasText(evidence)) {
            return new LinkedHashMap<>();
        }
        try {
            JsonNode node = objectMapper.readTree(evidence);
            return objectMapper.convertValue(node, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception ignored) {
            return new LinkedHashMap<>();
        }
    }

    private String traceString(Map<String, Object> trace, String key) {
        if (trace == null || trace.isEmpty() || key == null || key.isBlank()) {
            return null;
        }
        Object value = trace.get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    private Set<String> normalizeUpperFilterValues(List<String> rawValues) {
        return normalizeFilterValues(rawValues).stream()
                .map(value -> value.trim().toUpperCase(Locale.ROOT))
                .collect(Collectors.toSet());
    }

    private Set<String> normalizeLowerFilterValues(List<String> rawValues) {
        return normalizeFilterValues(rawValues).stream()
                .map(value -> value.trim().toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
    }

    private Set<String> normalizeFilterValues(List<String> rawValues) {
        if (rawValues == null || rawValues.isEmpty()) {
            return Set.of();
        }
        Set<String> values = new HashSet<>();
        for (String rawValue : rawValues) {
            if (!hasText(rawValue)) {
                continue;
            }
            String[] splitValues = rawValue.split(",");
            for (String splitValue : splitValues) {
                String normalized = splitValue == null ? "" : splitValue.trim();
                if (normalized.isEmpty() || "ALL".equalsIgnoreCase(normalized)) {
                    continue;
                }
                values.add(normalized);
            }
        }
        return values;
    }

    private List<String> sortByPreferredOrder(Set<String> values, List<String> preferredOrder) {
        Set<String> remaining = new LinkedHashSet<>(values);
        List<String> sorted = new ArrayList<>();
        for (String preferredValue : preferredOrder) {
            if (remaining.remove(preferredValue)) {
                sorted.add(preferredValue);
            }
        }
        sorted.addAll(remaining.stream().sorted().toList());
        return sorted;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
