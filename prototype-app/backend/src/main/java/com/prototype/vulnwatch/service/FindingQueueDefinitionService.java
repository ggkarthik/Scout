package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingQueueDefinitionResponse;
import com.prototype.vulnwatch.dto.FindingSummaryResponse;
import com.prototype.vulnwatch.dto.FindingsFilter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingQueueDefinitionService {

    private static final String KIND_BUILT_IN = "BUILT_IN";
    private static final String OWNER_TYPE_SYSTEM = "SYSTEM";

    private final FindingAnalyticsService findingAnalyticsService;
    private final Map<String, QueueDefinition> builtInDefinitions;

    public FindingQueueDefinitionService(FindingAnalyticsService findingAnalyticsService) {
        this.findingAnalyticsService = findingAnalyticsService;
        this.builtInDefinitions = buildDefinitions();
    }

    @Transactional(readOnly = true)
    public List<FindingQueueDefinitionResponse> listBuiltInQueues(Tenant tenant, String defaultQueueRef) {
        return builtInDefinitions.values().stream()
                .map(definition -> toBuiltInResponse(tenant, definition, Objects.equals(definition.key(), defaultQueueRef)))
                .toList();
    }

    @Transactional(readOnly = true)
    public Optional<FindingQueueDefinitionResponse> getBuiltInQueue(Tenant tenant, String queueRef, String defaultQueueRef) {
        return findBuiltIn(queueRef)
                .map(definition -> toBuiltInResponse(tenant, definition, Objects.equals(definition.key(), defaultQueueRef)));
    }

    public Optional<FindingsFilter> findBuiltInFilter(String queueRef) {
        return findBuiltIn(queueRef).map(QueueDefinition::filter);
    }

    public Optional<String> findBuiltInTitle(String queueRef) {
        return findBuiltIn(queueRef).map(QueueDefinition::title);
    }

    public boolean isBuiltIn(String queueRef) {
        return findBuiltIn(queueRef).isPresent();
    }

    private FindingQueueDefinitionResponse toBuiltInResponse(Tenant tenant, QueueDefinition definition, boolean isDefault) {
        FindingSummaryResponse summary = findingAnalyticsService.getSummary(tenant, definition.filter());
        return new FindingQueueDefinitionResponse(
                null,
                definition.key(),
                definition.title(),
                definition.description(),
                KIND_BUILT_IN,
                OWNER_TYPE_SYSTEM,
                false,
                isDefault,
                findingAnalyticsService.getMatchingCount(tenant, definition.filter()),
                definition.filter(),
                summary
        );
    }

    private Optional<QueueDefinition> findBuiltIn(String queueRef) {
        String normalized = queueRef == null ? "" : queueRef.trim().toLowerCase(Locale.ROOT);
        return Optional.ofNullable(builtInDefinitions.get(normalized));
    }

    private Map<String, QueueDefinition> buildDefinitions() {
        Map<String, QueueDefinition> definitions = new LinkedHashMap<>();
        definitions.put("all-findings", new QueueDefinition(
                "all-findings",
                "All Findings",
                "Full findings backlog across the active tenant.",
                new FindingsFilter(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null)
        ));
        definitions.put("critical-open", new QueueDefinition(
                "critical-open",
                "Critical Open",
                "Open findings currently scored at critical severity.",
                new FindingsFilter(List.of("CRITICAL"), List.of("OPEN"), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null)
        ));
        definitions.put("overdue", new QueueDefinition(
                "overdue",
                "Overdue",
                "Open findings that are already past their due date.",
                new FindingsFilter(null, List.of("OPEN"), null, null, null, null, null, null, null, null, null, null, null, null, null, null, "overdue", null, null, null, null)
        ));
        definitions.put("unassigned-open", new QueueDefinition(
                "unassigned-open",
                "Unassigned Open",
                "Open findings with no current assignee.",
                new FindingsFilter(null, List.of("OPEN"), null, null, null, null, null, null, null, null, null, null, null, null, true, null, null, null, null, null, null)
        ));
        definitions.put("with-incidents", new QueueDefinition(
                "with-incidents",
                "With Incidents",
                "Findings already linked to incident records.",
                new FindingsFilter(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, true, null, null, null, null, null)
        ));
        definitions.put("incident-needed", new QueueDefinition(
                "incident-needed",
                "Incident Needed",
                "Open findings that do not yet have incident tracking.",
                new FindingsFilter(null, List.of("OPEN"), null, null, null, null, null, null, null, null, null, null, null, null, null, false, null, null, null, null, null)
        ));
        definitions.put("patch-available", new QueueDefinition(
                "patch-available",
                "Patch Available",
                "Findings where a fix is available now.",
                new FindingsFilter(null, List.of("OPEN"), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, true, null)
        ));
        definitions.put("sla-breach-risk", new QueueDefinition(
                "sla-breach-risk",
                "SLA Breach Risk",
                "Open findings already overdue or due within the next seven days.",
                new FindingsFilter(null, List.of("OPEN"), null, null, null, null, null, null, null, null, null, null, null, null, null, null, "due-soon", null, null, null, null)
        ));
        definitions.put("unassigned-critical", new QueueDefinition(
                "unassigned-critical",
                "Unassigned Critical",
                "Critical open findings without an assignee.",
                new FindingsFilter(List.of("CRITICAL"), List.of("OPEN"), null, null, null, null, null, null, null, null, null, null, null, null, true, null, null, null, null, null, null)
        ));
        definitions.put("deferred-expiring-soon", new QueueDefinition(
                "deferred-expiring-soon",
                "Deferred Expiring Soon",
                "Suppressed findings whose deferral expires within seven days.",
                new FindingsFilter(null, List.of("SUPPRESSED"), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, "expiring-soon")
        ));
        return definitions;
    }

    record QueueDefinition(
            String key,
            String title,
            String description,
            FindingsFilter filter
    ) {
    }
}
