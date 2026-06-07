package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.dto.FindingPortfolioQueueRollupResponse;
import com.prototype.vulnwatch.dto.FindingPortfolioRollupResponse;
import com.prototype.vulnwatch.dto.FindingQueueDefinitionResponse;
import com.prototype.vulnwatch.dto.FindingQueueWorkloadBreakdownResponse;
import com.prototype.vulnwatch.dto.FindingsFilter;
import com.prototype.vulnwatch.dto.FindingSummaryResponse;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingPortfolioRollupService {

    private static final int MAX_BREAKDOWN_ITEMS = 5;

    private final FindingListProjectionService findingListProjectionService;
    private final FindingQueueService findingQueueService;
    private final FindingAnalyticsService findingAnalyticsService;

    public FindingPortfolioRollupService(
            FindingListProjectionService findingListProjectionService,
            FindingQueueService findingQueueService,
            FindingAnalyticsService findingAnalyticsService
    ) {
        this.findingListProjectionService = findingListProjectionService;
        this.findingQueueService = findingQueueService;
        this.findingAnalyticsService = findingAnalyticsService;
    }

    @Transactional(readOnly = true)
    public FindingPortfolioRollupResponse getPortfolioRollup(Tenant tenant) {
        FindingsFilter openFilter = new FindingsFilter(
                null,
                List.of(FindingStatus.OPEN.name()),
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
        FindingSummaryResponse summary = findingAnalyticsService.getSummary(tenant, new FindingsFilter(
                null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null
        ));
        List<FindingQueueDefinitionResponse> queues = findingQueueService.listQueues(tenant);
        List<FindingListProjectionService.ProjectionRecord> openFindings = findingListProjectionService.loadRows(tenant, openFilter);

        return new FindingPortfolioRollupResponse(
                summary.openCount(),
                summary.criticalOpenCount(),
                summary.overdueOpenCount(),
                queues.stream()
                        .map(this::toQueueRollup)
                        .toList(),
                topBreakdown(openFindings, FindingListProjectionService.ProjectionRecord::ownerGroup, "No Owner Group"),
                topBreakdown(openFindings, FindingListProjectionService.ProjectionRecord::supportGroup, "No Support Group")
        );
    }

    private FindingPortfolioQueueRollupResponse toQueueRollup(FindingQueueDefinitionResponse queue) {
        return new FindingPortfolioQueueRollupResponse(
                queue.key(),
                queue.title(),
                queue.matchingCount(),
                queue.summary().openCount(),
                queue.summary().criticalOpenCount(),
                queue.summary().overdueOpenCount(),
                queue.summary().unassignedOpenCount(),
                queue.summary().withIncidentCount()
        );
    }

    private List<FindingQueueWorkloadBreakdownResponse> topBreakdown(
            List<FindingListProjectionService.ProjectionRecord> findings,
            java.util.function.Function<FindingListProjectionService.ProjectionRecord, String> labelExtractor,
            String fallback
    ) {
        Map<String, Long> counts = findings.stream()
                .collect(Collectors.groupingBy(
                        finding -> defaultLabel(labelExtractor.apply(finding), fallback),
                        LinkedHashMap::new,
                        Collectors.counting()
                ));
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder())
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(MAX_BREAKDOWN_ITEMS)
                .map(entry -> new FindingQueueWorkloadBreakdownResponse(entry.getKey(), entry.getValue()))
                .toList();
    }

    private String defaultLabel(String value, String fallback) {
        return FindingFilterSpecifications.hasText(value) ? value.trim() : fallback;
    }
}
