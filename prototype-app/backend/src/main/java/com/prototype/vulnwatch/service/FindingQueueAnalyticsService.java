package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.FindingEvent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingQueueAgingBucketResponse;
import com.prototype.vulnwatch.dto.FindingQueueAnalyticsResponse;
import com.prototype.vulnwatch.dto.FindingQueueAnalyticsTrendPointResponse;
import com.prototype.vulnwatch.dto.FindingQueueWorkloadBreakdownResponse;
import com.prototype.vulnwatch.dto.FindingsFilter;
import com.prototype.vulnwatch.repo.FindingEventRepository;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingQueueAnalyticsService {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final int DEFAULT_REOPEN_WINDOW_DAYS = 30;
    private static final int MAX_TOP_WORKLOAD_ITEMS = 5;

    private final FindingListProjectionService findingListProjectionService;
    private final FindingEventRepository findingEventRepository;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final ObjectMapper objectMapper;

    public FindingQueueAnalyticsService(
            FindingListProjectionService findingListProjectionService,
            FindingEventRepository findingEventRepository,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            ObjectMapper objectMapper
    ) {
        this.findingListProjectionService = findingListProjectionService;
        this.findingEventRepository = findingEventRepository;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public FindingQueueAnalyticsResponse getQueueAnalytics(Tenant tenant, FindingsFilter filter) {
        List<FindingListProjectionService.ProjectionRecord> findings = findingListProjectionService.loadRows(tenant, filter);
        List<FindingListProjectionService.ProjectionRecord> openFindings = findings.stream()
                .filter(FindingListProjectionService.ProjectionRecord::isOpen)
                .toList();

        Instant now = Instant.now();
        List<Long> openAges = openFindings.stream()
                .map(finding -> ageDays(anchorInstant(finding), now))
                .sorted()
                .toList();

        long reopenedCountLast30Days = countReopenedEvents(findings, tenant, DEFAULT_REOPEN_WINDOW_DAYS);
        long resolvedCountLast30Days = countResolvedEvents(findings, tenant, DEFAULT_REOPEN_WINDOW_DAYS);
        double reopenRatePercent = resolvedCountLast30Days <= 0
                ? 0.0
                : (reopenedCountLast30Days * 100.0) / resolvedCountLast30Days;

        long assignedOpenCount = openFindings.stream()
                .filter(finding -> FindingFilterSpecifications.hasText(finding.assignedTo()))
                .count();
        long unassignedOpenCount = openFindings.size() - assignedOpenCount;
        long withIncidentCount = openFindings.stream()
                .filter(finding -> FindingFilterSpecifications.hasText(finding.incidentId()))
                .count();
        long withoutIncidentCount = openFindings.size() - withIncidentCount;

        return new FindingQueueAnalyticsResponse(
                buildAgingBuckets(openAges),
                reopenRatePercent,
                reopenedCountLast30Days,
                assignedOpenCount,
                unassignedOpenCount,
                withIncidentCount,
                withoutIncidentCount,
                openAges.isEmpty() ? 0 : openAges.get(openAges.size() - 1),
                median(openAges),
                topBreakdown(openFindings, finding -> defaultLabel(finding.assignedTo(), "Unassigned")),
                topBreakdown(openFindings, finding -> defaultLabel(finding.supportGroup(), "No Support Group"))
        );
    }

    @Transactional(readOnly = true)
    public List<FindingQueueAnalyticsTrendPointResponse> getQueueAnalyticsTrend(Tenant tenant, FindingsFilter filter, int days) {
        int effectiveDays = Math.max(1, Math.min(90, days));
        List<FindingListProjectionService.ProjectionRecord> findings = findingListProjectionService.loadRows(tenant, filter);
        Instant now = Instant.now();
        Instant fromInclusive = now.minus(effectiveDays - 1L, ChronoUnit.DAYS).truncatedTo(ChronoUnit.DAYS);
        LocalDate startDate = fromInclusive.atZone(ZoneOffset.UTC).toLocalDate();
        Map<LocalDate, TrendAccumulator> accumulators = new LinkedHashMap<>();
        for (int index = 0; index < effectiveDays; index++) {
            LocalDate date = startDate.plusDays(index);
            accumulators.put(date, new TrendAccumulator());
        }

        for (FindingListProjectionService.ProjectionRecord finding : findings) {
            LocalDate createdDate = finding.createdAt().atZone(ZoneOffset.UTC).toLocalDate();
            TrendAccumulator accumulator = accumulators.get(createdDate);
            if (accumulator != null) {
                accumulator.openedCount++;
            }
        }

        List<FindingEvent> events = loadEvents(findings, fromInclusive, tenant);
        for (FindingEvent event : events) {
            LocalDate eventDate = event.getCreatedAt().atZone(ZoneOffset.UTC).toLocalDate();
            TrendAccumulator accumulator = accumulators.get(eventDate);
            if (accumulator == null) {
                continue;
            }
            if (isResolvedEvent(event)) {
                accumulator.resolvedCount++;
            }
            if (isReopenedEvent(event)) {
                accumulator.reopenedCount++;
            }
        }

        return accumulators.entrySet().stream()
                .map(entry -> new FindingQueueAnalyticsTrendPointResponse(
                        entry.getKey(),
                        entry.getValue().openedCount,
                        entry.getValue().resolvedCount,
                        entry.getValue().reopenedCount
                ))
                .toList();
    }

    private List<FindingEvent> loadEvents(List<FindingListProjectionService.ProjectionRecord> findings, Instant fromInclusive, Tenant tenant) {
        if (findings.isEmpty()) {
            return List.of();
        }
        List<UUID> findingIds = findings.stream().map(FindingListProjectionService.ProjectionRecord::findingId).toList();
        return tenantSchemaExecutionService.run(
                tenant,
                () -> findingEventRepository.findByFinding_IdInAndCreatedAtGreaterThanEqual(findingIds, fromInclusive)
        );
    }

    private long countReopenedEvents(List<FindingListProjectionService.ProjectionRecord> findings, Tenant tenant, int days) {
        Instant fromInclusive = Instant.now().minus(days, ChronoUnit.DAYS);
        return loadEvents(findings, fromInclusive, tenant).stream()
                .filter(this::isReopenedEvent)
                .count();
    }

    private long countResolvedEvents(List<FindingListProjectionService.ProjectionRecord> findings, Tenant tenant, int days) {
        Instant fromInclusive = Instant.now().minus(days, ChronoUnit.DAYS);
        return loadEvents(findings, fromInclusive, tenant).stream()
                .filter(this::isResolvedEvent)
                .count();
    }

    private List<FindingQueueAgingBucketResponse> buildAgingBuckets(List<Long> openAges) {
        long bucket0to7 = 0;
        long bucket8to30 = 0;
        long bucket31to90 = 0;
        long bucket90Plus = 0;
        for (long age : openAges) {
            if (age <= 7) {
                bucket0to7++;
            } else if (age <= 30) {
                bucket8to30++;
            } else if (age <= 90) {
                bucket31to90++;
            } else {
                bucket90Plus++;
            }
        }
        return List.of(
                new FindingQueueAgingBucketResponse("0-7d", bucket0to7),
                new FindingQueueAgingBucketResponse("8-30d", bucket8to30),
                new FindingQueueAgingBucketResponse("31-90d", bucket31to90),
                new FindingQueueAgingBucketResponse("90d+", bucket90Plus)
        );
    }

    private List<FindingQueueWorkloadBreakdownResponse> topBreakdown(
            List<FindingListProjectionService.ProjectionRecord> findings,
            java.util.function.Function<FindingListProjectionService.ProjectionRecord, String> labelExtractor
    ) {
        Map<String, Long> counts = findings.stream()
                .collect(Collectors.groupingBy(labelExtractor, LinkedHashMap::new, Collectors.counting()));
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder())
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(MAX_TOP_WORKLOAD_ITEMS)
                .map(entry -> new FindingQueueWorkloadBreakdownResponse(entry.getKey(), entry.getValue()))
                .toList();
    }

    private Instant anchorInstant(FindingListProjectionService.ProjectionRecord finding) {
        if (finding.firstObservedAt() != null) {
            return finding.firstObservedAt();
        }
        return finding.createdAt();
    }

    private long ageDays(Instant anchor, Instant now) {
        return Math.max(0, ChronoUnit.DAYS.between(anchor, now));
    }

    private long median(List<Long> sortedValues) {
        if (sortedValues.isEmpty()) {
            return 0;
        }
        int size = sortedValues.size();
        if (size % 2 == 1) {
            return sortedValues.get(size / 2);
        }
        long lower = sortedValues.get((size / 2) - 1);
        long upper = sortedValues.get(size / 2);
        return Math.round((lower + upper) / 2.0);
    }

    private String defaultLabel(String value, String fallback) {
        return FindingFilterSpecifications.hasText(value) ? value.trim() : fallback;
    }

    private boolean isReopenedEvent(FindingEvent event) {
        String eventType = event.getEventType() == null ? "" : event.getEventType().trim().toUpperCase();
        if (eventType.startsWith("REOPENED") || "SUPPRESSION_EXPIRED".equals(eventType)) {
            return true;
        }
        if (!"STATUS_CHANGED".equals(eventType)) {
            return false;
        }
        String fromStatus = statusValue(event, "from");
        String toStatus = statusValue(event, "to");
        return "OPEN".equals(toStatus) && !"OPEN".equals(fromStatus);
    }

    private boolean isResolvedEvent(FindingEvent event) {
        String eventType = event.getEventType() == null ? "" : event.getEventType().trim().toUpperCase();
        if (List.of("AUTO_RESOLVED_ASSET_INACTIVE", "AUTO_RESOLVED_NOT_OBSERVED", "EXACT_IMPACT_RESOLVED", "AUTO_CLOSED_POLICY")
                .contains(eventType)) {
            return true;
        }
        if (!"STATUS_CHANGED".equals(eventType)) {
            return false;
        }
        String toStatus = statusValue(event, "to");
        return "RESOLVED".equals(toStatus) || "AUTO_CLOSED".equals(toStatus);
    }

    private String statusValue(FindingEvent event, String key) {
        if (!FindingFilterSpecifications.hasText(event.getDetailsJson())) {
            return null;
        }
        try {
            Map<String, Object> details = objectMapper.readValue(event.getDetailsJson(), MAP_TYPE);
            Object raw = details.get(key);
            return raw == null ? null : raw.toString().trim().toUpperCase();
        } catch (Exception ignored) {
            return null;
        }
    }

    private static final class TrendAccumulator {
        private long openedCount;
        private long resolvedCount;
        private long reopenedCount;
    }
}
