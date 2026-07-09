package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.InventoryConnectorHealthResponse;
import com.prototype.vulnwatch.dto.OperationalConnectorIssueGroupResponse;
import com.prototype.vulnwatch.dto.OperationalTenantAttentionResponse;
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
public class PlatformTenantAttentionService {

    private static final String REASON_TENANT_SUSPENDED = "TENANT_SUSPENDED";
    private static final String REASON_TENANT_EXPIRED = "TENANT_EXPIRED";
    private static final String REASON_CONNECTOR_ERROR = "CONNECTOR_ERROR";
    private static final String REASON_CONNECTOR_PENDING = "CONNECTOR_PENDING";

    private final TenantService tenantService;
    private final PlatformInventoryConnectorHealthService platformInventoryConnectorHealthService;

    public PlatformTenantAttentionService(
            TenantService tenantService,
            PlatformInventoryConnectorHealthService platformInventoryConnectorHealthService
    ) {
        this.tenantService = tenantService;
        this.platformInventoryConnectorHealthService = platformInventoryConnectorHealthService;
    }

    public List<OperationalTenantAttentionResponse> listTenantAttention() {
        return TenantContext.runAsPlatform(() -> {
            Map<UUID, TenantAttentionAggregate> aggregates = new LinkedHashMap<>();

            for (Tenant tenant : tenantService.listTenants()) {
                String status = normalize(tenant.getStatus());
                if ("SUSPENDED".equals(status) || "EXPIRED".equals(status)) {
                    TenantAttentionAggregate aggregate = aggregates.computeIfAbsent(
                            tenant.getId(),
                            ignored -> new TenantAttentionAggregate(tenant.getId(), tenant.getName(), defaultStatus(tenant.getStatus()))
                    );
                    if ("SUSPENDED".equals(status)) {
                        aggregate.reasons.add(REASON_TENANT_SUSPENDED);
                    } else {
                        aggregate.reasons.add(REASON_TENANT_EXPIRED);
                    }
                }
            }

            for (InventoryConnectorHealthResponse connector : platformInventoryConnectorHealthService.listInventoryConnectorHealth()) {
                String healthState = normalize(connector.healthState());
                if (!"ERROR".equals(healthState) && !"PENDING".equals(healthState)) {
                    continue;
                }
                TenantAttentionAggregate aggregate = aggregates.computeIfAbsent(
                        connector.tenantId(),
                        ignored -> new TenantAttentionAggregate(connector.tenantId(), connector.tenantName(), "ACTIVE")
                );
                aggregate.affectedConnectors.add(connector.connectorKey());
                aggregate.reasons.add("ERROR".equals(healthState) ? REASON_CONNECTOR_ERROR : REASON_CONNECTOR_PENDING);
                aggregate.latestRelevantSyncAt = latestInstant(aggregate.latestRelevantSyncAt, connector.lastSyncAt());
            }

            return aggregates.values().stream()
                    .filter(aggregate -> !aggregate.reasons.isEmpty())
                    .sorted(Comparator
                            .comparingInt((TenantAttentionAggregate aggregate) -> lifecyclePriority(aggregate.tenantStatus))
                            .thenComparing((TenantAttentionAggregate left, TenantAttentionAggregate right) ->
                                    Integer.compare(right.reasons.size(), left.reasons.size()))
                            .thenComparing(aggregate -> aggregate.tenantName, Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)))
                    .map(aggregate -> new OperationalTenantAttentionResponse(
                            aggregate.tenantId,
                            aggregate.tenantName,
                            aggregate.tenantStatus,
                            List.copyOf(aggregate.reasons),
                            List.copyOf(aggregate.affectedConnectors),
                            aggregate.latestRelevantSyncAt
                    ))
                    .toList();
        });
    }

    public List<OperationalConnectorIssueGroupResponse> listConnectorIssues() {
        return TenantContext.runAsPlatform(() -> {
            Map<String, Set<String>> connectorTenants = new LinkedHashMap<>();
            for (InventoryConnectorHealthResponse connector : platformInventoryConnectorHealthService.listInventoryConnectorHealth()) {
                String healthState = normalize(connector.healthState());
                if (!"ERROR".equals(healthState) && !"PENDING".equals(healthState)) {
                    continue;
                }
                connectorTenants.computeIfAbsent(connector.connectorKey(), ignored -> new LinkedHashSet<>()).add(connector.tenantName());
            }

            List<OperationalConnectorIssueGroupResponse> groups = new ArrayList<>();
            connectorTenants.forEach((connectorKey, tenants) -> groups.add(new OperationalConnectorIssueGroupResponse(
                    connectorKey,
                    tenants.size(),
                    List.copyOf(tenants)
            )));
            groups.sort(Comparator
                    .comparingLong(OperationalConnectorIssueGroupResponse::affectedTenantCount).reversed()
                    .thenComparing(OperationalConnectorIssueGroupResponse::connectorKey, Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)));
            return groups;
        });
    }

    private String defaultStatus(String status) {
        return status == null || status.isBlank() ? "UNKNOWN" : status;
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private Instant latestInstant(Instant left, Instant right) {
        if (left == null) {
            return right;
        }
        if (right == null) {
            return left;
        }
        return right.isAfter(left) ? right : left;
    }

    private static int lifecyclePriority(String status) {
        String normalized = status == null ? "" : status.trim().toUpperCase(Locale.ROOT);
        if ("SUSPENDED".equals(normalized)) {
            return 0;
        }
        if ("EXPIRED".equals(normalized)) {
            return 1;
        }
        return 2;
    }

    private static final class TenantAttentionAggregate {
        private final UUID tenantId;
        private final String tenantName;
        private final String tenantStatus;
        private final Set<String> reasons = new LinkedHashSet<>();
        private final Set<String> affectedConnectors = new LinkedHashSet<>();
        private Instant latestRelevantSyncAt;

        private TenantAttentionAggregate(UUID tenantId, String tenantName, String tenantStatus) {
            this.tenantId = tenantId;
            this.tenantName = tenantName;
            this.tenantStatus = tenantStatus;
        }
    }
}
