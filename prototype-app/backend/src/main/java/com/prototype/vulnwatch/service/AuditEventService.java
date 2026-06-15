package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AuditEvent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OrgSpecificCveExposureRecomputeResponse;
import com.prototype.vulnwatch.dto.TenantExposureRefreshResponse;
import com.prototype.vulnwatch.repo.AuditEventRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditEventService {

    private final AuditEventRepository auditEventRepository;
    private final TenantRepository tenantRepository;
    private final RequestActorService requestActorService;

    public AuditEventService(
            AuditEventRepository auditEventRepository,
            TenantRepository tenantRepository,
            RequestActorService requestActorService
    ) {
        this.auditEventRepository = auditEventRepository;
        this.tenantRepository = tenantRepository;
        this.requestActorService = requestActorService;
    }

    @Transactional
    public void record(String action, String targetType, String targetId, String detailsJson) {
        record(action, targetType, targetId, detailsJson, null);
    }

    @Transactional
    public void record(String action, String targetType, String targetId, String detailsJson, String outcome) {
        RequestActor actor = requestActorService.currentActor();
        AuditEvent event = new AuditEvent();
        if (actor.tenantId() != null) {
            tenantRepository.findById(actor.tenantId()).ifPresent(event::setTenant);
        }
        event.setActorSubject(actor.userId());
        event.setActorRole(actor.roles().stream().findFirst().orElse(null));
        event.setAction(action);
        event.setTargetType(targetType);
        event.setTargetId(targetId);
        event.setDetailsJson(detailsJson);
        event.setOutcome(outcome);
        event.setRequestId(MDC.get("requestId"));
        auditEventRepository.save(event);
    }

    @Transactional
    public void recordTenantExposureRefresh(Tenant tenant, String endpoint, TenantExposureRefreshResponse response) {
        OrgSpecificCveExposureRecomputeResponse refresh = response == null ? null : response.refresh();
        String detailsJson = "{"
                + "\"operation\":\"tenant_exposure_refresh\","
                + "\"source\":\"central_vulnerability_repository\","
                + "\"endpoint\":\"" + escapeJson(endpoint) + "\","
                + "\"status\":\"" + escapeJson(response == null ? null : response.status()) + "\","
                + "\"message\":\"" + escapeJson(response == null ? null : response.message()) + "\","
                + "\"refreshScope\":\"" + escapeJson(refresh == null ? null : refresh.scope()) + "\","
                + "\"activeComponentCount\":" + number(refresh == null ? null : refresh.activeComponentCount()) + ","
                + "\"correlatedExposureCount\":" + number(refresh == null ? null : refresh.correlatedExposureCount()) + ","
                + "\"stateRowsChanged\":" + number(refresh == null ? null : refresh.stateRowsChanged()) + ","
                + "\"exposureStateRowCount\":" + number(refresh == null ? null : refresh.exposureStateRowCount()) + ","
                + "\"openFindingsCount\":" + number(refresh == null ? null : refresh.openFindingsCount()) + ","
                + "\"refreshedAt\":\"" + escapeJson(response == null || response.refreshedAt() == null ? null : response.refreshedAt().toString()) + "\""
                + "}";
        record("tenant.org_cves.refresh", "tenant", tenant == null ? null : tenant.getId().toString(), detailsJson);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> listForTenant(UUID tenantId) {
        return auditEventRepository.findTop100ByTenantIdOrderByOccurredAtDesc(tenantId);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> listAllForTenant(UUID tenantId) {
        return auditEventRepository.findByTenantIdOrderByOccurredAtDesc(tenantId);
    }

    public String toCsv(List<AuditEvent> events) {
        StringBuilder csv = new StringBuilder("occurredAt,tenantId,actorSubject,actorRole,action,targetType,targetId,outcome,requestId,detailsJson\n");
        for (AuditEvent event : events) {
            csv.append(csv(event.getOccurredAt()))
                    .append(',')
                    .append(csv(event.getTenant() == null ? null : event.getTenant().getId()))
                    .append(',')
                    .append(csv(event.getActorSubject()))
                    .append(',')
                    .append(csv(event.getActorRole()))
                    .append(',')
                    .append(csv(event.getAction()))
                    .append(',')
                    .append(csv(event.getTargetType()))
                    .append(',')
                    .append(csv(event.getTargetId()))
                    .append(',')
                    .append(csv(event.getOutcome()))
                    .append(',')
                    .append(csv(event.getRequestId()))
                    .append(',')
                    .append(csv(event.getDetailsJson()))
                    .append('\n');
        }
        return csv.toString();
    }

    @Transactional(readOnly = true)
    public Map<String, Object> supportBundle(UUID tenantId) {
        List<AuditEvent> events = listForTenant(tenantId);
        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("generatedAt", Instant.now());
        bundle.put("tenantId", tenantId);
        bundle.put("recentAuditEventCount", events.size());
        bundle.put("recentAuditEvents", events.stream().map(event -> Map.of(
                "occurredAt", event.getOccurredAt(),
                "actorSubject", nullToEmpty(event.getActorSubject()),
                "action", nullToEmpty(event.getAction()),
                "targetType", nullToEmpty(event.getTargetType()),
                "targetId", nullToEmpty(event.getTargetId()),
                "outcome", nullToEmpty(event.getOutcome()),
                "requestId", nullToEmpty(event.getRequestId())
        )).toList());
        return bundle;
    }

    private String number(Number value) {
        return value == null ? "null" : value.toString();
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String csv(Object value) {
        String text = value == null ? "" : value.toString();
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
