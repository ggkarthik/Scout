package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.AuditEvent;
import com.prototype.vulnwatch.dto.AuditEventResponse;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantAccessControlService;
import com.prototype.vulnwatch.service.TenantQuotaService;
import java.util.Map;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/audit-events")
public class AuditEventController {

    private final AuditEventService auditEventService;
    private final RequestActorService requestActorService;
    private final TenantQuotaService tenantQuotaService;
    private final TenantAccessControlService tenantAccessControlService;

    public AuditEventController(
            AuditEventService auditEventService,
            RequestActorService requestActorService,
            TenantQuotaService tenantQuotaService,
            TenantAccessControlService tenantAccessControlService
    ) {
        this.auditEventService = auditEventService;
        this.requestActorService = requestActorService;
        this.tenantQuotaService = tenantQuotaService;
        this.tenantAccessControlService = tenantAccessControlService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public List<AuditEventResponse> list() {
        var actor = requestActorService.currentActor();
        tenantAccessControlService.assertTenantAccess(actor, actor.tenantId());
        return auditEventService.listForTenant(actor.tenantId()).stream()
                .map(this::toResponse)
                .toList();
    }

    @GetMapping(value = "/export", produces = "text/csv")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public ResponseEntity<String> exportCsv() {
        var actor = requestActorService.currentActor();
        tenantAccessControlService.assertTenantAccess(actor, actor.tenantId());
        List<AuditEvent> events = auditEventService.listAllForTenant(actor.tenantId());
        tenantQuotaService.assertCanExportRows(actor.tenantId(), events.size());
        auditEventService.record("audit_events.exported", "tenant", actor.tenantId().toString(),
                "{\"format\":\"csv\",\"rowCount\":" + events.size() + "}");
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"vulnwatch-audit-events.csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(auditEventService.toCsv(events));
    }

    @GetMapping("/support-bundle")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public Map<String, Object> supportBundle() {
        var actor = requestActorService.currentActor();
        tenantAccessControlService.assertTenantAccess(actor, actor.tenantId());
        auditEventService.record("support.bundle.exported", "tenant", actor.tenantId().toString(), null);
        return auditEventService.supportBundle(actor.tenantId());
    }

    private AuditEventResponse toResponse(AuditEvent event) {
        return new AuditEventResponse(
                event.getId(),
                event.getOccurredAt(),
                event.getTenant() == null ? null : event.getTenant().getId(),
                event.getActorSubject(),
                event.getActorRole(),
                event.getAction(),
                event.getTargetType(),
                event.getTargetId(),
                event.getOutcome(),
                event.getDetailsJson());
    }
}
