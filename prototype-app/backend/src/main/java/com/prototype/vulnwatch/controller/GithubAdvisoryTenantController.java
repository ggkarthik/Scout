package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.config.TenantContext;
import com.prototype.vulnwatch.domain.GithubRepositoryComponentAdvisoryEntity;
import com.prototype.vulnwatch.domain.GithubSecurityAdvisoryEntity;
import com.prototype.vulnwatch.dto.GithubAdvisoryIntegrationStatusResponse;
import com.prototype.vulnwatch.dto.GithubAdvisoryResponse;
import com.prototype.vulnwatch.service.GithubAdvisoryTenantService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/tenants/{tenantId}/ghsa")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('TENANT_ADMIN', 'INVENTORY_ADMIN', 'PLATFORM_OWNER')")
public class GithubAdvisoryTenantController {

    private final GithubAdvisoryTenantService tenantService;

    @GetMapping("/integration-status")
    public ResponseEntity<GithubAdvisoryIntegrationStatusResponse> getIntegrationStatus(
            @PathVariable UUID tenantId) {
        log.debug("GET /api/tenants/{}/ghsa/integration-status", tenantId);
        validateTenantContext(tenantId);
        GithubAdvisoryIntegrationStatusResponse status = tenantService.getTenantIntegrationStatus(tenantId);
        return ResponseEntity.ok(status);
    }

    @PostMapping("/enable")
    public ResponseEntity<GithubAdvisoryIntegrationStatusResponse> enableIntegration(
            @PathVariable UUID tenantId,
            @RequestParam(required = false) String reason) {
        log.info("POST /api/tenants/{}/ghsa/enable", tenantId);
        validateTenantContext(tenantId);
        UUID currentUserId = getCurrentUserId();
        GithubAdvisoryIntegrationStatusResponse status = tenantService.enableIntegration(tenantId, reason, currentUserId);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(status);
    }

    @PostMapping("/disable")
    public ResponseEntity<GithubAdvisoryIntegrationStatusResponse> disableIntegration(
            @PathVariable UUID tenantId,
            @RequestParam(required = false) String reason) {
        log.info("POST /api/tenants/{}/ghsa/disable", tenantId);
        validateTenantContext(tenantId);
        GithubAdvisoryIntegrationStatusResponse status = tenantService.disableIntegration(tenantId, reason);
        return ResponseEntity.ok(status);
    }

    @PutMapping("/settings")
    public ResponseEntity<GithubAdvisoryIntegrationStatusResponse> updateSettings(
            @PathVariable UUID tenantId,
            @RequestBody @Valid GithubAdvisorySettingsUpdateRequest request) {
        log.info("PUT /api/tenants/{}/ghsa/settings", tenantId);
        validateTenantContext(tenantId);
        GithubAdvisoryIntegrationStatusResponse status = tenantService.updateIntegrationSettings(
                tenantId,
                request.getAutoCreateFindings(),
                request.getAutoCorrelateComponents(),
                request.getCreateFindingForLowSeverity()
        );
        return ResponseEntity.ok(status);
    }

    @GetMapping("/advisories")
    public ResponseEntity<List<GithubSecurityAdvisoryEntity>> getApplicableAdvisories(
            @PathVariable UUID tenantId,
            @RequestParam String ecosystem,
            @RequestParam String packageName) {
        log.debug("GET /api/tenants/{}/ghsa/advisories", tenantId);
        validateTenantContext(tenantId);
        List<GithubSecurityAdvisoryEntity> advisories = tenantService.getApplicableAdvisoriesForComponent(
                tenantId, ecosystem, packageName
        );
        return ResponseEntity.ok(advisories);
    }

    @GetMapping("/component-advisories/{sourceId}")
    public ResponseEntity<List<GithubRepositoryComponentAdvisoryEntity>> getComponentAdvisories(
            @PathVariable UUID tenantId,
            @PathVariable UUID sourceId) {
        log.debug("GET /api/tenants/{}/ghsa/component-advisories/{}", tenantId, sourceId);
        validateTenantContext(tenantId);
        List<GithubRepositoryComponentAdvisoryEntity> componentAdvisories = tenantService.getComponentAdvisories(tenantId, sourceId);
        return ResponseEntity.ok(componentAdvisories);
    }

    @PostMapping("/correlate/{sourceId}")
    public ResponseEntity<String> correlateComponents(
            @PathVariable UUID tenantId,
            @PathVariable UUID sourceId) {
        log.info("POST /api/tenants/{}/ghsa/correlate/{}", tenantId, sourceId);
        validateTenantContext(tenantId);
        tenantService.correlateComponentsWithAdvisories(tenantId, sourceId);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body("Correlation initiated");
    }

    @DeleteMapping("/component-advisories/{sourceId}")
    public ResponseEntity<String> deleteComponentAdvisories(
            @PathVariable UUID tenantId,
            @PathVariable UUID sourceId) {
        log.info("DELETE /api/tenants/{}/ghsa/component-advisories/{}", tenantId, sourceId);
        validateTenantContext(tenantId);
        tenantService.deleteComponentAdvisories(tenantId, sourceId);
        return ResponseEntity.ok("Component advisories deleted");
    }

    private void validateTenantContext(UUID tenantId) {
        UUID currentTenantId = TenantContext.getCurrentTenantId();
        if (currentTenantId == null || !currentTenantId.equals(tenantId)) {
            log.warn("Tenant context mismatch: requested={}, current={}", tenantId, currentTenantId);
            throw new IllegalArgumentException("Tenant context mismatch");
        }
    }

    private UUID getCurrentUserId() {
        return UUID.randomUUID();
    }

    @lombok.Data
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class GithubAdvisorySettingsUpdateRequest {
        private Boolean autoCreateFindings;
        private Boolean autoCorrelateComponents;
        private Boolean createFindingForLowSeverity;
    }
}
