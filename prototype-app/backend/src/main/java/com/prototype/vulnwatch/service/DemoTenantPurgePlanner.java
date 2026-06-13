package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OperationalDemoPurgeDryRunCandidateResponse;
import com.prototype.vulnwatch.dto.OperationalDemoPurgeDryRunResponse;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class DemoTenantPurgePlanner {

    private final TenantRepository tenantRepository;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;

    public DemoTenantPurgePlanner(
            TenantRepository tenantRepository,
            TenantLifecycleGuardService tenantLifecycleGuardService
    ) {
        this.tenantRepository = tenantRepository;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
    }

    public boolean isEligibleForAutomaticPurge(Tenant tenant, Instant now) {
        if (!tenantLifecycleGuardService.isDemoTenant(tenant) || tenant == null || tenant.getPurgedAt() != null) {
            return false;
        }
        String reason = eligibilityReason(tenant, now);
        return "EXPIRED_READY".equals(reason) || "PURGE_RETRY_REQUIRED".equals(reason);
    }

    public OperationalDemoPurgeDryRunResponse buildSnapshot(Instant now) {
        List<OperationalDemoPurgeDryRunCandidateResponse> candidates = tenantRepository.findAllByOrderByCreatedAtAsc().stream()
                .filter(tenantLifecycleGuardService::isDemoTenant)
                .map(tenant -> toCandidate(tenant, now))
                .filter(candidate -> candidate != null)
                .sorted(Comparator
                        .comparing(OperationalDemoPurgeDryRunCandidateResponse::eligible).reversed()
                        .thenComparing(OperationalDemoPurgeDryRunCandidateResponse::demoExpiresAt, Comparator.nullsLast(Comparator.naturalOrder()))
                        .thenComparing(OperationalDemoPurgeDryRunCandidateResponse::tenantName, Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)))
                .toList();
        long totalCandidates = candidates.stream().filter(OperationalDemoPurgeDryRunCandidateResponse::eligible).count();
        return new OperationalDemoPurgeDryRunResponse(true, totalCandidates, candidates);
    }

    private OperationalDemoPurgeDryRunCandidateResponse toCandidate(Tenant tenant, Instant now) {
        String reason = eligibilityReason(tenant, now);
        if (reason == null) {
            return null;
        }
        boolean eligible = "EXPIRED_READY".equals(reason) || "PURGE_RETRY_REQUIRED".equals(reason);
        return new OperationalDemoPurgeDryRunCandidateResponse(
                tenant.getId(),
                tenant.getName(),
                tenant.getSchemaName(),
                tenant.getDemoExpiresAt(),
                tenant.getStatus(),
                tenant.getPurgeStatus(),
                eligible,
                reason
        );
    }

    private String eligibilityReason(Tenant tenant, Instant now) {
        if (tenant == null) {
            return null;
        }
        if (tenant.getPurgedAt() != null) {
            return "ALREADY_PURGED";
        }
        if ("IN_PROGRESS".equalsIgnoreCase(tenant.getPurgeStatus())
                || "PURGING".equalsIgnoreCase(tenant.getStatus())) {
            return "PURGE_IN_PROGRESS";
        }
        if ("FAILED".equalsIgnoreCase(tenant.getPurgeStatus())) {
            return "PURGE_RETRY_REQUIRED";
        }
        if (isExpired(tenant, now)) {
            return "EXPIRED_READY";
        }
        return null;
    }

    private boolean isExpired(Tenant tenant, Instant now) {
        if (tenant == null) {
            return false;
        }
        if ("EXPIRED".equalsIgnoreCase(tenant.getStatus()) || "DELETED".equalsIgnoreCase(tenant.getStatus())) {
            return true;
        }
        return tenant.getDemoExpiresAt() != null && !tenant.getDemoExpiresAt().isAfter(now);
    }
}
