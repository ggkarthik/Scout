package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.TenantQuotaUpdateRequest;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.NOT_FOUND;

@Service
public class TenantService {

    public static final String DEFAULT_TENANT_NAME = "Default Workspace";
    public static final String DEFAULT_TENANT_SCHEMA = "tenant_default";
    public static final String DEFAULT_PLAN_CODE = "ENTERPRISE";

    private final TenantRepository tenantRepository;
    private final TenantSchemaService tenantSchemaService;

    public TenantService(
            TenantRepository tenantRepository,
            TenantSchemaService tenantSchemaService
    ) {
        this.tenantRepository = tenantRepository;
        this.tenantSchemaService = tenantSchemaService;
    }

    @Transactional
    public Tenant getDefaultTenant() {
        return tenantRepository.findByNameIgnoreCase(DEFAULT_TENANT_NAME)
                .or(() -> tenantRepository.findBySchemaName(DEFAULT_TENANT_SCHEMA))
                .or(() -> tenantRepository.findAllByOrderByCreatedAtAsc().stream()
                        .filter(this::isUsableDefaultTenantCandidate)
                        .findFirst())
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Default workspace not found"));
    }

    @Transactional(readOnly = true)
    public Tenant resolveTenant(Long legacyTenantId) {
        if (legacyTenantId == null) {
            throw new ResponseStatusException(NOT_FOUND, "Tenant is required");
        }
        UUID legacyTenantUuid = new UUID(0L, legacyTenantId);
        return tenantRepository.findById(legacyTenantUuid)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Tenant not found"));
    }

    @Transactional(readOnly = true)
    public Tenant resolveTenantUuid(UUID tenantId) {
        if (tenantId == null) {
            throw new ResponseStatusException(NOT_FOUND, "Tenant is required");
        }
        return tenantRepository.findById(tenantId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Tenant not found"));
    }

    @Transactional(readOnly = true)
    public Tenant requireTenantUuid(UUID tenantId) {
        return resolveTenantUuid(tenantId);
    }

    @Transactional(readOnly = true)
    public List<Tenant> listTenants() {
        return tenantRepository.findAllByOrderByCreatedAtAsc();
    }

    @Transactional(readOnly = true)
    public List<Tenant> listActiveTenants() {
        return tenantRepository.findAllByOrderByCreatedAtAsc().stream()
                .filter(this::isActiveTenantForBackgroundWork)
                .toList();
    }

    public Tenant createTenant(String name, String slug, String planCode, String billingRef) {
        Tenant tenant = new Tenant();
        tenant.setName(requireText(name, "name"));
        tenant.setSlug(normalizeSlug(slug == null || slug.isBlank() ? name : slug));
        tenant.setSchemaName(tenantSchemaService.deriveSchemaName(tenant.getSlug()));
        tenant.setPlanCode(normalizePlanCode(planCode));
        tenant.setBillingRef(billingRef == null || billingRef.isBlank() ? null : billingRef.trim());
        tenant.setStatus("PROVISIONING");
        return tenantRepository.save(tenant);
    }

    @Transactional
    public Tenant retryProvisioning(UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        if (!"PROVISIONING_FAILED".equalsIgnoreCase(tenant.getStatus())) {
            throw new IllegalArgumentException("Only PROVISIONING_FAILED tenants can be retried");
        }
        tenant.setStatus("PROVISIONING");
        tenant.setUpdatedAt(Instant.now());
        return tenantRepository.save(tenant);
    }

    @Transactional
    public Tenant updateStatus(UUID tenantId, String status) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        String normalizedStatus = requireText(status, "status").toUpperCase();
        tenant.setStatus(normalizedStatus);
        tenant.setUpdatedAt(Instant.now());
        tenant.setSuspendedAt("SUSPENDED".equals(normalizedStatus) ? Instant.now() : null);
        return tenantRepository.save(tenant);
    }

    @Transactional
    public Tenant updateQuotas(UUID tenantId, TenantQuotaUpdateRequest request) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        tenant.setMaxConnectorCount(nonNegative(request.maxConnectorCount(), "maxConnectorCount"));
        tenant.setMaxServiceAccountCount(nonNegative(request.maxServiceAccountCount(), "maxServiceAccountCount"));
        tenant.setMaxDailySbomUploads(nonNegative(request.maxDailySbomUploads(), "maxDailySbomUploads"));
        tenant.setMaxExportRows(nonNegative(request.maxExportRows(), "maxExportRows"));
        tenant.setMaxDailyExposureRefreshes(nonNegative(request.maxDailyExposureRefreshes(), "maxDailyExposureRefreshes"));
        tenant.setSbomRateLimitWindowSeconds(nullableNonNegative(request.sbomRateLimitWindowSeconds(), "sbomRateLimitWindowSeconds"));
        tenant.setMaxSbomJobsPerRateLimitWindow(nullableNonNegative(request.maxSbomJobsPerRateLimitWindow(), "maxSbomJobsPerRateLimitWindow"));
        tenant.setMaxActiveSbomJobs(nullableNonNegative(request.maxActiveSbomJobs(), "maxActiveSbomJobs"));
        tenant.setUpdatedAt(Instant.now());
        return tenantRepository.save(tenant);
    }
    private String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }

    private String normalizeSlug(String value) {
        String slug = requireText(value, "slug")
                .toLowerCase()
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("(^-|-$)", "");
        if (slug.isBlank()) {
            throw new IllegalArgumentException("slug must contain at least one letter or digit");
        }
        return slug;
    }

    private Integer nonNegative(Integer value, String field) {
        if (value == null) {
            throw new IllegalArgumentException(field + " is required");
        }
        if (value < 0) {
            throw new IllegalArgumentException(field + " must be >= 0");
        }
        return value;
    }

    private Integer nullableNonNegative(Integer value, String field) {
        if (value == null) {
            return null;
        }
        if (value < 0) {
            throw new IllegalArgumentException(field + " must be >= 0");
        }
        return value;
    }

    private String normalizePlanCode(String planCode) {
        if (planCode == null || planCode.isBlank()) {
            return DEFAULT_PLAN_CODE;
        }
        return planCode.trim().toUpperCase();
    }

    private boolean isUsableDefaultTenantCandidate(Tenant tenant) {
        return tenant.getDeletedAt() == null
                && tenant.getPurgedAt() == null
                && "ACTIVE".equalsIgnoreCase(tenant.getStatus());
    }

    private boolean isActiveTenantForBackgroundWork(Tenant tenant) {
        if (tenant == null) {
            return false;
        }
        String status = tenant.getStatus() == null ? "" : tenant.getStatus().trim().toUpperCase(Locale.ROOT);
        return "ACTIVE".equals(status)
                && tenant.getDeletedAt() == null
                && tenant.getExpiredAt() == null
                && tenant.getPurgeStartedAt() == null
                && tenant.getPurgedAt() == null;
    }
}
