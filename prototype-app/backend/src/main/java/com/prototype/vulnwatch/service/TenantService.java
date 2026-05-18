package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class TenantService {

    public static final String DEFAULT_TENANT_NAME = "Default Workspace";

    private final TenantRepository tenantRepository;

    public TenantService(TenantRepository tenantRepository) {
        this.tenantRepository = tenantRepository;
    }

    @Transactional
    public Tenant getDefaultTenant() {
        return tenantRepository.findByNameIgnoreCase(DEFAULT_TENANT_NAME)
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

    @Transactional
    public Tenant createTenant(String name, String slug, String planCode, String billingRef) {
        Tenant tenant = new Tenant();
        tenant.setName(requireText(name, "name"));
        tenant.setSlug(normalizeSlug(slug == null || slug.isBlank() ? name : slug));
        tenant.setPlanCode(planCode == null || planCode.isBlank() ? "pilot" : planCode.trim());
        tenant.setBillingRef(billingRef == null || billingRef.isBlank() ? null : billingRef.trim());
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
}
