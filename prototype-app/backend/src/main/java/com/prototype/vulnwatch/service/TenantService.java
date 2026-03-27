package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
                .orElseGet(this::resolveExistingTenantOrCreateDefault);
    }

    @Transactional(readOnly = true)
    public Tenant resolveTenant(Long legacyTenantId) {
        if (legacyTenantId == null) {
            return getDefaultTenant();
        }
        UUID legacyTenantUuid = new UUID(0L, legacyTenantId);
        return tenantRepository.findById(legacyTenantUuid)
                .orElseGet(this::getDefaultTenant);
    }

    @Transactional(readOnly = true)
    public Tenant resolveTenantUuid(UUID tenantId) {
        if (tenantId == null) {
            return getDefaultTenant();
        }
        return tenantRepository.findById(tenantId)
                .orElseGet(this::getDefaultTenant);
    }

    private Tenant resolveExistingTenantOrCreateDefault() {
        List<Tenant> existingTenants = tenantRepository.findAllByOrderByCreatedAtAsc();
        if (!existingTenants.isEmpty()) {
            return existingTenants.get(0);
        }

        Tenant tenant = new Tenant();
        tenant.setName(DEFAULT_TENANT_NAME);
        return tenantRepository.save(tenant);
    }
}
