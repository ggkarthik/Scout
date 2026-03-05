package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.Comparator;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TenantService {

    public static final String DEFAULT_TENANT_NAME = "Default Workspace";

    private final TenantRepository tenantRepository;
    private final AssetRepository assetRepository;

    public TenantService(TenantRepository tenantRepository, AssetRepository assetRepository) {
        this.tenantRepository = tenantRepository;
        this.assetRepository = assetRepository;
    }

    @Transactional
    public Tenant getDefaultTenant() {
        return tenantRepository.findByNameIgnoreCase(DEFAULT_TENANT_NAME)
                .orElseGet(this::resolveExistingTenantOrCreateDefault);
    }

    private Tenant resolveExistingTenantOrCreateDefault() {
        List<Tenant> existingTenants = tenantRepository.findAllByOrderByCreatedAtAsc();
        if (!existingTenants.isEmpty()) {
            return existingTenants.stream()
                    .max(Comparator.comparingLong(assetRepository::countByTenant))
                    .orElse(existingTenants.get(0));
        }

        Tenant tenant = new Tenant();
        tenant.setName(DEFAULT_TENANT_NAME);
        return tenantRepository.save(tenant);
    }
}
