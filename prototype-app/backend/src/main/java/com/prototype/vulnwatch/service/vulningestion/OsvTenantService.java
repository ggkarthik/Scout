package com.prototype.vulnwatch.service.vulningestion;

import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.domain.OsvAdvisoryEntity;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.OsvAdvisoryRepository;
import com.prototype.vulnwatch.service.FindingService;
import com.prototype.vulnwatch.service.TenantService;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class OsvTenantService {

    private final OsvAdvisoryRepository osvAdvisoryRepository;
    private final TenantService tenantService;
    private final FindingService findingService;

    /**
     * Correlate OSV advisories for all enabled tenants
     * Runs after platform OSV sync (02:50)
     * Scheduled to execute after OsvPlatformService completes
     */
    @Scheduled(cron = "0 50 2 * * *")
    public void correlateOsvForAllEnabledTenants() {
        log.info("Starting OSV correlation for all tenants");

        try {
            List<Tenant> allTenants = tenantService.listTenants();

            for (Tenant tenant : allTenants) {
                try {
                    TenantContext.setCurrentTenantId(tenant.getId());
                    correlateOsvAdvisoriesForTenant(tenant.getId());
                } catch (Exception e) {
                    log.warn("Failed to correlate OSV for tenant: {}", tenant.getId(), e);
                } finally {
                    TenantContext.clear();
                }
            }

            log.info("OSV correlation completed for all tenants");

        } catch (Exception e) {
            log.error("Failed to correlate OSV for tenants", e);
        }
    }

    /**
     * Correlate OSV advisories for a specific tenant
     * Tenant context must be set before calling
     */
    @Transactional
    public void correlateOsvAdvisoriesForTenant(UUID tenantId) {
        log.debug("Correlating OSV advisories for tenant: {}", tenantId);

        try {
            List<OsvAdvisoryEntity> osvAdvisories = osvAdvisoryRepository.findAll();

            if (osvAdvisories.isEmpty()) {
                log.debug("No OSV advisories found in platform cache");
                return;
            }

            log.debug("Found {} OSV advisories to correlate", osvAdvisories.size());

            long correlatedCount = 0;
            for (OsvAdvisoryEntity advisory : osvAdvisories) {
                try {
                    boolean correlated = correlateComponentsToAdvisory(tenantId, advisory);
                    if (correlated) {
                        correlatedCount++;
                    }
                } catch (Exception e) {
                    log.debug("Failed to correlate advisory: {}", advisory.getOsvId(), e);
                }
            }

            log.debug("Correlated {} OSV advisories for tenant: {}", correlatedCount, tenantId);

        } catch (Exception e) {
            log.error("Error correlating OSV advisories for tenant: {}", tenantId, e);
        }
    }

    /**
     * Check if tenant has components affected by this advisory
     * Create findings if affected
     */
    private boolean correlateComponentsToAdvisory(UUID tenantId, OsvAdvisoryEntity advisory) {
        try {
            // TODO: Implement component matching logic
            // This requires access to tenant's inventory components
            // 1. Get components in tenant matching advisory ecosystem + packageName
            // 2. Check if component version is in affected range
            // 3. Create finding if affected

            log.debug("Correlating advisory {} to tenant components", advisory.getOsvId());

            // Placeholder: return false until inventory service is integrated
            return false;

        } catch (Exception e) {
            log.debug("Error correlating components to advisory: {}", advisory.getOsvId(), e);
            return false;
        }
    }
}
