package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.config.TenantContext;
import com.prototype.vulnwatch.domain.GithubAdvisoryIntegrationEntity;
import com.prototype.vulnwatch.domain.GithubRepositoryComponentAdvisoryEntity;
import com.prototype.vulnwatch.domain.GithubSecurityAdvisoryEntity;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GithubAdvisoryIntegrationStatusResponse;
import com.prototype.vulnwatch.repo.GithubAdvisoryIntegrationRepository;
import com.prototype.vulnwatch.repo.GithubRepositoryComponentAdvisoryRepository;
import com.prototype.vulnwatch.repo.GithubSecurityAdvisoryRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
public class GithubAdvisoryTenantService {

    private final GithubAdvisoryIntegrationRepository integrationRepository;
    private final GithubRepositoryComponentAdvisoryRepository componentAdvisoryRepository;
    private final GithubSecurityAdvisoryRepository securityAdvisoryRepository;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public GithubAdvisoryTenantService(
            GithubAdvisoryIntegrationRepository integrationRepository,
            GithubRepositoryComponentAdvisoryRepository componentAdvisoryRepository,
            GithubSecurityAdvisoryRepository securityAdvisoryRepository,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService) {
        this.integrationRepository = integrationRepository;
        this.componentAdvisoryRepository = componentAdvisoryRepository;
        this.securityAdvisoryRepository = securityAdvisoryRepository;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @Transactional
    public GithubAdvisoryIntegrationStatusResponse getTenantIntegrationStatus(UUID tenantId) {
        log.debug("Fetching GHSA integration status for tenant: {}", tenantId);
        Tenant tenant = tenantService.getTenant(tenantId);

        GithubAdvisoryIntegrationEntity integration = integrationRepository
                .findByTenant_Id(tenantId)
                .orElseGet(() -> createNewIntegration(tenant));

        long affectedComponentCount = componentAdvisoryRepository
                .findAll()
                .stream()
                .filter(GithubRepositoryComponentAdvisoryEntity::getIsAffected)
                .count();

        return toIntegrationStatusResponse(integration, affectedComponentCount);
    }

    @Transactional
    public GithubAdvisoryIntegrationStatusResponse enableIntegration(UUID tenantId, String reason, UUID enabledByUserId) {
        log.info("Enabling GHSA integration for tenant: {}", tenantId);
        Tenant tenant = tenantService.getTenant(tenantId);

        GithubAdvisoryIntegrationEntity integration = integrationRepository
                .findByTenant_Id(tenantId)
                .orElseGet(() -> createNewIntegration(tenant));

        integration.setIsEnabled(true);
        integration.setEnabledAt(Instant.now());
        integration.setReasonEnabled(reason);
        integration.setEnabledByUserId(enabledByUserId);
        integration.setUpdatedAt(Instant.now());
        integrationRepository.save(integration);

        log.info("GHSA integration enabled for tenant: {}", tenantId);
        return getTenantIntegrationStatus(tenantId);
    }

    @Transactional
    public GithubAdvisoryIntegrationStatusResponse disableIntegration(UUID tenantId, String reason) {
        log.info("Disabling GHSA integration for tenant: {}", tenantId);
        Tenant tenant = tenantService.getTenant(tenantId);

        GithubAdvisoryIntegrationEntity integration = integrationRepository
                .findByTenant_Id(tenantId)
                .orElseGet(() -> createNewIntegration(tenant));

        integration.setIsEnabled(false);
        integration.setDisabledAt(Instant.now());
        integration.setUpdatedAt(Instant.now());
        integrationRepository.save(integration);

        log.info("GHSA integration disabled for tenant: {}", tenantId);
        return getTenantIntegrationStatus(tenantId);
    }

    @Transactional
    public GithubAdvisoryIntegrationStatusResponse updateIntegrationSettings(
            UUID tenantId,
            Boolean autoCreateFindings,
            Boolean autoCorrelateComponents,
            Boolean createFindingForLowSeverity) {
        log.debug("Updating GHSA integration settings for tenant: {}", tenantId);
        Tenant tenant = tenantService.getTenant(tenantId);

        GithubAdvisoryIntegrationEntity integration = integrationRepository
                .findByTenant_Id(tenantId)
                .orElseGet(() -> createNewIntegration(tenant));

        if (autoCreateFindings != null) {
            integration.setAutoCreateFindings(autoCreateFindings);
        }
        if (autoCorrelateComponents != null) {
            integration.setAutoCorrelateComponents(autoCorrelateComponents);
        }
        if (createFindingForLowSeverity != null) {
            integration.setCreateFindingForLowSeverity(createFindingForLowSeverity);
        }

        integration.setUpdatedAt(Instant.now());
        integrationRepository.save(integration);

        log.info("GHSA integration settings updated for tenant: {}", tenantId);
        return getTenantIntegrationStatus(tenantId);
    }

    @Transactional(readOnly = true)
    public List<GithubSecurityAdvisoryEntity> getApplicableAdvisoriesForComponent(
            UUID tenantId,
            String ecosystem,
            String packageName) {
        log.debug("Fetching applicable GHSA advisories for tenant: {}, ecosystem: {}, package: {}",
                tenantId, ecosystem, packageName);
        return securityAdvisoryRepository.findApplicableByEcosystemAndPackageName(ecosystem, packageName);
    }

    @Transactional(readOnly = true)
    public List<GithubRepositoryComponentAdvisoryEntity> getComponentAdvisories(UUID tenantId, UUID sourceId) {
        log.debug("Fetching component advisories for tenant: {}, source: {}", tenantId, sourceId);
        return componentAdvisoryRepository.findBySourceId(tenantId, sourceId);
    }

    @Transactional
    public void correlateComponentsWithAdvisories(UUID tenantId, UUID sourceId) {
        log.info("Starting correlation of components with GHSA advisories for tenant: {}, source: {}", tenantId, sourceId);
        Tenant tenant = tenantService.getTenant(tenantId);

        GithubAdvisoryIntegrationEntity integration = integrationRepository
                .findByTenant_Id(tenantId)
                .orElse(null);

        if (integration == null || !integration.getIsEnabled() || !integration.getAutoCorrelateComponents()) {
            log.debug("GHSA correlation disabled or not enabled for tenant: {}", tenantId);
            return;
        }

        List<GithubRepositoryComponentAdvisoryEntity> componentAdvisories = componentAdvisoryRepository
                .findBySourceId(tenantId, sourceId);

        for (GithubRepositoryComponentAdvisoryEntity componentAdvisory : componentAdvisories) {
            if (componentAdvisory.getIsAffected()) {
                log.debug("Component {} is affected by advisory {}",
                        componentAdvisory.getComponentId(), componentAdvisory.getAdvisoryId());
            }
        }

        log.info("Completed correlation of components with GHSA advisories for tenant: {}, source: {}", tenantId, sourceId);
    }

    @Transactional
    public void deleteComponentAdvisories(UUID tenantId, UUID sourceId) {
        log.info("Deleting component advisories for tenant: {}, source: {}", tenantId, sourceId);
        componentAdvisoryRepository.deleteBySourceId(tenantId, sourceId);
        log.info("Component advisories deleted for tenant: {}, source: {}", tenantId, sourceId);
    }

    @Transactional(readOnly = true)
    public boolean isIntegrationEnabled(UUID tenantId) {
        return integrationRepository
                .findByTenant_Id(tenantId)
                .map(GithubAdvisoryIntegrationEntity::getIsEnabled)
                .orElse(false);
    }

    private GithubAdvisoryIntegrationStatusResponse toIntegrationStatusResponse(
            GithubAdvisoryIntegrationEntity entity,
            long affectedComponentCount) {
        return GithubAdvisoryIntegrationStatusResponse.builder()
                .id(entity.getId())
                .tenantId(entity.getTenant().getId())
                .tenantName(entity.getTenant().getName())
                .isEnabled(entity.getIsEnabled())
                .enabledAt(entity.getEnabledAt())
                .disabledAt(entity.getDisabledAt())
                .autoCreateFindings(entity.getAutoCreateFindings())
                .autoCorrelateComponents(entity.getAutoCorrelateComponents())
                .createFindingForLowSeverity(entity.getCreateFindingForLowSeverity())
                .reasonEnabled(entity.getReasonEnabled())
                .enabledByUserId(entity.getEnabledByUserId())
                .createdAt(entity.getCreatedAt())
                .updatedAt(entity.getUpdatedAt())
                .affectedComponentsCount((int) affectedComponentCount)
                .build();
    }

    private GithubAdvisoryIntegrationEntity createNewIntegration(Tenant tenant) {
        log.debug("Creating new GHSA integration entity for tenant: {}", tenant.getId());
        GithubAdvisoryIntegrationEntity integration = new GithubAdvisoryIntegrationEntity();
        integration.setId(UUID.randomUUID());
        integration.setTenant(tenant);
        integration.setIsEnabled(false);
        integration.setAutoCreateFindings(true);
        integration.setAutoCorrelateComponents(true);
        integration.setCreateFindingForLowSeverity(false);
        integration.setCreatedAt(Instant.now());
        integration.setUpdatedAt(Instant.now());
        return integrationRepository.save(integration);
    }
}
