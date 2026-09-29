package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.GithubAdvisoryIntegrationEntity;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GithubAdvisoryIntegrationRepository extends JpaRepository<GithubAdvisoryIntegrationEntity, UUID> {

    Optional<GithubAdvisoryIntegrationEntity> findByTenant(Tenant tenant);

    Optional<GithubAdvisoryIntegrationEntity> findByTenant_Id(UUID tenantId);

    List<GithubAdvisoryIntegrationEntity> findByTenant_IdAndIsEnabledTrue(UUID tenantId);

    List<GithubAdvisoryIntegrationEntity> findByIsEnabledTrue();

    List<GithubAdvisoryIntegrationEntity> findAllByTenant_Id(UUID tenantId);
}
