package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.ServiceNowCmdbConfig;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Connector rows live in the per-tenant schema behind a {@code tenant_isolation} policy, so
 * queries here are already confined to the calling tenant. An unused, tenant-unqualified
 * {@code findBySourceSystemIgnoreCase} was removed anyway: it read as though it could span
 * tenants, and it had no caller to justify the ambiguity.
 */
public interface ServiceNowCmdbConfigRepository extends JpaRepository<ServiceNowCmdbConfig, UUID> {
    Optional<ServiceNowCmdbConfig> findByTenant_IdAndSourceSystemIgnoreCase(UUID tenantId, String sourceSystem);
    List<ServiceNowCmdbConfig> findByEnabledTrueAndAutoSyncEnabledTrueOrderByUpdatedAtAsc();
    long countByTenant_Id(UUID tenantId);
}
