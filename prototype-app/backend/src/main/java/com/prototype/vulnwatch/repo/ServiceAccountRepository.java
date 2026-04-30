package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.ServiceAccount;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ServiceAccountRepository extends JpaRepository<ServiceAccount, UUID> {
    Optional<ServiceAccount> findByKeyId(String keyId);
    List<ServiceAccount> findByTenantIdOrderByCreatedAtAsc(UUID tenantId);
    long countByTenant_Id(UUID tenantId);
}
