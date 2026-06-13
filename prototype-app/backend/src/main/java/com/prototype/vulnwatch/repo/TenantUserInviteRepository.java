package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.TenantUserInvite;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantUserInviteRepository extends JpaRepository<TenantUserInvite, UUID> {
    List<TenantUserInvite> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);
    Optional<TenantUserInvite> findByIdAndTenantId(UUID id, UUID tenantId);
    Optional<TenantUserInvite> findByToken(String token);
    Optional<TenantUserInvite> findFirstByTenantIdAndEmailIgnoreCaseAndStatusInOrderByCreatedAtDesc(
            UUID tenantId,
            String email,
            List<String> statuses
    );
}
