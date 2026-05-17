package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantRepository extends JpaRepository<Tenant, UUID> {
    Optional<Tenant> findByNameIgnoreCase(String name);
    Optional<Tenant> findBySlugIgnoreCase(String slug);
    boolean existsByNameIgnoreCase(String name);
    boolean existsBySlugIgnoreCase(String slug);
    List<Tenant> findAllByOrderByCreatedAtAsc();
    List<Tenant> findByPlanCodeIgnoreCaseAndStatusIgnoreCaseAndDemoExpiresAtBefore(String planCode, String status, Instant now);
}
