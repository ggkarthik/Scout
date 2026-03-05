package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantRepository extends JpaRepository<Tenant, UUID> {
    Optional<Tenant> findByNameIgnoreCase(String name);
    List<Tenant> findAllByOrderByCreatedAtAsc();
}
