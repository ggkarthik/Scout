package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RiskPolicyRepository extends JpaRepository<RiskPolicy, UUID> {
    Optional<RiskPolicy> findByTenant(Tenant tenant);

    Optional<RiskPolicy> findTopByOrderByUpdatedAtDesc();
}
