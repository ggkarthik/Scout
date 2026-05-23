package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.OwnershipRule;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OwnershipRuleRepository extends JpaRepository<OwnershipRule, UUID> {
    List<OwnershipRule> findAllByOrderByExecutionOrderAscCreatedAtAsc();
}
