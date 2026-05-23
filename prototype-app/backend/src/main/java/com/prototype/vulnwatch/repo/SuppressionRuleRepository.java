package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.SuppressionRule;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SuppressionRuleRepository extends JpaRepository<SuppressionRule, UUID> {
    List<SuppressionRule> findAllByOrderByCreatedAtAsc();
}
