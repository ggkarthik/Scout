package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.BomComponentWorkflow;
import com.prototype.vulnwatch.domain.BomWorkflowStatus;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BomComponentWorkflowRepository extends JpaRepository<BomComponentWorkflow, UUID> {

    List<BomComponentWorkflow> findByBomComponentIdAndWorkflowStatus(UUID bomComponentId, BomWorkflowStatus workflowStatus);

    List<BomComponentWorkflow> findByBomComponentIdIn(Collection<UUID> bomComponentIds);

    java.util.Optional<BomComponentWorkflow> findFirstByBomComponentIdAndInvestigationKey(UUID bomComponentId, String investigationKey);
}
