package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.BomComponentEvidence;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BomComponentEvidenceRepository extends JpaRepository<BomComponentEvidence, UUID> {

    List<BomComponentEvidence> findByBomComponentIdOrderByCreatedAtAsc(UUID bomComponentId);

    List<BomComponentEvidence> findByBomComponentIdIn(Collection<UUID> bomComponentIds);

    List<BomComponentEvidence> findByBomIdIn(Collection<UUID> bomIds);

    long countByBomId(UUID bomId);
}
