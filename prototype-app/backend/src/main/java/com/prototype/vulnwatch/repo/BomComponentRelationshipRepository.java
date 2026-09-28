package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.BomComponentRelationship;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/** See {@link BomSourceRepository} on why these are not tenant-qualified. */
@Repository
public interface BomComponentRelationshipRepository
        extends JpaRepository<BomComponentRelationship, UUID> {

    List<BomComponentRelationship> findByBomId(UUID bomId);

    List<BomComponentRelationship> findBySourceComponentId(UUID sourceComponentId);

    void deleteByBomId(UUID bomId);
}
