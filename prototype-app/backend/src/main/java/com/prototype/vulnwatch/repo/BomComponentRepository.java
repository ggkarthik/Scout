package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.BomComponent;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface BomComponentRepository extends JpaRepository<BomComponent, UUID> {

    List<BomComponent> findByBomIdAndActiveTrue(UUID bomId, Pageable pageable);

    List<BomComponent> findByBomIdAndActiveTrue(UUID bomId);

    List<BomComponent> findByBomIdInAndActiveTrue(Collection<UUID> bomIds);

    long countByBomIdAndActiveTrue(UUID bomId);

    @Modifying
    @Query("UPDATE BomComponent c SET c.active = false WHERE c.bomId = :bomId AND c.active = true")
    int softDeleteByBomId(@Param("bomId") UUID bomId);
}
