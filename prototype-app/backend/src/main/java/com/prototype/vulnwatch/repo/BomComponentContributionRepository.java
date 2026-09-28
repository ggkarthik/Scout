package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.BomComponentContribution;
import com.prototype.vulnwatch.domain.BomContributionState;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** See {@link BomSourceRepository} on why these are not tenant-qualified. */
@Repository
public interface BomComponentContributionRepository
        extends JpaRepository<BomComponentContribution, UUID> {

    Optional<BomComponentContribution> findBySourceIdAndInventoryComponentId(
            UUID sourceId, UUID inventoryComponentId);

    List<BomComponentContribution> findBySourceId(UUID sourceId);

    /** Claims carried by one document version, for when that document is deleted. */
    List<BomComponentContribution> findByBomId(UUID bomId);

    List<BomComponentContribution> findByInventoryComponentId(UUID inventoryComponentId);

    /**
     * Every claim standing against a component. Reconciliation reads this to decide whether
     * a withdrawal leaves any remaining support, or conflicts with an asserted absence.
     */
    List<BomComponentContribution> findByInventoryComponentIdAndContributionState(
            UUID inventoryComponentId, BomContributionState contributionState);

    List<BomComponentContribution> findBySourceIdAndContributionState(
            UUID sourceId, BomContributionState contributionState);

    long countByInventoryComponentIdAndContributionState(
            UUID inventoryComponentId, BomContributionState contributionState);
}
