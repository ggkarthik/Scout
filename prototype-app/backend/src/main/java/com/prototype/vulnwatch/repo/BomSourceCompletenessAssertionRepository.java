package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.BomSourceCompletenessAssertion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** See {@link BomSourceRepository} on why these are not tenant-qualified. */
@Repository
public interface BomSourceCompletenessAssertionRepository
        extends JpaRepository<BomSourceCompletenessAssertion, UUID> {

    List<BomSourceCompletenessAssertion> findBySourceIdOrderByAssertedAtDesc(UUID sourceId);

    Optional<BomSourceCompletenessAssertion> findFirstBySourceIdOrderByAssertedAtDesc(UUID sourceId);

    Optional<BomSourceCompletenessAssertion> findByBomId(UUID bomId);
}
