package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AiBomProjectionReceipt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

/** See {@link BomSourceRepository} on why these are not tenant-qualified. */
@Repository
public interface AiBomProjectionReceiptRepository extends JpaRepository<AiBomProjectionReceipt, UUID> {

    boolean existsByTenantIdAndSourceIdAndSourceRevisionAndOperationAndProjectionVersion(
            UUID tenantId, UUID sourceId, long sourceRevision, String operation, int projectionVersion);
}
