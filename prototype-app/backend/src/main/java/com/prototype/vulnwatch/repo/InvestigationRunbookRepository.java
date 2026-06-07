package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.InvestigationRunbook;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InvestigationRunbookRepository extends JpaRepository<InvestigationRunbook, UUID> {

    Optional<InvestigationRunbook> findByTenantIdAndCveExternalId(UUID tenantId, String cveExternalId);
}
