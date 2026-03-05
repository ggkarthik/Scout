package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrgCveRecordRepository extends JpaRepository<OrgCveRecord, UUID> {
    Optional<OrgCveRecord> findByTenantAndVulnerability_Id(Tenant tenant, UUID vulnerabilityId);

    List<OrgCveRecord> findByTenantAndVulnerability_IdIn(Tenant tenant, Collection<UUID> vulnerabilityIds);
}
