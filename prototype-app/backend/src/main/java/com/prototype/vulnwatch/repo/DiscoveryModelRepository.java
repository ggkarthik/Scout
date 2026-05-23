package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.DiscoveryModel;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DiscoveryModelRepository extends JpaRepository<DiscoveryModel, UUID> {
    List<DiscoveryModel> findByTenant_IdAndPrimaryKeyIn(UUID tenantId, Collection<String> primaryKeys);
    List<DiscoveryModel> findByPrimaryKeyIn(Collection<String> primaryKeys);
}
