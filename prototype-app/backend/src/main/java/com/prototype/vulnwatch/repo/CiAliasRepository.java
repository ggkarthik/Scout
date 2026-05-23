package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CiAlias;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;

public interface CiAliasRepository extends JpaRepository<CiAlias, UUID> {
    Optional<CiAlias> findByTenant_IdAndNormalizedAliasNameAndSourceSystem(
            UUID tenantId,
            String normalizedAliasName,
            String sourceSystem
    );
    Optional<CiAlias> findByNormalizedAliasNameAndSourceSystem(
            String normalizedAliasName,
            String sourceSystem
    );

    List<CiAlias> findByTenant_IdAndNormalizedAliasName(
            @Param("tenantId") UUID tenantId,
            @Param("normalizedAliasName") String normalizedAliasName
    );
    List<CiAlias> findByNormalizedAliasName(String normalizedAliasName);

    List<CiAlias> findByTenant_IdAndNormalizedAliasNameIn(UUID tenantId, Collection<String> normalizedAliasNames);
    List<CiAlias> findByNormalizedAliasNameIn(Collection<String> normalizedAliasNames);

    List<CiAlias> findByTenant_IdAndCi_IdIn(UUID tenantId, Collection<UUID> ciIds);
    List<CiAlias> findByCi_IdIn(Collection<UUID> ciIds);

    List<CiAlias> findByTenant_IdAndCi_IdOrderByAliasNameAsc(UUID tenantId, UUID ciId);
    List<CiAlias> findByCi_IdOrderByAliasNameAsc(UUID ciId);
}
