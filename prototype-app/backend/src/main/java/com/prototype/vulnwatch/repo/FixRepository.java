package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Fix;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface FixRepository extends JpaRepository<Fix, UUID> {

    Optional<Fix> findByExternalIdAndSourceSystem(String externalId, String sourceSystem);

    List<Fix> findBySourceSystem(String sourceSystem);

    List<Fix> findByFixType(Fix.FixType fixType);

    List<Fix> findByEcosystem(String ecosystem);

    List<Fix> findByPackageNameAndEcosystem(String packageName, String ecosystem);

    @Query("SELECT f FROM Fix f WHERE f.status = 'ACTIVE' ORDER BY f.createdAt DESC")
    List<Fix> findActiveFixesMostRecent();

    @Query("""
        SELECT f FROM Fix f
        JOIN CveFixMap cfm ON f.id = cfm.fixId
        WHERE cfm.cveId = :cveId
        AND f.status = 'ACTIVE'
        """)
    List<Fix> findByCveId(@Param("cveId") String cveId);

    @Query("""
        SELECT f FROM Fix f
        WHERE f.sourceSystem = :sourceSystem
        AND f.status = 'ACTIVE'
        AND f.syncedAt IS NOT NULL
        ORDER BY f.syncedAt DESC
        LIMIT 1
        """)
    Optional<Fix> findMostRecentSyncedBySourceSystem(@Param("sourceSystem") String sourceSystem);

    @Query("""
        SELECT f FROM Fix f
        WHERE f.externalId IN :externalIds
        AND f.sourceSystem = :sourceSystem
        """)
    List<Fix> findByExternalIdsAndSourceSystem(
        @Param("externalIds") List<String> externalIds,
        @Param("sourceSystem") String sourceSystem
    );
}
