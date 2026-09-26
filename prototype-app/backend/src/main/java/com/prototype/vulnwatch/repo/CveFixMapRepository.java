package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CveFixMap;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface CveFixMapRepository extends JpaRepository<CveFixMap, UUID> {

    List<CveFixMap> findByCveId(String cveId);

    List<CveFixMap> findByFixId(UUID fixId);

    @Query("""
        SELECT cfm FROM CveFixMap cfm
        WHERE cfm.cveId = :cveId
        AND cfm.relationshipType = :relationshipType
        """)
    List<CveFixMap> findByCveIdAndRelationshipType(
        @Param("cveId") String cveId,
        @Param("relationshipType") CveFixMap.RelationshipType relationshipType
    );

    @Query("""
        SELECT cfm FROM CveFixMap cfm
        WHERE cfm.fixId = :fixId
        AND cfm.relationshipType = :relationshipType
        """)
    List<CveFixMap> findByFixIdAndRelationshipType(
        @Param("fixId") UUID fixId,
        @Param("relationshipType") CveFixMap.RelationshipType relationshipType
    );

    @Query("""
        SELECT COUNT(cfm) FROM CveFixMap cfm
        WHERE cfm.cveId = :cveId
        """)
    long countByCveId(@Param("cveId") String cveId);

    @Query("""
        SELECT COUNT(cfm) FROM CveFixMap cfm
        WHERE cfm.fixId = :fixId
        """)
    long countByFixId(@Param("fixId") UUID fixId);

    boolean existsByFixIdAndCveId(UUID fixId, String cveId);
}
