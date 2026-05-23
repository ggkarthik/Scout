package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Investigation;
import com.prototype.vulnwatch.domain.Vulnerability;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface InvestigationRepository extends JpaRepository<Investigation, Long> {

    @Override
    @EntityGraph(attributePaths = "vulnerability")
    Optional<Investigation> findById(Long id);

    @EntityGraph(attributePaths = "vulnerability")
    Optional<Investigation> findByIdAndTenantId(Long id, UUID tenantId);

    Page<Investigation> findAll(Pageable pageable);

    Page<Investigation> findByTenantId(UUID tenantId, Pageable pageable);

    @EntityGraph(attributePaths = "vulnerability")
    List<Investigation> findByVulnerability(Vulnerability vulnerability);

    @EntityGraph(attributePaths = "vulnerability")
    List<Investigation> findByVulnerabilityAndTenantId(Vulnerability vulnerability, UUID tenantId);

    @EntityGraph(attributePaths = "vulnerability")
    @Query("SELECT i FROM Investigation i WHERE i.vulnerability.externalId = :cveId")
    List<Investigation> findByCveId(@Param("cveId") String cveId);

    @EntityGraph(attributePaths = "vulnerability")
    @Query("SELECT i FROM Investigation i WHERE i.tenant.id = :tenantId AND i.vulnerability.externalId = :cveId")
    List<Investigation> findByTenantIdAndCveId(@Param("tenantId") UUID tenantId, @Param("cveId") String cveId);

    Page<Investigation> findByTenantIdAndStatus(UUID tenantId, Investigation.InvestigationStatus status, Pageable pageable);

    Page<Investigation> findByTenantIdAndAssignedTo(UUID tenantId, String assignedTo, Pageable pageable);

    long countByTenantIdAndStatus(UUID tenantId, Investigation.InvestigationStatus status);

    default Optional<Investigation> findByIdAndTenantId(Long id, Long tenantId) {
        return findByIdAndTenantId(id, toTenantUuid(tenantId));
    }

    default Page<Investigation> findByTenantId(Long tenantId, Pageable pageable) {
        return findByTenantId(toTenantUuid(tenantId), pageable);
    }

    default List<Investigation> findByVulnerabilityAndTenantId(Vulnerability vulnerability, Long tenantId) {
        return findByVulnerabilityAndTenantId(vulnerability, toTenantUuid(tenantId));
    }

    default List<Investigation> findByTenantIdAndCveId(Long tenantId, String cveId) {
        return findByTenantIdAndCveId(toTenantUuid(tenantId), cveId);
    }

    default Page<Investigation> findByTenantIdAndStatus(Long tenantId, Investigation.InvestigationStatus status, Pageable pageable) {
        return findByTenantIdAndStatus(toTenantUuid(tenantId), status, pageable);
    }

    default Page<Investigation> findByTenantIdAndAssignedTo(Long tenantId, String assignedTo, Pageable pageable) {
        return findByTenantIdAndAssignedTo(toTenantUuid(tenantId), assignedTo, pageable);
    }

    default long countByTenantIdAndStatus(Long tenantId, Investigation.InvestigationStatus status) {
        return countByTenantIdAndStatus(toTenantUuid(tenantId), status);
    }

    private static UUID toTenantUuid(Long tenantId) {
        return tenantId == null ? null : new UUID(0L, tenantId);
    }
}
