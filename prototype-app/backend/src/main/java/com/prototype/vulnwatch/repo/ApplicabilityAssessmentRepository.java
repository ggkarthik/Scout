package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.ApplicabilityAssessment;
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
public interface ApplicabilityAssessmentRepository extends JpaRepository<ApplicabilityAssessment, Long> {

    @Override
    @EntityGraph(attributePaths = "vulnerability")
    Optional<ApplicabilityAssessment> findById(Long id);

    @EntityGraph(attributePaths = "vulnerability")
    Optional<ApplicabilityAssessment> findByIdAndTenantId(Long id, UUID tenantId);

    Page<ApplicabilityAssessment> findAll(Pageable pageable);

    Page<ApplicabilityAssessment> findByTenantId(UUID tenantId, Pageable pageable);

    @EntityGraph(attributePaths = "vulnerability")
    List<ApplicabilityAssessment> findByVulnerability(Vulnerability vulnerability);

    @EntityGraph(attributePaths = "vulnerability")
    List<ApplicabilityAssessment> findByVulnerabilityAndTenantId(Vulnerability vulnerability, UUID tenantId);

    @EntityGraph(attributePaths = "vulnerability")
    @Query("SELECT a FROM ApplicabilityAssessment a WHERE a.vulnerability.externalId = :cveId")
    List<ApplicabilityAssessment> findByCveId(@Param("cveId") String cveId);

    @EntityGraph(attributePaths = "vulnerability")
    @Query("SELECT a FROM ApplicabilityAssessment a WHERE a.tenant.id = :tenantId AND a.vulnerability.externalId = :cveId")
    List<ApplicabilityAssessment> findByTenantIdAndCveId(@Param("tenantId") UUID tenantId, @Param("cveId") String cveId);

    Page<ApplicabilityAssessment> findByTenantIdAndStatus(UUID tenantId, ApplicabilityAssessment.AssessmentStatus status, Pageable pageable);

    Page<ApplicabilityAssessment> findByTenantIdAndFinalResult(UUID tenantId, ApplicabilityAssessment.AssessmentResult finalResult, Pageable pageable);

    long countByTenantIdAndStatus(UUID tenantId, ApplicabilityAssessment.AssessmentStatus status);

    default Optional<ApplicabilityAssessment> findByIdAndTenantId(Long id, Long tenantId) {
        return findByIdAndTenantId(id, toTenantUuid(tenantId));
    }

    default Page<ApplicabilityAssessment> findByTenantId(Long tenantId, Pageable pageable) {
        return findByTenantId(toTenantUuid(tenantId), pageable);
    }

    default List<ApplicabilityAssessment> findByVulnerabilityAndTenantId(Vulnerability vulnerability, Long tenantId) {
        return findByVulnerabilityAndTenantId(vulnerability, toTenantUuid(tenantId));
    }

    default List<ApplicabilityAssessment> findByTenantIdAndCveId(Long tenantId, String cveId) {
        return findByTenantIdAndCveId(toTenantUuid(tenantId), cveId);
    }

    default Page<ApplicabilityAssessment> findByTenantIdAndStatus(Long tenantId, ApplicabilityAssessment.AssessmentStatus status, Pageable pageable) {
        return findByTenantIdAndStatus(toTenantUuid(tenantId), status, pageable);
    }

    default Page<ApplicabilityAssessment> findByTenantIdAndFinalResult(Long tenantId, ApplicabilityAssessment.AssessmentResult finalResult, Pageable pageable) {
        return findByTenantIdAndFinalResult(toTenantUuid(tenantId), finalResult, pageable);
    }

    default long countByTenantIdAndStatus(Long tenantId, ApplicabilityAssessment.AssessmentStatus status) {
        return countByTenantIdAndStatus(toTenantUuid(tenantId), status);
    }

    private static UUID toTenantUuid(Long tenantId) {
        return tenantId == null ? null : new UUID(0L, tenantId);
    }
}
