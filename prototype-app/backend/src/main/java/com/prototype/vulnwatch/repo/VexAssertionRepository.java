package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.VexAssertion;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface VexAssertionRepository extends JpaRepository<VexAssertion, UUID> {

    List<VexAssertion> findByVulnerability_IdIn(Collection<UUID> vulnerabilityIds);

    List<VexAssertion> findByTarget_IdIn(Collection<UUID> targetIds);

    @Query("""
            select va
            from VexAssertion va
            where va.vulnerability.id = :vulnerabilityId
              and lower(va.sourceSystem) like concat('%', lower(:sourceFragment), '%')
            """)
    List<VexAssertion> findByVulnerabilityAndSourceContains(
            @Param("vulnerabilityId") UUID vulnerabilityId,
            @Param("sourceFragment") String sourceFragment
    );

    @Query("""
            select distinct va.sourceSystem
            from VexAssertion va
            """)
    Set<String> findDistinctSourceSystems();

    @Query("""
            select count(va)
            from VexAssertion va
            """)
    long countAllAssertions();
}
