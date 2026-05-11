package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface FixRecordRepository extends JpaRepository<FixRecord, UUID> {

    List<FixRecord> findByTenantAndCveIdOrderByCreatedAtAsc(Tenant tenant, String cveId);

    @Query("SELECT f FROM FixRecord f WHERE f.tenant = :tenant AND f.softwareEntitiesJson LIKE :nameLike ORDER BY f.createdAt ASC")
    List<FixRecord> findByTenantAndSoftwareNameContaining(@Param("tenant") Tenant tenant, @Param("nameLike") String nameLike);

    @Modifying
    @Query("delete from FixRecord f where f.tenant = :tenant and f.cveId = :cveId")
    void deleteByTenantAndCveId(@Param("tenant") Tenant tenant, @Param("cveId") String cveId);
}
