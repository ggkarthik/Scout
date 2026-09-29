package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.GithubRepositoryComponentAdvisoryEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface GithubRepositoryComponentAdvisoryRepository extends JpaRepository<GithubRepositoryComponentAdvisoryEntity, UUID> {

    @Query("SELECT g FROM GithubRepositoryComponentAdvisoryEntity g WHERE g.tenant.id = :tenantId AND g.githubSource.id = :sourceId AND g.componentId = :componentId AND g.advisoryId = :advisoryId")
    Optional<GithubRepositoryComponentAdvisoryEntity> findBySourceIdAndComponentIdAndAdvisoryId(
            @Param("tenantId") UUID tenantId,
            @Param("sourceId") UUID sourceId,
            @Param("componentId") String componentId,
            @Param("advisoryId") UUID advisoryId
    );

    @Query("SELECT g FROM GithubRepositoryComponentAdvisoryEntity g WHERE g.tenant.id = :tenantId AND g.githubSource.id = :sourceId AND g.isAffected = true")
    List<GithubRepositoryComponentAdvisoryEntity> findBySourceIdAndIsAffectedTrue(
            @Param("tenantId") UUID tenantId,
            @Param("sourceId") UUID sourceId
    );

    @Query("SELECT g FROM GithubRepositoryComponentAdvisoryEntity g WHERE g.tenant.id = :tenantId AND g.githubSource.id = :sourceId")
    List<GithubRepositoryComponentAdvisoryEntity> findBySourceId(
            @Param("tenantId") UUID tenantId,
            @Param("sourceId") UUID sourceId
    );

    @Query("SELECT g FROM GithubRepositoryComponentAdvisoryEntity g WHERE g.tenant.id = :tenantId AND g.componentId = :componentId")
    List<GithubRepositoryComponentAdvisoryEntity> findByComponentId(
            @Param("tenantId") UUID tenantId,
            @Param("componentId") String componentId
    );

    @Query("SELECT g FROM GithubRepositoryComponentAdvisoryEntity g WHERE g.tenant.id = :tenantId AND g.finding.id = :findingId")
    List<GithubRepositoryComponentAdvisoryEntity> findByFindingId(
            @Param("tenantId") UUID tenantId,
            @Param("findingId") UUID findingId
    );

    @Query("DELETE FROM GithubRepositoryComponentAdvisoryEntity g WHERE g.tenant.id = :tenantId AND g.githubSource.id = :sourceId")
    void deleteBySourceId(
            @Param("tenantId") UUID tenantId,
            @Param("sourceId") UUID sourceId
    );
}
