package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.GithubSecurityAdvisoryEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface GithubSecurityAdvisoryRepository extends JpaRepository<GithubSecurityAdvisoryEntity, UUID> {

    Optional<GithubSecurityAdvisoryEntity> findByGhsaId(String ghsaId);

    Optional<GithubSecurityAdvisoryEntity> findByCveId(String cveId);

    List<GithubSecurityAdvisoryEntity> findByEcosystemAndPackageName(String ecosystem, String packageName);

    @Query("SELECT g FROM GithubSecurityAdvisoryEntity g WHERE g.ecosystem = :ecosystem AND g.packageName = :packageName AND g.isApplicable = true")
    List<GithubSecurityAdvisoryEntity> findApplicableByEcosystemAndPackageName(
            @Param("ecosystem") String ecosystem,
            @Param("packageName") String packageName
    );

    @Query("SELECT g FROM GithubSecurityAdvisoryEntity g WHERE g.ghsaId IN :ghsaIds")
    List<GithubSecurityAdvisoryEntity> findByGhsaIds(@Param("ghsaIds") List<String> ghsaIds);

    List<GithubSecurityAdvisoryEntity> findByIsApplicableTrue();
}
