package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AdvisoryEquivalenceEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AdvisoryEquivalenceRepository extends JpaRepository<AdvisoryEquivalenceEntity, UUID> {

  List<AdvisoryEquivalenceEntity> findByNvdCveId(String cveId);

  Optional<AdvisoryEquivalenceEntity> findByGhsaId(String ghsaId);

  Optional<AdvisoryEquivalenceEntity> findByOsvId(String osvId);

  boolean existsByNvdCveIdAndGhsaIdAndOsvId(String nvd, String ghsa, String osv);
}
