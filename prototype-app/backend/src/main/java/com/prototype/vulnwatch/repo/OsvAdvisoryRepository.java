package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.OsvAdvisoryEntity;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OsvAdvisoryRepository extends JpaRepository<OsvAdvisoryEntity, UUID> {

  List<OsvAdvisoryEntity> findByEcosystemAndPackageName(String ecosystem, String packageName);

  List<OsvAdvisoryEntity> findBySource(String source);

  Optional<OsvAdvisoryEntity> findByOsvId(String osvId);

  List<OsvAdvisoryEntity> findByModifiedAtAfter(Instant since);

  long countByEcosystem(String ecosystem);
}
