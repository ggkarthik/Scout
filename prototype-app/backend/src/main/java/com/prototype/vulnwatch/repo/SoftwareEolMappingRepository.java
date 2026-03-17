package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.SoftwareEolMapping;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface SoftwareEolMappingRepository extends JpaRepository<SoftwareEolMapping, Long> {

    Optional<SoftwareEolMapping> findByNormalizedKey(String normalizedKey);

    Optional<SoftwareEolMapping> findBySoftwareIdentityId(UUID softwareIdentityId);

    List<SoftwareEolMapping> findByEolSlugIsNull();

    @Query("select distinct m.eolSlug from SoftwareEolMapping m where m.eolSlug is not null")
    List<String> findDistinctMappedSlugs();
}
