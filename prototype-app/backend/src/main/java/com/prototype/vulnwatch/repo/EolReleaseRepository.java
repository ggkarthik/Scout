package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.EolRelease;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EolReleaseRepository extends JpaRepository<EolRelease, Long> {

    List<EolRelease> findByProductSlug(String productSlug);

    Optional<EolRelease> findByProductSlugAndCycle(String productSlug, String cycle);

    void deleteByProductSlug(String productSlug);
}
