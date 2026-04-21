package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.EolRelease;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface EolReleaseRepository extends JpaRepository<EolRelease, Long> {

    List<EolRelease> findByProductSlug(String productSlug);

    Optional<EolRelease> findByProductSlugAndCycle(String productSlug, String cycle);

    @Query("""
            select r.productSlug, count(r)
            from EolRelease r
            group by r.productSlug
            """)
    List<Object[]> countReleasesByProductSlug();

    void deleteByProductSlug(String productSlug);
}
