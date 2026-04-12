package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.EolProductCatalog;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface EolProductCatalogRepository extends JpaRepository<EolProductCatalog, Long> {

    Optional<EolProductCatalog> findBySlug(String slug);

    boolean existsBySlug(String slug);

    Optional<EolProductCatalog> findByCpeVendorAndCpeProduct(String cpeVendor, String cpeProduct);

    Optional<EolProductCatalog> findByPurlTypeAndPurlNamespace(String purlType, String purlNamespace);

    Optional<EolProductCatalog> findByPurlType(String purlType);

    @Query("select e.slug from EolProductCatalog e")
    List<String> findAllSlugs();

    /**
     * Returns slugs that have at least one identifier (CPE or PURL).
     * Used as a bounded first-run fallback instead of fetching all 600+ catalog entries.
     */
    @Query("select e.slug from EolProductCatalog e where e.cpeVendor is not null or e.purlType is not null")
    List<String> findSlugsByHasIdentifiers();

    /** Text-search fallback: slug or displayName contains the given term (case-insensitive). */
    List<EolProductCatalog> findTop5BySlugContainingIgnoreCaseOrDisplayNameContainingIgnoreCase(
            String slugFragment, String displayNameFragment);
}
