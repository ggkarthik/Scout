package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.EolProductCatalog;
import com.prototype.vulnwatch.domain.SoftwareEolMapping;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.repo.EolProductCatalogRepository;
import com.prototype.vulnwatch.repo.SoftwareEolMappingRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import com.prototype.vulnwatch.util.CpeUtil;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Resolves a SoftwareIdentity to an endoflife.date product slug using a 4-tier strategy:
 *
 * Tier 1 — CPE match (EXACT confidence): parses cpe23 from SoftwareIdentity, looks up
 *   cpe_vendor + cpe_product in an in-memory catalog map.
 *
 * Tier 2 — PURL match (HIGH confidence): parses purl type and namespace, looks up in
 *   in-memory catalog maps + curated type/namespace hint map.
 *
 * Tier 3 — Alias match (MEDIUM confidence): checks product name/vendor against the
 *   aliases stored on catalog entries.
 *
 * Tier 4 — Normalized name match (MEDIUM confidence): uses normalized_publisher + normalized_product
 *   against a curated hint map.
 *
 * resolveAll() loads the entire catalog into in-memory Maps at the start of the run,
 * eliminating per-identity DB queries. Identities are processed in pages of 500 to bound heap usage.
 */
@Service
public class EolSlugResolverService {

    private static final Logger LOG = LoggerFactory.getLogger(EolSlugResolverService.class);

    private static final int IDENTITY_PAGE_SIZE = 500;
    private static final Set<String> LIBRARY_ECOSYSTEMS = Set.of(
            "npm",
            "pypi",
            "gem",
            "cargo",
            "nuget",
            "composer",
            "maven",
            "gomod",
            "golang",
            "go",
            "rubygems"
    );

    // Curated PURL type+namespace → slug hints.
    private static final Map<String, String> PURL_HINTS = Map.ofEntries(
            Map.entry("deb/ubuntu", "ubuntu"),
            Map.entry("deb/debian", "debian"),
            Map.entry("rpm/rhel", "rhel"),
            Map.entry("rpm/centos", "centos"),
            Map.entry("rpm/fedora", "fedora"),
            Map.entry("rpm/opensuse", "opensuse"),
            Map.entry("rpm/sles", "sles"),
            Map.entry("apk/alpine", "alpine"),
            Map.entry("maven/org.springframework.boot", "spring-boot"),
            Map.entry("maven/org.apache.tomcat", "tomcat"),
            Map.entry("maven/mysql", "mysql"),
            Map.entry("maven/org.postgresql", "postgresql"),
            Map.entry("oci/library", "docker")
    );

    // Curated "publisher::product" → slug hints for Tier 4 name matching.
    private static final Map<String, String> NAME_HINTS = Map.ofEntries(
            Map.entry("canonical::ubuntu", "ubuntu"),
            Map.entry("debian::debian", "debian"),
            Map.entry("redhat::rhel", "rhel"),
            Map.entry("redhat::red hat enterprise linux", "rhel"),
            Map.entry("centos::centos", "centos"),
            Map.entry("microsoft::windows 10", "windows"),
            Map.entry("microsoft::windows 11", "windows"),
            Map.entry("microsoft::windows server 2019", "windows-server"),
            Map.entry("microsoft::windows server 2022", "windows-server"),
            Map.entry("microsoft::windows server 2025", "windows-server"),
            Map.entry("microsoft::sql server", "mssqlserver"),
            Map.entry("microsoft::iis", "iis"),
            Map.entry("oracle::java", "java"),
            Map.entry("oracle::mysql", "mysql"),
            Map.entry("adoptium::temurin", "java"),
            Map.entry("amazon::corretto", "amazon-corretto"),
            Map.entry("apache::tomcat", "tomcat"),
            Map.entry("apache::httpd", "apache"),
            Map.entry("apache::http server", "apache"),
            Map.entry("nginx::nginx", "nginx"),
            Map.entry("postgresql::postgresql", "postgresql"),
            Map.entry("mongodb::mongodb", "mongodb"),
            Map.entry("elastic::elasticsearch", "elasticsearch"),
            Map.entry("elastic::kibana", "kibana"),
            Map.entry("kubernetes::kubernetes", "kubernetes"),
            Map.entry("docker::docker", "docker"),
            Map.entry("python::python", "python"),
            Map.entry("nodejs::node.js", "nodejs"),
            Map.entry("php::php", "php"),
            Map.entry("ruby::ruby", "ruby"),
            Map.entry("golang::go", "go"),
            Map.entry("rust::rust", "rust"),
            Map.entry("apple::macos", "macos"),
            Map.entry("apple::mac os x", "macos")
    );

    private final SoftwareIdentityRepository softwareIdentityRepository;
    private final EolProductCatalogRepository eolProductCatalogRepository;
    private final SoftwareEolMappingRepository softwareEolMappingRepository;

    public EolSlugResolverService(
            SoftwareIdentityRepository softwareIdentityRepository,
            EolProductCatalogRepository eolProductCatalogRepository,
            SoftwareEolMappingRepository softwareEolMappingRepository) {
        this.softwareIdentityRepository = softwareIdentityRepository;
        this.eolProductCatalogRepository = eolProductCatalogRepository;
        this.softwareEolMappingRepository = softwareEolMappingRepository;
    }

    /**
     * Resolves all SoftwareIdentities, using in-memory catalog maps for O(1) lookups.
     * Processes identities in pages to bound heap usage.
     * Batch-saves all new/updated mappings at the end of each page.
     */
    @Transactional
    public int resolveAll() {
        // --- Build in-memory lookup maps from catalog (single DB query) ---
        List<EolProductCatalog> catalog = eolProductCatalogRepository.findAll();

        Map<String, String> cpeMap         = new HashMap<>(catalog.size());
        Map<String, String> purlTypeNsMap  = new HashMap<>(catalog.size());
        Map<String, String> purlTypeMap    = new HashMap<>();
        Map<String, String> aliasMap       = new HashMap<>();
        Map<String, Boolean> slugSet       = new HashMap<>(catalog.size());

        for (EolProductCatalog entry : catalog) {
            String slug = entry.getSlug();
            slugSet.put(slug, Boolean.TRUE);

            if (entry.getCpeVendor() != null && entry.getCpeProduct() != null) {
                cpeMap.putIfAbsent(entry.getCpeVendor() + "::" + entry.getCpeProduct(), slug);
            }
            if (entry.getPurlType() != null) {
                if (entry.getPurlNamespace() != null) {
                    purlTypeNsMap.putIfAbsent(entry.getPurlType() + "/" + entry.getPurlNamespace(), slug);
                }
                purlTypeMap.putIfAbsent(entry.getPurlType(), slug);
            }
            for (String alias : entry.getAliasesList()) {
                String normalizedAlias = alias.trim().toLowerCase(Locale.ROOT);
                if (!normalizedAlias.isBlank()) {
                    aliasMap.putIfAbsent(normalizedAlias, slug);
                }
            }
        }

        // --- Load existing mappings into memory (single DB query) ---
        Map<String, SoftwareEolMapping> existingMappings = new HashMap<>();
        softwareEolMappingRepository.findAll()
                .forEach(m -> existingMappings.put(m.getNormalizedKey(), m));

        // --- Process identities in pages ---
        int resolved = 0;
        int pageNum = 0;
        Page<SoftwareIdentity> page;

        do {
            page = softwareIdentityRepository.findAll(PageRequest.of(pageNum++, IDENTITY_PAGE_SIZE));
            List<SoftwareEolMapping> toSave = new ArrayList<>();

            for (SoftwareIdentity identity : page.getContent()) {
                String key = buildNormalizedKey(identity);

                SoftwareEolMapping existing = existingMappings.get(key);
                if (existing != null && existing.isConfirmed()) {
                    continue; // never overwrite confirmed manual mappings
                }

                SlugMatch match = resolveWithMaps(identity, cpeMap, purlTypeNsMap, purlTypeMap, aliasMap, slugSet);
                if (match == null) continue;

                SoftwareEolMapping mapping = existing != null ? existing : new SoftwareEolMapping();
                mapping.setNormalizedKey(key);
                mapping.setSoftwareIdentityId(identity.getId());
                mapping.setEolSlug(match.slug());
                mapping.setMatchConfidence(match.confidence());
                mapping.setMatchMethod(match.method());
                mapping.touch();
                toSave.add(mapping);
                resolved++;
            }

            if (!toSave.isEmpty()) {
                softwareEolMappingRepository.saveAll(toSave);
            }
        } while (page.hasNext());

        LOG.info("EOL slug resolution complete — resolved {} identities", resolved);
        return resolved;
    }

    /**
     * Resolves a single SoftwareIdentity to an EOL slug (used for individual calls / EolService).
     * Falls back to DB lookups since no in-memory maps are available for single calls.
     */
    @Transactional
    public boolean resolveIdentity(SoftwareIdentity identity) {
        String normalizedKey = buildNormalizedKey(identity);

        java.util.Optional<SoftwareEolMapping> existing = softwareEolMappingRepository.findByNormalizedKey(normalizedKey);
        if (existing.isPresent() && existing.get().isConfirmed()) {
            return false;
        }

        SlugMatch match = resolve(identity);
        if (match == null) return false;

        SoftwareEolMapping mapping = existing.orElseGet(SoftwareEolMapping::new);
        mapping.setNormalizedKey(normalizedKey);
        mapping.setSoftwareIdentityId(identity.getId());
        mapping.setEolSlug(match.slug());
        mapping.setMatchConfidence(match.confidence());
        mapping.setMatchMethod(match.method());
        mapping.touch();
        softwareEolMappingRepository.save(mapping);
        return true;
    }

    /**
     * Public single-identity resolution using DB lookups (no in-memory maps).
     */
    public SlugMatch resolve(SoftwareIdentity identity) {
        SlugMatch cpeMatch = resolveViaCpe(identity.getCpe23());
        if (cpeMatch != null) return cpeMatch;

        SlugMatch purlMatch = resolveViaPurl(identity.getPurl());
        if (purlMatch != null) return purlMatch;

        SlugMatch aliasMatch = resolveViaAliasDb(identity.getVendor(), identity.getProduct());
        if (aliasMatch != null) return aliasMatch;

        return resolveViaName(identity.getVendor(), identity.getProduct());
    }

    public boolean shouldSurfaceForLifecycleReview(SoftwareIdentity identity, List<String> ecosystems) {
        if (identity == null) {
            return false;
        }
        if (resolve(identity) != null) {
            return true;
        }
        if (identity.getCpe23() != null && !identity.getCpe23().isBlank()) {
            return true;
        }
        List<String> normalizedEcosystems = ecosystems == null
                ? List.of()
                : ecosystems.stream()
                        .filter(value -> value != null && !value.isBlank())
                        .map(value -> value.trim().toLowerCase(Locale.ROOT))
                        .distinct()
                        .toList();
        if (normalizedEcosystems.isEmpty()) {
            return true;
        }
        return normalizedEcosystems.stream().anyMatch(ecosystem -> !LIBRARY_ECOSYSTEMS.contains(ecosystem));
    }

    // -------------------------------------------------------------------------
    // In-memory resolution (used by resolveAll)
    // -------------------------------------------------------------------------

    private SlugMatch resolveWithMaps(
            SoftwareIdentity identity,
            Map<String, String> cpeMap,
            Map<String, String> purlTypeNsMap,
            Map<String, String> purlTypeMap,
            Map<String, String> aliasMap,
            Map<String, Boolean> slugSet) {

        // Tier 1: CPE
        SlugMatch cpe = resolveViaCpeMap(identity.getCpe23(), cpeMap, slugSet);
        if (cpe != null) return cpe;

        // Tier 2: PURL
        SlugMatch purl = resolveViaPurlMap(identity.getPurl(), purlTypeNsMap, purlTypeMap);
        if (purl != null) return purl;

        // Tier 3: Alias
        SlugMatch alias = resolveViaAliasMap(identity.getVendor(), identity.getProduct(), aliasMap, slugSet);
        if (alias != null) return alias;

        // Tier 4: Name hints
        return resolveViaName(identity.getVendor(), identity.getProduct());
    }

    // -------------------------------------------------------------------------
    // Tier 1: CPE (in-memory)
    // -------------------------------------------------------------------------

    private SlugMatch resolveViaCpeMap(String cpe23, Map<String, String> cpeMap, Map<String, Boolean> slugSet) {
        if (cpe23 == null || cpe23.isBlank()) return null;
        CpeUtil.ParsedCpe parsed = CpeUtil.parse(cpe23);
        if (parsed.vendor().isBlank() || parsed.product().isBlank()) return null;

        String slug = cpeMap.get(parsed.vendor() + "::" + parsed.product());
        if (slug != null) return new SlugMatch(slug, "EXACT", "CPE");

        // Product slug direct match
        if (slugSet.containsKey(parsed.product())) {
            return new SlugMatch(parsed.product(), "HIGH", "CPE_PRODUCT");
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Tier 2: PURL (in-memory)
    // -------------------------------------------------------------------------

    private SlugMatch resolveViaPurlMap(String purl, Map<String, String> purlTypeNsMap, Map<String, String> purlTypeMap) {
        if (purl == null || purl.isBlank()) return null;
        String[] parts = parsePurlParts(purl);
        String type = parts[0];
        String namespace = parts[1];

        // Curated hints first (faster than DB map for common cases)
        if (namespace != null) {
            String hint = PURL_HINTS.get(type + "/" + namespace);
            if (hint != null) return new SlugMatch(hint, "HIGH", "PURL");
        }

        // Catalog DB maps
        if (namespace != null) {
            String slug = purlTypeNsMap.get(type + "/" + namespace);
            if (slug != null) return new SlugMatch(slug, "HIGH", "PURL_DB");
        }

        return null;
    }

    // -------------------------------------------------------------------------
    // Tier 3: Alias (in-memory)
    // -------------------------------------------------------------------------

    private SlugMatch resolveViaAliasMap(String vendor, String product,
            Map<String, String> aliasMap, Map<String, Boolean> slugSet) {
        if (product == null || product.isBlank()) return null;
        String normProduct = product.trim().toLowerCase(Locale.ROOT);

        // Try direct product name as alias
        String slug = aliasMap.get(normProduct);
        if (slug != null) return new SlugMatch(slug, "MEDIUM", "ALIAS");

        // Try "vendor product" combined
        if (vendor != null && !vendor.isBlank()) {
            String combined = vendor.trim().toLowerCase(Locale.ROOT) + " " + normProduct;
            slug = aliasMap.get(combined);
            if (slug != null) return new SlugMatch(slug, "MEDIUM", "ALIAS");
        }

        // Try product slug (dashes instead of spaces)
        String productSlug = normProduct.replaceAll("\\s+", "-");
        if (aliasMap.containsKey(productSlug)) {
            return new SlugMatch(aliasMap.get(productSlug), "MEDIUM", "ALIAS");
        }
        if (slugSet.containsKey(productSlug)) {
            return new SlugMatch(productSlug, "MEDIUM", "ALIAS_SLUG");
        }

        return null;
    }

    // -------------------------------------------------------------------------
    // Tier 1–3: DB fallbacks (for single-identity resolve())
    // -------------------------------------------------------------------------

    private SlugMatch resolveViaCpe(String cpe23) {
        if (cpe23 == null || cpe23.isBlank()) return null;
        CpeUtil.ParsedCpe parsed = CpeUtil.parse(cpe23);
        if (parsed.vendor().isBlank() || parsed.product().isBlank()) return null;

        java.util.Optional<EolProductCatalog> match = eolProductCatalogRepository
                .findByCpeVendorAndCpeProduct(parsed.vendor(), parsed.product());
        if (match.isPresent()) return new SlugMatch(match.get().getSlug(), "EXACT", "CPE");

        if (eolProductCatalogRepository.existsBySlug(parsed.product())) {
            return new SlugMatch(parsed.product(), "HIGH", "CPE_PRODUCT");
        }
        return null;
    }

    private SlugMatch resolveViaPurl(String purl) {
        if (purl == null || purl.isBlank()) return null;
        String[] parts = parsePurlParts(purl);
        String type = parts[0];
        String namespace = parts[1];

        if (namespace != null) {
            String hint = PURL_HINTS.get(type + "/" + namespace);
            if (hint != null) return new SlugMatch(hint, "HIGH", "PURL");
        }

        if (namespace != null) {
            java.util.Optional<EolProductCatalog> dbMatch = eolProductCatalogRepository
                    .findByPurlTypeAndPurlNamespace(type, namespace);
            if (dbMatch.isPresent()) return new SlugMatch(dbMatch.get().getSlug(), "HIGH", "PURL_DB");
        }
        return null;
    }

    private SlugMatch resolveViaAliasDb(String vendor, String product) {
        if (product == null || product.isBlank()) return null;
        String normProduct = product.trim().toLowerCase(Locale.ROOT);

        List<EolProductCatalog> all = eolProductCatalogRepository.findAll();
        for (EolProductCatalog entry : all) {
            for (String alias : entry.getAliasesList()) {
                if (alias.equalsIgnoreCase(normProduct)) {
                    return new SlugMatch(entry.getSlug(), "MEDIUM", "ALIAS");
                }
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Tier 4: Name matching (static hints only)
    // -------------------------------------------------------------------------

    private SlugMatch resolveViaName(String vendor, String product) {
        if (product == null || product.isBlank()) return null;
        String normVendor  = vendor == null ? "" : vendor.trim().toLowerCase(Locale.ROOT);
        String normProduct = product.trim().toLowerCase(Locale.ROOT);

        String key = normVendor + "::" + normProduct;
        if (NAME_HINTS.containsKey(key)) return new SlugMatch(NAME_HINTS.get(key), "MEDIUM", "NAME");

        String productSlug = normProduct.replaceAll("\\s+", "-");
        if (eolProductCatalogRepository.existsBySlug(productSlug)) {
            return new SlugMatch(productSlug, "MEDIUM", "NAME_SLUG");
        }

        String productNoVersion = normProduct.replaceAll("\\s+\\d[\\d.]*$", "").trim();
        if (!productNoVersion.equals(normProduct)) {
            String slugNoVersion = productNoVersion.replaceAll("\\s+", "-");
            if (eolProductCatalogRepository.existsBySlug(slugNoVersion)) {
                return new SlugMatch(slugNoVersion, "MEDIUM", "NAME_SLUG");
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private String buildNormalizedKey(SoftwareIdentity identity) {
        String vendor  = identity.getVendor()  == null ? "" : identity.getVendor().trim().toLowerCase(Locale.ROOT);
        String product = identity.getProduct() == null ? "" : identity.getProduct().trim().toLowerCase(Locale.ROOT);
        return vendor + "::" + product;
    }

    /** Parses a PURL into [type, namespace]. namespace may be null. */
    private String[] parsePurlParts(String purl) {
        if (purl == null || purl.isBlank()) return new String[]{"", null};
        String stripped = purl.startsWith("pkg:") ? purl.substring(4) : purl;
        int slashIdx = stripped.indexOf('/');
        String type = slashIdx > 0
                ? stripped.substring(0, slashIdx).toLowerCase(Locale.ROOT)
                : stripped.toLowerCase(Locale.ROOT);
        String remainder = slashIdx > 0 ? stripped.substring(slashIdx + 1) : "";
        int nextSlash = remainder.indexOf('/');
        String namespace = nextSlash > 0
                ? remainder.substring(0, nextSlash).toLowerCase(Locale.ROOT)
                : remainder.split("@")[0].split("#")[0].toLowerCase(Locale.ROOT);
        return new String[]{type, namespace.isBlank() ? null : namespace};
    }

    public record SlugMatch(String slug, String confidence, String method) {}
}
