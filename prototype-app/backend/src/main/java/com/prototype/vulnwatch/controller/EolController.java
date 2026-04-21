package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.ComponentEolStatusDto;
import com.prototype.vulnwatch.dto.EolMappingConfirmRequest;
import com.prototype.vulnwatch.dto.EolProductCatalogDto;
import com.prototype.vulnwatch.dto.EolReleaseDto;
import com.prototype.vulnwatch.dto.EolSlugSuggestionDto;
import com.prototype.vulnwatch.dto.EolSummaryDto;
import com.prototype.vulnwatch.dto.EolUnresolvedMappingDto;
import com.prototype.vulnwatch.dto.PackageAssetDto;
import com.prototype.vulnwatch.dto.PackageEolStatusDto;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.EolRefreshService;
import com.prototype.vulnwatch.service.EolService;
import com.prototype.vulnwatch.service.EolSlugResolverService;
import java.util.List;
import java.util.Map;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/eol")
public class EolController {

    private final EolService eolService;
    private final EolRefreshService eolRefreshService;
    private final EolSlugResolverService slugResolverService;

    public EolController(EolService eolService, EolRefreshService eolRefreshService,
            EolSlugResolverService slugResolverService) {
        this.eolService = eolService;
        this.eolRefreshService = eolRefreshService;
        this.slugResolverService = slugResolverService;
    }

    /**
     * Summary counts: EOL / near-EOL / supported / unknown across active inventory.
     */
    @GetMapping("/status/summary")
    public EolSummaryDto getSummary() {
        return eolService.getSummary();
    }

    /**
     * Paged list of inventory components with their EOL status.
     * filter: eol | near-eol | ok | unknown (blank = all)
     */
    @GetMapping("/status/components")
    public Page<ComponentEolStatusDto> getComponentStatuses(
            @RequestParam(required = false) String filter,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        return eolService.getComponentStatuses(filter, page, Math.min(size, 200));
    }

    /**
     * Paged list of packages (grouped across all assets) with their EOL status and impacted asset count.
     * One row per unique (package_name, ecosystem, eol_slug, eol_cycle, eol_date, is_eol) combination.
     */
    @GetMapping("/status/packages")
    public Page<PackageEolStatusDto> getPackageStatuses(
            @RequestParam(required = false) String filter,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        return eolService.getPackageStatuses(filter, page, Math.min(size, 200));
    }

    /**
     * Assets that have a specific package installed, with the installed version(s).
     * Used for drill-down from the package-centric EOL table.
     */
    @GetMapping("/status/packages/assets")
    public Page<PackageAssetDto> getPackageAssets(
            @RequestParam String packageName,
            @RequestParam(required = false) String ecosystem,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        return eolService.getPackageAssets(packageName, ecosystem, page, Math.min(size, 200));
    }

    /**
     * Full EOL product catalog (slugs + CPE/PURL identifiers).
     */
    @GetMapping("/products")
    public List<EolProductCatalogDto> listProducts() {
        return eolService.listProducts();
    }

    /**
     * All release cycles for a specific product slug.
     */
    @GetMapping("/products/{slug}/releases")
    public List<EolReleaseDto> listReleases(@PathVariable String slug) {
        return eolService.listReleases(slug);
    }

    /**
     * Returns backend-computed slug candidates for a given normalizedKey.
     * Runs all 4 resolution tiers and returns up to 5 candidates with confidence and method.
     */
    @GetMapping("/mappings/suggestions")
    public List<EolSlugSuggestionDto> listSuggestions(@RequestParam String normalizedKey) {
        return slugResolverService.resolveSuggestions(normalizedKey);
    }

    /**
     * Manually confirm or override an EOL slug mapping for a normalized product key.
     */
    @PostMapping("/mappings/confirm")
    public Map<String, String> confirmMapping(@RequestBody EolMappingConfirmRequest request) {
        eolService.confirmMapping(request);
        return Map.of("status", "confirmed");
    }

    // -------------------------------------------------------------------------
    // Manual trigger endpoints (Connect UI)
    // -------------------------------------------------------------------------

    @PostMapping("/admin/refresh/catalog")
    public SyncTriggerResponse triggerCatalogRefresh() {
        return eolRefreshService.triggerCatalogRefresh();
    }

    @PostMapping("/admin/refresh/releases")
    public SyncTriggerResponse triggerReleaseRefresh() {
        return eolRefreshService.triggerReleaseRefresh();
    }

    @PostMapping("/admin/refresh/mappings")
    public SyncTriggerResponse triggerMappingResolve() {
        return eolRefreshService.triggerMappingResolve();
    }

    @PostMapping("/admin/refresh/denormalize")
    public SyncTriggerResponse triggerDenormalize() {
        return eolRefreshService.triggerDenormalize();
    }

    @PostMapping("/admin/refresh/full")
    public SyncTriggerResponse triggerFullRefresh() {
        return eolRefreshService.triggerFullRefresh();
    }

    /**
     * Software identities that have no EOL slug mapping yet (for analyst review).
     */
    @GetMapping("/mappings/unresolved")
    public Page<EolUnresolvedMappingDto> listUnresolved(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        return eolService.listUnresolvedMappings(page, Math.min(size, 100));
    }
}
