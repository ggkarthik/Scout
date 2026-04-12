package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.ComponentEolStatusDto;
import com.prototype.vulnwatch.dto.EolMappingConfirmRequest;
import com.prototype.vulnwatch.dto.EolProductCatalogDto;
import com.prototype.vulnwatch.dto.EolReleaseDto;
import com.prototype.vulnwatch.dto.EolSummaryDto;
import com.prototype.vulnwatch.dto.EolUnresolvedMappingDto;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.EolRefreshService;
import com.prototype.vulnwatch.service.EolService;
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

    public EolController(EolService eolService, EolRefreshService eolRefreshService) {
        this.eolService = eolService;
        this.eolRefreshService = eolRefreshService;
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
    public List<EolUnresolvedMappingDto> listUnresolved() {
        return eolService.listUnresolvedMappings();
    }
}
