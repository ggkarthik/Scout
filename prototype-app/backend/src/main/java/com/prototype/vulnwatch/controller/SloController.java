package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.SloStatusResponse;
import com.prototype.vulnwatch.service.SloMetricsService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * BLG-014: SLO status endpoint.
 *
 * GET /api/slo/status — returns a real-time snapshot of whether the platform is
 * meeting its defined service level objectives.  The response is intentionally
 * lightweight (no DB joins) so it can be polled by monitoring systems without
 * significant overhead.
 */
@RestController
@RequestMapping("/api/slo")
public class SloController {

    private final SloMetricsService sloMetricsService;

    public SloController(SloMetricsService sloMetricsService) {
        this.sloMetricsService = sloMetricsService;
    }

    @GetMapping("/status")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SloStatusResponse status() {
        return sloMetricsService.evaluate();
    }
}
