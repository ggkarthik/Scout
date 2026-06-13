package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.PlatformVulnIntelDetailResponse;
import com.prototype.vulnwatch.dto.PlatformVulnRepoPageResponse;
import com.prototype.vulnwatch.dto.PlatformVulnSourceStatsResponse;
import com.prototype.vulnwatch.dto.VulnRepoDashboardResponse;
import com.prototype.vulnwatch.service.PlatformVulnRepoService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/platform/vuln-repo")
@RequiredArgsConstructor
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class PlatformVulnRepoController {

    private final PlatformVulnRepoService platformVulnRepoService;

    @GetMapping("/dashboard")
    public VulnRepoDashboardResponse getDashboard() {
        return platformVulnRepoService.getDashboard();
    }

    @GetMapping("/vulnerabilities")
    public PlatformVulnRepoPageResponse listVulnerabilities(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(required = false) String query,
            @RequestParam(required = false) Boolean inKev,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String source
    ) {
        return platformVulnRepoService.listVulnerabilities(page, size, query, inKev, severity, source);
    }

    @GetMapping("/source-stats")
    public PlatformVulnSourceStatsResponse getSourceStats() {
        return platformVulnRepoService.getSourceStats();
    }

    @GetMapping("/intel/{externalId}")
    public PlatformVulnIntelDetailResponse getIntelDetail(@PathVariable String externalId) {
        return platformVulnRepoService.getIntelDetail(externalId);
    }
}
