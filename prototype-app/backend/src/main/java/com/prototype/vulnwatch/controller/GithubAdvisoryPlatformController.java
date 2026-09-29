package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.GithubAdvisorySyncStatusResponse;
import com.prototype.vulnwatch.service.GithubAdvisoryPlatformService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/platform/ghsa")
@RequiredArgsConstructor
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class GithubAdvisoryPlatformController {

    private final GithubAdvisoryPlatformService platformService;

    @GetMapping("/sync-status")
    public ResponseEntity<GithubAdvisorySyncStatusResponse> getSyncStatus() {
        log.debug("GET /api/platform/ghsa/sync-status");
        GithubAdvisorySyncStatusResponse status = platformService.getPlatformSyncStatus();
        return ResponseEntity.ok(status);
    }

    @PostMapping("/sync/trigger")
    public ResponseEntity<GithubAdvisorySyncStatusResponse> triggerSync() {
        log.info("POST /api/platform/ghsa/sync/trigger");
        GithubAdvisorySyncStatusResponse status = platformService.initiatePlatformSync();
        if ("SYNCING".equals(status.getStatus())) {
            return ResponseEntity.accepted().body(status);
        }
        return ResponseEntity.ok(status);
    }

    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        log.debug("GET /api/platform/ghsa/health");
        boolean isSyncing = platformService.isSyncInProgress();
        if (isSyncing) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body("GHSA sync in progress");
        }
        return ResponseEntity.ok("GHSA platform service is healthy");
    }
}
