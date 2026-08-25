package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridPhase1PolicyMigrationService;
import com.prototype.vulnwatch.aisecurity.service.AiGridPhase1PolicyMigrationService.MigrationPreview;
import com.prototype.vulnwatch.aisecurity.service.AiGridPhase1PolicyMigrationService.MigrationResult;
import com.prototype.vulnwatch.service.RequestActorService;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/platform/ai-grid/migrations/phase-1")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class AiGridPhase1PolicyMigrationController {
    private final AiGridPhase1PolicyMigrationService migration;
    private final RequestActorService actors;

    public AiGridPhase1PolicyMigrationController(AiGridPhase1PolicyMigrationService migration, RequestActorService actors) {
        this.migration = migration;
        this.actors = actors;
    }

    @GetMapping("/tenants/{tenantId}/preview")
    public MigrationPreview preview(@PathVariable UUID tenantId) { return migration.preview(tenantId); }

    @PostMapping("/tenants/{tenantId}/apply")
    public MigrationResult apply(@PathVariable UUID tenantId) {
        return migration.apply(tenantId, actors.currentActor().userId());
    }
}
