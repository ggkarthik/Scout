package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridPhase1PreviewService;
import com.prototype.vulnwatch.service.RequestActorService;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/platform/ai-grid/releases/phase-1/preview")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class AiGridPhase1PreviewController {
    private final AiGridPhase1PreviewService preview;
    private final RequestActorService actors;

    public AiGridPhase1PreviewController(AiGridPhase1PreviewService preview, RequestActorService actors) {
        this.preview = preview;
        this.actors = actors;
    }

    @GetMapping
    public AiGridPhase1PreviewService.PreviewStatus status() { return preview.status(); }

    @GetMapping("/profile")
    public AiGridPhase1PreviewService.PreviewCertificationProfile profile() {
        return preview.certificationProfile();
    }

    @PostMapping("/catalog-check")
    public AiGridPhase1PreviewService.PreviewGate catalogCheck() { return preview.runCatalogCheck(actor()); }

    @PostMapping("/performance-check")
    public AiGridPhase1PreviewService.PreviewGate performanceCheck(@RequestBody PerformanceCommand command) {
        return preview.runPerformanceCheck(command.tenantId(), command.baselineRunId(), command.candidateRunId(), actor());
    }

    @PostMapping("/rollback-check")
    public AiGridPhase1PreviewService.PreviewGate rollbackCheck(@RequestBody RollbackCommand command) {
        return preview.runRollbackChecks(command.policyByProvider(), actor());
    }

    @PostMapping("/internal-canary")
    public AiGridPhase1PreviewService.PreviewGate internalCanary(@RequestBody CanaryCommand command) {
        return preview.runInternalCanary(command.tenantId(), command.runId(), actor());
    }

    @PostMapping("/gates/{gateKey}")
    public AiGridPhase1PreviewService.PreviewGate gate(
            @PathVariable String gateKey,
            @RequestBody AiGridPhase1PreviewService.GateCommand command) {
        return preview.recordGate(gateKey, command, actor());
    }

    @PostMapping("/promote-internal")
    public AiGridPhase1PreviewService.PreviewStatus promoteInternal(@RequestBody TenantCommand command) {
        return preview.promoteInternal(command.tenantId(), actor());
    }

    @PostMapping("/cohort")
    public AiGridPhase1PreviewService.PreviewStatus cohort(@RequestBody CohortCommand command) {
        return preview.replaceCohort(command.tenantIds(), actor());
    }

    @PostMapping("/pause")
    public AiGridPhase1PreviewService.PreviewStatus pause() { return preview.pause(actor()); }

    @PostMapping("/resume")
    public AiGridPhase1PreviewService.PreviewStatus resume() { return preview.resume(actor()); }

    private String actor() { return actors.currentActor().userId(); }

    public record TenantCommand(UUID tenantId) {}
    public record CohortCommand(List<UUID> tenantIds) {}
    public record PerformanceCommand(UUID tenantId, UUID baselineRunId, UUID candidateRunId) {}
    public record RollbackCommand(Map<String, String> policyByProvider) {}
    public record CanaryCommand(UUID tenantId, UUID runId) {}
}
