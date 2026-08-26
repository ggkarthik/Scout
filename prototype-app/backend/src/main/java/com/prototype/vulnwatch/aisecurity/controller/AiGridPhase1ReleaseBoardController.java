package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridPhase1ReleaseBoardService;
import com.prototype.vulnwatch.service.RequestActorService;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/platform/ai-grid/releases/phase-1")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class AiGridPhase1ReleaseBoardController {
    private final AiGridPhase1ReleaseBoardService board;
    private final RequestActorService actors;
    public AiGridPhase1ReleaseBoardController(AiGridPhase1ReleaseBoardService board, RequestActorService actors) { this.board = board; this.actors = actors; }
    @GetMapping public AiGridPhase1ReleaseBoardService.Board board() { return board.board(); }
    @PostMapping("/canary-runs/{tenantId}/{runId}") public AiGridPhase1ReleaseBoardService.Gate canary(@PathVariable UUID tenantId, @PathVariable UUID runId) { return board.recordCanaryRun(tenantId, runId, actors.currentActor().userId()); }
    @PostMapping("/performance/{tenantId}/{baselineRunId}/{candidateRunId}") public AiGridPhase1ReleaseBoardService.Gate performance(@PathVariable UUID tenantId, @PathVariable UUID baselineRunId, @PathVariable UUID candidateRunId) { return board.recordPerformanceComparison(tenantId, baselineRunId, candidateRunId, actors.currentActor().userId()); }
    @PostMapping("/rollback-drills/{provider}/{policyId}") public AiGridPhase1ReleaseBoardService.Gate rollback(@PathVariable String provider, @PathVariable String policyId) { return board.demonstrateRollback(provider, policyId, actors.currentActor().userId()); }
    @PostMapping("/promote") public AiGridPhase1ReleaseBoardService.Board promote() { return board.promote(actors.currentActor().userId()); }
}
