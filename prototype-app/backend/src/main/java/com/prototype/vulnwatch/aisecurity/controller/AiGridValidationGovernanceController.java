package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.AdjudicationCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.AnswerKeyCase;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.AnswerKeyEnvironment;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.AnswerKeyRun;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.CaseCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.EnvironmentCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.LabelCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.PrecisionReview;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.PrecisionReviewCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.PrecisionSample;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.PrecisionSampleCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.ReleaseDecision;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.ReleaseReadiness;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.RunCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridR1CertificationService;
import com.prototype.vulnwatch.aisecurity.service.AiGridR2CertificationService;
import com.prototype.vulnwatch.aisecurity.service.AiGridR1CertificationService.EvidenceCommand;
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
@RequestMapping("/api/platform/ai-grid/validation")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class AiGridValidationGovernanceController {
    private final AiGridValidationGovernanceService governance;
    private final AiGridR1CertificationService r1Certification;
    private final AiGridR2CertificationService r2Certification;
    private final RequestActorService actors;

    public AiGridValidationGovernanceController(AiGridValidationGovernanceService governance,
                                                AiGridR1CertificationService r1Certification,
                                                AiGridR2CertificationService r2Certification,
                                                RequestActorService actors) {
        this.governance = governance;
        this.r1Certification = r1Certification;
        this.r2Certification = r2Certification;
        this.actors = actors;
    }

    @GetMapping("/answer-keys")
    public List<AnswerKeyEnvironment> environments() {
        return governance.environments();
    }

    @PostMapping("/answer-keys")
    public AnswerKeyEnvironment createEnvironment(@RequestBody EnvironmentCommand command) {
        return governance.createEnvironment(command, actor());
    }

    @GetMapping("/answer-keys/{environmentId}/cases")
    public List<AnswerKeyCase> cases(@PathVariable UUID environmentId) {
        return governance.cases(environmentId);
    }

    @PostMapping("/answer-keys/{environmentId}/cases")
    public AnswerKeyCase addCase(@PathVariable UUID environmentId, @RequestBody CaseCommand command) {
        return governance.addCase(environmentId, command, actor());
    }

    @PostMapping("/answer-keys/{environmentId}/certify")
    public AnswerKeyEnvironment certify(@PathVariable UUID environmentId) {
        return governance.certifyEnvironment(environmentId, actor());
    }

    @PostMapping("/answer-keys/{environmentId}/runs")
    public AnswerKeyRun recordRun(@PathVariable UUID environmentId, @RequestBody RunCommand command) {
        return governance.recordRun(environmentId, command, actor());
    }

    @GetMapping("/policies/{policyId}/versions/{version}/digest")
    public Map<String, String> policyDigest(@PathVariable String policyId, @PathVariable String version) {
        return Map.of("digest", governance.policyDigest(policyId, version));
    }

    @GetMapping("/policies/{policyId}/versions/{version}/release-readiness")
    public ReleaseReadiness releaseReadiness(@PathVariable String policyId, @PathVariable String version) {
        return governance.releaseReadiness(policyId, version);
    }

    @PostMapping("/precision-reviews")
    public PrecisionReview createReview(@RequestBody PrecisionReviewCommand command) {
        return governance.createPrecisionReview(command, actor());
    }

    @GetMapping("/precision-reviews/{reviewId}")
    public PrecisionReview review(@PathVariable UUID reviewId) {
        return governance.precisionReview(reviewId);
    }

    @PostMapping("/precision-reviews/{reviewId}/samples")
    public PrecisionSample addSample(@PathVariable UUID reviewId, @RequestBody PrecisionSampleCommand command) {
        return governance.addPrecisionSample(reviewId, command);
    }

    @PostMapping("/precision-reviews/{reviewId}/samples/{sampleId}/labels")
    public void label(@PathVariable UUID reviewId, @PathVariable UUID sampleId,
                      @RequestBody LabelCommand command) {
        governance.submitLabel(reviewId, sampleId, command, actor());
    }

    @PostMapping("/precision-reviews/{reviewId}/samples/{sampleId}/adjudicate")
    public void adjudicate(@PathVariable UUID reviewId, @PathVariable UUID sampleId,
                           @RequestBody AdjudicationCommand command) {
        governance.adjudicate(reviewId, sampleId, command, actor());
    }

    @PostMapping("/precision-reviews/{reviewId}/bias")
    public PrecisionReview assessBias(@PathVariable UUID reviewId, @RequestBody BiasCommand command) {
        return governance.assessBias(reviewId, command.passed(), command.rationale(), actor());
    }

    @PostMapping("/precision-reviews/{reviewId}/finalize")
    public PrecisionReview finalizeReview(@PathVariable UUID reviewId) {
        return governance.finalizePrecisionReview(reviewId);
    }

    @PostMapping("/policies/{policyId}/versions/{version}/publish")
    public ReleaseDecision publish(@PathVariable String policyId, @PathVariable String version) {
        return governance.publishPolicy(policyId, version, actor());
    }

    @GetMapping("/releases/r1/readiness")
    public AiGridR1CertificationService.ReleaseReadiness r1Readiness() {
        return r1Certification.readiness();
    }

    @PostMapping("/releases/r1/evidence")
    public AiGridR1CertificationService.GateEvidence recordR1Evidence(@RequestBody EvidenceCommand command) {
        return r1Certification.recordEvidence(command, actor());
    }

    @PostMapping("/releases/r1/decisions")
    public AiGridR1CertificationService.ReleaseDecision decideR1() {
        return r1Certification.decide(actor());
    }

    @GetMapping("/releases/r2/readiness")
    public AiGridR2CertificationService.Readiness r2Readiness() { return r2Certification.readiness(); }

    @PostMapping("/releases/r2/precision-reviews")
    public PrecisionReview recordR2Precision(
            @RequestBody AiGridR2CertificationService.PrecisionReviewCommand command) {
        return r2Certification.createPrecisionReview(command, actor());
    }

    @PostMapping("/releases/r2/decisions")
    public AiGridR2CertificationService.Decision decideR2() { return r2Certification.decide(actor()); }

    private String actor() {
        return actors.currentActor().userId();
    }

    public record BiasCommand(boolean passed, String rationale) {}
}
