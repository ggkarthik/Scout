package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "org_cve_records",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_org_cve_record_tenant_vulnerability",
                        columnNames = {"tenant_id", "vulnerability_id"}
                )
        },
        indexes = {
                @Index(name = "idx_org_cve_record_tenant_vulnerability", columnList = "tenant_id,vulnerability_id"),
                @Index(name = "idx_org_cve_record_tenant_external_id", columnList = "tenant_id,external_id"),
                @Index(name = "idx_org_cve_record_tenant_applicability", columnList = "tenant_id,applicability_state"),
                @Index(name = "idx_org_cve_record_tenant_impacted", columnList = "tenant_id,impacted"),
                @Index(name = "idx_org_cve_record_tenant_impact_state", columnList = "tenant_id,impact_state"),
                @Index(name = "idx_org_cve_record_tenant_suppressed_until", columnList = "tenant_id,suppressed_until"),
                @Index(
                        name = "idx_org_cve_record_tenant_rank",
                        columnList = "tenant_id,impacted,applicability_state,cvss_score,external_id"
                )
        }
)
public class OrgCveRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(optional = false)
    @JoinColumn(name = "vulnerability_id")
    private Vulnerability vulnerability;

    @Column(name = "external_id", nullable = false)
    private String externalId;

    @Column(nullable = false)
    private String severity = "UNKNOWN";

    @Column(name = "cvss_score")
    private Double cvssScore;

    @Column(name = "epss_score")
    private Double epssScore;

    @Column(name = "in_kev", nullable = false)
    private boolean inKev;

    @Column(name = "vuln_status")
    private String vulnStatus;

    @Enumerated(EnumType.STRING)
    @Column(name = "applicability_state", nullable = false, length = 40)
    private ApplicabilityState applicabilityState = ApplicabilityState.UNKNOWN;

    @Column(nullable = false)
    private boolean impacted;

    @Enumerated(EnumType.STRING)
    @Column(name = "impact_state", nullable = false, length = 40)
    private ImpactState impactState = ImpactState.UNKNOWN;

    @Column(name = "impact_reason", length = 120)
    private String impactReason;

    @Column(name = "matched_component_count", nullable = false)
    private long matchedComponentCount;

    @Column(name = "matched_software_count", nullable = false)
    private long matchedSoftwareCount;

    @Column(name = "matched_asset_count", nullable = false)
    private long matchedAssetCount;

    @Column(name = "applicable_component_count", nullable = false)
    private long applicableComponentCount;

    @Column(name = "impacted_component_count", nullable = false)
    private long impactedComponentCount;

    @Column(name = "not_affected_component_count", nullable = false)
    private long notAffectedComponentCount;

    @Column(name = "fixed_component_count", nullable = false)
    private long fixedComponentCount;

    @Column(name = "no_patch_component_count", nullable = false)
    private long noPatchComponentCount;

    @Column(name = "under_investigation_component_count", nullable = false)
    private long underInvestigationComponentCount;

    @Column(name = "unknown_component_count", nullable = false)
    private long unknownComponentCount;

    @Column(name = "eol_component_count", nullable = false)
    private long eolComponentCount;

    @Column(name = "eos_component_count", nullable = false)
    private long eosComponentCount;

    @Column(name = "review_reason", length = 120)
    private String reviewReason;

    @Column(name = "suppression_reason", length = 120)
    private String suppressionReason;

    @Column(name = "suppression_justification", length = 4000)
    private String suppressionJustification;

    @Column(name = "suppressed_by", length = 255)
    private String suppressedBy;

    @Column(name = "suppressed_at")
    private Instant suppressedAt;

    @Column(name = "suppressed_until")
    private Instant suppressedUntil;

    @Column(name = "last_evaluated_at", nullable = false)
    private Instant lastEvaluatedAt = Instant.now();

    @Column(name = "investigation_summary_input_json", length = 200000)
    private String investigationSummaryInputJson;

    @Column(name = "investigation_summary_output_json", length = 200000)
    private String investigationSummaryOutputJson;

    @Column(name = "investigation_summary_mode", length = 32)
    private String investigationSummaryMode;

    @Column(name = "investigation_summary_generated_at")
    private Instant investigationSummaryGeneratedAt;

    @Column(name = "ai_solution_json", length = 200000)
    private String aiSolutionJson;

    @Column(name = "ai_solution_generated_at")
    private Instant aiSolutionGeneratedAt;

    @Column(name = "ai_actions_json", length = 50000)
    private String aiActionsJson;

    @Column(name = "ai_actions_generated_at")
    private Instant aiActionsGeneratedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "org_impact", length = 10)
    private OrgImpact orgImpact;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    public String getExternalId() {
        return externalId;
    }

    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public Double getCvssScore() {
        return cvssScore;
    }

    public void setCvssScore(Double cvssScore) {
        this.cvssScore = cvssScore;
    }

    public Double getEpssScore() {
        return epssScore;
    }

    public void setEpssScore(Double epssScore) {
        this.epssScore = epssScore;
    }

    public boolean isInKev() {
        return inKev;
    }

    public void setInKev(boolean inKev) {
        this.inKev = inKev;
    }

    public String getVulnStatus() {
        return vulnStatus;
    }

    public void setVulnStatus(String vulnStatus) {
        this.vulnStatus = vulnStatus;
    }

    public ApplicabilityState getApplicabilityState() {
        return applicabilityState;
    }

    public void setApplicabilityState(ApplicabilityState applicabilityState) {
        this.applicabilityState = applicabilityState;
    }

    public boolean isImpacted() {
        return impacted;
    }

    public void setImpacted(boolean impacted) {
        this.impacted = impacted;
    }

    public ImpactState getImpactState() {
        return impactState;
    }

    public void setImpactState(ImpactState impactState) {
        this.impactState = impactState;
    }

    public String getImpactReason() {
        return impactReason;
    }

    public void setImpactReason(String impactReason) {
        this.impactReason = impactReason;
    }

    public long getMatchedComponentCount() {
        return matchedComponentCount;
    }

    public void setMatchedComponentCount(long matchedComponentCount) {
        this.matchedComponentCount = matchedComponentCount;
    }

    public long getMatchedSoftwareCount() {
        return matchedSoftwareCount;
    }

    public void setMatchedSoftwareCount(long matchedSoftwareCount) {
        this.matchedSoftwareCount = matchedSoftwareCount;
    }

    public long getMatchedAssetCount() {
        return matchedAssetCount;
    }

    public void setMatchedAssetCount(long matchedAssetCount) {
        this.matchedAssetCount = matchedAssetCount;
    }

    public long getApplicableComponentCount() {
        return applicableComponentCount;
    }

    public void setApplicableComponentCount(long applicableComponentCount) {
        this.applicableComponentCount = applicableComponentCount;
    }

    public long getImpactedComponentCount() {
        return impactedComponentCount;
    }

    public void setImpactedComponentCount(long impactedComponentCount) {
        this.impactedComponentCount = impactedComponentCount;
    }

    public long getNotAffectedComponentCount() {
        return notAffectedComponentCount;
    }

    public void setNotAffectedComponentCount(long notAffectedComponentCount) {
        this.notAffectedComponentCount = notAffectedComponentCount;
    }

    public long getFixedComponentCount() {
        return fixedComponentCount;
    }

    public void setFixedComponentCount(long fixedComponentCount) {
        this.fixedComponentCount = fixedComponentCount;
    }

    public long getNoPatchComponentCount() {
        return noPatchComponentCount;
    }

    public void setNoPatchComponentCount(long noPatchComponentCount) {
        this.noPatchComponentCount = noPatchComponentCount;
    }

    public long getUnderInvestigationComponentCount() {
        return underInvestigationComponentCount;
    }

    public void setUnderInvestigationComponentCount(long underInvestigationComponentCount) {
        this.underInvestigationComponentCount = underInvestigationComponentCount;
    }

    public long getUnknownComponentCount() {
        return unknownComponentCount;
    }

    public void setUnknownComponentCount(long unknownComponentCount) {
        this.unknownComponentCount = unknownComponentCount;
    }

    public long getEolComponentCount() {
        return eolComponentCount;
    }

    public void setEolComponentCount(long eolComponentCount) {
        this.eolComponentCount = eolComponentCount;
    }

    public long getEosComponentCount() {
        return eosComponentCount;
    }

    public void setEosComponentCount(long eosComponentCount) {
        this.eosComponentCount = eosComponentCount;
    }

    public String getReviewReason() {
        return reviewReason;
    }

    public void setReviewReason(String reviewReason) {
        this.reviewReason = reviewReason;
    }

    public String getSuppressionReason() {
        return suppressionReason;
    }

    public void setSuppressionReason(String suppressionReason) {
        this.suppressionReason = suppressionReason;
    }

    public String getSuppressionJustification() {
        return suppressionJustification;
    }

    public void setSuppressionJustification(String suppressionJustification) {
        this.suppressionJustification = suppressionJustification;
    }

    public String getSuppressedBy() {
        return suppressedBy;
    }

    public void setSuppressedBy(String suppressedBy) {
        this.suppressedBy = suppressedBy;
    }

    public Instant getSuppressedAt() {
        return suppressedAt;
    }

    public void setSuppressedAt(Instant suppressedAt) {
        this.suppressedAt = suppressedAt;
    }

    public Instant getSuppressedUntil() {
        return suppressedUntil;
    }

    public void setSuppressedUntil(Instant suppressedUntil) {
        this.suppressedUntil = suppressedUntil;
    }

    public boolean isActivelySuppressed(Instant at) {
        if (suppressedAt == null) {
            return false;
        }
        if (suppressedUntil == null) {
            return true;
        }
        Instant reference = at == null ? Instant.now() : at;
        return suppressedUntil.isAfter(reference);
    }

    public Instant getLastEvaluatedAt() {
        return lastEvaluatedAt;
    }

    public void setLastEvaluatedAt(Instant lastEvaluatedAt) {
        this.lastEvaluatedAt = lastEvaluatedAt;
    }

    public String getInvestigationSummaryInputJson() {
        return investigationSummaryInputJson;
    }

    public void setInvestigationSummaryInputJson(String investigationSummaryInputJson) {
        this.investigationSummaryInputJson = investigationSummaryInputJson;
    }

    public String getInvestigationSummaryOutputJson() {
        return investigationSummaryOutputJson;
    }

    public void setInvestigationSummaryOutputJson(String investigationSummaryOutputJson) {
        this.investigationSummaryOutputJson = investigationSummaryOutputJson;
    }

    public String getInvestigationSummaryMode() {
        return investigationSummaryMode;
    }

    public void setInvestigationSummaryMode(String investigationSummaryMode) {
        this.investigationSummaryMode = investigationSummaryMode;
    }

    public Instant getInvestigationSummaryGeneratedAt() {
        return investigationSummaryGeneratedAt;
    }

    public void setInvestigationSummaryGeneratedAt(Instant investigationSummaryGeneratedAt) {
        this.investigationSummaryGeneratedAt = investigationSummaryGeneratedAt;
    }

    public String getAiSolutionJson() {
        return aiSolutionJson;
    }

    public void setAiSolutionJson(String aiSolutionJson) {
        this.aiSolutionJson = aiSolutionJson;
    }

    public Instant getAiSolutionGeneratedAt() {
        return aiSolutionGeneratedAt;
    }

    public void setAiSolutionGeneratedAt(Instant aiSolutionGeneratedAt) {
        this.aiSolutionGeneratedAt = aiSolutionGeneratedAt;
    }

    public String getAiActionsJson() {
        return aiActionsJson;
    }

    public void setAiActionsJson(String aiActionsJson) {
        this.aiActionsJson = aiActionsJson;
    }

    public Instant getAiActionsGeneratedAt() {
        return aiActionsGeneratedAt;
    }

    public void setAiActionsGeneratedAt(Instant aiActionsGeneratedAt) {
        this.aiActionsGeneratedAt = aiActionsGeneratedAt;
    }

    public OrgImpact getOrgImpact() {
        return orgImpact;
    }

    public void setOrgImpact(OrgImpact orgImpact) {
        this.orgImpact = orgImpact;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
