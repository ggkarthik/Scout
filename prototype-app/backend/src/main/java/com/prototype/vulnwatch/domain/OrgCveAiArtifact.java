package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapsId;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "org_cve_ai_artifacts")
public class OrgCveAiArtifact {

    @Id
    @Column(name = "org_cve_record_id", nullable = false)
    private UUID orgCveRecordId;

    @MapsId
    @OneToOne(optional = false)
    @JoinColumn(name = "org_cve_record_id")
    private OrgCveRecord orgCveRecord;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "investigation_summary_input_json", columnDefinition = "jsonb")
    private String investigationSummaryInputJson;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "investigation_summary_output_json", columnDefinition = "jsonb")
    private String investigationSummaryOutputJson;

    @Column(name = "investigation_summary_mode")
    private String investigationSummaryMode;

    @Column(name = "investigation_summary_generated_at")
    private Instant investigationSummaryGeneratedAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "ai_solution_json", columnDefinition = "jsonb")
    private String aiSolutionJson;

    @Column(name = "ai_solution_generated_at")
    private Instant aiSolutionGeneratedAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "ai_actions_json", columnDefinition = "jsonb")
    private String aiActionsJson;

    @Column(name = "ai_actions_generated_at")
    private Instant aiActionsGeneratedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public OrgCveRecord getOrgCveRecord() {
        return orgCveRecord;
    }

    public void setOrgCveRecord(OrgCveRecord orgCveRecord) {
        this.orgCveRecord = orgCveRecord;
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
