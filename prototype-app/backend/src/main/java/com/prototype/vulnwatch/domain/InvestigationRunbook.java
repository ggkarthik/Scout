package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(
    name = "investigation_runbook",
    uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "cve_external_id"})
)
public class InvestigationRunbook {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "cve_external_id", nullable = false, length = 50)
    private String cveExternalId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "task_states", columnDefinition = "jsonb", nullable = false)
    private String taskStatesJson = "[]";

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "agent_suggestions", columnDefinition = "jsonb", nullable = false)
    private String agentSuggestionsJson = "{}";

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "fp_overrides", columnDefinition = "jsonb", nullable = false)
    private String fpOverridesJson = "[]";

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "log_entries", columnDefinition = "jsonb", nullable = false)
    private String logEntriesJson = "[]";

    @Column(name = "lead_analyst", length = 100)
    private String leadAnalyst;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "agent_confidence", columnDefinition = "jsonb")
    private String agentConfidenceJson;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "agent_run_meta", columnDefinition = "jsonb")
    private String agentRunMetaJson;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @PreUpdate
    void touch() {
        this.updatedAt = Instant.now();
    }

    public UUID getId() { return id; }

    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }

    public String getCveExternalId() { return cveExternalId; }
    public void setCveExternalId(String cveExternalId) { this.cveExternalId = cveExternalId; }

    public String getTaskStatesJson() { return taskStatesJson; }
    public void setTaskStatesJson(String taskStatesJson) { this.taskStatesJson = taskStatesJson; }

    public String getAgentSuggestionsJson() { return agentSuggestionsJson; }
    public void setAgentSuggestionsJson(String agentSuggestionsJson) { this.agentSuggestionsJson = agentSuggestionsJson; }

    public String getFpOverridesJson() { return fpOverridesJson; }
    public void setFpOverridesJson(String fpOverridesJson) { this.fpOverridesJson = fpOverridesJson; }

    public String getLogEntriesJson() { return logEntriesJson; }
    public void setLogEntriesJson(String logEntriesJson) { this.logEntriesJson = logEntriesJson; }

    public String getLeadAnalyst() { return leadAnalyst; }
    public void setLeadAnalyst(String leadAnalyst) { this.leadAnalyst = leadAnalyst; }

    public String getAgentConfidenceJson() { return agentConfidenceJson; }
    public void setAgentConfidenceJson(String agentConfidenceJson) { this.agentConfidenceJson = agentConfidenceJson; }

    public String getAgentRunMetaJson() { return agentRunMetaJson; }
    public void setAgentRunMetaJson(String agentRunMetaJson) { this.agentRunMetaJson = agentRunMetaJson; }

    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
