package com.prototype.vulnwatch.domain;

import jakarta.persistence.Basic;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(
        name = "findings",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_findings_component_vulnerability", columnNames = {"component_id", "vulnerability_id"})
        },
        indexes = {
                @Index(name = "idx_findings_tenant_status_updated", columnList = "tenant_id,status,updated_at"),
                @Index(name = "idx_findings_tenant_component_vuln", columnList = "tenant_id,component_id,vulnerability_id"),
                @Index(name = "idx_findings_asset_id", columnList = "asset_id"),
                @Index(name = "idx_findings_vulnerability_id", columnList = "vulnerability_id"),
                @Index(name = "idx_findings_vulnerability_status", columnList = "vulnerability_id,status"),
                @Index(name = "idx_findings_vex_status", columnList = "vex_status"),
                @Index(name = "idx_findings_vex_freshness", columnList = "vex_freshness"),
                @Index(name = "idx_findings_vex_provider", columnList = "vex_provider")
        }
)
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "display_id", nullable = false, updatable = false, length = 16)
    private String displayId;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(optional = false)
    @JoinColumn(name = "asset_id")
    private Asset asset;

    @ManyToOne(optional = false)
    @JoinColumn(name = "component_id")
    private InventoryComponent component;

    @ManyToOne(optional = false)
    @JoinColumn(name = "vulnerability_id")
    private Vulnerability vulnerability;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FindingStatus status = FindingStatus.OPEN;

    @Enumerated(EnumType.STRING)
    @Column(name = "decision_state", length = 40)
    private FindingDecisionState decisionState = FindingDecisionState.NEEDS_REVIEW;

    @Enumerated(EnumType.STRING)
    @Column(name = "creation_source", nullable = false, length = 32)
    private FindingCreationSource creationSource = FindingCreationSource.AUTOMATIC;

    @Column(nullable = false)
    private double riskScore;

    @Column
    private double confidenceScore;

    @Column(nullable = false)
    private String matchedBy;

    @Column(length = 255)
    private String assignedTo;

    @Column(length = 255)
    private String assignedBy;

    @Column
    private Instant assignedAt;

    @Column
    private Instant dueAt;

    @Column(name = "severity_override", length = 16)
    private String severityOverride;

    @Column(length = 2000)
    private String suppressionReason;

    @Column
    private Instant suppressedUntil;

    @Basic(fetch = FetchType.LAZY)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private String evidence;

    @Column(name = "vex_status", length = 64)
    private String vexStatus;

    @Column(name = "vex_freshness", length = 64)
    private String vexFreshness;

    @Column(name = "vex_provider", length = 128)
    private String vexProvider;

    @Column(name = "matched_vex_assertion_id")
    private UUID matchedVexAssertionId;

    @Basic(fetch = FetchType.LAZY)
    @Column(name = "precedence_trace", columnDefinition = "TEXT")
    private String precedenceTrace;

    @Column(name = "suppressed_by_rule_id")
    private UUID suppressedByRuleId;

    @Column(name = "suppressed_by_rule_name")
    private String suppressedByRuleName;

    @Column(name = "owner_group", length = 255)
    private String ownerGroup;

    /** ServiceNow incident number linked to this finding (e.g. INC0010005) */
    @Column(name = "incident_id", length = 64)
    private String incidentId;

    /** Last known status of the linked ServiceNow incident (e.g. New, In Progress, Resolved) */
    @Column(name = "incident_status", length = 64)
    private String incidentStatus;

    @Column
    private Instant firstObservedAt = Instant.now();

    @Column
    private Instant lastObservedAt = Instant.now();

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public String getDisplayId() {
        return displayId;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public Asset getAsset() {
        return asset;
    }

    public void setAsset(Asset asset) {
        this.asset = asset;
    }

    public InventoryComponent getComponent() {
        return component;
    }

    public void setComponent(InventoryComponent component) {
        this.component = component;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    public FindingStatus getStatus() {
        return status;
    }

    public void setStatus(FindingStatus status) {
        this.status = status;
    }

    public FindingDecisionState getDecisionState() {
        return decisionState;
    }

    public void setDecisionState(FindingDecisionState decisionState) {
        this.decisionState = decisionState;
    }

    public FindingCreationSource getCreationSource() {
        return creationSource;
    }

    public void setCreationSource(FindingCreationSource creationSource) {
        this.creationSource = creationSource == null ? FindingCreationSource.AUTOMATIC : creationSource;
    }

    public double getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(double riskScore) {
        this.riskScore = riskScore;
    }

    public double getConfidenceScore() {
        return confidenceScore;
    }

    public void setConfidenceScore(double confidenceScore) {
        this.confidenceScore = confidenceScore;
    }

    public String getMatchedBy() {
        return matchedBy;
    }

    public void setMatchedBy(String matchedBy) {
        this.matchedBy = matchedBy;
    }

    public String getAssignedTo() {
        return assignedTo;
    }

    public void setAssignedTo(String assignedTo) {
        this.assignedTo = assignedTo;
    }

    public String getAssignedBy() {
        return assignedBy;
    }

    public void setAssignedBy(String assignedBy) {
        this.assignedBy = assignedBy;
    }

    public Instant getAssignedAt() {
        return assignedAt;
    }

    public void setAssignedAt(Instant assignedAt) {
        this.assignedAt = assignedAt;
    }

    public Instant getDueAt() {
        return dueAt;
    }

    public void setDueAt(Instant dueAt) {
        this.dueAt = dueAt;
    }

    public String getSuppressionReason() {
        return suppressionReason;
    }

    public void setSuppressionReason(String suppressionReason) {
        this.suppressionReason = suppressionReason;
    }

    public Instant getSuppressedUntil() {
        return suppressedUntil;
    }

    public void setSuppressedUntil(Instant suppressedUntil) {
        this.suppressedUntil = suppressedUntil;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getVexStatus() {
        return vexStatus;
    }

    public void setVexStatus(String vexStatus) {
        this.vexStatus = vexStatus;
    }

    public String getVexFreshness() {
        return vexFreshness;
    }

    public void setVexFreshness(String vexFreshness) {
        this.vexFreshness = vexFreshness;
    }

    public String getVexProvider() {
        return vexProvider;
    }

    public void setVexProvider(String vexProvider) {
        this.vexProvider = vexProvider;
    }

    public UUID getMatchedVexAssertionId() {
        return matchedVexAssertionId;
    }

    public void setMatchedVexAssertionId(UUID matchedVexAssertionId) {
        this.matchedVexAssertionId = matchedVexAssertionId;
    }

    public String getPrecedenceTrace() {
        return precedenceTrace;
    }

    public void setPrecedenceTrace(String precedenceTrace) {
        this.precedenceTrace = precedenceTrace;
    }

    public Instant getFirstObservedAt() {
        return firstObservedAt;
    }

    public void setFirstObservedAt(Instant firstObservedAt) {
        this.firstObservedAt = firstObservedAt;
    }

    public Instant getLastObservedAt() {
        return lastObservedAt;
    }

    public void setLastObservedAt(Instant lastObservedAt) {
        this.lastObservedAt = lastObservedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public UUID getSuppressedByRuleId() { return suppressedByRuleId; }
    public void setSuppressedByRuleId(UUID suppressedByRuleId) { this.suppressedByRuleId = suppressedByRuleId; }

    public String getSuppressedByRuleName() { return suppressedByRuleName; }
    public void setSuppressedByRuleName(String suppressedByRuleName) { this.suppressedByRuleName = suppressedByRuleName; }

    public String getOwnerGroup() { return ownerGroup; }
    public void setOwnerGroup(String ownerGroup) { this.ownerGroup = ownerGroup; }

    public String getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(String incidentId) {
        this.incidentId = incidentId;
    }

    public String getIncidentStatus() {
        return incidentStatus;
    }

    public void setIncidentStatus(String incidentStatus) {
        this.incidentStatus = incidentStatus;
    }

    public String getSeverityOverride() {
        return severityOverride;
    }

    public void setSeverityOverride(String severityOverride) {
        this.severityOverride = severityOverride;
    }

    @PrePersist
    void ensureIdentifiers() {
        if (id == null) {
            id = UUID.randomUUID();
        }
        if (displayId == null || displayId.isBlank()) {
            String compactId = id.toString().replace("-", "").toUpperCase();
            displayId = "F-" + compactId.substring(0, 12);
        }
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
