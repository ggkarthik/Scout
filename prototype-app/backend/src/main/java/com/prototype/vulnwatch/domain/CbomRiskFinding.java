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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(
        name = "cbom_risk_findings",
        uniqueConstraints = {
                @UniqueConstraint(name = "cbom_risk_findings_tenant_id_cbom_component_id_finding_fingerprint_key",
                        columnNames = {"tenant_id", "cbom_component_id", "finding_fingerprint"})
        },
        indexes = {
                @Index(name = "idx_cbom_risk_findings_component", columnList = "cbom_component_id"),
                @Index(name = "idx_cbom_risk_findings_tenant_status", columnList = "tenant_id,status,severity")
        }
)
public class CbomRiskFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(optional = false)
    @JoinColumn(name = "cbom_component_id")
    private CbomComponent component;

    @Column(name = "rule_id", nullable = false, length = 100)
    private String ruleId;

    @Column(name = "rule_version", nullable = false, length = 20)
    private String ruleVersion = "1";

    @Column(name = "finding_fingerprint", nullable = false)
    private String findingFingerprint;

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_class", nullable = false, length = 80)
    private CbomRiskClass riskClass;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private CbomRiskSeverity severity;

    @Column(nullable = false)
    private String title;

    private String detail;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private String evidence;

    private String recommendation;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private CbomFindingStatus status = CbomFindingStatus.OPEN;

    @Column(name = "first_seen_at", nullable = false)
    private Instant firstSeenAt = Instant.now();

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt = Instant.now();

    @Column(name = "resolved_at")
    private Instant resolvedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }
    public CbomComponent getComponent() { return component; }
    public void setComponent(CbomComponent component) { this.component = component; }
    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }
    public String getRuleVersion() { return ruleVersion; }
    public void setRuleVersion(String ruleVersion) { this.ruleVersion = ruleVersion; }
    public String getFindingFingerprint() { return findingFingerprint; }
    public void setFindingFingerprint(String findingFingerprint) { this.findingFingerprint = findingFingerprint; }
    public CbomRiskClass getRiskClass() { return riskClass; }
    public void setRiskClass(CbomRiskClass riskClass) { this.riskClass = riskClass; }
    public CbomRiskSeverity getSeverity() { return severity; }
    public void setSeverity(CbomRiskSeverity severity) { this.severity = severity; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDetail() { return detail; }
    public void setDetail(String detail) { this.detail = detail; }
    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }
    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
    public CbomFindingStatus getStatus() { return status; }
    public void setStatus(CbomFindingStatus status) { this.status = status; }
    public Instant getFirstSeenAt() { return firstSeenAt; }
    public void setFirstSeenAt(Instant firstSeenAt) { this.firstSeenAt = firstSeenAt; }
    public Instant getLastSeenAt() { return lastSeenAt; }
    public void setLastSeenAt(Instant lastSeenAt) { this.lastSeenAt = lastSeenAt; }
    public Instant getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(Instant resolvedAt) { this.resolvedAt = resolvedAt; }
    public Instant getCreatedAt() { return createdAt; }
}
