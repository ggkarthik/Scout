package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "cbom_posture_summary",
        uniqueConstraints = {
                @UniqueConstraint(name = "cbom_posture_summary_tenant_id_asset_id_key", columnNames = {"tenant_id", "asset_id"})
        },
        indexes = {
                @Index(name = "idx_cbom_posture_summary_tenant", columnList = "tenant_id")
        }
)
public class CbomPostureSummary {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(optional = false)
    @JoinColumn(name = "asset_id")
    private Asset asset;

    @ManyToOne
    @JoinColumn(name = "last_source_bom_id")
    private BomIngestionRecord lastSourceBom;

    @Column(name = "total_components", nullable = false)
    private int totalComponents;
    @Column(name = "critical_findings", nullable = false)
    private int criticalFindings;
    @Column(name = "high_findings", nullable = false)
    private int highFindings;
    @Column(name = "medium_findings", nullable = false)
    private int mediumFindings;
    @Column(name = "low_findings", nullable = false)
    private int lowFindings;
    @Column(name = "info_findings", nullable = false)
    private int infoFindings;
    @Column(name = "accepted_findings", nullable = false)
    private int acceptedFindings;
    @Column(name = "quantum_vulnerable", nullable = false)
    private int quantumVulnerable;
    @Column(name = "weak_algorithms", nullable = false)
    private int weakAlgorithms;
    @Column(name = "expiring_certs", nullable = false)
    private int expiringCerts;
    @Column(name = "posture_score")
    private BigDecimal postureScore;
    @Column(name = "last_evaluated_at")
    private Instant lastEvaluatedAt;

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }
    public Asset getAsset() { return asset; }
    public void setAsset(Asset asset) { this.asset = asset; }
    public BomIngestionRecord getLastSourceBom() { return lastSourceBom; }
    public void setLastSourceBom(BomIngestionRecord lastSourceBom) { this.lastSourceBom = lastSourceBom; }
    public int getTotalComponents() { return totalComponents; }
    public void setTotalComponents(int totalComponents) { this.totalComponents = totalComponents; }
    public int getCriticalFindings() { return criticalFindings; }
    public void setCriticalFindings(int criticalFindings) { this.criticalFindings = criticalFindings; }
    public int getHighFindings() { return highFindings; }
    public void setHighFindings(int highFindings) { this.highFindings = highFindings; }
    public int getMediumFindings() { return mediumFindings; }
    public void setMediumFindings(int mediumFindings) { this.mediumFindings = mediumFindings; }
    public int getLowFindings() { return lowFindings; }
    public void setLowFindings(int lowFindings) { this.lowFindings = lowFindings; }
    public int getInfoFindings() { return infoFindings; }
    public void setInfoFindings(int infoFindings) { this.infoFindings = infoFindings; }
    public int getAcceptedFindings() { return acceptedFindings; }
    public void setAcceptedFindings(int acceptedFindings) { this.acceptedFindings = acceptedFindings; }
    public int getQuantumVulnerable() { return quantumVulnerable; }
    public void setQuantumVulnerable(int quantumVulnerable) { this.quantumVulnerable = quantumVulnerable; }
    public int getWeakAlgorithms() { return weakAlgorithms; }
    public void setWeakAlgorithms(int weakAlgorithms) { this.weakAlgorithms = weakAlgorithms; }
    public int getExpiringCerts() { return expiringCerts; }
    public void setExpiringCerts(int expiringCerts) { this.expiringCerts = expiringCerts; }
    public BigDecimal getPostureScore() { return postureScore; }
    public void setPostureScore(BigDecimal postureScore) { this.postureScore = postureScore; }
    public Instant getLastEvaluatedAt() { return lastEvaluatedAt; }
    public void setLastEvaluatedAt(Instant lastEvaluatedAt) { this.lastEvaluatedAt = lastEvaluatedAt; }
}
