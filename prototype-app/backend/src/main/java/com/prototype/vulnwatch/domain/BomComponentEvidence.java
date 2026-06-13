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
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "bom_component_evidence",
        indexes = {
                @Index(name = "idx_bom_evidence_component", columnList = "bom_component_id,evidence_type"),
                @Index(name = "idx_bom_evidence_bom", columnList = "bom_id")
        }
)
public class BomComponentEvidence {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "bom_component_id", nullable = false)
    private UUID bomComponentId;

    @Column(name = "bom_id", nullable = false)
    private UUID bomId;

    @Column(name = "evidence_type", nullable = false, length = 40)
    private String evidenceType;

    @Column(name = "evidence_key")
    private String evidenceKey;

    @Column(name = "evidence_value")
    private String evidenceValue;

    @Column(name = "source_system", length = 80)
    private String sourceSystem;

    @Column(name = "source_reference")
    private String sourceReference;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public UUID getId() { return id; }

    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }

    public UUID getBomComponentId() { return bomComponentId; }
    public void setBomComponentId(UUID bomComponentId) { this.bomComponentId = bomComponentId; }

    public UUID getBomId() { return bomId; }
    public void setBomId(UUID bomId) { this.bomId = bomId; }

    public String getEvidenceType() { return evidenceType; }
    public void setEvidenceType(String evidenceType) { this.evidenceType = evidenceType; }

    public String getEvidenceKey() { return evidenceKey; }
    public void setEvidenceKey(String evidenceKey) { this.evidenceKey = evidenceKey; }

    public String getEvidenceValue() { return evidenceValue; }
    public void setEvidenceValue(String evidenceValue) { this.evidenceValue = evidenceValue; }

    public String getSourceSystem() { return sourceSystem; }
    public void setSourceSystem(String sourceSystem) { this.sourceSystem = sourceSystem; }

    public String getSourceReference() { return sourceReference; }
    public void setSourceReference(String sourceReference) { this.sourceReference = sourceReference; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
