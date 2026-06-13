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
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "bom_component_workflows",
        indexes = {
                @Index(name = "idx_bom_workflow_component", columnList = "bom_component_id,workflow_status"),
                @Index(name = "idx_bom_workflow_link", columnList = "vulnerability_link_id")
        }
)
public class BomComponentWorkflow {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "bom_component_id", nullable = false)
    private UUID bomComponentId;

    @Column(name = "vulnerability_link_id")
    private UUID vulnerabilityLinkId;

    @Column(name = "workflow_type", nullable = false, length = 40)
    private String workflowType = "INVESTIGATION";

    @Enumerated(EnumType.STRING)
    @Column(name = "workflow_status", nullable = false, length = 40)
    private BomWorkflowStatus workflowStatus = BomWorkflowStatus.DISCOVERED;

    @Column(name = "workflow_reason")
    private String workflowReason;

    @Column(name = "investigation_key", length = 128)
    private String investigationKey;

    @Column(name = "finding_id")
    private UUID findingId;

    @Column(name = "started_at", nullable = false)
    private Instant startedAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @Column(name = "closed_at")
    private Instant closedAt;

    public UUID getId() { return id; }

    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }

    public UUID getBomComponentId() { return bomComponentId; }
    public void setBomComponentId(UUID bomComponentId) { this.bomComponentId = bomComponentId; }

    public UUID getVulnerabilityLinkId() { return vulnerabilityLinkId; }
    public void setVulnerabilityLinkId(UUID vulnerabilityLinkId) { this.vulnerabilityLinkId = vulnerabilityLinkId; }

    public String getWorkflowType() { return workflowType; }
    public void setWorkflowType(String workflowType) { this.workflowType = workflowType; }

    public BomWorkflowStatus getWorkflowStatus() { return workflowStatus; }
    public void setWorkflowStatus(BomWorkflowStatus workflowStatus) { this.workflowStatus = workflowStatus; }

    public String getWorkflowReason() { return workflowReason; }
    public void setWorkflowReason(String workflowReason) { this.workflowReason = workflowReason; }

    public String getInvestigationKey() { return investigationKey; }
    public void setInvestigationKey(String investigationKey) { this.investigationKey = investigationKey; }

    public UUID getFindingId() { return findingId; }
    public void setFindingId(UUID findingId) { this.findingId = findingId; }

    public Instant getStartedAt() { return startedAt; }
    public void setStartedAt(Instant startedAt) { this.startedAt = startedAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }

    public Instant getClosedAt() { return closedAt; }
    public void setClosedAt(Instant closedAt) { this.closedAt = closedAt; }
}
