package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Investigation entity for tracking detailed analysis of CVEs
 */
@Entity
@Table(name = "investigations")
@Data
@EqualsAndHashCode(of = "id")
public class Investigation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "vulnerability_id", nullable = false)
    private Vulnerability vulnerability;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false, length = 50)
    @Enumerated(EnumType.STRING)
    private InvestigationStatus status = InvestigationStatus.OPEN;

    @Column(name = "assigned_to", length = 100)
    private String assignedTo;

    @Column(name = "priority", length = 20)
    @Enumerated(EnumType.STRING)
    private InvestigationPriority priority = InvestigationPriority.MEDIUM;

    @Column(columnDefinition = "TEXT")
    private String notes;

    @Column(name = "exploit_available")
    private Boolean exploitAvailable;

    @Column(name = "exploit_details", columnDefinition = "TEXT")
    private String exploitDetails;

    @Column(name = "patch_available")
    private Boolean patchAvailable;

    @Column(name = "patch_details", columnDefinition = "TEXT")
    private String patchDetails;

    @Column(name = "systems_affected", columnDefinition = "TEXT")
    private String systemsAffected;

    @Column(name = "business_impact", columnDefinition = "TEXT")
    private String businessImpact;

    @Column(name = "mitigation_steps", columnDefinition = "TEXT")
    private String mitigationSteps;

    @Column(name = "vuln_references", columnDefinition = "TEXT")
    private String references;

    @OneToMany(mappedBy = "investigation", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<InvestigationAttachment> attachments = new ArrayList<>();

    @OneToMany(mappedBy = "investigation", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<InvestigationActivity> activities = new ArrayList<>();

    @Column(name = "created_by", length = 100)
    private String createdBy;

    @Column(name = "modified_by", length = 100)
    private String modifiedBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "closed_at")
    private Instant closedAt;

    public enum InvestigationStatus {
        OPEN,
        IN_PROGRESS,
        PENDING_REVIEW,
        CLOSED,
        REOPENED
    }

    public enum InvestigationPriority {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW
    }

    public void addActivity(InvestigationActivity activity) {
        activities.add(activity);
        activity.setInvestigation(this);
    }

    public void addAttachment(InvestigationAttachment attachment) {
        attachments.add(attachment);
        attachment.setInvestigation(this);
    }
}
