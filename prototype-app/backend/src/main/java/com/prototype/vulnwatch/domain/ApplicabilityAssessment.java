package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;

/**
 * Applicability Assessment entity for tracking CVE assessment workflow
 */
@Entity
@Table(name = "applicability_assessments")
@Data
@EqualsAndHashCode(of = "id")
public class ApplicabilityAssessment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "vulnerability_id", nullable = false)
    private Vulnerability vulnerability;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "status", nullable = false, length = 50)
    @Enumerated(EnumType.STRING)
    private AssessmentStatus status = AssessmentStatus.IN_PROGRESS;

    // Step 1: Software Detection
    @Column(name = "software_detected")
    private Boolean softwareDetected;

    @Column(name = "detection_method", length = 100)
    private String detectionMethod;

    @Column(name = "affected_components", columnDefinition = "TEXT")
    private String affectedComponents;

    // Step 2: Version Check
    @Column(name = "vulnerable_version_present")
    private Boolean vulnerableVersionPresent;

    @Column(name = "current_version", length = 100)
    private String currentVersion;

    @Column(name = "vulnerable_version_range", length = 200)
    private String vulnerableVersionRange;

    @Column(name = "fixed_version", length = 100)
    private String fixedVersion;

    // Step 3: Configuration Check
    @Column(name = "vulnerable_configuration")
    private Boolean vulnerableConfiguration;

    @Column(name = "configuration_details", columnDefinition = "TEXT")
    private String configurationDetails;

    @Column(name = "attack_vector_accessible")
    private Boolean attackVectorAccessible;

    // Step 4: Assessment Result
    @Column(name = "final_result", length = 50)
    @Enumerated(EnumType.STRING)
    private AssessmentResult finalResult;

    @Column(name = "confidence_level", length = 20)
    @Enumerated(EnumType.STRING)
    private ConfidenceLevel confidenceLevel;

    @Column(name = "justification", columnDefinition = "TEXT")
    private String justification;

    @Column(name = "recommended_action", columnDefinition = "TEXT")
    private String recommendedAction;

    @Column(name = "assessed_by", length = 100)
    private String assessedBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    public enum AssessmentStatus {
        IN_PROGRESS,
        COMPLETED,
        CANCELLED
    }

    public enum AssessmentResult {
        AFFECTED,
        NOT_AFFECTED,
        UNDER_INVESTIGATION,
        INCONCLUSIVE
    }

    public enum ConfidenceLevel {
        HIGH,
        MEDIUM,
        LOW
    }
}
