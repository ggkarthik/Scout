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

    public Long getId() {
        return id;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public AssessmentStatus getStatus() {
        return status;
    }

    public void setStatus(AssessmentStatus status) {
        this.status = status;
    }

    public Boolean getSoftwareDetected() {
        return softwareDetected;
    }

    public void setSoftwareDetected(Boolean softwareDetected) {
        this.softwareDetected = softwareDetected;
    }

    public String getDetectionMethod() {
        return detectionMethod;
    }

    public void setDetectionMethod(String detectionMethod) {
        this.detectionMethod = detectionMethod;
    }

    public String getAffectedComponents() {
        return affectedComponents;
    }

    public void setAffectedComponents(String affectedComponents) {
        this.affectedComponents = affectedComponents;
    }

    public Boolean getVulnerableVersionPresent() {
        return vulnerableVersionPresent;
    }

    public void setVulnerableVersionPresent(Boolean vulnerableVersionPresent) {
        this.vulnerableVersionPresent = vulnerableVersionPresent;
    }

    public String getCurrentVersion() {
        return currentVersion;
    }

    public void setCurrentVersion(String currentVersion) {
        this.currentVersion = currentVersion;
    }

    public String getVulnerableVersionRange() {
        return vulnerableVersionRange;
    }

    public void setVulnerableVersionRange(String vulnerableVersionRange) {
        this.vulnerableVersionRange = vulnerableVersionRange;
    }

    public String getFixedVersion() {
        return fixedVersion;
    }

    public void setFixedVersion(String fixedVersion) {
        this.fixedVersion = fixedVersion;
    }

    public Boolean getVulnerableConfiguration() {
        return vulnerableConfiguration;
    }

    public void setVulnerableConfiguration(Boolean vulnerableConfiguration) {
        this.vulnerableConfiguration = vulnerableConfiguration;
    }

    public String getConfigurationDetails() {
        return configurationDetails;
    }

    public void setConfigurationDetails(String configurationDetails) {
        this.configurationDetails = configurationDetails;
    }

    public Boolean getAttackVectorAccessible() {
        return attackVectorAccessible;
    }

    public void setAttackVectorAccessible(Boolean attackVectorAccessible) {
        this.attackVectorAccessible = attackVectorAccessible;
    }

    public AssessmentResult getFinalResult() {
        return finalResult;
    }

    public void setFinalResult(AssessmentResult finalResult) {
        this.finalResult = finalResult;
    }

    public ConfidenceLevel getConfidenceLevel() {
        return confidenceLevel;
    }

    public void setConfidenceLevel(ConfidenceLevel confidenceLevel) {
        this.confidenceLevel = confidenceLevel;
    }

    public String getJustification() {
        return justification;
    }

    public void setJustification(String justification) {
        this.justification = justification;
    }

    public String getRecommendedAction() {
        return recommendedAction;
    }

    public void setRecommendedAction(String recommendedAction) {
        this.recommendedAction = recommendedAction;
    }

    public String getAssessedBy() {
        return assessedBy;
    }

    public void setAssessedBy(String assessedBy) {
        this.assessedBy = assessedBy;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }

    public void setCompletedAt(Instant completedAt) {
        this.completedAt = completedAt;
    }
}
