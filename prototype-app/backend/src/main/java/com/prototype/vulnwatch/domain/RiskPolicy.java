package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "risk_policies")
public class RiskPolicy {

    public enum FindingGenerationMode {
        AUTO,
        MANUAL
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne(optional = false)
    @JoinColumn(name = "tenant_id", unique = true)
    private Tenant tenant;

    @Column(nullable = false)
    private double criticalThreshold = 9.0;

    @Column(nullable = false)
    private double highThreshold = 7.0;

    @Column(nullable = false)
    private int criticalSlaDays = 7;

    @Column(nullable = false)
    private int highSlaDays = 14;

    @Column(nullable = false)
    private int mediumSlaDays = 30;

    @Column(nullable = false)
    private int lowSlaDays = 60;

    @Column(nullable = false)
    private double assetCriticalSlaMultiplier = 0.5;

    @Column(nullable = false)
    private double assetHighSlaMultiplier = 0.75;

    @Column(nullable = false)
    private double assetMediumSlaMultiplier = 1.0;

    @Column(nullable = false)
    private double assetLowSlaMultiplier = 1.25;

    @Column(nullable = false)
    private boolean autoCloseEnabled = false;

    @Column(length = 255)
    private String autoCloseAssetIdentifier;

    @Column(nullable = false)
    private int autoCloseAfterDays = 0;

    @Enumerated(EnumType.STRING)
    @Column(name = "finding_generation_mode", nullable = false, length = 20)
    private FindingGenerationMode findingGenerationMode = FindingGenerationMode.MANUAL;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "findings_score_config", columnDefinition = "jsonb")
    private String findingsScoreConfig = "[]";

    @Column(name = "agent_auto_threshold", nullable = false)
    private double agentAutoThreshold = 0.85;

    @Column(name = "agent_review_threshold", nullable = false)
    private double agentReviewThreshold = 0.60;

    @Column(name = "agent_max_concurrent", nullable = false)
    private int agentMaxConcurrent = 10;

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public double getCriticalThreshold() {
        return criticalThreshold;
    }

    public void setCriticalThreshold(double criticalThreshold) {
        this.criticalThreshold = criticalThreshold;
    }

    public double getHighThreshold() {
        return highThreshold;
    }

    public void setHighThreshold(double highThreshold) {
        this.highThreshold = highThreshold;
    }

    public int getCriticalSlaDays() {
        return criticalSlaDays;
    }

    public void setCriticalSlaDays(int criticalSlaDays) {
        this.criticalSlaDays = criticalSlaDays;
    }

    public int getHighSlaDays() {
        return highSlaDays;
    }

    public void setHighSlaDays(int highSlaDays) {
        this.highSlaDays = highSlaDays;
    }

    public int getMediumSlaDays() {
        return mediumSlaDays;
    }

    public void setMediumSlaDays(int mediumSlaDays) {
        this.mediumSlaDays = mediumSlaDays;
    }

    public int getLowSlaDays() {
        return lowSlaDays;
    }

    public void setLowSlaDays(int lowSlaDays) {
        this.lowSlaDays = lowSlaDays;
    }

    public double getAssetCriticalSlaMultiplier() {
        return assetCriticalSlaMultiplier;
    }

    public void setAssetCriticalSlaMultiplier(double assetCriticalSlaMultiplier) {
        this.assetCriticalSlaMultiplier = assetCriticalSlaMultiplier;
    }

    public double getAssetHighSlaMultiplier() {
        return assetHighSlaMultiplier;
    }

    public void setAssetHighSlaMultiplier(double assetHighSlaMultiplier) {
        this.assetHighSlaMultiplier = assetHighSlaMultiplier;
    }

    public double getAssetMediumSlaMultiplier() {
        return assetMediumSlaMultiplier;
    }

    public void setAssetMediumSlaMultiplier(double assetMediumSlaMultiplier) {
        this.assetMediumSlaMultiplier = assetMediumSlaMultiplier;
    }

    public double getAssetLowSlaMultiplier() {
        return assetLowSlaMultiplier;
    }

    public void setAssetLowSlaMultiplier(double assetLowSlaMultiplier) {
        this.assetLowSlaMultiplier = assetLowSlaMultiplier;
    }

    public boolean isAutoCloseEnabled() {
        return autoCloseEnabled;
    }

    public void setAutoCloseEnabled(boolean autoCloseEnabled) {
        this.autoCloseEnabled = autoCloseEnabled;
    }

    public String getAutoCloseAssetIdentifier() {
        return autoCloseAssetIdentifier;
    }

    public void setAutoCloseAssetIdentifier(String autoCloseAssetIdentifier) {
        this.autoCloseAssetIdentifier = autoCloseAssetIdentifier;
    }

    public int getAutoCloseAfterDays() {
        return autoCloseAfterDays;
    }

    public void setAutoCloseAfterDays(int autoCloseAfterDays) {
        this.autoCloseAfterDays = autoCloseAfterDays;
    }

    public FindingGenerationMode getFindingGenerationMode() {
        return findingGenerationMode;
    }

    public void setFindingGenerationMode(FindingGenerationMode findingGenerationMode) {
        this.findingGenerationMode = findingGenerationMode == null ? FindingGenerationMode.MANUAL : findingGenerationMode;
    }

    public String getFindingsScoreConfig() {
        return findingsScoreConfig == null ? "[]" : findingsScoreConfig;
    }

    public void setFindingsScoreConfig(String findingsScoreConfig) {
        this.findingsScoreConfig = findingsScoreConfig == null ? "[]" : findingsScoreConfig;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public double getAgentAutoThreshold() { return agentAutoThreshold; }
    public void setAgentAutoThreshold(double agentAutoThreshold) { this.agentAutoThreshold = agentAutoThreshold; }

    public double getAgentReviewThreshold() { return agentReviewThreshold; }
    public void setAgentReviewThreshold(double agentReviewThreshold) { this.agentReviewThreshold = agentReviewThreshold; }

    public int getAgentMaxConcurrent() { return agentMaxConcurrent; }
    public void setAgentMaxConcurrent(int agentMaxConcurrent) { this.agentMaxConcurrent = agentMaxConcurrent; }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
