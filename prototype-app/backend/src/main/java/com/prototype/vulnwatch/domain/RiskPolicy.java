package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "risk_policies")
public class RiskPolicy {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne(optional = false)
    @JoinColumn(name = "tenant_id", unique = true)
    private Tenant tenant;

    @Column(nullable = false)
    private double cvssWeight = 1.0;

    @Column(nullable = false)
    private double kevBoost = 2.0;

    @Column(nullable = false)
    private double epssWeight = 1.0;

    @Column(nullable = false)
    private int vexNotAffectedFreshnessDays = 30;

    @Column(nullable = false)
    private int vexFixedFreshnessDays = 30;

    @Column(nullable = false)
    private double vexKnownAffectedBoost = 0.4;

    @Column(nullable = false)
    private double vexUnderInvestigationPenalty = 0.2;

    @Column(nullable = false)
    private double vexNotAffectedReduction = 0.8;

    @Column(nullable = false)
    private double vexStalePenalty = 0.5;

    @Column(nullable = false)
    private double criticalThreshold = 9.0;

    @Column(nullable = false)
    private double highThreshold = 7.0;

    @Column(nullable = false)
    private double assetCriticalRiskBoost = 1.5;

    @Column(nullable = false)
    private double assetHighRiskBoost = 1.0;

    @Column(nullable = false)
    private double assetMediumRiskBoost = 0.5;

    @Column(nullable = false)
    private double assetLowRiskBoost = 0.0;

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

    public double getCvssWeight() {
        return cvssWeight;
    }

    public void setCvssWeight(double cvssWeight) {
        this.cvssWeight = cvssWeight;
    }

    public double getKevBoost() {
        return kevBoost;
    }

    public void setKevBoost(double kevBoost) {
        this.kevBoost = kevBoost;
    }

    public double getEpssWeight() {
        return epssWeight;
    }

    public void setEpssWeight(double epssWeight) {
        this.epssWeight = epssWeight;
    }

    public int getVexNotAffectedFreshnessDays() {
        return vexNotAffectedFreshnessDays;
    }

    public void setVexNotAffectedFreshnessDays(int vexNotAffectedFreshnessDays) {
        this.vexNotAffectedFreshnessDays = vexNotAffectedFreshnessDays;
    }

    public int getVexFixedFreshnessDays() {
        return vexFixedFreshnessDays;
    }

    public void setVexFixedFreshnessDays(int vexFixedFreshnessDays) {
        this.vexFixedFreshnessDays = vexFixedFreshnessDays;
    }

    public double getVexKnownAffectedBoost() {
        return vexKnownAffectedBoost;
    }

    public void setVexKnownAffectedBoost(double vexKnownAffectedBoost) {
        this.vexKnownAffectedBoost = vexKnownAffectedBoost;
    }

    public double getVexUnderInvestigationPenalty() {
        return vexUnderInvestigationPenalty;
    }

    public void setVexUnderInvestigationPenalty(double vexUnderInvestigationPenalty) {
        this.vexUnderInvestigationPenalty = vexUnderInvestigationPenalty;
    }

    public double getVexNotAffectedReduction() {
        return vexNotAffectedReduction;
    }

    public void setVexNotAffectedReduction(double vexNotAffectedReduction) {
        this.vexNotAffectedReduction = vexNotAffectedReduction;
    }

    public double getVexStalePenalty() {
        return vexStalePenalty;
    }

    public void setVexStalePenalty(double vexStalePenalty) {
        this.vexStalePenalty = vexStalePenalty;
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

    public double getAssetCriticalRiskBoost() {
        return assetCriticalRiskBoost;
    }

    public void setAssetCriticalRiskBoost(double assetCriticalRiskBoost) {
        this.assetCriticalRiskBoost = assetCriticalRiskBoost;
    }

    public double getAssetHighRiskBoost() {
        return assetHighRiskBoost;
    }

    public void setAssetHighRiskBoost(double assetHighRiskBoost) {
        this.assetHighRiskBoost = assetHighRiskBoost;
    }

    public double getAssetMediumRiskBoost() {
        return assetMediumRiskBoost;
    }

    public void setAssetMediumRiskBoost(double assetMediumRiskBoost) {
        this.assetMediumRiskBoost = assetMediumRiskBoost;
    }

    public double getAssetLowRiskBoost() {
        return assetLowRiskBoost;
    }

    public void setAssetLowRiskBoost(double assetLowRiskBoost) {
        this.assetLowRiskBoost = assetLowRiskBoost;
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

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
