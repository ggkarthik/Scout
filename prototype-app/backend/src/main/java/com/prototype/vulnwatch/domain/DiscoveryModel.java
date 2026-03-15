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
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "discovery_models",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_discovery_models_tenant_primary_key", columnNames = {"tenant_id", "primary_key"})
        },
        indexes = {
                @Index(name = "idx_discovery_models_product_hash", columnList = "product_hash"),
                @Index(name = "idx_discovery_models_version_hash", columnList = "version_hash")
        }
)
public class DiscoveryModel {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "primary_key", nullable = false, length = 500)
    private String primaryKey;

    @Column(name = "normalization_status", length = 80)
    private String normalizationStatus;

    @Column
    private boolean approved;

    @Column(name = "low_confidence")
    private boolean lowConfidence;

    @Column(name = "normalized_product", length = 255)
    private String normalizedProduct;

    @Column(name = "normalized_publisher", length = 255)
    private String normalizedPublisher;

    @Column(name = "normalized_version", length = 255)
    private String normalizedVersion;

    @Column(name = "product_hash", length = 255)
    private String productHash;

    @Column(name = "version_hash", length = 255)
    private String versionHash;

    @Column(name = "full_version", length = 255)
    private String fullVersion;

    @Column(length = 120)
    private String platform;

    @Column(length = 120)
    private String language;

    @Column(name = "ml_model_version", length = 120)
    private String mlModelVersion;

    @Column(name = "display_name", length = 500)
    private String displayName;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
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

    public String getPrimaryKey() {
        return primaryKey;
    }

    public void setPrimaryKey(String primaryKey) {
        this.primaryKey = primaryKey;
    }

    public String getNormalizationStatus() {
        return normalizationStatus;
    }

    public void setNormalizationStatus(String normalizationStatus) {
        this.normalizationStatus = normalizationStatus;
    }

    public boolean isApproved() {
        return approved;
    }

    public void setApproved(boolean approved) {
        this.approved = approved;
    }

    public boolean isLowConfidence() {
        return lowConfidence;
    }

    public void setLowConfidence(boolean lowConfidence) {
        this.lowConfidence = lowConfidence;
    }

    public String getNormalizedProduct() {
        return normalizedProduct;
    }

    public void setNormalizedProduct(String normalizedProduct) {
        this.normalizedProduct = normalizedProduct;
    }

    public String getNormalizedPublisher() {
        return normalizedPublisher;
    }

    public void setNormalizedPublisher(String normalizedPublisher) {
        this.normalizedPublisher = normalizedPublisher;
    }

    public String getNormalizedVersion() {
        return normalizedVersion;
    }

    public void setNormalizedVersion(String normalizedVersion) {
        this.normalizedVersion = normalizedVersion;
    }

    public String getProductHash() {
        return productHash;
    }

    public void setProductHash(String productHash) {
        this.productHash = productHash;
    }

    public String getVersionHash() {
        return versionHash;
    }

    public void setVersionHash(String versionHash) {
        this.versionHash = versionHash;
    }

    public String getFullVersion() {
        return fullVersion;
    }

    public void setFullVersion(String fullVersion) {
        this.fullVersion = fullVersion;
    }

    public String getPlatform() {
        return platform;
    }

    public void setPlatform(String platform) {
        this.platform = platform;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public String getMlModelVersion() {
        return mlModelVersion;
    }

    public void setMlModelVersion(String mlModelVersion) {
        this.mlModelVersion = mlModelVersion;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
