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
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import com.prototype.vulnwatch.util.IdentityUtil;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "inventory_components",
        indexes = {
                @Index(name = "idx_inventory_tenant_asset", columnList = "tenant_id,asset_id"),
                @Index(name = "idx_inventory_sbom_upload", columnList = "sbom_upload_id"),
                @Index(name = "idx_inventory_software_identity", columnList = "software_identity_id"),
                @Index(name = "idx_inventory_component_digest", columnList = "component_digest"),
                @Index(name = "idx_inventory_norm_purl_tenant", columnList = "normalized_purl,tenant_id"),
                @Index(name = "idx_inventory_coord_key_tenant", columnList = "coord_key,tenant_id")
        }
)
public class InventoryComponent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(optional = false)
    @JoinColumn(name = "asset_id")
    private Asset asset;

    @ManyToOne(optional = false)
    @JoinColumn(name = "sbom_upload_id")
    private SbomUpload sbomUpload;

    @ManyToOne
    @JoinColumn(name = "software_identity_id")
    private SoftwareIdentity softwareIdentity;

    @Column(nullable = false)
    private String ecosystem;

    @Column(nullable = false)
    private String packageName;

    @Column(nullable = false)
    private String version;

    @Column(name = "normalized_name", length = 500)
    private String normalizedName;

    @Column(name = "normalized_version", length = 255)
    private String normalizedVersion;

    @Column(nullable = false)
    private String purl;

    @Column(name = "normalized_purl", length = 1200)
    private String normalizedPurl;

    @Column(name = "coord_key", length = 500)
    private String coordKey;

    @Column(name = "component_digest", length = 120)
    private String componentDigest;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private InventoryComponentStatus componentStatus = InventoryComponentStatus.ACTIVE;

    @Column(nullable = false)
    private Instant ingestedAt = Instant.now();

    @Column(nullable = false)
    private Instant lastObservedAt = Instant.now();

    @Column
    private Instant retiredAt;

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public Asset getAsset() {
        return asset;
    }

    public void setAsset(Asset asset) {
        this.asset = asset;
    }

    public SbomUpload getSbomUpload() {
        return sbomUpload;
    }

    public void setSbomUpload(SbomUpload sbomUpload) {
        this.sbomUpload = sbomUpload;
    }

    public SoftwareIdentity getSoftwareIdentity() {
        return softwareIdentity;
    }

    public void setSoftwareIdentity(SoftwareIdentity softwareIdentity) {
        this.softwareIdentity = softwareIdentity;
    }

    public String getEcosystem() {
        return ecosystem;
    }

    public void setEcosystem(String ecosystem) {
        this.ecosystem = ecosystem;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getPurl() {
        return purl;
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }

    public String getNormalizedPurl() {
        return normalizedPurl;
    }

    public void setNormalizedPurl(String normalizedPurl) {
        this.normalizedPurl = normalizedPurl;
    }

    public String getCoordKey() {
        return coordKey;
    }

    public void setCoordKey(String coordKey) {
        this.coordKey = coordKey;
    }

    public String getNormalizedName() {
        return normalizedName;
    }

    public void setNormalizedName(String normalizedName) {
        this.normalizedName = normalizedName;
    }

    public String getNormalizedVersion() {
        return normalizedVersion;
    }

    public void setNormalizedVersion(String normalizedVersion) {
        this.normalizedVersion = normalizedVersion;
    }

    public String getComponentDigest() {
        return componentDigest;
    }

    public void setComponentDigest(String componentDigest) {
        this.componentDigest = componentDigest;
    }

    public Instant getIngestedAt() {
        return ingestedAt;
    }

    public void setIngestedAt(Instant ingestedAt) {
        this.ingestedAt = ingestedAt;
    }

    public InventoryComponentStatus getComponentStatus() {
        return componentStatus;
    }

    public void setComponentStatus(InventoryComponentStatus componentStatus) {
        this.componentStatus = componentStatus;
    }

    public Instant getLastObservedAt() {
        return lastObservedAt;
    }

    public void setLastObservedAt(Instant lastObservedAt) {
        this.lastObservedAt = lastObservedAt;
    }

    public Instant getRetiredAt() {
        return retiredAt;
    }

    public void setRetiredAt(Instant retiredAt) {
        this.retiredAt = retiredAt;
    }

    @PrePersist
    @PreUpdate
    void synchronizeLookupKeys() {
        String normalizedPurlValue = IdentityUtil.normalizePurl(purl);
        this.normalizedPurl = normalizedPurlValue.isBlank() ? null : normalizedPurlValue;
        this.coordKey = IdentityUtil.coordKey(ecosystem, packageName);
    }
}
