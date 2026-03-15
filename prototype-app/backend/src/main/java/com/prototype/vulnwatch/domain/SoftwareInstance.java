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
        name = "software_instances",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_software_instances_ci_product_version_evidence",
                        columnNames = {"ci_id", "normalized_product", "normalized_version", "version_evidence"}
                )
        },
        indexes = {
                @Index(name = "idx_software_instances_ci", columnList = "ci_id"),
                @Index(name = "idx_software_instances_identity", columnList = "software_identity_id"),
                @Index(name = "idx_software_instances_discovery_model", columnList = "discovery_model_id")
        }
)
public class SoftwareInstance {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(optional = false)
    @JoinColumn(name = "ci_id")
    private Ci ci;

    @ManyToOne
    @JoinColumn(name = "discovery_model_id")
    private DiscoveryModel discoveryModel;

    @ManyToOne
    @JoinColumn(name = "software_identity_id")
    private SoftwareIdentity softwareIdentity;

    @ManyToOne
    @JoinColumn(name = "inventory_component_id")
    private InventoryComponent inventoryComponent;

    @Column(name = "display_name", nullable = false, length = 500)
    private String displayName;

    @Column(length = 255)
    private String publisher;

    @Column(length = 255)
    private String version;

    @Column(name = "normalized_product", nullable = false, length = 255)
    private String normalizedProduct;

    @Column(name = "normalized_publisher", length = 255)
    private String normalizedPublisher;

    @Column(name = "normalized_version", length = 255)
    private String normalizedVersion;

    @Column(name = "install_date")
    private Instant installDate;

    @Column(name = "last_scanned")
    private Instant lastScanned;

    @Column(name = "last_used")
    private Instant lastUsed;

    @Column(name = "active_install")
    private boolean activeInstall = true;

    @Column(name = "unlicensed_install")
    private boolean unlicensedInstall;

    @Column(name = "discovery_model_pk", length = 500)
    private String discoveryModelPk;

    @Column(name = "version_evidence", length = 1000)
    private String versionEvidence;

    @Column(name = "source_system", nullable = false, length = 64)
    private String sourceSystem;

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

    public Ci getCi() {
        return ci;
    }

    public void setCi(Ci ci) {
        this.ci = ci;
    }

    public DiscoveryModel getDiscoveryModel() {
        return discoveryModel;
    }

    public void setDiscoveryModel(DiscoveryModel discoveryModel) {
        this.discoveryModel = discoveryModel;
    }

    public SoftwareIdentity getSoftwareIdentity() {
        return softwareIdentity;
    }

    public void setSoftwareIdentity(SoftwareIdentity softwareIdentity) {
        this.softwareIdentity = softwareIdentity;
    }

    public InventoryComponent getInventoryComponent() {
        return inventoryComponent;
    }

    public void setInventoryComponent(InventoryComponent inventoryComponent) {
        this.inventoryComponent = inventoryComponent;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getPublisher() {
        return publisher;
    }

    public void setPublisher(String publisher) {
        this.publisher = publisher;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
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

    public Instant getInstallDate() {
        return installDate;
    }

    public void setInstallDate(Instant installDate) {
        this.installDate = installDate;
    }

    public Instant getLastScanned() {
        return lastScanned;
    }

    public void setLastScanned(Instant lastScanned) {
        this.lastScanned = lastScanned;
    }

    public Instant getLastUsed() {
        return lastUsed;
    }

    public void setLastUsed(Instant lastUsed) {
        this.lastUsed = lastUsed;
    }

    public boolean isActiveInstall() {
        return activeInstall;
    }

    public void setActiveInstall(boolean activeInstall) {
        this.activeInstall = activeInstall;
    }

    public boolean isUnlicensedInstall() {
        return unlicensedInstall;
    }

    public void setUnlicensedInstall(boolean unlicensedInstall) {
        this.unlicensedInstall = unlicensedInstall;
    }

    public String getDiscoveryModelPk() {
        return discoveryModelPk;
    }

    public void setDiscoveryModelPk(String discoveryModelPk) {
        this.discoveryModelPk = discoveryModelPk;
    }

    public String getVersionEvidence() {
        return versionEvidence;
    }

    public void setVersionEvidence(String versionEvidence) {
        this.versionEvidence = versionEvidence;
    }

    public String getSourceSystem() {
        return sourceSystem;
    }

    public void setSourceSystem(String sourceSystem) {
        this.sourceSystem = sourceSystem;
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
