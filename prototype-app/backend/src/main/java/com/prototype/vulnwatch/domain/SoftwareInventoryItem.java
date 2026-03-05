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
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "software_inventory_items",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_software_inventory_tenant_component",
                        columnNames = {"tenant_id", "component_id"}
                )
        },
        indexes = {
                @Index(name = "idx_software_inventory_tenant_component", columnList = "tenant_id,component_id"),
                @Index(name = "idx_software_inventory_tenant_status", columnList = "tenant_id,component_status"),
                @Index(name = "idx_software_inventory_tenant_pkg", columnList = "tenant_id,ecosystem,package_name,version")
        }
)
public class SoftwareInventoryItem {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(optional = false)
    @JoinColumn(name = "component_id")
    private InventoryComponent component;

    @ManyToOne
    @JoinColumn(name = "asset_id")
    private Asset asset;

    @Column(nullable = false)
    private String ecosystem;

    @Column(name = "package_name", nullable = false)
    private String packageName;

    @Column(nullable = false)
    private String version;

    @Column(nullable = false)
    private String purl;

    @Enumerated(EnumType.STRING)
    @Column(name = "component_status", nullable = false)
    private InventoryComponentStatus componentStatus = InventoryComponentStatus.ACTIVE;

    @Column(name = "first_seen_at", nullable = false)
    private Instant firstSeenAt = Instant.now();

    @Column(name = "last_observed_at")
    private Instant lastObservedAt;

    @Column(name = "synced_at", nullable = false)
    private Instant syncedAt = Instant.now();

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

    public InventoryComponent getComponent() {
        return component;
    }

    public void setComponent(InventoryComponent component) {
        this.component = component;
    }

    public Asset getAsset() {
        return asset;
    }

    public void setAsset(Asset asset) {
        this.asset = asset;
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

    public InventoryComponentStatus getComponentStatus() {
        return componentStatus;
    }

    public void setComponentStatus(InventoryComponentStatus componentStatus) {
        this.componentStatus = componentStatus;
    }

    public Instant getFirstSeenAt() {
        return firstSeenAt;
    }

    public void setFirstSeenAt(Instant firstSeenAt) {
        this.firstSeenAt = firstSeenAt;
    }

    public Instant getLastObservedAt() {
        return lastObservedAt;
    }

    public void setLastObservedAt(Instant lastObservedAt) {
        this.lastObservedAt = lastObservedAt;
    }

    public Instant getSyncedAt() {
        return syncedAt;
    }

    public void setSyncedAt(Instant syncedAt) {
        this.syncedAt = syncedAt;
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
