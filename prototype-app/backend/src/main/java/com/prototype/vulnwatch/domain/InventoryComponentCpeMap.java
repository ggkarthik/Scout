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
        name = "inventory_component_cpe_map",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_inventory_component_cpe",
                        columnNames = {"tenant_id", "component_id", "cpe_id"}
                )
        },
        indexes = {
                @Index(name = "idx_iccm_tenant_cpe", columnList = "tenant_id,cpe_id"),
                @Index(name = "idx_iccm_tenant_component", columnList = "tenant_id,component_id")
        }
)
public class InventoryComponentCpeMap {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(optional = false)
    @JoinColumn(name = "component_id")
    private InventoryComponent component;

    @ManyToOne(optional = false)
    @JoinColumn(name = "cpe_id")
    private CpeDim cpeDim;

    @Column(name = "observed_version", length = 255)
    private String observedVersion;

    @Column(name = "first_seen_at", nullable = false)
    private Instant firstSeenAt = Instant.now();

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt = Instant.now();

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

    public CpeDim getCpeDim() {
        return cpeDim;
    }

    public void setCpeDim(CpeDim cpeDim) {
        this.cpeDim = cpeDim;
    }

    public String getObservedVersion() {
        return observedVersion;
    }

    public void setObservedVersion(String observedVersion) {
        this.observedVersion = observedVersion;
    }

    public Instant getFirstSeenAt() {
        return firstSeenAt;
    }

    public void setFirstSeenAt(Instant firstSeenAt) {
        this.firstSeenAt = firstSeenAt;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    public void setLastSeenAt(Instant lastSeenAt) {
        this.lastSeenAt = lastSeenAt;
    }
}
