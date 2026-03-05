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
        name = "assets",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_assets_tenant_identifier", columnNames = {"tenant_id", "identifier"})
        },
        indexes = {
                @Index(name = "idx_assets_tenant_id", columnList = "tenant_id")
        }
)
public class Asset {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AssetType type;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String identifier;

    @Column(length = 255)
    private String serviceName;

    @Column(length = 64)
    private String environment;

    @Column(length = 255)
    private String ownerTeam;

    @Column(length = 255)
    private String ownerEmail;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private BusinessCriticality businessCriticality = BusinessCriticality.MEDIUM;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AssetState state = AssetState.ACTIVE;

    @Column
    private Instant lastInventoryAt;

    @Column
    private Instant lastCmdbSyncAt;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public AssetType getType() {
        return type;
    }

    public void setType(AssetType type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getEnvironment() {
        return environment;
    }

    public void setEnvironment(String environment) {
        this.environment = environment;
    }

    public String getOwnerTeam() {
        return ownerTeam;
    }

    public void setOwnerTeam(String ownerTeam) {
        this.ownerTeam = ownerTeam;
    }

    public String getOwnerEmail() {
        return ownerEmail;
    }

    public void setOwnerEmail(String ownerEmail) {
        this.ownerEmail = ownerEmail;
    }

    public BusinessCriticality getBusinessCriticality() {
        return businessCriticality;
    }

    public void setBusinessCriticality(BusinessCriticality businessCriticality) {
        this.businessCriticality = businessCriticality;
    }

    public AssetState getState() {
        return state;
    }

    public void setState(AssetState state) {
        this.state = state;
    }

    public Instant getLastInventoryAt() {
        return lastInventoryAt;
    }

    public void setLastInventoryAt(Instant lastInventoryAt) {
        this.lastInventoryAt = lastInventoryAt;
    }

    public Instant getLastCmdbSyncAt() {
        return lastCmdbSyncAt;
    }

    public void setLastCmdbSyncAt(Instant lastCmdbSyncAt) {
        this.lastCmdbSyncAt = lastCmdbSyncAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
