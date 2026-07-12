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
        name = "azure_discovery_targets",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_azure_discovery_targets_config_subscription",
                        columnNames = {"config_id", "subscription_id"}
                )
        },
        indexes = {
                @Index(name = "idx_azure_discovery_targets_config", columnList = "config_id"),
                @Index(name = "idx_azure_discovery_targets_tenant_enabled", columnList = "tenant_id,enabled")
        }
)
public class AzureDiscoveryTarget {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(optional = false)
    @JoinColumn(name = "config_id")
    private AzureDiscoveryConfig config;

    @Column(name = "subscription_id", length = 64)
    private String subscriptionId;

    @Column(name = "subscription_name", length = 255)
    private String subscriptionName;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "regions_json", nullable = false)
    private String regionsJson = "[\"eastus2\"]";

    @Column(name = "last_test_status", length = 64)
    private String lastTestStatus;

    @Column(name = "last_test_message", length = 2000)
    private String lastTestMessage;

    @Column(name = "last_tested_at")
    private Instant lastTestedAt;

    @Column(name = "last_sync_at")
    private Instant lastSyncAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }
    public AzureDiscoveryConfig getConfig() { return config; }
    public void setConfig(AzureDiscoveryConfig config) { this.config = config; }
    public String getSubscriptionId() { return subscriptionId; }
    public void setSubscriptionId(String subscriptionId) { this.subscriptionId = subscriptionId; }
    public String getSubscriptionName() { return subscriptionName; }
    public void setSubscriptionName(String subscriptionName) { this.subscriptionName = subscriptionName; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getRegionsJson() { return regionsJson; }
    public void setRegionsJson(String regionsJson) { this.regionsJson = regionsJson; }
    public String getLastTestStatus() { return lastTestStatus; }
    public void setLastTestStatus(String lastTestStatus) { this.lastTestStatus = lastTestStatus; }
    public String getLastTestMessage() { return lastTestMessage; }
    public void setLastTestMessage(String lastTestMessage) { this.lastTestMessage = lastTestMessage; }
    public Instant getLastTestedAt() { return lastTestedAt; }
    public void setLastTestedAt(Instant lastTestedAt) { this.lastTestedAt = lastTestedAt; }
    public Instant getLastSyncAt() { return lastSyncAt; }
    public void setLastSyncAt(Instant lastSyncAt) { this.lastSyncAt = lastSyncAt; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void touch() { this.updatedAt = Instant.now(); }
}
