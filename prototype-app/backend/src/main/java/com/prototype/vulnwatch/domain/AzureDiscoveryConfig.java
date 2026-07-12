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
        name = "azure_discovery_configs",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_azure_discovery_configs_tenant_source",
                        columnNames = {"tenant_id", "source_system"}
                )
        },
        indexes = {
                @Index(name = "idx_azure_discovery_configs_enabled", columnList = "enabled,auto_sync_enabled"),
                @Index(name = "idx_azure_discovery_configs_tenant", columnList = "tenant_id")
        }
)
public class AzureDiscoveryConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "source_system", nullable = false, length = 80)
    private String sourceSystem = "azure";

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_type", nullable = false, length = 32)
    private AzureAuthType authType = AzureAuthType.CLIENT_SECRET;

    @Column(name = "azure_tenant_id", length = 128)
    private String azureTenantId;

    @Column(name = "client_id", length = 255)
    private String clientId;

    @Column(name = "client_secret", length = 4000)
    private String clientSecret;

    @Column(name = "subscription_ids_json", nullable = false, columnDefinition = "TEXT")
    private String subscriptionIdsJson = "[]";

    @Column(name = "regions_json", nullable = false, columnDefinition = "TEXT")
    private String regionsJson = "[\"eastus2\"]";

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "auto_sync_enabled", nullable = false)
    private boolean autoSyncEnabled = false;

    @Column(name = "interval_minutes", nullable = false)
    private Integer intervalMinutes = 1440;

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

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public String getSourceSystem() {
        return sourceSystem;
    }

    public void setSourceSystem(String sourceSystem) {
        this.sourceSystem = sourceSystem;
    }

    public AzureAuthType getAuthType() {
        return authType;
    }

    public void setAuthType(AzureAuthType authType) {
        this.authType = authType;
    }

    public String getAzureTenantId() {
        return azureTenantId;
    }

    public void setAzureTenantId(String azureTenantId) {
        this.azureTenantId = azureTenantId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getSubscriptionIdsJson() {
        return subscriptionIdsJson;
    }

    public void setSubscriptionIdsJson(String subscriptionIdsJson) {
        this.subscriptionIdsJson = subscriptionIdsJson;
    }

    public String getRegionsJson() {
        return regionsJson;
    }

    public void setRegionsJson(String regionsJson) {
        this.regionsJson = regionsJson;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isAutoSyncEnabled() {
        return autoSyncEnabled;
    }

    public void setAutoSyncEnabled(boolean autoSyncEnabled) {
        this.autoSyncEnabled = autoSyncEnabled;
    }

    public Integer getIntervalMinutes() {
        return intervalMinutes;
    }

    public void setIntervalMinutes(Integer intervalMinutes) {
        this.intervalMinutes = intervalMinutes;
    }

    public String getLastTestStatus() {
        return lastTestStatus;
    }

    public void setLastTestStatus(String lastTestStatus) {
        this.lastTestStatus = lastTestStatus;
    }

    public String getLastTestMessage() {
        return lastTestMessage;
    }

    public void setLastTestMessage(String lastTestMessage) {
        this.lastTestMessage = lastTestMessage;
    }

    public Instant getLastTestedAt() {
        return lastTestedAt;
    }

    public void setLastTestedAt(Instant lastTestedAt) {
        this.lastTestedAt = lastTestedAt;
    }

    public Instant getLastSyncAt() {
        return lastSyncAt;
    }

    public void setLastSyncAt(Instant lastSyncAt) {
        this.lastSyncAt = lastSyncAt;
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
