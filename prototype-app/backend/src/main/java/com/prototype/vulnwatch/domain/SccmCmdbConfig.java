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
        name = "sccm_cmdb_configs",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_sccm_cmdb_configs_tenant_source", columnNames = {"tenant_id", "source_system"})
        },
        indexes = {
                @Index(name = "idx_sccm_cmdb_configs_enabled", columnList = "enabled,auto_sync_enabled"),
                @Index(name = "idx_sccm_cmdb_configs_tenant", columnList = "tenant_id")
        }
)
public class SccmCmdbConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "source_system", nullable = false, length = 80)
    private String sourceSystem = "sccm";

    @Column(name = "jdbc_url", length = 1000)
    private String jdbcUrl;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_type", nullable = false, length = 32)
    private SccmAuthType authType = SccmAuthType.SQL_AUTH;

    @Column(length = 255)
    private String username;

    @Column(name = "credential_secret", length = 4000)
    private String credentialSecret;

    @Column(name = "site_code", length = 20)
    private String siteCode;

    @Column(name = "database_name", nullable = false, length = 255)
    private String databaseName = "CM_P01";

    @Column(name = "fetch_size", nullable = false)
    private Integer fetchSize = 500;

    @Column(name = "query_timeout_seconds", nullable = false)
    private Integer queryTimeoutSeconds = 120;

    @Column(name = "mock_mode", nullable = false)
    private boolean mockMode = false;

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

    public String getJdbcUrl() {
        return jdbcUrl;
    }

    public void setJdbcUrl(String jdbcUrl) {
        this.jdbcUrl = jdbcUrl;
    }

    public SccmAuthType getAuthType() {
        return authType;
    }

    public void setAuthType(SccmAuthType authType) {
        this.authType = authType;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getCredentialSecret() {
        return credentialSecret;
    }

    public void setCredentialSecret(String credentialSecret) {
        this.credentialSecret = credentialSecret;
    }

    public String getSiteCode() {
        return siteCode;
    }

    public void setSiteCode(String siteCode) {
        this.siteCode = siteCode;
    }

    public String getDatabaseName() {
        return databaseName;
    }

    public void setDatabaseName(String databaseName) {
        this.databaseName = databaseName;
    }

    public Integer getFetchSize() {
        return fetchSize;
    }

    public void setFetchSize(Integer fetchSize) {
        this.fetchSize = fetchSize;
    }

    public Integer getQueryTimeoutSeconds() {
        return queryTimeoutSeconds;
    }

    public void setQueryTimeoutSeconds(Integer queryTimeoutSeconds) {
        this.queryTimeoutSeconds = queryTimeoutSeconds;
    }

    public boolean isMockMode() {
        return mockMode;
    }

    public void setMockMode(boolean mockMode) {
        this.mockMode = mockMode;
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
