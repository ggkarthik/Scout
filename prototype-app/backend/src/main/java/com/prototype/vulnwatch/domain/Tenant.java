package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(schema = "platform", name = "tenants")
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(unique = true, length = 120)
    private String slug;

    @Column(name = "schema_name", nullable = false, unique = true, length = 120)
    private String schemaName = "tenant_default";

    @Column(nullable = false, length = 32)
    private String status = "ACTIVE";

    @Column(nullable = false, length = 64)
    private String planCode = "ENTERPRISE";

    @Column(length = 255)
    private String billingRef;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    private Instant suspendedAt;

    private Instant deletedAt;

    private Instant demoExpiresAt;

    private Instant expiredAt;

    private Instant purgeStartedAt;

    private Instant purgedAt;

    @Column(length = 32)
    private String purgeStatus;

    @Column(length = 2000)
    private String purgeError;

    @Column(length = 255)
    private String demoCreatedBy;

    @Column(length = 64)
    private String demoSource;

    @Column(length = 255)
    private String demoOwnerEmail;

    @Column(nullable = false)
    private boolean demoDataRequested;

    @Column(nullable = false, length = 32)
    private String demoDataStatus = "NOT_REQUESTED";

    @Column(length = 64)
    private String demoDataVersion;

    private Instant demoDataSeededAt;

    @Column(length = 2000)
    private String demoDataError;

    @Column(nullable = false)
    private Integer maxConnectorCount = 10;

    @Column(nullable = false)
    private Integer maxServiceAccountCount = 25;

    @Column(nullable = false)
    private Integer maxDailySbomUploads = 100;

    @Column(nullable = false)
    private Integer maxExportRows = 50_000;

    @Column(nullable = false)
    private Integer maxDailyExposureRefreshes = 25;

    private Integer sbomRateLimitWindowSeconds;

    private Integer maxSbomJobsPerRateLimitWindow;

    private Integer maxActiveSbomJobs;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    /**
     * Legacy compatibility for older APIs still passing numeric tenant IDs.
     * Maps deterministic numeric IDs to UUID space.
     */
    public void setId(Long legacyTenantId) {
        if (legacyTenantId == null) {
            this.id = null;
            return;
        }
        this.id = new UUID(0L, legacyTenantId);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSlug() {
        return slug;
    }

    public void setSlug(String slug) {
        this.slug = slug;
    }

    public String getSchemaName() {
        return schemaName;
    }

    public void setSchemaName(String schemaName) {
        this.schemaName = schemaName;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getPlanCode() {
        return planCode;
    }

    public void setPlanCode(String planCode) {
        this.planCode = planCode;
    }

    public String getBillingRef() {
        return billingRef;
    }

    public void setBillingRef(String billingRef) {
        this.billingRef = billingRef;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Instant getSuspendedAt() {
        return suspendedAt;
    }

    public void setSuspendedAt(Instant suspendedAt) {
        this.suspendedAt = suspendedAt;
    }

    public Instant getDeletedAt() {
        return deletedAt;
    }

    public void setDeletedAt(Instant deletedAt) {
        this.deletedAt = deletedAt;
    }

    public Instant getDemoExpiresAt() {
        return demoExpiresAt;
    }

    public void setDemoExpiresAt(Instant demoExpiresAt) {
        this.demoExpiresAt = demoExpiresAt;
    }

    public String getDemoCreatedBy() {
        return demoCreatedBy;
    }

    public void setDemoCreatedBy(String demoCreatedBy) {
        this.demoCreatedBy = demoCreatedBy;
    }

    public String getDemoSource() {
        return demoSource;
    }

    public void setDemoSource(String demoSource) {
        this.demoSource = demoSource;
    }

    public String getDemoOwnerEmail() {
        return demoOwnerEmail;
    }

    public void setDemoOwnerEmail(String demoOwnerEmail) {
        this.demoOwnerEmail = demoOwnerEmail;
    }

    public boolean isDemoDataRequested() {
        return demoDataRequested;
    }

    public void setDemoDataRequested(boolean demoDataRequested) {
        this.demoDataRequested = demoDataRequested;
    }

    public String getDemoDataStatus() {
        return demoDataStatus;
    }

    public void setDemoDataStatus(String demoDataStatus) {
        this.demoDataStatus = demoDataStatus;
    }

    public String getDemoDataVersion() {
        return demoDataVersion;
    }

    public void setDemoDataVersion(String demoDataVersion) {
        this.demoDataVersion = demoDataVersion;
    }

    public Instant getDemoDataSeededAt() {
        return demoDataSeededAt;
    }

    public void setDemoDataSeededAt(Instant demoDataSeededAt) {
        this.demoDataSeededAt = demoDataSeededAt;
    }

    public String getDemoDataError() {
        return demoDataError;
    }

    public void setDemoDataError(String demoDataError) {
        this.demoDataError = demoDataError;
    }

    public Instant getExpiredAt() {
        return expiredAt;
    }

    public void setExpiredAt(Instant expiredAt) {
        this.expiredAt = expiredAt;
    }

    public Instant getPurgeStartedAt() {
        return purgeStartedAt;
    }

    public void setPurgeStartedAt(Instant purgeStartedAt) {
        this.purgeStartedAt = purgeStartedAt;
    }

    public Instant getPurgedAt() {
        return purgedAt;
    }

    public void setPurgedAt(Instant purgedAt) {
        this.purgedAt = purgedAt;
    }

    public String getPurgeStatus() {
        return purgeStatus;
    }

    public void setPurgeStatus(String purgeStatus) {
        this.purgeStatus = purgeStatus;
    }

    public String getPurgeError() {
        return purgeError;
    }

    public void setPurgeError(String purgeError) {
        this.purgeError = purgeError;
    }

    public Integer getMaxConnectorCount() {
        return maxConnectorCount;
    }

    public void setMaxConnectorCount(Integer maxConnectorCount) {
        this.maxConnectorCount = maxConnectorCount;
    }

    public Integer getMaxServiceAccountCount() {
        return maxServiceAccountCount;
    }

    public void setMaxServiceAccountCount(Integer maxServiceAccountCount) {
        this.maxServiceAccountCount = maxServiceAccountCount;
    }

    public Integer getMaxDailySbomUploads() {
        return maxDailySbomUploads;
    }

    public void setMaxDailySbomUploads(Integer maxDailySbomUploads) {
        this.maxDailySbomUploads = maxDailySbomUploads;
    }

    public Integer getMaxExportRows() {
        return maxExportRows;
    }

    public void setMaxExportRows(Integer maxExportRows) {
        this.maxExportRows = maxExportRows;
    }

    public Integer getMaxDailyExposureRefreshes() {
        return maxDailyExposureRefreshes;
    }

    public void setMaxDailyExposureRefreshes(Integer maxDailyExposureRefreshes) {
        this.maxDailyExposureRefreshes = maxDailyExposureRefreshes;
    }

    public Integer getSbomRateLimitWindowSeconds() {
        return sbomRateLimitWindowSeconds;
    }

    public void setSbomRateLimitWindowSeconds(Integer sbomRateLimitWindowSeconds) {
        this.sbomRateLimitWindowSeconds = sbomRateLimitWindowSeconds;
    }

    public Integer getMaxSbomJobsPerRateLimitWindow() {
        return maxSbomJobsPerRateLimitWindow;
    }

    public void setMaxSbomJobsPerRateLimitWindow(Integer maxSbomJobsPerRateLimitWindow) {
        this.maxSbomJobsPerRateLimitWindow = maxSbomJobsPerRateLimitWindow;
    }

    public Integer getMaxActiveSbomJobs() {
        return maxActiveSbomJobs;
    }

    public void setMaxActiveSbomJobs(Integer maxActiveSbomJobs) {
        this.maxActiveSbomJobs = maxActiveSbomJobs;
    }
}
