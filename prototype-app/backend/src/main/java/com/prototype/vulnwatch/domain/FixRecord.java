package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(
        name = "fix_records",
        indexes = {
                @Index(name = "idx_fix_records_tenant_cve", columnList = "tenant_id,cve_id")
        }
)
public class FixRecord {

    public enum FixType {
        UPGRADE,
        PATCH,
        WORKAROUND,
        CONFIGURATION_CHANGE,
        EOL_MIGRATION,
        COMPENSATING_CONTROL,
        NO_FIX
    }

    public enum RecommendationSource {
        VENDOR_INTELLIGENCE,
        REFERENCE,
        AI,
        ANALYST
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "cve_id", nullable = false)
    private String cveId;

    /** JSON array of CVE IDs that share the same fix, e.g. ["CVE-2024-1111","CVE-2024-2222"] */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "related_cve_ids", columnDefinition = "jsonb")
    private String relatedCveIdsJson;

    @Column(nullable = false)
    private String summary;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "fix_type", nullable = false, length = 40)
    private String fixType;

    /** JSON array: [{name, ecosystem, version, assetCount}] */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "software_entities", columnDefinition = "jsonb")
    private String softwareEntitiesJson;

    /** null = all platforms; otherwise "Windows", "Linux", "macOS", etc. */
    @Column(name = "os_hint", length = 60)
    private String osHint;

    @Column(name = "recommendation_source", nullable = false, length = 40)
    private String recommendationSource;

    /** JSON array of URLs used to generate this fix. */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "source_urls", columnDefinition = "jsonb")
    private String sourceUrlsJson;

    @Column(name = "generated_at", nullable = false)
    private Instant generatedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        createdAt = now;
        updatedAt = now;
        if (generatedAt == null) generatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }

    public UUID getId() { return id; }

    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }

    public String getCveId() { return cveId; }
    public void setCveId(String cveId) { this.cveId = cveId; }

    public String getRelatedCveIdsJson() { return relatedCveIdsJson; }
    public void setRelatedCveIdsJson(String relatedCveIdsJson) { this.relatedCveIdsJson = relatedCveIdsJson; }

    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getFixType() { return fixType; }
    public void setFixType(String fixType) { this.fixType = fixType; }

    public String getSoftwareEntitiesJson() { return softwareEntitiesJson; }
    public void setSoftwareEntitiesJson(String softwareEntitiesJson) { this.softwareEntitiesJson = softwareEntitiesJson; }

    public String getOsHint() { return osHint; }
    public void setOsHint(String osHint) { this.osHint = osHint; }

    public String getRecommendationSource() { return recommendationSource; }
    public void setRecommendationSource(String recommendationSource) { this.recommendationSource = recommendationSource; }

    public String getSourceUrlsJson() { return sourceUrlsJson; }
    public void setSourceUrlsJson(String sourceUrlsJson) { this.sourceUrlsJson = sourceUrlsJson; }

    public Instant getGeneratedAt() { return generatedAt; }
    public void setGeneratedAt(Instant generatedAt) { this.generatedAt = generatedAt; }

    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
