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
        name = "ci_aliases",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_ci_aliases_tenant_alias_source",
                        columnNames = {"tenant_id", "normalized_alias_name", "source_system"}
                )
        },
        indexes = {
                @Index(name = "idx_ci_aliases_tenant_alias", columnList = "tenant_id,normalized_alias_name"),
                @Index(name = "idx_ci_aliases_ci", columnList = "ci_id")
        }
)
public class CiAlias {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(optional = false)
    @JoinColumn(name = "ci_id")
    private Ci ci;

    @Column(name = "alias_name", nullable = false, length = 255)
    private String aliasName;

    @Column(name = "normalized_alias_name", nullable = false, length = 255)
    private String normalizedAliasName;

    @Column(name = "source_system", nullable = false, length = 64)
    private String sourceSystem;

    @Column(name = "first_seen_at", nullable = false)
    private Instant firstSeenAt = Instant.now();

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt = Instant.now();

    @Column
    private Double confidence;

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

    public String getAliasName() {
        return aliasName;
    }

    public void setAliasName(String aliasName) {
        this.aliasName = aliasName;
    }

    public String getNormalizedAliasName() {
        return normalizedAliasName;
    }

    public void setNormalizedAliasName(String normalizedAliasName) {
        this.normalizedAliasName = normalizedAliasName;
    }

    public String getSourceSystem() {
        return sourceSystem;
    }

    public void setSourceSystem(String sourceSystem) {
        this.sourceSystem = sourceSystem;
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

    public Double getConfidence() {
        return confidence;
    }

    public void setConfidence(Double confidence) {
        this.confidence = confidence;
    }
}
