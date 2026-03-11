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
        name = "vex_assertions",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_vex_assertions_target", columnNames = "target_id"),
                @UniqueConstraint(
                        name = "uk_vex_assertions_statement",
                        columnNames = {"vulnerability_id", "source_system", "document_id", "statement_key"}
                )
        },
        indexes = {
                @Index(name = "idx_vex_assertions_vulnerability", columnList = "vulnerability_id"),
                @Index(name = "idx_vex_assertions_source", columnList = "source_system"),
                @Index(name = "idx_vex_assertions_target", columnList = "target_id"),
                @Index(name = "idx_vex_assertions_identity", columnList = "software_identity_id"),
                @Index(name = "idx_vex_assertions_cpe", columnList = "cpe_id")
        }
)
public class VexAssertion {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "vulnerability_id")
    private Vulnerability vulnerability;

    @ManyToOne
    @JoinColumn(name = "observation_id")
    private VulnerabilityIntelObservation observation;

    @ManyToOne(optional = false)
    @JoinColumn(name = "target_id")
    private VulnerabilityTarget target;

    @ManyToOne
    @JoinColumn(name = "software_identity_id")
    private SoftwareIdentity softwareIdentity;

    @ManyToOne
    @JoinColumn(name = "cpe_id")
    private CpeDim cpeDim;

    @Column(name = "source_system", nullable = false, length = 80)
    private String sourceSystem;

    @Column(nullable = false, length = 120)
    private String provider;

    @Column(name = "document_id", nullable = false, length = 255)
    private String documentId;

    @Column(name = "statement_key", nullable = false, length = 512)
    private String statementKey;

    @Column(nullable = false, length = 64)
    private String status;

    @Column(name = "trust_tier", nullable = false, length = 40)
    private String trustTier;

    @Column(nullable = false, length = 40)
    private String freshness;

    @Column(length = 120)
    private String ecosystem;

    @Column(length = 120)
    private String namespace;

    @Column(name = "package_name", length = 220)
    private String packageName;

    @Column(name = "normalized_product_key", nullable = false, length = 500)
    private String normalizedProductKey;

    @Column(name = "version_exact", length = 255)
    private String versionExact;

    @Column(name = "version_start", length = 255)
    private String versionStart;

    @Column(name = "start_inclusive")
    private Boolean startInclusive;

    @Column(name = "version_end", length = 255)
    private String versionEnd;

    @Column(name = "end_inclusive")
    private Boolean endInclusive;

    @Column(name = "fixed_version", length = 255)
    private String fixedVersion;

    @Column(name = "raw_target", columnDefinition = "TEXT")
    private String rawTarget;

    @Column(name = "evidence_json", columnDefinition = "TEXT")
    private String evidenceJson;

    @Column(name = "published_at")
    private Instant publishedAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt = Instant.now();

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    public VulnerabilityIntelObservation getObservation() {
        return observation;
    }

    public void setObservation(VulnerabilityIntelObservation observation) {
        this.observation = observation;
    }

    public VulnerabilityTarget getTarget() {
        return target;
    }

    public void setTarget(VulnerabilityTarget target) {
        this.target = target;
    }

    public SoftwareIdentity getSoftwareIdentity() {
        return softwareIdentity;
    }

    public void setSoftwareIdentity(SoftwareIdentity softwareIdentity) {
        this.softwareIdentity = softwareIdentity;
    }

    public CpeDim getCpeDim() {
        return cpeDim;
    }

    public void setCpeDim(CpeDim cpeDim) {
        this.cpeDim = cpeDim;
    }

    public String getSourceSystem() {
        return sourceSystem;
    }

    public void setSourceSystem(String sourceSystem) {
        this.sourceSystem = sourceSystem;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getDocumentId() {
        return documentId;
    }

    public void setDocumentId(String documentId) {
        this.documentId = documentId;
    }

    public String getStatementKey() {
        return statementKey;
    }

    public void setStatementKey(String statementKey) {
        this.statementKey = statementKey;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getTrustTier() {
        return trustTier;
    }

    public void setTrustTier(String trustTier) {
        this.trustTier = trustTier;
    }

    public String getFreshness() {
        return freshness;
    }

    public void setFreshness(String freshness) {
        this.freshness = freshness;
    }

    public String getEcosystem() {
        return ecosystem;
    }

    public void setEcosystem(String ecosystem) {
        this.ecosystem = ecosystem;
    }

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getNormalizedProductKey() {
        return normalizedProductKey;
    }

    public void setNormalizedProductKey(String normalizedProductKey) {
        this.normalizedProductKey = normalizedProductKey;
    }

    public String getVersionExact() {
        return versionExact;
    }

    public void setVersionExact(String versionExact) {
        this.versionExact = versionExact;
    }

    public String getVersionStart() {
        return versionStart;
    }

    public void setVersionStart(String versionStart) {
        this.versionStart = versionStart;
    }

    public Boolean getStartInclusive() {
        return startInclusive;
    }

    public void setStartInclusive(Boolean startInclusive) {
        this.startInclusive = startInclusive;
    }

    public String getVersionEnd() {
        return versionEnd;
    }

    public void setVersionEnd(String versionEnd) {
        this.versionEnd = versionEnd;
    }

    public Boolean getEndInclusive() {
        return endInclusive;
    }

    public void setEndInclusive(Boolean endInclusive) {
        this.endInclusive = endInclusive;
    }

    public String getFixedVersion() {
        return fixedVersion;
    }

    public void setFixedVersion(String fixedVersion) {
        this.fixedVersion = fixedVersion;
    }

    public String getRawTarget() {
        return rawTarget;
    }

    public void setRawTarget(String rawTarget) {
        this.rawTarget = rawTarget;
    }

    public String getEvidenceJson() {
        return evidenceJson;
    }

    public void setEvidenceJson(String evidenceJson) {
        this.evidenceJson = evidenceJson;
    }

    public Instant getPublishedAt() {
        return publishedAt;
    }

    public void setPublishedAt(Instant publishedAt) {
        this.publishedAt = publishedAt;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    public void setLastSeenAt(Instant lastSeenAt) {
        this.lastSeenAt = lastSeenAt;
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
