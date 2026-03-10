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
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "sbom_uploads",
        indexes = {
                @Index(name = "idx_sbom_upload_tenant_uploaded", columnList = "tenant_id,uploaded_at"),
                @Index(name = "idx_sbom_upload_asset_uploaded", columnList = "asset_id,uploaded_at")
        }
)
public class SbomUpload {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(optional = false)
    @JoinColumn(name = "asset_id")
    private Asset asset;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SbomFormat format = SbomFormat.UNKNOWN;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private SbomIngestionStatus status = SbomIngestionStatus.SUCCESS;

    @Column(nullable = false)
    private Instant uploadedAt = Instant.now();

    @Column(nullable = false, length = 10000)
    private String originalFilename;

    @Column(length = 64)
    private String ingestionSourceType;

    @Column(length = 64)
    private String ingestionSourceSystem;

    @Column(length = 10000)
    private String sourceReference;

    @Column(length = 10000)
    private String sourceEndpoint;

    private Integer fetchStatusCode;

    @Column(length = 512)
    private String contentType;

    private Long contentLengthBytes;

    @Column(length = 128)
    private String contentSha256;

    private Integer componentCount;

    private Integer findingsGenerated;

    @Column(name = "evidence_json", columnDefinition = "TEXT")
    private String evidenceJson;

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public Asset getAsset() {
        return asset;
    }

    public void setAsset(Asset asset) {
        this.asset = asset;
    }

    public SbomFormat getFormat() {
        return format;
    }

    public void setFormat(SbomFormat format) {
        this.format = format;
    }

    public SbomIngestionStatus getStatus() {
        return status;
    }

    public void setStatus(SbomIngestionStatus status) {
        this.status = status;
    }

    public Instant getUploadedAt() {
        return uploadedAt;
    }

    public String getOriginalFilename() {
        return originalFilename;
    }

    public void setOriginalFilename(String originalFilename) {
        this.originalFilename = originalFilename;
    }

    public String getIngestionSourceType() {
        return ingestionSourceType;
    }

    public void setIngestionSourceType(String ingestionSourceType) {
        this.ingestionSourceType = ingestionSourceType;
    }

    public String getIngestionSourceSystem() {
        return ingestionSourceSystem;
    }

    public void setIngestionSourceSystem(String ingestionSourceSystem) {
        this.ingestionSourceSystem = ingestionSourceSystem;
    }

    public String getSourceReference() {
        return sourceReference;
    }

    public void setSourceReference(String sourceReference) {
        this.sourceReference = sourceReference;
    }

    public String getSourceEndpoint() {
        return sourceEndpoint;
    }

    public void setSourceEndpoint(String sourceEndpoint) {
        this.sourceEndpoint = sourceEndpoint;
    }

    public Integer getFetchStatusCode() {
        return fetchStatusCode;
    }

    public void setFetchStatusCode(Integer fetchStatusCode) {
        this.fetchStatusCode = fetchStatusCode;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public Long getContentLengthBytes() {
        return contentLengthBytes;
    }

    public void setContentLengthBytes(Long contentLengthBytes) {
        this.contentLengthBytes = contentLengthBytes;
    }

    public String getContentSha256() {
        return contentSha256;
    }

    public void setContentSha256(String contentSha256) {
        this.contentSha256 = contentSha256;
    }

    public Integer getComponentCount() {
        return componentCount;
    }

    public void setComponentCount(Integer componentCount) {
        this.componentCount = componentCount;
    }

    public Integer getFindingsGenerated() {
        return findingsGenerated;
    }

    public void setFindingsGenerated(Integer findingsGenerated) {
        this.findingsGenerated = findingsGenerated;
    }

    public String getEvidenceJson() {
        return evidenceJson;
    }

    public void setEvidenceJson(String evidenceJson) {
        this.evidenceJson = evidenceJson;
    }
}
