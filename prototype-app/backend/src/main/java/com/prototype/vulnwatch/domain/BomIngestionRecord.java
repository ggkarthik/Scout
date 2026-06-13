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
        name = "bom_ingestion_records",
        indexes = {
                @Index(name = "idx_bom_ir_tenant",      columnList = "tenant_id"),
                @Index(name = "idx_bom_ir_asset",       columnList = "asset_id"),
                @Index(name = "idx_bom_ir_status_type", columnList = "tenant_id,bom_type,status"),
                @Index(name = "idx_bom_ir_ingested_at", columnList = "tenant_id,ingested_at")
        }
)
public class BomIngestionRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "sbom_upload_id")
    private UUID sbomUploadId;

    @Column(name = "asset_id")
    private UUID assetId;

    @Enumerated(EnumType.STRING)
    @Column(name = "bom_type", nullable = false, length = 20)
    private BomType bomType;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private SbomFormat format;

    @Column(name = "format_version", length = 10)
    private String formatVersion;

    @Column(name = "serial_number")
    private String serialNumber;

    @Column(length = 255)
    private String supplier;

    @Column(name = "source_method", nullable = false, length = 20)
    private String sourceMethod = "URL";

    @Enumerated(EnumType.STRING)
    @Column(name = "source_type", nullable = false, length = 40)
    private BomSourceType sourceType = BomSourceType.URL;

    @Column(name = "source_system", length = 80)
    private String sourceSystem;

    @Column(name = "source_reference")
    private String sourceReference;

    @Column(name = "source_endpoint")
    private String sourceEndpoint;

    @Column(name = "source_label")
    private String sourceLabel;

    @Column(name = "source_url")
    private String sourceUrl;

    @Enumerated(EnumType.STRING)
    @Column(name = "spec_family", nullable = false, length = 30)
    private BomSpecificationFamily specFamily = BomSpecificationFamily.UNKNOWN;

    @Enumerated(EnumType.STRING)
    @Column(name = "document_format", nullable = false, length = 20)
    private BomDocumentFormat documentFormat = BomDocumentFormat.UNKNOWN;

    @Column(name = "document_name")
    private String documentName;

    @Column(name = "content_type", length = 120)
    private String contentType;

    @Column(name = "content_length_bytes")
    private Long contentLengthBytes;

    @Column(name = "checksum_sha256", length = 128)
    private String checksumSha256;

    @Column(name = "component_count", nullable = false)
    private int componentCount = 0;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private BomStatus status = BomStatus.ACTIVE;

    @Column(name = "superseded_by")
    private UUID supersededBy;

    @Column(name = "previous_bom_id")
    private UUID previousBomId;

    @Column(name = "ingested_at", nullable = false)
    private Instant ingestedAt = Instant.now();

    @Column(name = "ingested_by", length = 255)
    private String ingestedBy;

    public UUID getId() { return id; }

    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }

    public UUID getSbomUploadId() { return sbomUploadId; }
    public void setSbomUploadId(UUID sbomUploadId) { this.sbomUploadId = sbomUploadId; }

    public UUID getAssetId() { return assetId; }
    public void setAssetId(UUID assetId) { this.assetId = assetId; }

    public BomType getBomType() { return bomType; }
    public void setBomType(BomType bomType) { this.bomType = bomType; }

    public SbomFormat getFormat() { return format; }
    public void setFormat(SbomFormat format) { this.format = format; }

    public String getFormatVersion() { return formatVersion; }
    public void setFormatVersion(String formatVersion) { this.formatVersion = formatVersion; }

    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

    public String getSupplier() { return supplier; }
    public void setSupplier(String supplier) { this.supplier = supplier; }

    public String getSourceMethod() { return sourceMethod; }
    public void setSourceMethod(String sourceMethod) { this.sourceMethod = sourceMethod; }

    public BomSourceType getSourceType() { return sourceType; }
    public void setSourceType(BomSourceType sourceType) { this.sourceType = sourceType; }

    public String getSourceSystem() { return sourceSystem; }
    public void setSourceSystem(String sourceSystem) { this.sourceSystem = sourceSystem; }

    public String getSourceReference() { return sourceReference; }
    public void setSourceReference(String sourceReference) { this.sourceReference = sourceReference; }

    public String getSourceEndpoint() { return sourceEndpoint; }
    public void setSourceEndpoint(String sourceEndpoint) { this.sourceEndpoint = sourceEndpoint; }

    public String getSourceLabel() { return sourceLabel; }
    public void setSourceLabel(String sourceLabel) { this.sourceLabel = sourceLabel; }

    public String getSourceUrl() { return sourceUrl; }
    public void setSourceUrl(String sourceUrl) { this.sourceUrl = sourceUrl; }

    public BomSpecificationFamily getSpecFamily() { return specFamily; }
    public void setSpecFamily(BomSpecificationFamily specFamily) { this.specFamily = specFamily; }

    public BomDocumentFormat getDocumentFormat() { return documentFormat; }
    public void setDocumentFormat(BomDocumentFormat documentFormat) { this.documentFormat = documentFormat; }

    public String getDocumentName() { return documentName; }
    public void setDocumentName(String documentName) { this.documentName = documentName; }

    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }

    public Long getContentLengthBytes() { return contentLengthBytes; }
    public void setContentLengthBytes(Long contentLengthBytes) { this.contentLengthBytes = contentLengthBytes; }

    public String getChecksumSha256() { return checksumSha256; }
    public void setChecksumSha256(String checksumSha256) { this.checksumSha256 = checksumSha256; }

    public int getComponentCount() { return componentCount; }
    public void setComponentCount(int componentCount) { this.componentCount = componentCount; }

    public BomStatus getStatus() { return status; }
    public void setStatus(BomStatus status) { this.status = status; }

    public UUID getSupersededBy() { return supersededBy; }
    public void setSupersededBy(UUID supersededBy) { this.supersededBy = supersededBy; }

    public UUID getPreviousBomId() { return previousBomId; }
    public void setPreviousBomId(UUID previousBomId) { this.previousBomId = previousBomId; }

    public Instant getIngestedAt() { return ingestedAt; }
    public void setIngestedAt(Instant ingestedAt) { this.ingestedAt = ingestedAt; }

    public String getIngestedBy() { return ingestedBy; }
    public void setIngestedBy(String ingestedBy) { this.ingestedBy = ingestedBy; }
}
