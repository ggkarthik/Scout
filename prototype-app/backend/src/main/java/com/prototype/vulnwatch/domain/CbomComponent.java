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
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

@Entity
@Table(
        name = "cbom_components",
        uniqueConstraints = {
                @UniqueConstraint(name = "cbom_components_tenant_id_source_bom_id_component_fingerprint_key",
                        columnNames = {"tenant_id", "source_bom_id", "component_fingerprint"})
        },
        indexes = {
                @Index(name = "idx_cbom_components_tenant_asset", columnList = "tenant_id,asset_id"),
                @Index(name = "idx_cbom_components_source_bom", columnList = "source_bom_id"),
                @Index(name = "idx_cbom_components_asset_type", columnList = "tenant_id,asset_type")
        }
)
public class CbomComponent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne
    @JoinColumn(name = "asset_id")
    private Asset asset;

    @ManyToOne(optional = false)
    @JoinColumn(name = "source_bom_id")
    private BomIngestionRecord sourceBom;

    @Column(name = "bom_ref")
    private String bomRef;

    @Column(name = "component_fingerprint", nullable = false)
    private String componentFingerprint;

    @Column(nullable = false)
    private String name;

    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "asset_type", nullable = false, length = 60)
    private CbomAssetType assetType = CbomAssetType.UNKNOWN;

    @Column(name = "component_type")
    private String componentType;

    private String primitive;

    @Column(name = "parameter_set_identifier")
    private String parameterSetIdentifier;

    @Column(name = "key_size")
    private Integer keySize;

    private String curve;
    private String padding;

    @Column(name = "protocol_version")
    private String protocolVersion;

    private String state;
    private String format;

    @Column(name = "storage_location")
    private String storageLocation;

    private String transmission;
    private String sensitivity;

    @Column(name = "used_in")
    private String usedIn;

    @Column(name = "not_before")
    private LocalDate notBefore;

    @Column(name = "not_after")
    private LocalDate notAfter;

    private String issuer;
    private String subject;

    @Column(name = "serial_number")
    private String serialNumber;

    @Column(name = "signature_algorithm")
    private String signatureAlgorithm;

    @Column(name = "key_usage")
    private String keyUsage;

    @Column(name = "risk_score")
    private BigDecimal riskScore;

    @Column(nullable = false)
    private boolean active = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @PreUpdate
    public void touch() {
        this.updatedAt = Instant.now();
    }

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }
    public Asset getAsset() { return asset; }
    public void setAsset(Asset asset) { this.asset = asset; }
    public BomIngestionRecord getSourceBom() { return sourceBom; }
    public void setSourceBom(BomIngestionRecord sourceBom) { this.sourceBom = sourceBom; }
    public String getBomRef() { return bomRef; }
    public void setBomRef(String bomRef) { this.bomRef = bomRef; }
    public String getComponentFingerprint() { return componentFingerprint; }
    public void setComponentFingerprint(String componentFingerprint) { this.componentFingerprint = componentFingerprint; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public CbomAssetType getAssetType() { return assetType; }
    public void setAssetType(CbomAssetType assetType) { this.assetType = assetType; }
    public String getComponentType() { return componentType; }
    public void setComponentType(String componentType) { this.componentType = componentType; }
    public String getPrimitive() { return primitive; }
    public void setPrimitive(String primitive) { this.primitive = primitive; }
    public String getParameterSetIdentifier() { return parameterSetIdentifier; }
    public void setParameterSetIdentifier(String parameterSetIdentifier) { this.parameterSetIdentifier = parameterSetIdentifier; }
    public Integer getKeySize() { return keySize; }
    public void setKeySize(Integer keySize) { this.keySize = keySize; }
    public String getCurve() { return curve; }
    public void setCurve(String curve) { this.curve = curve; }
    public String getPadding() { return padding; }
    public void setPadding(String padding) { this.padding = padding; }
    public String getProtocolVersion() { return protocolVersion; }
    public void setProtocolVersion(String protocolVersion) { this.protocolVersion = protocolVersion; }
    public String getState() { return state; }
    public void setState(String state) { this.state = state; }
    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }
    public String getStorageLocation() { return storageLocation; }
    public void setStorageLocation(String storageLocation) { this.storageLocation = storageLocation; }
    public String getTransmission() { return transmission; }
    public void setTransmission(String transmission) { this.transmission = transmission; }
    public String getSensitivity() { return sensitivity; }
    public void setSensitivity(String sensitivity) { this.sensitivity = sensitivity; }
    public String getUsedIn() { return usedIn; }
    public void setUsedIn(String usedIn) { this.usedIn = usedIn; }
    public LocalDate getNotBefore() { return notBefore; }
    public void setNotBefore(LocalDate notBefore) { this.notBefore = notBefore; }
    public LocalDate getNotAfter() { return notAfter; }
    public void setNotAfter(LocalDate notAfter) { this.notAfter = notAfter; }
    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }
    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public void setSignatureAlgorithm(String signatureAlgorithm) { this.signatureAlgorithm = signatureAlgorithm; }
    public String getKeyUsage() { return keyUsage; }
    public void setKeyUsage(String keyUsage) { this.keyUsage = keyUsage; }
    public BigDecimal getRiskScore() { return riskScore; }
    public void setRiskScore(BigDecimal riskScore) { this.riskScore = riskScore; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
