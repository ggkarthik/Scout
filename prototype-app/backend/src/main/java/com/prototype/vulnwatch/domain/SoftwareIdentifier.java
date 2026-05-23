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
        schema = "platform",
        name = "software_identifiers",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_software_identifier_identity_type_value",
                        columnNames = {"software_identity_id", "id_type", "normalized_value"}
                )
        },
        indexes = {
                @Index(name = "idx_software_identifier_type_value", columnList = "id_type,normalized_value"),
                @Index(name = "idx_software_identifier_identity", columnList = "software_identity_id")
        }
)
public class SoftwareIdentifier {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "software_identity_id")
    private SoftwareIdentity softwareIdentity;

    @Enumerated(EnumType.STRING)
    @Column(name = "id_type", nullable = false, length = 40)
    private IdentifierType idType;

    @Column(length = 1000)
    private String rawValue;

    @Column(name = "normalized_value", nullable = false, length = 1000)
    private String normalizedValue;

    @Column(nullable = false, length = 80)
    private String source = "system";

    @Column(nullable = false)
    private boolean verified = false;

    private Double confidence;

    /**
     * BLG-015: Free-text note explaining how this identifier was established.
     * Examples: "extracted from CycloneDX SBOM", "matched via CSAF advisory purl field".
     */
    @Column(length = 500)
    private String provenanceNote;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public SoftwareIdentity getSoftwareIdentity() {
        return softwareIdentity;
    }

    public void setSoftwareIdentity(SoftwareIdentity softwareIdentity) {
        this.softwareIdentity = softwareIdentity;
    }

    public IdentifierType getIdType() {
        return idType;
    }

    public void setIdType(IdentifierType idType) {
        this.idType = idType;
    }

    public String getRawValue() {
        return rawValue;
    }

    public void setRawValue(String rawValue) {
        this.rawValue = rawValue;
    }

    public String getNormalizedValue() {
        return normalizedValue;
    }

    public void setNormalizedValue(String normalizedValue) {
        this.normalizedValue = normalizedValue;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public boolean isVerified() {
        return verified;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    public Double getConfidence() {
        return confidence;
    }

    public void setConfidence(Double confidence) {
        this.confidence = confidence;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public String getProvenanceNote() {
        return provenanceNote;
    }

    public void setProvenanceNote(String provenanceNote) {
        this.provenanceNote = provenanceNote;
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
