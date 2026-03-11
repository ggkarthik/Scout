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
        name = "identity_links",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_identity_links_pair_type_source",
                        columnNames = {"from_identifier_id", "to_identifier_id", "link_type", "source"}
                )
        },
        indexes = {
                @Index(name = "idx_identity_links_from", columnList = "from_identifier_id"),
                @Index(name = "idx_identity_links_to", columnList = "to_identifier_id")
        }
)
public class IdentityLink {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "from_identifier_id")
    private SoftwareIdentifier fromIdentifier;

    @ManyToOne(optional = false)
    @JoinColumn(name = "to_identifier_id")
    private SoftwareIdentifier toIdentifier;

    @Column(nullable = false, length = 80)
    private String linkType;

    @Column(nullable = false, length = 80)
    private String source;

    @Column(nullable = false)
    private boolean verified = false;

    private Double confidence;

    /**
     * BLG-015: When this link was last verified by an automated or manual process.
     * NULL means the link has not been re-verified since creation.
     */
    @Column
    private Instant verifiedAt;

    /**
     * BLG-015: Process or user that performed the last verification.
     * Examples: "identity-graph-service", "manual-review".
     */
    @Column(length = 255)
    private String verifiedBy;

    /**
     * BLG-015: Free-text note explaining the evidence for this cross-source link.
     * Examples: "NVD CPE dictionary match", "CSAF product ID mapping".
     */
    @Column(length = 500)
    private String provenanceNote;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public SoftwareIdentifier getFromIdentifier() {
        return fromIdentifier;
    }

    public void setFromIdentifier(SoftwareIdentifier fromIdentifier) {
        this.fromIdentifier = fromIdentifier;
    }

    public SoftwareIdentifier getToIdentifier() {
        return toIdentifier;
    }

    public void setToIdentifier(SoftwareIdentifier toIdentifier) {
        this.toIdentifier = toIdentifier;
    }

    public String getLinkType() {
        return linkType;
    }

    public void setLinkType(String linkType) {
        this.linkType = linkType;
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

    public Instant getVerifiedAt() {
        return verifiedAt;
    }

    public void setVerifiedAt(Instant verifiedAt) {
        this.verifiedAt = verifiedAt;
    }

    public String getVerifiedBy() {
        return verifiedBy;
    }

    public void setVerifiedBy(String verifiedBy) {
        this.verifiedBy = verifiedBy;
    }

    public String getProvenanceNote() {
        return provenanceNote;
    }

    public void setProvenanceNote(String provenanceNote) {
        this.provenanceNote = provenanceNote;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
