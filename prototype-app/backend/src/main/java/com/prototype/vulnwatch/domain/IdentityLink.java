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

    @ManyToOne
    @JoinColumn(name = "from_identifier_id")
    private SoftwareIdentifier fromIdentifier;

    @ManyToOne
    @JoinColumn(name = "to_identifier_id")
    private SoftwareIdentifier toIdentifier;

    @Column(nullable = false, length = 80)
    private String linkType;

    @Column(nullable = false, length = 80)
    private String source;

    @Column(nullable = false)
    private boolean verified = false;

    private Double confidence;

    @Column(name = "source_type", length = 80)
    private String sourceType;

    @Column(name = "source_id", length = 255)
    private String sourceId;

    @Column(name = "target_type", length = 80)
    private String targetType;

    @Column(name = "target_id", length = 255)
    private String targetId;

    @Enumerated(EnumType.STRING)
    @Column(name = "match_rule", length = 40)
    private IdentityMatchRule matchRule;

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

    @Column(name = "last_seen_at")
    private Instant lastSeenAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

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

    public String getSourceType() {
        return sourceType;
    }

    public void setSourceType(String sourceType) {
        this.sourceType = sourceType;
    }

    public String getSourceId() {
        return sourceId;
    }

    public void setSourceId(String sourceId) {
        this.sourceId = sourceId;
    }

    public String getTargetType() {
        return targetType;
    }

    public void setTargetType(String targetType) {
        this.targetType = targetType;
    }

    public String getTargetId() {
        return targetId;
    }

    public void setTargetId(String targetId) {
        this.targetId = targetId;
    }

    public IdentityMatchRule getMatchRule() {
        return matchRule;
    }

    public void setMatchRule(IdentityMatchRule matchRule) {
        this.matchRule = matchRule;
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

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    public void setLastSeenAt(Instant lastSeenAt) {
        this.lastSeenAt = lastSeenAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void touch() {
        this.updatedAt = Instant.now();
        this.lastSeenAt = this.updatedAt;
    }
}
