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

    public Instant getCreatedAt() {
        return createdAt;
    }
}
