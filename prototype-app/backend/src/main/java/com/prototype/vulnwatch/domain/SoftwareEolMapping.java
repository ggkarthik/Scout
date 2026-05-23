package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        schema = "platform",
        name = "software_eol_mapping",
        indexes = {
                @Index(name = "idx_software_eol_mapping_identity", columnList = "software_identity_id"),
                @Index(name = "idx_software_eol_mapping_slug", columnList = "eol_slug")
        }
)
public class SoftwareEolMapping {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "software_identity_id")
    private UUID softwareIdentityId;

    @Column(name = "normalized_key", nullable = false, unique = true, length = 500)
    private String normalizedKey;

    @Column(name = "eol_slug", length = 200)
    private String eolSlug;

    @Column(name = "match_confidence", length = 20)
    private String matchConfidence;

    @Column(name = "match_method", length = 50)
    private String matchMethod;

    @Column(nullable = false)
    private boolean confirmed;

    @Column(name = "confirmed_by", length = 200)
    private String confirmedBy;

    @Column(name = "confirmed_at")
    private Instant confirmedAt;

    @Column(name = "previous_slug", length = 200)
    private String previousSlug;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    public Long getId() {
        return id;
    }

    public UUID getSoftwareIdentityId() {
        return softwareIdentityId;
    }

    public void setSoftwareIdentityId(UUID softwareIdentityId) {
        this.softwareIdentityId = softwareIdentityId;
    }

    public String getNormalizedKey() {
        return normalizedKey;
    }

    public void setNormalizedKey(String normalizedKey) {
        this.normalizedKey = normalizedKey;
    }

    public String getEolSlug() {
        return eolSlug;
    }

    public void setEolSlug(String eolSlug) {
        this.eolSlug = eolSlug;
    }

    public String getMatchConfidence() {
        return matchConfidence;
    }

    public void setMatchConfidence(String matchConfidence) {
        this.matchConfidence = matchConfidence;
    }

    public String getMatchMethod() {
        return matchMethod;
    }

    public void setMatchMethod(String matchMethod) {
        this.matchMethod = matchMethod;
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public void setConfirmed(boolean confirmed) {
        this.confirmed = confirmed;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public String getConfirmedBy() {
        return confirmedBy;
    }

    public void setConfirmedBy(String confirmedBy) {
        this.confirmedBy = confirmedBy;
    }

    public Instant getConfirmedAt() {
        return confirmedAt;
    }

    public void setConfirmedAt(Instant confirmedAt) {
        this.confirmedAt = confirmedAt;
    }

    public String getPreviousSlug() {
        return previousSlug;
    }

    public void setPreviousSlug(String previousSlug) {
        this.previousSlug = previousSlug;
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
