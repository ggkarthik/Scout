package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.time.LocalDate;

@Entity
@Table(
        schema = "platform",
        name = "eol_release",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_eol_release_slug_cycle", columnNames = {"product_slug", "cycle"})
        },
        indexes = {
                @Index(name = "idx_eol_release_product_slug", columnList = "product_slug"),
                @Index(name = "idx_eol_release_is_eol", columnList = "is_eol")
        }
)
public class EolRelease {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "product_slug", nullable = false, length = 200)
    private String productSlug;

    @Column(nullable = false, length = 100)
    private String cycle;

    @Column(name = "release_date")
    private LocalDate releaseDate;

    @Column(name = "eol_date")
    private LocalDate eolDate;

    @Column(name = "eol_boolean")
    private Boolean eolBoolean;

    @Column(name = "support_end_date")
    private LocalDate supportEndDate;

    @Column(name = "extended_support_date")
    private LocalDate extendedSupportDate;

    @Column(name = "latest_version", length = 100)
    private String latestVersion;

    @Column(name = "latest_release_date")
    private LocalDate latestReleaseDate;

    @Column(name = "is_lts", nullable = false)
    private boolean lts;

    @Column(name = "is_eol", nullable = false)
    private boolean eol;

    @Column(name = "is_eoas")
    private Boolean eoas;

    @Column(name = "is_eoes")
    private Boolean eoes;

    @Column(name = "security_support_date")
    private LocalDate securitySupportDate;

    @Column(name = "official_source_url", length = 500)
    private String officialSourceUrl;

    @Column(name = "support_phase", length = 30)
    private String supportPhase;

    @Column(nullable = false)
    private boolean discontinued;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    public Long getId() {
        return id;
    }

    public String getProductSlug() {
        return productSlug;
    }

    public void setProductSlug(String productSlug) {
        this.productSlug = productSlug;
    }

    public String getCycle() {
        return cycle;
    }

    public void setCycle(String cycle) {
        this.cycle = cycle;
    }

    public LocalDate getReleaseDate() {
        return releaseDate;
    }

    public void setReleaseDate(LocalDate releaseDate) {
        this.releaseDate = releaseDate;
    }

    public LocalDate getEolDate() {
        return eolDate;
    }

    public void setEolDate(LocalDate eolDate) {
        this.eolDate = eolDate;
    }

    public Boolean getEolBoolean() {
        return eolBoolean;
    }

    public void setEolBoolean(Boolean eolBoolean) {
        this.eolBoolean = eolBoolean;
    }

    public LocalDate getSupportEndDate() {
        return supportEndDate;
    }

    public void setSupportEndDate(LocalDate supportEndDate) {
        this.supportEndDate = supportEndDate;
    }

    public LocalDate getExtendedSupportDate() {
        return extendedSupportDate;
    }

    public void setExtendedSupportDate(LocalDate extendedSupportDate) {
        this.extendedSupportDate = extendedSupportDate;
    }

    public String getLatestVersion() {
        return latestVersion;
    }

    public void setLatestVersion(String latestVersion) {
        this.latestVersion = latestVersion;
    }

    public LocalDate getLatestReleaseDate() {
        return latestReleaseDate;
    }

    public void setLatestReleaseDate(LocalDate latestReleaseDate) {
        this.latestReleaseDate = latestReleaseDate;
    }

    public boolean isLts() {
        return lts;
    }

    public void setLts(boolean lts) {
        this.lts = lts;
    }

    public boolean isEol() {
        return eol;
    }

    public void setEol(boolean eol) {
        this.eol = eol;
    }

    public Boolean getEoas() {
        return eoas;
    }

    public void setEoas(Boolean eoas) {
        this.eoas = eoas;
    }

    public Boolean getEoes() {
        return eoes;
    }

    public void setEoes(Boolean eoes) {
        this.eoes = eoes;
    }

    public LocalDate getSecuritySupportDate() {
        return securitySupportDate;
    }

    public void setSecuritySupportDate(LocalDate securitySupportDate) {
        this.securitySupportDate = securitySupportDate;
    }

    public String getOfficialSourceUrl() {
        return officialSourceUrl;
    }

    public void setOfficialSourceUrl(String officialSourceUrl) {
        this.officialSourceUrl = officialSourceUrl;
    }

    public String getSupportPhase() {
        return supportPhase;
    }

    public void setSupportPhase(String supportPhase) {
        this.supportPhase = supportPhase;
    }

    public boolean isDiscontinued() {
        return discontinued;
    }

    public void setDiscontinued(boolean discontinued) {
        this.discontinued = discontinued;
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
