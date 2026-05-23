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
import java.util.UUID;

@Entity
@Table(
        schema = "platform",
        name = "cpe_dim",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_cpe_dim_normalized", columnNames = {"normalized_cpe"})
        },
        indexes = {
                @Index(name = "idx_cpe_dim_key", columnList = "cpe_key"),
                @Index(name = "idx_cpe_dim_normalized", columnList = "normalized_cpe")
        }
)
public class CpeDim {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 1200)
    private String rawCpe;

    @Column(name = "normalized_cpe", nullable = false, length = 1200)
    private String normalizedCpe;

    @Column(nullable = false, length = 500)
    private String part;

    @Column(nullable = false, length = 500)
    private String vendor;

    @Column(nullable = false, length = 500)
    private String product;

    @Column(length = 500)
    private String version;

    @Column(length = 500)
    private String update;

    @Column(length = 500)
    private String edition;

    @Column(length = 500)
    private String language;

    @Column(length = 500)
    private String swEdition;

    @Column(length = 500)
    private String targetSw;

    @Column(length = 500)
    private String targetHw;

    @Column(length = 500)
    private String other;

    @Column(name = "cpe_key", nullable = false, length = 1000)
    private String cpeKey;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public String getRawCpe() {
        return rawCpe;
    }

    public void setRawCpe(String rawCpe) {
        this.rawCpe = rawCpe;
    }

    public String getNormalizedCpe() {
        return normalizedCpe;
    }

    public void setNormalizedCpe(String normalizedCpe) {
        this.normalizedCpe = normalizedCpe;
    }

    public String getPart() {
        return part;
    }

    public void setPart(String part) {
        this.part = part;
    }

    public String getVendor() {
        return vendor;
    }

    public void setVendor(String vendor) {
        this.vendor = vendor;
    }

    public String getProduct() {
        return product;
    }

    public void setProduct(String product) {
        this.product = product;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getUpdate() {
        return update;
    }

    public void setUpdate(String update) {
        this.update = update;
    }

    public String getEdition() {
        return edition;
    }

    public void setEdition(String edition) {
        this.edition = edition;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public String getSwEdition() {
        return swEdition;
    }

    public void setSwEdition(String swEdition) {
        this.swEdition = swEdition;
    }

    public String getTargetSw() {
        return targetSw;
    }

    public void setTargetSw(String targetSw) {
        this.targetSw = targetSw;
    }

    public String getTargetHw() {
        return targetHw;
    }

    public void setTargetHw(String targetHw) {
        this.targetHw = targetHw;
    }

    public String getOther() {
        return other;
    }

    public void setOther(String other) {
        this.other = other;
    }

    public String getCpeKey() {
        return cpeKey;
    }

    public void setCpeKey(String cpeKey) {
        this.cpeKey = cpeKey;
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
