package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "software_models")
public class SoftwareModel {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String normalizedKey;

    @Column(nullable = false)
    private String canonicalPublisher;

    @Column(nullable = false)
    private String canonicalProduct;

    @Column(nullable = false)
    private String primaryIdentifierType;

    @Column(nullable = false)
    private String primaryIdentifier;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public String getNormalizedKey() {
        return normalizedKey;
    }

    public void setNormalizedKey(String normalizedKey) {
        this.normalizedKey = normalizedKey;
    }

    public String getCanonicalPublisher() {
        return canonicalPublisher;
    }

    public void setCanonicalPublisher(String canonicalPublisher) {
        this.canonicalPublisher = canonicalPublisher;
    }

    public String getCanonicalProduct() {
        return canonicalProduct;
    }

    public void setCanonicalProduct(String canonicalProduct) {
        this.canonicalProduct = canonicalProduct;
    }

    public String getPrimaryIdentifierType() {
        return primaryIdentifierType;
    }

    public void setPrimaryIdentifierType(String primaryIdentifierType) {
        this.primaryIdentifierType = primaryIdentifierType;
    }

    public String getPrimaryIdentifier() {
        return primaryIdentifier;
    }

    public void setPrimaryIdentifier(String primaryIdentifier) {
        this.primaryIdentifier = primaryIdentifier;
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
