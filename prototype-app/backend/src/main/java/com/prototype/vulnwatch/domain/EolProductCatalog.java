package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(
        schema = "platform",
        name = "eol_product_catalog",
        indexes = {
                @Index(name = "idx_eol_catalog_cpe", columnList = "cpe_vendor,cpe_product"),
                @Index(name = "idx_eol_catalog_purl", columnList = "purl_type,purl_namespace")
        }
)
public class EolProductCatalog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 200)
    private String slug;

    @Column(name = "cpe_vendor", length = 200)
    private String cpeVendor;

    @Column(name = "cpe_product", length = 200)
    private String cpeProduct;

    @Column(name = "purl_type", length = 100)
    private String purlType;

    @Column(name = "purl_namespace", length = 200)
    private String purlNamespace;

    @Column(name = "display_name", length = 200)
    private String displayName;

    @Column(name = "aliases", columnDefinition = "text")
    private String aliases; // comma-separated, lower-cased alias strings

    @Column(name = "last_modified", length = 50)
    private String lastModified; // Last-Modified header value from API for conditional fetch

    @Column(name = "last_fetched_at")
    private Instant lastFetchedAt;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    public Long getId() {
        return id;
    }

    public String getSlug() {
        return slug;
    }

    public void setSlug(String slug) {
        this.slug = slug;
    }

    public String getCpeVendor() {
        return cpeVendor;
    }

    public void setCpeVendor(String cpeVendor) {
        this.cpeVendor = cpeVendor;
    }

    public String getCpeProduct() {
        return cpeProduct;
    }

    public void setCpeProduct(String cpeProduct) {
        this.cpeProduct = cpeProduct;
    }

    public String getPurlType() {
        return purlType;
    }

    public void setPurlType(String purlType) {
        this.purlType = purlType;
    }

    public String getPurlNamespace() {
        return purlNamespace;
    }

    public void setPurlNamespace(String purlNamespace) {
        this.purlNamespace = purlNamespace;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getAliases() {
        return aliases;
    }

    public void setAliases(String aliases) {
        this.aliases = aliases;
    }

    public java.util.List<String> getAliasesList() {
        if (aliases == null || aliases.isBlank()) {
            return java.util.List.of();
        }
        return java.util.Arrays.asList(aliases.split(","));
    }

    public void setAliasesList(java.util.List<String> aliasList) {
        this.aliases = (aliasList == null || aliasList.isEmpty())
                ? null
                : String.join(",", aliasList);
    }

    public String getLastModified() {
        return lastModified;
    }

    public void setLastModified(String lastModified) {
        this.lastModified = lastModified;
    }

    public Instant getLastFetchedAt() {
        return lastFetchedAt;
    }

    public void setLastFetchedAt(Instant lastFetchedAt) {
        this.lastFetchedAt = lastFetchedAt;
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
