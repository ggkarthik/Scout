package com.prototype.vulnwatch.domain;

/**
 * BLG-015: Typed constants for the link_type column in identity_links.
 *
 * Using an enum (stored as its name()) replaces raw string literals scattered
 * across IdentityGraphService and prevents typos from silently creating orphan
 * link-type values.
 *
 * PURL_EQUIV      — two PURLs resolve to the same software identity
 *                   (e.g. pkg:npm/lodash and pkg:npm/%40types/lodash after type aliasing)
 * PURL_TO_CPE     — a PURL has been mapped to an equivalent CPE 2.3 string
 *                   (enables NVD applicability lookups for SBOM-sourced components)
 * PURL_TO_COORD   — a PURL has been mapped to a package-coordinator key
 *                   (eco:namespace:package form for cross-source joins)
 * DIGEST_MATCH    — two identifiers resolve to the same artifact by content hash
 *                   (OCI image digest or file SHA-256)
 * ALIAS           — one package name is a known alias of another in the same ecosystem
 *                   (e.g. "babel-core" → "@babel/core")
 */
public enum IdentityLinkType {
    PURL_EQUIV,
    PURL_TO_CPE,
    PURL_TO_COORD,
    DIGEST_MATCH,
    ALIAS;

    /** Returns the value to store in the link_type column. */
    public String value() {
        return name().toLowerCase().replace('_', '-');
    }
}
