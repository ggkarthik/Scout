package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(
    name = "github_security_advisories",
    schema = "public",
    indexes = {
        @Index(name = "idx_ghsa_id", columnList = "ghsa_id"),
        @Index(name = "idx_ghsa_package", columnList = "ecosystem,package_name"),
        @Index(name = "idx_ghsa_cve", columnList = "cve_id"),
        @Index(name = "idx_ghsa_applicable", columnList = "is_applicable")
    }
)
@Data
@NoArgsConstructor
@AllArgsConstructor
public class GithubSecurityAdvisoryEntity {

    @Id
    private java.util.UUID id;

    @Column(nullable = false, unique = true, length = 20)
    private String ghsaId;

    @Column(length = 20)
    private String cveId;

    @Column(nullable = false, length = 500)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(nullable = false, length = 20)
    private String severity;

    private Double cvssScore;

    @Column(length = 100)
    private String cvssVector;

    @Column(nullable = false, length = 50)
    private String ecosystem;

    @Column(nullable = false, length = 255)
    private String packageName;

    @Column(length = 50)
    private String affectedVersionsStart;

    @Column(length = 50)
    private String affectedVersionsEnd;

    @Column(length = 500)
    private String affectedVersionsPattern;

    @Column(columnDefinition = "TEXT")
    private String fixedVersions;

    @Column(length = 500)
    private String githubAdvisoryUrl;

    @Column(nullable = false)
    private Instant publishedAt;

    private Instant updatedAt;

    private Instant withdrawnAt;

    private Instant firstSyncedAt;

    private Instant lastSyncedAt;

    @Column(nullable = false)
    private Boolean isApplicable = true;

    @Column(length = 64)
    private String syncHash;

    @Column(nullable = false)
    private Instant createdAt;
}
