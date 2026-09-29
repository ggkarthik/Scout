package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(
    name = "tenant_github_repository_component_advisories",
    indexes = {
        @Index(name = "idx_repo_comp_advisory_source", columnList = "tenant_id,github_source_id"),
        @Index(name = "idx_repo_comp_advisory_affected", columnList = "tenant_id,is_affected"),
        @Index(name = "idx_repo_comp_advisory_finding", columnList = "tenant_id,finding_id")
    }
)
@Data
@NoArgsConstructor
@AllArgsConstructor
public class GithubRepositoryComponentAdvisoryEntity {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "github_source_id", nullable = false)
    private GithubSbomSource githubSource;

    @Column(nullable = false, length = 500)
    private String componentId;

    @Column(nullable = false)
    private UUID advisoryId;

    @Column(nullable = false)
    private Boolean isAffected;

    @Column(nullable = false, length = 50)
    private String installedVersion;

    @Column(nullable = false)
    private Boolean isInstalledVersionVulnerable;

    @Column(length = 255)
    private String vulnerableRangeReason;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "finding_id")
    private Finding finding;

    @Column(length = 50)
    private String findingKind = "AI_GITHUB_ADVISORY";

    @Column(length = 50)
    private String recommendedFixedVersion;

    private Boolean upgradeAvailable;

    private Instant discoveredAt;

    private Instant firstAlertSentAt;

    private Instant lastAlertSentAt;

    @Column(nullable = false)
    private Instant createdAt;

    private Instant updatedAt;
}
