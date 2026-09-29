package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
    name = "asset_fix_status",
    indexes = {
        @Index(name = "idx_asset_fix_status_tenant_id", columnList = "tenant_id"),
        @Index(name = "idx_asset_fix_status_asset_id", columnList = "asset_id"),
        @Index(name = "idx_asset_fix_status_fix_id", columnList = "fix_id"),
        @Index(name = "idx_asset_fix_status_deployment_status", columnList = "deployment_status")
    }
)
@Data
@EqualsAndHashCode(of = "id")
public class AssetFixStatus {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private UUID tenantId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "asset_id", nullable = false)
    private Asset asset;

    @Column(nullable = false)
    private UUID fixId;

    @Column(nullable = false)
    private Boolean applicable = true;

    @Enumerated(EnumType.STRING)
    @Column(length = 50)
    private DeploymentStatus deploymentStatus = DeploymentStatus.PENDING;

    @Column(name = "deployed_at")
    private Instant deployedAt;

    @Column(name = "source_system", length = 50)
    private String sourceSystem;

    @Column(name = "deployment_job_id", length = 200)
    private String deploymentJobId;

    @Column(columnDefinition = "TEXT")
    private String notes;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;

    public enum DeploymentStatus {
        NOT_APPLICABLE,
        PENDING,
        IN_PROGRESS,
        DEPLOYED,
        FAILED
    }
}
