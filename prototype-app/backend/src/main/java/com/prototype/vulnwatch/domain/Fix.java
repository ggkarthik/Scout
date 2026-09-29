package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
    schema = "platform",
    name = "fixes",
    indexes = {
        @Index(name = "idx_fixes_source_system", columnList = "source_system"),
        @Index(name = "idx_fixes_fix_type", columnList = "fix_type"),
        @Index(name = "idx_fixes_ecosystem", columnList = "ecosystem"),
        @Index(name = "idx_fixes_status", columnList = "status"),
        @Index(name = "idx_fixes_created_at", columnList = "created_at DESC")
    }
)
@Data
@EqualsAndHashCode(of = "id")
public class Fix {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 200)
    private String externalId;

    @Column(nullable = false, length = 50)
    private String sourceSystem;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private FixType fixType;

    @Column(nullable = false, length = 500)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(length = 120)
    private String ecosystem;

    @Column(name = "package_name", length = 220)
    private String packageName;

    @Column(length = 100)
    private String fixedVersion;

    @Column(length = 20)
    private String severity;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private EffortLevel effort;

    @Column(name = "risk_level", length = 20)
    private String riskLevel;

    @Column(name = "requires_reboot")
    private Boolean requiresReboot = false;

    @Column(name = "estimated_downtime_minutes")
    private Integer estimatedDowntimeMinutes;

    @Column(name = "applicable_assets")
    private Integer applicableAssets = 0;

    @Column(name = "deployed_assets")
    private Integer deployedAssets = 0;

    @Column(name = "deployment_rate")
    private Double deploymentRate = 0.0;

    @Enumerated(EnumType.STRING)
    @Column(length = 50)
    private FixStatus status = FixStatus.ACTIVE;

    @Column(name = "installation_instructions", columnDefinition = "TEXT")
    private String installationInstructions;

    @Column(name = "known_limitations", columnDefinition = "TEXT")
    private String knownLimitations;

    @Column(name = "patch_url", length = 1000)
    private String patchUrl;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "superseded_by_fix_id")
    private Fix supersededByFix;

    @Column(name = "source_metadata", columnDefinition = "JSONB")
    @JdbcTypeCode(SqlTypes.JSON)
    private JsonNode sourceMetadata;

    @Column(name = "created_by")
    private UUID createdBy;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;

    @Column(name = "synced_at")
    private Instant syncedAt;

    public enum FixType {
        PATCH,
        WORKAROUND,
        COMPENSATING_CONTROL,
        MITIGATION
    }

    public enum FixStatus {
        ACTIVE,
        DEPRECATED,
        SUPERSEDED,
        EXPERIMENTAL
    }

    public enum EffortLevel {
        LOW,
        MEDIUM,
        HIGH
    }

    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW
    }
}
