package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.Instant;
import java.util.UUID;

/**
 * Durable completed-work receipt for AI-BOM projection. A job's QUEUED/RUNNING dedupe only
 * prevents duplicate <em>queued</em> work; a receipt is what stops a redelivered or re-claimed
 * job from projecting the same source revision twice after the real work already finished.
 */
@Entity
@Table(
    name = "ai_bom_projection_receipts",
    uniqueConstraints = @UniqueConstraint(columnNames =
        {"tenant_id", "source_id", "source_revision", "operation", "projection_version"})
)
@Data
@EqualsAndHashCode(of = "id")
public class AiBomProjectionReceipt {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "source_id", nullable = false)
    private UUID sourceId;

    @Column(name = "source_revision", nullable = false)
    private long sourceRevision;

    @Column(name = "operation", nullable = false, length = 64)
    private String operation;

    @Column(name = "projection_version", nullable = false)
    private int projectionVersion = 1;

    @Column(name = "completed_at", nullable = false)
    private Instant completedAt;
}
