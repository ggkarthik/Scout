package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Per-asset reconciliation gate.
 *
 * <p>Contribution rows for historical uploads have to be reconstructed, because the
 * BOM-to-inventory link was never stored. Until an asset reaches
 * {@link BomBackfillState#BACKFILLED}, its components stay LEGACY_UNKNOWN and no absence may
 * be inferred from a missing contribution row.
 */
@Entity
@Table(
    name = "bom_asset_backfill_state",
    uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "asset_id"}),
    indexes = @Index(name = "idx_bom_asset_backfill_pending", columnList = "tenant_id,state")
)
@Data
@EqualsAndHashCode(of = "id")
public class BomAssetBackfillState {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "asset_id", nullable = false)
    private UUID assetId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 24)
    private BomBackfillState state = BomBackfillState.PENDING;

    @Column(name = "attempt_count", nullable = false)
    private int attemptCount;

    /** A database constraint keeps this in step with the state. */
    @Column(name = "backfilled_at")
    private Instant backfilledAt;

    @Column(name = "failure_message")
    private String failureMessage;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
