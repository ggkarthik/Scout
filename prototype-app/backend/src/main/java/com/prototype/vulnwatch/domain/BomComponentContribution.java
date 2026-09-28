package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.Instant;
import java.util.UUID;

/**
 * One source's standing claim that an inventory component is present.
 *
 * <p>This is the mapping the pipeline previously discarded: the BOM-to-inventory match was
 * recomputed at ingest and never stored, so a component could not record that two sources
 * independently vouched for it, and a partial replacement could not withdraw one source's
 * support without looking like the component had vanished.
 */
@Entity
@Table(
    name = "bom_component_contributions",
    uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "source_id", "inventory_component_id"}),
    indexes = {
        @Index(name = "idx_bom_contributions_inventory", columnList = "tenant_id,inventory_component_id,contribution_state"),
        @Index(name = "idx_bom_contributions_source", columnList = "tenant_id,source_id,contribution_state"),
        @Index(name = "idx_bom_contributions_bom", columnList = "bom_id")
    }
)
@Data
@EqualsAndHashCode(of = "id")
public class BomComponentContribution {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "source_id", nullable = false)
    private UUID sourceId;

    /** Document version that last carried this claim. */
    @Column(name = "bom_id", nullable = false)
    private UUID bomId;

    /** Null for backfilled rows, which reconstruct the link without identifying the BOM component. */
    @Column(name = "bom_component_id")
    private UUID bomComponentId;

    @Column(name = "inventory_component_id", nullable = false)
    private UUID inventoryComponentId;

    @Column(name = "resolved_identity_key", nullable = false, length = 700)
    private String resolvedIdentityKey;

    @Enumerated(EnumType.STRING)
    @Column(name = "contribution_state", nullable = false, length = 24)
    private BomContributionState contributionState = BomContributionState.SUPPORTED;

    /**
     * Set when a replacement under an asserted complete scope omitted the component. Only
     * this, absent any conflicting support, may lead to retirement.
     */
    @Column(name = "authoritative_absence", nullable = false)
    private boolean authoritativeAbsence;

    @Column(name = "first_contributed_at", nullable = false)
    private Instant firstContributedAt;

    @Column(name = "last_contributed_at", nullable = false)
    private Instant lastContributedAt;

    /** Withdrawal audit timestamp. A database constraint keeps this in step with the state. */
    @Column(name = "withdrawn_at")
    private Instant withdrawnAt;
}
