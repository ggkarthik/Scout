package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * A stable logical BOM source: an identity that outlives the individual documents uploaded
 * against it.
 *
 * <p>Document versions are rows in {@code bom_ingestion_records} pointing here via
 * {@code source_id}; {@link #currentBomId} names the current one. Source identity is
 * deliberately independent of document id and checksum, so replacing a source is a distinct
 * act from uploading an unrelated document that happens to share a supplier.
 */
@Entity
@Table(
    name = "bom_sources",
    indexes = {
        @Index(name = "idx_bom_sources_tenant_asset", columnList = "tenant_id,asset_id,bom_type"),
        @Index(name = "idx_bom_sources_tenant_state", columnList = "tenant_id,state")
    }
)
@Data
@Getter
@Setter
@EqualsAndHashCode(of = "id")
public class BomSource {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Enumerated(EnumType.STRING)
    @Column(name = "bom_type", nullable = false, length = 20)
    private BomType bomType;

    /** Null until the asset is resolved; a source may be registered before that. */
    @Column(name = "asset_id")
    private UUID assetId;

    @Column(length = 255)
    private String supplier;

    @Column(name = "source_reference")
    private String sourceReference;

    /**
     * Deterministic identity for automated callers, so a scheduled sync replaces its own
     * source rather than accumulating one per run. Null for manual uploads.
     */
    @Column(name = "source_key", length = 700)
    private String sourceKey;

    @Column(name = "current_bom_id")
    private UUID currentBomId;

    /**
     * Monotonic per source. Milestone 2 keys projection work by (source, revision) so
     * obsolete work can be discarded rather than reprocessed.
     */
    @Column(nullable = false)
    private long revision;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private BomSourceCompleteness completeness = BomSourceCompleteness.PARTIAL;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private BomSourceState state = BomSourceState.ACTIVE;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
