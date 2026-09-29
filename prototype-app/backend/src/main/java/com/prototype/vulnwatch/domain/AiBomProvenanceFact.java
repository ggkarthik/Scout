package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.Instant;
import java.util.UUID;

/**
 * Storage for the {@code provenance.ai_bom_present} fact (registered in the platform fact
 * catalog). Deliberately not {@code ai_grid_facts}: that table requires a connector-observed
 * artifact/snapshot/run, which an AI-BOM-only asset with no cloud connector never has.
 */
@Entity
@Table(
    name = "ai_bom_provenance_facts",
    uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "asset_id", "fact_key"}),
    indexes = @Index(name = "idx_ai_bom_provenance_facts_source", columnList = "tenant_id,source_id")
)
@Data
@EqualsAndHashCode(of = "id")
public class AiBomProvenanceFact {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "asset_id", nullable = false)
    private UUID assetId;

    @Column(name = "source_id", nullable = false)
    private UUID sourceId;

    /** The document version that produced this projection. */
    @Column(name = "bom_id", nullable = false)
    private UUID bomId;

    @Column(name = "fact_key", nullable = false, length = 255)
    private String factKey = "provenance.ai_bom_present";

    @Column(name = "value_boolean", nullable = false)
    private boolean valueBoolean = true;

    @Column(name = "evidence_class", nullable = false, length = 32)
    private String evidenceClass = "BOM_DOCUMENT";

    @Column(name = "bom_format", length = 32)
    private String bomFormat;

    @Column(name = "spec_version", length = 32)
    private String specVersion;

    @Column(name = "document_ingested_at", nullable = false)
    private Instant documentIngestedAt;

    @Column(name = "projected_at", nullable = false)
    private Instant projectedAt;

    @Column(name = "projection_version", nullable = false)
    private int projectionVersion = 1;
}
