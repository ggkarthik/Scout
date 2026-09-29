package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.Instant;
import java.util.UUID;

/**
 * A dependency or composition edge a BOM declared between its own components.
 *
 * <p>Recorded verbatim and not interpreted. A CycloneDX {@code dependsOn} edge says one
 * component depends on another; it does not say a model was trained on a dataset, or that a
 * dataset is served at inference time. Deriving training or serving usage from a generic edge
 * would manufacture provenance the document never asserted, and that would then feed policy
 * decisions.
 */
@Entity
@Table(
    name = "bom_component_relationships",
    uniqueConstraints = @UniqueConstraint(
        columnNames = {"tenant_id", "bom_id", "source_ref", "target_ref", "relationship_type"}),
    indexes = {
        @Index(name = "idx_bom_component_relationships_bom", columnList = "tenant_id,bom_id"),
        @Index(name = "idx_bom_component_relationships_source", columnList = "tenant_id,source_component_id")
    }
)
@Data
@EqualsAndHashCode(of = "id")
public class BomComponentRelationship {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "bom_id", nullable = false)
    private UUID bomId;

    /**
     * The bom-ref exactly as the document wrote it. Kept even when it resolves to no
     * component: a document may reference a ref it never defines, and discarding those edges
     * would silently lose structure the customer declared.
     */
    @Column(name = "source_ref", nullable = false)
    private String sourceRef;

    @Column(name = "target_ref", nullable = false)
    private String targetRef;

    @Column(name = "source_component_id")
    private UUID sourceComponentId;

    @Column(name = "target_component_id")
    private UUID targetComponentId;

    /** Only what the document structurally expressed: DEPENDS_ON or COMPOSED_OF. */
    @Column(name = "relationship_type", nullable = false, length = 32)
    private String relationshipType;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
