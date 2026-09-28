package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/**
 * Append-only record of a completeness claim: who asserted it, over which asset scope, when.
 *
 * <p>Asserting {@link BomSourceCompleteness#COMPLETE_ASSET_SOFTWARE} is what allows a later
 * replacement to retire components, so it is authorization-gated and every replacement must
 * repeat it rather than inheriting the previous claim.
 */
@Entity
@Table(
    name = "bom_source_completeness_assertions",
    indexes = @Index(name = "idx_bom_source_assertions_source", columnList = "tenant_id,source_id,asserted_at")
)
@Data
@EqualsAndHashCode(of = "id")
public class BomSourceCompletenessAssertion {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "source_id", nullable = false)
    private UUID sourceId;

    /** Document version the assertion accompanied. */
    @Column(name = "bom_id", nullable = false)
    private UUID bomId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private BomSourceCompleteness completeness;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "asset_scope_json", nullable = false)
    private String assetScopeJson;

    @Column(name = "asserted_by", nullable = false, length = 255)
    private String assertedBy;

    @Column(name = "asserted_at", nullable = false)
    private Instant assertedAt;
}
