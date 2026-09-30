package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/**
 * A model or dataset an uploaded AI-BOM declared.
 *
 * <p>A declaration is not a deployment. This deliberately does not live in
 * ai_security_artifacts, which holds resources a connector observed in a cloud account and
 * whose contents the assessment pipeline evaluates against policies written for
 * provider-observed configuration. A link to an artifact is established only once deployment
 * is actually verified, and until then {@code deploymentState} stays UNVERIFIED.
 */
@Entity
@Table(
    name = "ai_bom_declared_resources",
    uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "source_id", "identity_value"}),
    indexes = {
        @Index(name = "idx_ai_bom_declared_resources_source", columnList = "tenant_id,source_id"),
        @Index(name = "idx_ai_bom_declared_resources_kind",
               columnList = "tenant_id,resource_kind,deployment_state")
    }
)
@Data
@Getter
@Setter
@EqualsAndHashCode(of = "id")
public class AiBomDeclaredResource {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "source_id", nullable = false)
    private UUID sourceId;

    /** Document version that last declared it, so a claim traces back to its evidence. */
    @Column(name = "bom_id", nullable = false)
    private UUID bomId;

    @Column(name = "bom_component_id")
    private UUID bomComponentId;

    @Enumerated(EnumType.STRING)
    @Column(name = "resource_kind", nullable = false, length = 16)
    private AiBomDeclaredResourceKind resourceKind;

    @Column(nullable = false, length = 512)
    private String name;

    @Column(length = 255)
    private String version;

    @Enumerated(EnumType.STRING)
    @Column(name = "identity_kind", nullable = false, length = 32)
    private AiBomDeclaredIdentityKind identityKind;

    @Column(name = "identity_value", nullable = false, length = 1024)
    private String identityValue;

    @Enumerated(EnumType.STRING)
    @Column(name = "deployment_state", nullable = false, length = 24)
    private AiBomDeploymentState deploymentState = AiBomDeploymentState.UNVERIFIED;

    @Column(name = "linked_artifact_id")
    private UUID linkedArtifactId;

    @Enumerated(EnumType.STRING)
    @Column(name = "link_method", length = 32)
    private AiBomLinkMethod linkMethod;

    @Column(name = "link_reviewed_by", length = 255)
    private String linkReviewedBy;

    @Column(name = "link_reviewed_at")
    private Instant linkReviewedAt;

    /**
     * A reviewer's not-yet-confirmed candidate mapping (Milestone 3 part 5.3). Never presented
     * as a deployment -- {@code linked_artifact_id} only changes once a (possibly different)
     * reviewer approves it, which is what the V7 link-consistency check still governs.
     */
    @Column(name = "proposed_artifact_id")
    private UUID proposedArtifactId;

    @Column(name = "proposed_by", length = 255)
    private String proposedBy;

    @Column(name = "proposed_at")
    private Instant proposedAt;

    @Column(name = "first_declared_at", nullable = false)
    private Instant firstDeclaredAt;

    @Column(name = "last_declared_at", nullable = false)
    private Instant lastDeclaredAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "attributes_json", nullable = false)
    private String attributesJson = "{}";
}
