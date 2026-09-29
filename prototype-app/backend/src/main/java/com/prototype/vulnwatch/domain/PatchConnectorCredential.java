package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
    name = "patch_connector_credentials",
    schema = "platform",
    indexes = {
        @Index(name = "idx_patch_connector_credentials_tenant", columnList = "tenant_id, connector_type"),
        @Index(name = "idx_patch_connector_credentials_type", columnList = "connector_type")
    },
    uniqueConstraints = @UniqueConstraint(
        name = "unique_tenant_connector",
        columnNames = {"tenant_id", "connector_type"}
    )
)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PatchConnectorCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "connector_type", nullable = false, length = 50)
    private String connectorType;

    @Column(name = "tenant_id")
    private UUID tenantId;

    @Column(name = "auth_method", length = 50)
    private String authMethod;

    @Column(name = "encrypted_secret", nullable = false, columnDefinition = "TEXT")
    private String encryptedSecret;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
