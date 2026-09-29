package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
    schema = "platform",
    name = "cve_fix_map",
    indexes = {
        @Index(name = "idx_cve_fix_map_fix_id", columnList = "fix_id"),
        @Index(name = "idx_cve_fix_map_cve_id", columnList = "cve_id")
    }
)
@Data
@EqualsAndHashCode(of = "id")
public class CveFixMap {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private UUID fixId;

    @Column(nullable = false, length = 50)
    private String cveId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private RelationshipType relationshipType;

    @Enumerated(EnumType.STRING)
    @Column(length = 50)
    private ConfidenceLevel confidence;

    @Column(name = "mapping_source", length = 100)
    private String mappingSource;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;

    public enum RelationshipType {
        RESOLVES,
        MITIGATES,
        WORKAROUND_FOR
    }

    public enum ConfidenceLevel {
        HIGH,
        MEDIUM,
        LOW
    }
}
