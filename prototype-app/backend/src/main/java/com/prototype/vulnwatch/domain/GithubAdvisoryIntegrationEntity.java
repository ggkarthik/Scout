package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "tenant_ghsa_integrations")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class GithubAdvisoryIntegrationEntity {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false)
    private Boolean isEnabled = false;

    private Instant enabledAt;

    private Instant disabledAt;

    @Column(nullable = false)
    private Boolean autoCreateFindings = true;

    @Column(nullable = false)
    private Boolean autoCorrelateComponents = true;

    @Column(nullable = false)
    private Boolean createFindingForLowSeverity = false;

    @Column(length = 255)
    private String reasonEnabled;

    private UUID enabledByUserId;

    @Column(nullable = false)
    private Instant createdAt;

    private Instant updatedAt;
}
