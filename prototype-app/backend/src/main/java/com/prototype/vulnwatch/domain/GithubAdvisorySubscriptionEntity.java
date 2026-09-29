package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(
    name = "tenant_ghsa_subscriptions",
    indexes = {
        @Index(name = "idx_ghsa_subscription_unique", columnList = "tenant_id,advisory_id"),
        @Index(name = "idx_ghsa_subscription_active", columnList = "tenant_id,is_active")
    }
)
@Data
@NoArgsConstructor
@AllArgsConstructor
public class GithubAdvisorySubscriptionEntity {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false)
    private UUID advisoryId;

    @Column(length = 100)
    private String subscriptionReason;

    @Column(nullable = false)
    private Boolean isActive = true;

    private Instant subscribedAt;

    private Instant unsubscribedAt;

    @Column(nullable = false)
    private Instant createdAt;
}
