package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "finding_delta_queue")
public class FindingDeltaQueueEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 30)
    private String eventType;

    private UUID tenantId;
    private UUID componentId;
    private UUID vulnerabilityId;

    @Column(length = 500)
    private String sourceKey;

    @Column(length = 255)
    private String sourceTag;

    @Column(nullable = false, length = 700)
    private String dedupeKey;

    @Column(nullable = false, length = 20)
    private String status = "PENDING";

    @Column(nullable = false)
    private int attemptCount = 0;

    @Column(nullable = false)
    private int maxAttempts = 3;

    @Column(nullable = false)
    private Instant enqueuedAt = Instant.now();

    @Column(nullable = false)
    private Instant visibleAfter = Instant.now();

    private Instant processingStartedAt;
    private Instant completedAt;

    @Column(columnDefinition = "text")
    private String errorMessage;

    // --- getters / setters ---

    public Long getId() { return id; }

    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }

    public UUID getTenantId() { return tenantId; }
    public void setTenantId(UUID tenantId) { this.tenantId = tenantId; }

    public UUID getComponentId() { return componentId; }
    public void setComponentId(UUID componentId) { this.componentId = componentId; }

    public UUID getVulnerabilityId() { return vulnerabilityId; }
    public void setVulnerabilityId(UUID vulnerabilityId) { this.vulnerabilityId = vulnerabilityId; }

    public String getSourceKey() { return sourceKey; }
    public void setSourceKey(String sourceKey) { this.sourceKey = sourceKey; }

    public String getSourceTag() { return sourceTag; }
    public void setSourceTag(String sourceTag) { this.sourceTag = sourceTag; }

    public String getDedupeKey() { return dedupeKey; }
    public void setDedupeKey(String dedupeKey) { this.dedupeKey = dedupeKey; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public int getAttemptCount() { return attemptCount; }
    public void setAttemptCount(int attemptCount) { this.attemptCount = attemptCount; }

    public int getMaxAttempts() { return maxAttempts; }
    public void setMaxAttempts(int maxAttempts) { this.maxAttempts = maxAttempts; }

    public Instant getEnqueuedAt() { return enqueuedAt; }

    public Instant getVisibleAfter() { return visibleAfter; }
    public void setVisibleAfter(Instant visibleAfter) { this.visibleAfter = visibleAfter; }

    public Instant getProcessingStartedAt() { return processingStartedAt; }
    public void setProcessingStartedAt(Instant processingStartedAt) { this.processingStartedAt = processingStartedAt; }

    public Instant getCompletedAt() { return completedAt; }
    public void setCompletedAt(Instant completedAt) { this.completedAt = completedAt; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
}
