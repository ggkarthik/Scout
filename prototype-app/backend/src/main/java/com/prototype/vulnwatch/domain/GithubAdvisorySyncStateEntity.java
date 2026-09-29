package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "github_advisory_sync_state", schema = "public")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class GithubAdvisorySyncStateEntity {

    @Id
    private UUID id;

    @Column(length = 50, nullable = false)
    private String syncType = "GITHUB_GHSA";

    @Column(length = 20, nullable = false)
    private String status = "IDLE";

    private Instant lastFullSyncAt;

    private Instant lastIncrementalSyncAt;

    private Instant nextScheduledSyncAt;

    @Column(columnDefinition = "TEXT")
    private String lastCursor;

    @Column(nullable = false)
    private Boolean syncComplete = false;

    private Integer advisoriesSynced = 0;

    private Integer advisoriesNewlyFound = 0;

    private Integer advisoriesUpdated = 0;

    private Integer syncDurationMs;

    @Column(columnDefinition = "TEXT")
    private String lastError;

    private Integer consecutiveErrors = 0;

    @Column(nullable = false)
    private Instant createdAt;

    private Instant updatedAt;
}
