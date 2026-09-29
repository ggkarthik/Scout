package com.prototype.vulnwatch.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GithubAdvisorySyncStatusResponse {

    private UUID id;

    private String syncType;

    private String status;

    private Instant lastFullSyncAt;

    private Instant lastIncrementalSyncAt;

    private Instant nextScheduledSyncAt;

    private Boolean syncComplete;

    private Integer advisoriesSynced;

    private Integer advisoriesNewlyFound;

    private Integer advisoriesUpdated;

    private Integer syncDurationMs;

    private String lastError;

    private Integer consecutiveErrors;

    private Instant createdAt;

    private Instant updatedAt;

    private Long elapsedMinutesSinceLastSync;

    private String nextSyncIn;
}
