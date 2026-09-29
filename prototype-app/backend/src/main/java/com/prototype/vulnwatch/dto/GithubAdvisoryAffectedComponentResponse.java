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
public class GithubAdvisoryAffectedComponentResponse {

    private UUID id;

    private String componentId;

    private String installedVersion;

    private Boolean isInstalledVersionVulnerable;

    private String vulnerableRangeReason;

    private String recommendedFixedVersion;

    private Boolean upgradeAvailable;

    private UUID findingId;

    private String findingKind;

    private Instant discoveredAt;

    private Instant firstAlertSentAt;

    private Instant lastAlertSentAt;

    private Instant createdAt;

    private Instant updatedAt;
}
