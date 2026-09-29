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
public class GithubAdvisoryIntegrationStatusResponse {

    private UUID id;

    private UUID tenantId;

    private String tenantName;

    private Boolean isEnabled;

    private Instant enabledAt;

    private Instant disabledAt;

    private Boolean autoCreateFindings;

    private Boolean autoCorrelateComponents;

    private Boolean createFindingForLowSeverity;

    private String reasonEnabled;

    private UUID enabledByUserId;

    private String enabledByUserName;

    private Instant createdAt;

    private Instant updatedAt;

    private GithubAdvisorySyncStatusResponse syncStatus;

    private Integer totalAdvisoriesTracked;

    private Integer applicableAdvisoriesForTenant;

    private Integer affectedComponentsCount;
}
