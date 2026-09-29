package com.prototype.vulnwatch.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.List;
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
public class GithubAdvisoryResponse {

    private UUID id;

    private String ghsaId;

    private String cveId;

    private String title;

    private String description;

    private String severity;

    private Double cvssScore;

    private String cvssVector;

    private String ecosystem;

    private String packageName;

    private String affectedVersionsStart;

    private String affectedVersionsEnd;

    private String affectedVersionsPattern;

    private String fixedVersions;

    private String githubAdvisoryUrl;

    private Instant publishedAt;

    private Instant updatedAt;

    private Instant withdrawnAt;

    private Instant firstSyncedAt;

    private Instant lastSyncedAt;

    private Boolean isApplicable;

    private List<GithubAdvisoryAffectedComponentResponse> affectedComponents;

    private Integer matchedComponentCount;

    private Instant createdAt;
}
