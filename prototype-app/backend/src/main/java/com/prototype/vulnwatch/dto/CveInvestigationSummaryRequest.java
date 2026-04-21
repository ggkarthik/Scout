package com.prototype.vulnwatch.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public record CveInvestigationSummaryRequest(
        @NotNull @Valid Summary summary,
        @Valid Investigation investigation,
        @NotNull @Valid List<RunbookResult> runbookResults,
        @NotNull @Valid List<AffectedAsset> affectedAssets,
        @NotNull @Valid List<FalsePositiveRow> falsePositiveRows,
        @NotNull @Valid List<EolRow> eolRows,
        @Valid List<SolutionRow> solutionRows
) {

    public record Summary(
            @NotBlank String cveId,
            @NotBlank String title,
            String description,
            String severity,
            Double cvssScore,
            Double epssScore,
            Boolean inKev,
            Boolean exploitAvailable,
            Boolean patchAvailable,
            String patchVersions
    ) {}

    public record Investigation(
            String leadAnalyst
    ) {}

    public record RunbookResult(
            @NotBlank String id,
            @NotBlank String title,
            @NotBlank String state
    ) {}

    public record AffectedAsset(
            @NotBlank String id,
            @NotBlank String hostname,
            String ipAddress,
            String os,
            String owner,
            String environment,
            Boolean externalFacing,
            Boolean critical,
            @NotNull @Valid List<MatchedSoftware> matchedSoftware
    ) {}

    public record MatchedSoftware(
            @NotBlank String software,
            String version
    ) {}

    public record FalsePositiveRow(
            @NotBlank String software,
            String version,
            @NotNull Boolean falsePositive,
            Integer assetsNotImpacted,
            String vendorAdvisory,
            String vendorGuidance
    ) {}

    public record EolRow(
            @NotBlank String software,
            String vendor,
            String version,
            String lifecycle,
            String endOfSupport,
            String endOfLife,
            String recommendedUpgrade
    ) {}

    public record SolutionRow(
            @NotBlank String software,
            String version,
            String vendor,
            Integer impactedAssets,
            String solutionType,
            String solutionDetail,
            String targetVersion
    ) {}
}
