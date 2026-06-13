package com.prototype.vulnwatch.dto;

public record EolReleaseSummary(
        String cycle,
        String releaseDate,
        String eolDate,
        String supportEndDate,
        String latestVersion,
        String latestReleaseDate,
        boolean isEol,
        boolean isLts
) {}
