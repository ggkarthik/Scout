package com.prototype.vulnwatch.dto;

import java.time.LocalDate;

public record EolReleaseDto(
        String cycle,
        LocalDate releaseDate,
        LocalDate eolDate,
        Boolean eolBoolean,
        LocalDate supportEndDate,
        LocalDate extendedSupportDate,
        LocalDate securitySupportDate,
        String latestVersion,
        LocalDate latestReleaseDate,
        boolean lts,
        boolean isEol,
        Boolean isEoas,
        Boolean isEoes,
        boolean discontinued,
        String officialSourceUrl,
        String supportPhase
) {
}
