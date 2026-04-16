package com.prototype.vulnwatch.dto;

public record UpgradeRecommendationResponse(
    String recommendedVersion,
    String upgradeNotes,
    String urgency
) {}
