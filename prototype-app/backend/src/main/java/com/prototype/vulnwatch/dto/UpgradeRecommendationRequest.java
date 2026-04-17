package com.prototype.vulnwatch.dto;

import java.util.List;

public record UpgradeRecommendationRequest(
    String softwareName,
    String vendor,
    String currentVersion,
    String eolDate,
    List<String> cveIds
) {}
