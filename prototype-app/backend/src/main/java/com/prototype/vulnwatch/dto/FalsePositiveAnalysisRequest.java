package com.prototype.vulnwatch.dto;

import java.util.List;

public record FalsePositiveAnalysisRequest(List<AssetCriterionDto> criteria) {}
