package com.prototype.vulnwatch.dto;

import java.util.List;

public record EolAnalysisRequest(List<AssetCriterionDto> criteria) {}
