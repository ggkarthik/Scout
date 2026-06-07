package com.prototype.vulnwatch.dto;

import java.util.List;

public record FalsePositiveAnalysisResponse(List<FalsePositiveResultDto> results) {}
