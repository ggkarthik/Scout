package com.prototype.vulnwatch.dto;

import java.util.List;

public record AgentRunRequest(List<AssetCriterionDto> criteria) {}
