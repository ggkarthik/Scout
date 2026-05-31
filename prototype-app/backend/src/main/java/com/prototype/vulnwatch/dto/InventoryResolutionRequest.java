package com.prototype.vulnwatch.dto;

import java.util.List;

public record InventoryResolutionRequest(List<AssetCriterionDto> criteria) {}
