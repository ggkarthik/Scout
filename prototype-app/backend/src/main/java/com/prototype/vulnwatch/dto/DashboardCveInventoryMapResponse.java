package com.prototype.vulnwatch.dto;

import java.util.List;

public record DashboardCveInventoryMapResponse(
        List<CveInventoryMappingRecordResponse> topHighRisk,
        List<CveInventoryMappingRecordResponse> latest
) {
}
