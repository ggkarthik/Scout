package com.prototype.vulnwatch.dto;

import java.util.List;

public record InventoryComponentPageResponse(
        List<InventoryComponentResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {
}
