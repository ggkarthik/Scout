package com.prototype.vulnwatch.dto;

import java.util.List;

public record TenantBulkInviteResponse(
        int requestedCount,
        int invitedCount,
        int failedCount,
        List<TenantBulkInviteItemResponse> results
) {
}
