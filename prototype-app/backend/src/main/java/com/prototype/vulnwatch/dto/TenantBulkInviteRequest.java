package com.prototype.vulnwatch.dto;

import java.util.List;

public record TenantBulkInviteRequest(
        List<TenantInviteRequest> invites
) {
}
