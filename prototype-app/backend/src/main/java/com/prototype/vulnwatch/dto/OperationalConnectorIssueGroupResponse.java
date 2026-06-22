package com.prototype.vulnwatch.dto;

import java.util.List;

public record OperationalConnectorIssueGroupResponse(
        String connectorKey,
        long affectedTenantCount,
        List<String> affectedTenants
) {
}
