package com.prototype.vulnwatch.dto;

public record TenantCreateRequest(
        String name,
        String slug,
        String planCode,
        String billingRef,
        boolean addDemoData
) {
}
