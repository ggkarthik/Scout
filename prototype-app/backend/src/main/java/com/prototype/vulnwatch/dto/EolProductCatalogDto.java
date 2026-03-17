package com.prototype.vulnwatch.dto;

public record EolProductCatalogDto(
        String slug,
        String displayName,
        String cpeVendor,
        String cpeProduct,
        String purlType,
        String purlNamespace
) {
}
