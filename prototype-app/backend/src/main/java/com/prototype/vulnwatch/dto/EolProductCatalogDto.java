package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

public record EolProductCatalogDto(
        String slug,
        String displayName,
        String cpeVendor,
        String cpeProduct,
        String purlType,
        String purlNamespace,
        List<String> aliases,
        String lastModified,
        Instant lastFetchedAt
) {
}
