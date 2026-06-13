package com.prototype.vulnwatch.dto;

public record BomSupportEntryResponse(
        String specFamily,
        String documentFormat,
        String version,
        String supportLevel,
        boolean supported,
        String notes
) {}
