package com.prototype.vulnwatch.dto;

import java.util.List;

public record BomInspectionResponse(
        String format,
        String formatVersion,
        String specFamily,
        String documentFormat,
        String supportLevel,
        boolean supported,
        List<String> warnings
) {}
