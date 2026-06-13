package com.prototype.vulnwatch.dto;

import java.util.List;

public record BomSupportMatrixResponse(
        List<BomSupportEntryResponse> entries
) {}
