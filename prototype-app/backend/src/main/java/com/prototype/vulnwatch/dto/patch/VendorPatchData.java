package com.prototype.vulnwatch.dto.patch;

import java.time.Instant;
import java.util.Map;

public record VendorPatchData(
    String externalId,
    String title,
    String description,
    String fixedVersion,
    String ecosystem,
    String packageName,
    String severity,
    Instant releaseDate,
    String installationInstructions,
    String supersededByPatchId,
    Map<String, Object> sourceMetadata
) {
}
