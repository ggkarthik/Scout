package com.prototype.vulnwatch.dto;

/** One row of the Grid Exposure widget: open finding counts for one asset domain, by severity. */
public record GridExposureRowResponse(
        String assetType,
        long critical,
        long high,
        long medium,
        long low,
        long total
) {
}
