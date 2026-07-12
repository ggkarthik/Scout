package com.prototype.vulnwatch.dto;

import java.util.List;

/** Scout Grid exposure narrative: open findings by asset domain x severity.
 *  Rows are derived from {@link com.prototype.vulnwatch.domain.AssetType} so the grid
 *  extends automatically as new asset domains are added. */
public record GridExposureResponse(
        List<GridExposureRowResponse> rows
) {
}
