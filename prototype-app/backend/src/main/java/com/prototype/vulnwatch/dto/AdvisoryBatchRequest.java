package com.prototype.vulnwatch.dto;

import java.util.List;

public record AdvisoryBatchRequest(List<AdvisoryRequest> advisories) {
}
