package com.prototype.vulnwatch.service;

import java.util.Map;

public record NotApplicableProjection(
        long neverOpenedNotApplicable,
        long deferredUnderInvestigation,
        Map<String, Long> categories
) {
}
