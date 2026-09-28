package com.prototype.vulnwatch.service;

/**
 * Thrown when a source's daily projection admission budget is exhausted. Distinct from a
 * genuine processing failure: the worker must requeue the job via {@code visible_at} rather
 * than marking it failed, and must not run recordFailed's audit trail as though the work
 * itself went wrong.
 */
public class AiBomProjectionThrottledException extends RuntimeException {
    public AiBomProjectionThrottledException(String message) {
        super(message);
    }
}
