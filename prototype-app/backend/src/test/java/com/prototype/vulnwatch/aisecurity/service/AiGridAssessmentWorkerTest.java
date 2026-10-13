package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.*;
import java.sql.SQLException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.DataIntegrityViolationException;

class AiGridAssessmentWorkerTest {
    @Test void retriesOnlyConnectionSerializationAndDeadlockFailures() {
        for (String state : new String[]{"08001","08006","40001","40P01"}) {
            assertTrue(AiGridAssessmentWorker.retryable(new DataAccessResourceFailureException(
                    "SQL detail must stay private",new SQLException("sensitive detail",state))));
        }
        for (String state : new String[]{"23505","23502","42601","22003"}) {
            assertFalse(AiGridAssessmentWorker.retryable(new DataIntegrityViolationException(
                    "private constraint detail",new SQLException("sensitive detail",state))));
        }
        assertFalse(AiGridAssessmentWorker.retryable(new IllegalArgumentException("Invalid predicate")));
    }
    @Test void failureSummariesDoNotExposeSqlOrTenantDataAndHealthyResultsArePartial() {
        var failure=AiGridAssessmentService.PolicyFailure.from("broken-policy",new DataIntegrityViolationException("password=secret; tenant=private"));
        assertFalse(failure.summary().contains("secret"));
        assertFalse(failure.summary().contains("private"));
        assertEquals("PARTIAL",new AiGridAssessmentService.AssessmentSummary(1,3,java.util.List.of(failure)).assessmentStatus());
        assertEquals("FAILED",new AiGridAssessmentService.AssessmentSummary(0,0,java.util.List.of(failure)).assessmentStatus());
        assertEquals("COMPLETE",new AiGridAssessmentService.AssessmentSummary(0,0,java.util.List.of()).assessmentStatus());
    }
}
