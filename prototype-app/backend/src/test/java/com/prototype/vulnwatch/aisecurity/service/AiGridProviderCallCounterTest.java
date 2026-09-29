package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class AiGridProviderCallCounterTest {

    @Test
    void rejectsAnAttemptBeforeItCanCrossTheInRunCeiling() {
        AiGridProviderCallCounter counter = new AiGridProviderCallCounter();
        try (var measurement = counter.begin(2)) {
            counter.increment();
            counter.increment();
            assertThrows(AiGridProviderCallCounter.ProviderCallBudgetExceededException.class, counter::increment);
            assertEquals(2, measurement.count());
            assertEquals(2, measurement.ceiling());
        }
    }
}
