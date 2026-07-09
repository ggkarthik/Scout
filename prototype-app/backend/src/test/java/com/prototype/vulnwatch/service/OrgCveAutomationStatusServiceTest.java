package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingDeltaQueueEntryRepository;
import com.prototype.vulnwatch.repo.IngestionJobRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class OrgCveAutomationStatusServiceTest {

    @Mock
    private FindingDeltaQueueEntryRepository findingDeltaQueueEntryRepository;

    @Mock
    private IngestionJobRepository ingestionJobRepository;

    @Mock
    private OrgCveRecordRepository orgCveRecordRepository;

    @Mock
    private SyncRunRepository syncRunRepository;

    private OrgCveAutomationStatusService service;

    @BeforeEach
    void setUp() {
        service = new OrgCveAutomationStatusService(
                findingDeltaQueueEntryRepository,
                ingestionJobRepository,
                orgCveRecordRepository,
                syncRunRepository
        );
        ReflectionTestUtils.setField(service, "queueStaleThresholdMinutes", 10L);
    }

    @Test
    void getStatusIncludesProcessingAndIngestionSignals() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        FindingDeltaQueueEntryRepository.EventTypeCountRow pendingRow = new FindingDeltaQueueEntryRepository.EventTypeCountRow() {
            @Override
            public String getEventType() {
                return FindingDeltaQueueService.CVE_DELTA;
            }

            @Override
            public long getEntryCount() {
                return 3L;
            }
        };

        Instant now = Instant.now();
        when(findingDeltaQueueEntryRepository.countPendingByEventType()).thenReturn(List.of(pendingRow));
        when(findingDeltaQueueEntryRepository.countStaleVisible(any())).thenReturn(1L);
        FindingDeltaQueueEntryRepository.StatusSummaryRow queueSummary =
                new FindingDeltaQueueEntryRepository.StatusSummaryRow() {
                    @Override
                    public long getPendingCount() {
                        return 4L;
                    }

                    @Override
                    public long getProcessingCount() {
                        return 2L;
                    }

                    @Override
                    public long getFailedCount() {
                        return 0L;
                    }

                    @Override
                    public Instant getOldestVisiblePendingAt() {
                        return now.minusSeconds(75);
                    }

                    @Override
                    public Instant getOldestProcessingStartedAt() {
                        return now.minusSeconds(120);
                    }

                    @Override
                    public Instant getLatestCompletedAt() {
                        return now.minusSeconds(30);
                    }
                };
        IngestionJobRepository.StatusSummaryRow ingestionSummary =
                new IngestionJobRepository.StatusSummaryRow() {
                    @Override
                    public long getQueuedCount() {
                        return 6L;
                    }

                    @Override
                    public long getRunningCount() {
                        return 2L;
                    }

                    @Override
                    public Instant getOldestVisibleQueuedAt() {
                        return now.minusSeconds(45);
                    }

                    @Override
                    public Instant getOldestRunningStartedAt() {
                        return now.minusSeconds(180);
                    }
                };
        when(findingDeltaQueueEntryRepository.summarizeStatus(any())).thenReturn(queueSummary);
        when(ingestionJobRepository.summarizeStatus(any())).thenReturn(ingestionSummary);

        var response = service.getStatus(tenant);

        assertEquals(4L, response.pendingEventCount());
        assertEquals(2L, response.processingEventCount());
        assertEquals(3L, response.pendingByType().get(FindingDeltaQueueService.CVE_DELTA));
        assertEquals(1L, response.staleEventCount());
        assertEquals(6L, response.ingestionQueuedJobCount());
        assertEquals(2L, response.ingestionRunningJobCount());
        assertTrue(response.oldestPendingEventAgeSeconds() >= 70L);
        assertTrue(response.oldestProcessingEventAgeSeconds() >= 110L);
        assertTrue(response.oldestQueuedIngestionAgeSeconds() >= 40L);
        assertTrue(response.oldestRunningIngestionAgeSeconds() >= 170L);
    }
}
