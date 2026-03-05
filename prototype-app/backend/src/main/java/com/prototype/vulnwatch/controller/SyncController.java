package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.SyncRunResponse;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sync-runs")
public class SyncController {

    private final SyncRunRepository syncRunRepository;

    public SyncController(SyncRunRepository syncRunRepository) {
        this.syncRunRepository = syncRunRepository;
    }

    @GetMapping
    public List<SyncRunResponse> list() {
        List<SyncRun> queue = syncRunRepository.findQueueByStatuses(List.of("queued", "running")).stream()
                .sorted(Comparator
                        .comparingInt((SyncRun run) -> "running".equalsIgnoreCase(run.getStatus()) ? 0 : 1)
                        .thenComparing(SyncRun::getStartedAt))
                .toList();
        Map<UUID, Integer> queuePositions = new HashMap<>();
        for (int i = 0; i < queue.size(); i++) {
            queuePositions.put(queue.get(i).getId(), i + 1);
        }

        return syncRunRepository.findTop10ByOrderByStartedAtDesc().stream()
                .map(r -> new SyncRunResponse(
                        r.getId(),
                        r.getSyncType(),
                        r.getStatus(),
                        queuePositions.get(r.getId()),
                        r.getRecordsFetched(),
                        r.getRecordsInserted(),
                        r.getRecordsUpdated(),
                        r.getRecordsFailed(),
                        r.getStartedAt(),
                        r.getCompletedAt(),
                        r.getErrorMessage()
                ))
                .toList();
    }
}
