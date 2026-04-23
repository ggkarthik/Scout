package com.prototype.vulnwatch.controller;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.dto.SyncRunResponse;
import com.prototype.vulnwatch.dto.VulnIntelSourceSummary;
import com.prototype.vulnwatch.dto.VulnIntelSourceSummary.SourceStatus;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.service.SyncRunHistoryService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sync-runs")
public class SyncController {

    private static final List<String> VULN_INTEL_TYPES = List.of(
            "NVD", "KEV", "GHSA", "CSAF_MICROSOFT", "CSAF_REDHAT", "ADVISORY"
    );

    private final SyncRunHistoryService syncRunHistoryService;
    private final SyncRunRepository syncRunRepository;

    public SyncController(SyncRunHistoryService syncRunHistoryService, SyncRunRepository syncRunRepository) {
        this.syncRunHistoryService = syncRunHistoryService;
        this.syncRunRepository = syncRunRepository;
    }

    @GetMapping
    public List<SyncRunResponse> list(
            @RequestParam(defaultValue = "all") String category,
            @RequestParam(defaultValue = "10") int limit
    ) {
        return syncRunHistoryService.list(category, limit);
    }

    @GetMapping("/sources-summary")
    public VulnIntelSourceSummary sourcesSummary() {
        Map<String, SourceStatus> sources = new LinkedHashMap<>();
        for (String type : VULN_INTEL_TYPES) {
            syncRunRepository.findTopBySyncTypeIgnoreCaseOrderByStartedAtDesc(type)
                    .ifPresentOrElse(
                            run -> sources.put(type, toSourceStatus(run)),
                            () -> sources.put(type, new SourceStatus("never", null, 0, 0, 0, null))
                    );
        }
        return new VulnIntelSourceSummary(sources);
    }

    private static SourceStatus toSourceStatus(SyncRun run) {
        return new SourceStatus(
                run.getStatus(),
                run.getCompletedAt(),
                run.getRecordsInserted(),
                run.getRecordsUpdated(),
                run.getRecordsFetched(),
                run.getErrorMessage()
        );
    }
}
