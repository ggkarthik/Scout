package com.prototype.vulnwatch.controller;

import java.util.List;
import com.prototype.vulnwatch.dto.SyncRunResponse;
import com.prototype.vulnwatch.service.SyncRunHistoryService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sync-runs")
public class SyncController {

    private final SyncRunHistoryService syncRunHistoryService;

    public SyncController(SyncRunHistoryService syncRunHistoryService) {
        this.syncRunHistoryService = syncRunHistoryService;
    }

    @GetMapping
    public List<SyncRunResponse> list(
            @RequestParam(defaultValue = "all") String category,
            @RequestParam(defaultValue = "10") int limit
    ) {
        return syncRunHistoryService.list(category, limit);
    }
}
