package com.prototype.vulnwatch.dto;

import java.util.List;
import java.util.Map;

public record InvestigationRunbookRequest(
        List<RunbookTaskStateDto> taskStates,
        List<RunbookLogEntryDto> logEntries,
        String leadAnalyst,
        Map<String, String> agentConfidence  // taskId → "HIGH"|"MEDIUM"|"LOW"
) {}
