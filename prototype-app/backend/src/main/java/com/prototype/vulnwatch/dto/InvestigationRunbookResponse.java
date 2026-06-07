package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record InvestigationRunbookResponse(
        String id,
        String cveExternalId,
        List<RunbookTaskStateDto> taskStates,
        List<RunbookLogEntryDto> logEntries,
        String leadAnalyst,
        Map<String, String> agentConfidence,   // taskId → "HIGH"|"MEDIUM"|"LOW"
        Map<String, Object> agentSuggestions,  // componentId → AgentComponentSuggestion
        Instant createdAt,
        Instant updatedAt
) {}
