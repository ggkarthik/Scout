package com.prototype.vulnwatch.dto;

import java.util.List;
import java.util.Map;

public record AgentRunResponse(
        List<ResolvedInventorySoftwareDto> resolved,
        int totalAssets,
        List<FalsePositiveResultDto> fpResults,
        List<EolAnalysisResultDto> eolResults,
        Map<String, AgentTaskMetaDto> taskMeta,
        List<String> completedTaskIds,
        String ranAt
) {}
