package com.prototype.vulnwatch.dto;

public record AgentTaskMetaDto(
        String producedBy,
        String confidence,
        String reasoning
) {}
