package com.prototype.vulnwatch.dto;

public record ServiceNowIncidentResponse(
        String incidentNumber,
        String sysId,
        String url,
        String status,
        String message
) {}
