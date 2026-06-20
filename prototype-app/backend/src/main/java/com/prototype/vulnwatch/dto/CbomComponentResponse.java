package com.prototype.vulnwatch.dto;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.UUID;

public record CbomComponentResponse(
        UUID id,
        UUID assetId,
        UUID sourceBomId,
        String bomRef,
        String name,
        String description,
        String assetType,
        String componentType,
        String primitive,
        Integer keySize,
        String curve,
        String padding,
        String protocolVersion,
        String state,
        String format,
        String storageLocation,
        String transmission,
        String sensitivity,
        String usedIn,
        LocalDate notAfter,
        BigDecimal riskScore,
        int openFindingCount,
        int highFindingCount,
        int criticalFindingCount
) {}
