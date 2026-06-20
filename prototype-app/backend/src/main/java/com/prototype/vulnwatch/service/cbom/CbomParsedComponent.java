package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.CbomAssetType;
import java.time.LocalDate;

public record CbomParsedComponent(
        String bomRef,
        String componentFingerprint,
        String name,
        String description,
        CbomAssetType assetType,
        String componentType,
        String primitive,
        String parameterSetIdentifier,
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
        LocalDate notBefore,
        LocalDate notAfter,
        String issuer,
        String subject,
        String serialNumber,
        String signatureAlgorithm,
        String keyUsage
) {}
