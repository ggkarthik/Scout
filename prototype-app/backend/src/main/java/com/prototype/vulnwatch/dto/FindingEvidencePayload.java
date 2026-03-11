package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * BLG-012: Typed contract for the JSON evidence stored in findings.evidence (JSONB).
 *
 * Replacing the ad-hoc Map<String,Object> approach with this record means:
 *  - The evidence schema is defined in one place and enforced at compile time.
 *  - Consumers (UI, auditors, API) can rely on stable field names.
 *  - Jackson serialises the record to the same JSON shape as the old Map.
 *
 * All fields are nullable so partial evidence (e.g. during early correlation stages)
 * is still representable.
 */
public record FindingEvidencePayload(

        // --- match chain ---
        String matchedBy,
        List<String> matchChain,

        // --- decision ---
        String decisionState,
        String decisionReason,
        List<Map<String, Object>> sourcePrecedence,
        List<Map<String, Object>> consideredCandidates,
        Map<String, Object> precedenceTrace,

        // --- confidence ---
        Double confidence,
        Map<String, Double> confidenceBreakdown,

        // --- applicability ---
        String applicabilityResult,
        String applicabilityReason,
        Map<String, Object> applicabilityTrace,

        // --- risk ---
        Double riskScore,
        Map<String, Double> riskBreakdown,
        Map<String, Object> riskVexContext,

        // --- knowledge base ---
        String kbSnapshotVersion,

        // --- component ---
        UUID assetId,
        UUID componentId,
        String componentPurl,
        String componentDigest,
        String componentVersion,
        String componentEcosystem,
        String componentPackage,
        String softwareIdentityKey,

        // --- vulnerability ---
        String vulnerabilityId,
        String vulnerabilitySeverity,
        String vulnerabilityCvssVector,
        Instant vulnerabilityPublishedAt,
        Instant vulnerabilityLastModifiedAt,

        // --- target ---
        UUID targetId,
        String targetSource,
        String targetQualifiersJson,
        String targetType,
        String targetKey,
        String targetCpe,
        UUID targetCpeId,
        String targetNormalizedCpe,
        Integer targetCpeWildcardScore,
        String targetVersionScheme,
        String targetConstraintType,
        String targetVersionExact,
        String targetVersionStart,
        Boolean targetVersionStartInclusive,
        String targetVersionEnd,
        Boolean targetVersionEndInclusive,
        String targetIntroduced,
        String targetFixed,
        String targetQualifierPart,
        String targetQualifierVendor,
        String targetQualifierProduct,
        String targetQualifierVersion,
        String targetQualifierUpdate,
        String targetQualifierEdition,
        String targetQualifierLanguage,
        String targetQualifierSwEdition,
        String targetQualifierTargetSw,
        String targetQualifierTargetHw,
        String targetQualifierOther,

        // --- metadata ---
        Instant generatedAt
) {
}
