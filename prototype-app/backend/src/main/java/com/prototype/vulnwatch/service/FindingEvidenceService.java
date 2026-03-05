package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class FindingEvidenceService {

    private final ObjectMapper objectMapper;

    public FindingEvidenceService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String buildEvidence(
            InventoryComponent component,
            Vulnerability vulnerability,
            VulnerabilityTarget target,
            PrecedenceResolverService.CandidateDecision selected,
            PrecedenceResolverService.PrecedenceResolution resolution,
            RiskScoringService.RiskScoreOutcome riskScoreOutcome
    ) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("matchedBy", selected.matchedBy());
        payload.put("matchChain", List.of(selected.matchedBy(), "affectedness-deterministic", "source-precedence"));
        payload.put("decisionState", resolution.finalState().name());
        payload.put("decisionReason", resolution.reason());
        payload.put("sourcePrecedence", resolution.sourcePrecedence());
        payload.put("consideredCandidates", resolution.considered());
        payload.put("precedenceTrace", resolution.precedenceTrace());
        payload.put("confidence", selected.confidence());
        payload.put("confidenceBreakdown", selected.confidenceBreakdown());
        payload.put("applicabilityResult", selected.applicabilityDecision() == null ? "UNKNOWN" : selected.applicabilityDecision().result().name());
        payload.put("applicabilityReason", selected.applicabilityDecision() == null ? "missing_decision" : selected.applicabilityDecision().reason());
        payload.put("applicabilityTrace", selected.applicabilityDecision() == null ? Map.of() : selected.applicabilityDecision().trace());
        payload.put("riskScore", riskScoreOutcome == null ? null : riskScoreOutcome.score());
        payload.put("riskBreakdown", riskScoreOutcome == null ? Map.of() : riskScoreOutcome.breakdown());
        payload.put("riskVexContext", riskScoreOutcome == null ? Map.of() : riskScoreOutcome.vexContext());
        payload.put("kbSnapshotVersion", target.getKbVersion());
        payload.put("assetId", component.getAsset() == null ? null : component.getAsset().getId());
        payload.put("componentId", component.getId());
        payload.put("componentPurl", component.getPurl());
        payload.put("componentDigest", component.getComponentDigest());
        payload.put("componentVersion", component.getVersion());
        payload.put("componentEcosystem", component.getEcosystem());
        payload.put("componentPackage", component.getPackageName());
        payload.put("softwareIdentityKey", component.getSoftwareIdentity() == null ? null : component.getSoftwareIdentity().getCanonicalKey());
        payload.put("softwareModelKey", component.getSoftwareModel() == null ? null : component.getSoftwareModel().getNormalizedKey());
        payload.put("vulnerabilityId", vulnerability.getExternalId());
        payload.put("vulnerabilitySeverity", vulnerability.getSeverity());
        payload.put("vulnerabilityCvssVector", vulnerability.getCvssVector());
        payload.put("vulnerabilityPublishedAt", vulnerability.getPublishedAt());
        payload.put("vulnerabilityLastModifiedAt", vulnerability.getLastModifiedAt());
        payload.put("targetId", target.getId());
        payload.put("targetSource", target.getSource());
        payload.put("targetQualifiersJson", target.getQualifiersJson());
        payload.put("targetType", target.getTargetType() == null ? null : target.getTargetType().name());
        payload.put("targetKey", target.getNormalizedTargetKey());
        payload.put("targetCpe", target.getCpe());
        payload.put("targetCpeId", target.getCpeDim() == null ? null : target.getCpeDim().getId());
        payload.put("targetNormalizedCpe", target.getCpeDim() == null ? null : target.getCpeDim().getNormalizedCpe());
        payload.put("targetCpeWildcardScore", target.getCpeWildcardScore());
        payload.put("targetVersionScheme", target.getVersionScheme() == null ? null : target.getVersionScheme().name());
        payload.put("targetConstraintType", target.getConstraintType() == null ? null : target.getConstraintType().name());
        payload.put("targetVersionExact", target.getVersionExact());
        payload.put("targetVersionStart", target.getVersionStart());
        payload.put("targetVersionStartInclusive", target.getStartInclusive());
        payload.put("targetVersionEnd", target.getVersionEnd());
        payload.put("targetVersionEndInclusive", target.getEndInclusive());
        payload.put("targetIntroduced", target.getIntroduced());
        payload.put("targetFixed", target.getFixed());
        payload.put("targetQualifierPart", target.getQualifierPart());
        payload.put("targetQualifierVendor", target.getQualifierVendor());
        payload.put("targetQualifierProduct", target.getQualifierProduct());
        payload.put("targetQualifierVersion", target.getQualifierVersion());
        payload.put("targetQualifierUpdate", target.getQualifierUpdate());
        payload.put("targetQualifierEdition", target.getQualifierEdition());
        payload.put("targetQualifierLanguage", target.getQualifierLanguage());
        payload.put("targetQualifierSwEdition", target.getQualifierSwEdition());
        payload.put("targetQualifierTargetSw", target.getQualifierTargetSw());
        payload.put("targetQualifierTargetHw", target.getQualifierTargetHw());
        payload.put("targetQualifierOther", target.getQualifierOther());
        payload.put("generatedAt", Instant.now());

        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            return "{\"matchedBy\":\"" + selected.matchedBy() + "\"}";
        }
    }
}
