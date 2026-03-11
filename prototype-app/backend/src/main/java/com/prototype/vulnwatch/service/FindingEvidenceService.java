package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.dto.FindingEvidencePayload;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class FindingEvidenceService {

    private final ObjectMapper objectMapper;

    public FindingEvidenceService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * BLG-012: Builds a typed {@link FindingEvidencePayload} and serialises it to a JSON string
     * suitable for storage in the JSONB {@code findings.evidence} column.
     *
     * Using the record instead of an ad-hoc Map ensures the evidence schema is enforced at
     * compile time and documented in one place.
     */
    public String buildEvidence(
            InventoryComponent component,
            Vulnerability vulnerability,
            VulnerabilityTarget target,
            PrecedenceResolverService.CandidateDecision selected,
            PrecedenceResolverService.PrecedenceResolution resolution,
            RiskScoringService.RiskScoreOutcome riskScoreOutcome
    ) {
        FindingEvidencePayload payload = new FindingEvidencePayload(
                selected.matchedBy(),
                List.of(selected.matchedBy(), "affectedness-deterministic", "source-precedence"),
                resolution.finalState().name(),
                resolution.reason(),
                resolution.sourcePrecedence(),
                resolution.considered(),
                resolution.precedenceTrace(),
                selected.confidence(),
                selected.confidenceBreakdown(),
                selected.applicabilityDecision() == null ? "UNKNOWN" : selected.applicabilityDecision().result().name(),
                selected.applicabilityDecision() == null ? "missing_decision" : selected.applicabilityDecision().reason(),
                selected.applicabilityDecision() == null ? Map.of() : selected.applicabilityDecision().trace(),
                riskScoreOutcome == null ? null : riskScoreOutcome.score(),
                riskScoreOutcome == null ? Map.of() : riskScoreOutcome.breakdown(),
                riskScoreOutcome == null ? Map.of() : riskScoreOutcome.vexContext(),
                target.getKbVersion(),
                component.getAsset() == null ? null : component.getAsset().getId(),
                component.getId(),
                component.getPurl(),
                component.getComponentDigest(),
                component.getVersion(),
                component.getEcosystem(),
                component.getPackageName(),
                component.getSoftwareIdentity() == null ? null : component.getSoftwareIdentity().getCanonicalKey(),
                vulnerability.getExternalId(),
                vulnerability.getSeverity(),
                vulnerability.getCvssVector(),
                vulnerability.getPublishedAt(),
                vulnerability.getLastModifiedAt(),
                target.getId(),
                target.getSource(),
                target.getQualifiersJson(),
                target.getTargetType() == null ? null : target.getTargetType().name(),
                target.getNormalizedTargetKey(),
                target.getCpe(),
                target.getCpeDim() == null ? null : target.getCpeDim().getId(),
                target.getCpeDim() == null ? null : target.getCpeDim().getNormalizedCpe(),
                target.getCpeWildcardScore(),
                target.getVersionScheme() == null ? null : target.getVersionScheme().name(),
                target.getConstraintType() == null ? null : target.getConstraintType().name(),
                target.getVersionExact(),
                target.getVersionStart(),
                target.getStartInclusive(),
                target.getVersionEnd(),
                target.getEndInclusive(),
                target.getIntroduced(),
                target.getFixed(),
                target.getQualifierPart(),
                target.getQualifierVendor(),
                target.getQualifierProduct(),
                target.getQualifierVersion(),
                target.getQualifierUpdate(),
                target.getQualifierEdition(),
                target.getQualifierLanguage(),
                target.getQualifierSwEdition(),
                target.getQualifierTargetSw(),
                target.getQualifierTargetHw(),
                target.getQualifierOther(),
                Instant.now()
        );

        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            return "{\"matchedBy\":\"" + selected.matchedBy() + "\"}";
        }
    }
}
