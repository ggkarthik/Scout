package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityIntelObservation;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ObservationIngestionService {

    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository;
    private final VulnerabilityIntelSummaryService vulnerabilityIntelSummaryService;
    private final VulnerabilitySourceNormalizationService sourceNormalizationService;

    public ObservationIngestionService(
            VulnerabilityRepository vulnerabilityRepository,
            VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository,
            VulnerabilityIntelSummaryService vulnerabilityIntelSummaryService,
            VulnerabilitySourceNormalizationService sourceNormalizationService
    ) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.vulnerabilityIntelObservationRepository = vulnerabilityIntelObservationRepository;
        this.vulnerabilityIntelSummaryService = vulnerabilityIntelSummaryService;
        this.sourceNormalizationService = sourceNormalizationService;
    }

    @Transactional
    public VulnerabilityIntelligenceService.ObservationUpsertResult upsertObservation(
            VulnerabilityIntelligenceService.ObservationUpsertRequest request
    ) {
        String externalId = sourceNormalizationService.normalizeExternalId(request.externalId());
        String sourceSystem = sourceNormalizationService.normalizeSourceSystem(request.sourceSystem());
        String sourceRecordId = hasText(request.sourceRecordId()) ? request.sourceRecordId().trim() : externalId;

        Optional<Vulnerability> existingVulnerability = vulnerabilityRepository.findByExternalId(externalId);
        Vulnerability vulnerability = existingVulnerability.orElseGet(Vulnerability::new);
        boolean vulnerabilityCreated = existingVulnerability.isEmpty();
        if (vulnerabilityCreated) {
            vulnerability.setExternalId(externalId);
            vulnerability.setSource(sourceNormalizationService.mapSourceSystem(sourceSystem));
            vulnerability.setTitle(externalId);
            vulnerability.setSeverity("UNKNOWN");
            vulnerability = vulnerabilityRepository.save(vulnerability);
        }

        Optional<VulnerabilityIntelObservation> existingObservation = vulnerabilityIntelObservationRepository
                .findByVulnerabilityAndSourceSystemAndSourceRecordId(vulnerability, sourceSystem, sourceRecordId);
        if (existingObservation.isEmpty()) {
            existingObservation = vulnerabilityIntelObservationRepository.findByVulnerabilityOrderByLastSeenAtDesc(vulnerability)
                    .stream()
                    .filter(candidate -> Objects.equals(sourceRecordId, candidate.getSourceRecordId()))
                    .filter(candidate -> sourceNormalizationService.sourceSystemsEquivalentForRecordReuse(
                            sourceSystem,
                            sourceNormalizationService.normalizeSourceSystem(candidate.getSourceSystem())
                    ))
                    .findFirst();
        }
        VulnerabilityIntelObservation observation = existingObservation.orElseGet(VulnerabilityIntelObservation::new);
        boolean observationCreated = existingObservation.isEmpty();

        Instant now = Instant.now();
        if (observationCreated) {
            observation.setVulnerability(vulnerability);
            observation.setSourceRecordId(sourceRecordId);
            observation.setObservedAt(now);
        }
        observation.setSourceSystem(sourceSystem);

        String payloadHash = sha256Hex(request.rawPayload());
        boolean payloadChanged = !Objects.equals(observation.getPayloadHash(), payloadHash);
        observation.setSourceUrl(trimToNull(request.sourceUrl()));
        observation.setTitle(trimToNull(request.title()));
        observation.setDescription(trimToNull(request.description()));
        observation.setSeverity(sourceNormalizationService.normalizeUpperNullable(request.severity()));
        observation.setCvssScore(request.cvssScore());
        observation.setCvssVector(trimToNull(request.cvssVector()));
        observation.setEpssScore(request.epssScore());
        observation.setInKev(request.inKev());
        observation.setVulnStatus(trimToNull(request.vulnStatus()));
        observation.setCweIds(trimToNull(request.cweIds()));
        observation.setReferencesJson(trimToNull(request.referencesJson()));
        observation.setSourceIdentifier(trimToNull(request.sourceIdentifier()));
        observation.setPublishedAt(request.publishedAt());
        observation.setLastModifiedAt(request.lastModifiedAt());
        if (payloadChanged) {
            observation.setRawPayload(trimToNull(request.rawPayload()));
            observation.setPayloadHash(payloadHash);
        }
        observation.setLastSeenAt(now);
        observation.touch();
        vulnerabilityIntelObservationRepository.save(observation);

        vulnerabilityIntelSummaryService.mergeCanonicalAndRefresh(vulnerability);
        return new VulnerabilityIntelligenceService.ObservationUpsertResult(vulnerability, vulnerabilityCreated, observationCreated);
    }

    private boolean hasText(String value) {
        return sourceNormalizationService.hasText(value);
    }

    private String trimToNull(String value) {
        return hasText(value) ? value.trim() : null;
    }

    private String sha256Hex(String value) {
        if (!hasText(value)) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception ignored) {
            return null;
        }
    }
}
