package com.prototype.vulnwatch.aisecurity.aws;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.macie2.Macie2Client;
import software.amazon.awssdk.services.macie2.model.AccessDeniedException;
import software.amazon.awssdk.services.macie2.model.CriterionAdditionalProperties;
import software.amazon.awssdk.services.macie2.model.Finding;
import software.amazon.awssdk.services.macie2.model.FindingCriteria;
import software.amazon.awssdk.services.macie2.model.GetFindingsRequest;
import software.amazon.awssdk.services.macie2.model.GetMacieSessionRequest;
import software.amazon.awssdk.services.macie2.model.ListFindingsRequest;
import software.amazon.awssdk.services.macie2.model.MacieStatus;

/**
 * Reads the customer's existing AWS Macie classification results for a bucket. Never triggers a
 * new Macie classification job and never reads bucket object content itself — only Macie's own
 * finding metadata. Takes an already-built client so it can be unit tested against a mock.
 */
@Service
public class AwsMaciePiiLookupService {

    private static final String BUCKET_NAME_FIELD = "resourcesAffected.s3Bucket.name";
    private static final int MAX_FINDINGS = 50;

    public PiiLookupResult lookup(Macie2Client macie, String bucketName) {
        try {
            var session = macie.getMacieSession(GetMacieSessionRequest.builder().build());
            if (session.status() != MacieStatus.ENABLED) {
                return notScanned();
            }
            var listed = macie.listFindings(ListFindingsRequest.builder()
                    .maxResults(MAX_FINDINGS)
                    .findingCriteria(FindingCriteria.builder()
                            .criterion(Map.of(BUCKET_NAME_FIELD,
                                    CriterionAdditionalProperties.builder().eq(bucketName).build()))
                            .build())
                    .build());
            if (!listed.hasFindingIds() || listed.findingIds().isEmpty()) {
                return scannedClean();
            }
            List<Finding> findings = macie.getFindings(GetFindingsRequest.builder()
                    .findingIds(listed.findingIds()).build()).findings();
            return scannedPiiFound(findings);
        } catch (AccessDeniedException ex) {
            // Macie's own APIs return AccessDeniedException both when the caller lacks
            // permission and (far more commonly) when Macie simply isn't enabled for this
            // account/bucket. Treat either case as "not scanned" rather than a hard failure.
            return notScanned();
        } catch (Exception ex) {
            return lookupFailed();
        }
    }

    private PiiLookupResult scannedPiiFound(List<Finding> findings) {
        Set<String> infoTypes = new LinkedHashSet<>();
        Instant lastScannedAt = null;
        for (Finding finding : findings) {
            var result = finding.classificationDetails() == null ? null : finding.classificationDetails().result();
            if (result != null && result.hasSensitiveData()) {
                for (var item : result.sensitiveData()) {
                    if (item.hasDetections()) {
                        item.detections().forEach(detection -> infoTypes.add(detection.type()));
                    } else {
                        infoTypes.add(item.categoryAsString());
                    }
                }
            }
            if (finding.updatedAt() != null && (lastScannedAt == null || finding.updatedAt().isAfter(lastScannedAt))) {
                lastScannedAt = finding.updatedAt();
            }
        }
        return new PiiLookupResult("SCANNED_PII_FOUND", "AWS_MACIE", List.copyOf(infoTypes), findings.size(),
                lastScannedAt == null ? Instant.now() : lastScannedAt);
    }

    private PiiLookupResult scannedClean() {
        return new PiiLookupResult("SCANNED_CLEAN", "AWS_MACIE", List.of(), 0, Instant.now());
    }

    private PiiLookupResult notScanned() {
        return new PiiLookupResult("NOT_SCANNED", "AWS_MACIE", List.of(), 0, null);
    }

    private PiiLookupResult lookupFailed() {
        return new PiiLookupResult("LOOKUP_FAILED", "AWS_MACIE", List.of(), 0, null);
    }

    public record PiiLookupResult(
            String status,
            String source,
            List<String> infoTypes,
            int findingCount,
            Instant lastScannedAt
    ) {
    }
}
