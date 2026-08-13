package com.prototype.vulnwatch.aisecurity.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.macie2.Macie2Client;
import software.amazon.awssdk.services.macie2.model.AccessDeniedException;
import software.amazon.awssdk.services.macie2.model.ClassificationDetails;
import software.amazon.awssdk.services.macie2.model.ClassificationResult;
import software.amazon.awssdk.services.macie2.model.DefaultDetection;
import software.amazon.awssdk.services.macie2.model.Finding;
import software.amazon.awssdk.services.macie2.model.GetFindingsRequest;
import software.amazon.awssdk.services.macie2.model.GetFindingsResponse;
import software.amazon.awssdk.services.macie2.model.GetMacieSessionRequest;
import software.amazon.awssdk.services.macie2.model.GetMacieSessionResponse;
import software.amazon.awssdk.services.macie2.model.InternalServerException;
import software.amazon.awssdk.services.macie2.model.ListFindingsRequest;
import software.amazon.awssdk.services.macie2.model.ListFindingsResponse;
import software.amazon.awssdk.services.macie2.model.MacieStatus;
import software.amazon.awssdk.services.macie2.model.SensitiveDataItem;

class AwsMaciePiiLookupServiceTest {

    private final AwsMaciePiiLookupService service = new AwsMaciePiiLookupService();

    @Test
    void reportsNotScannedWhenMacieSessionIsNotEnabled() {
        Macie2Client macie = mock(Macie2Client.class);
        when(macie.getMacieSession(any(GetMacieSessionRequest.class)))
                .thenReturn(GetMacieSessionResponse.builder().status(MacieStatus.PAUSED).build());

        var result = service.lookup(macie, "my-bucket");
        assertEquals("NOT_SCANNED", result.status());
        assertEquals(0, result.findingCount());
    }

    @Test
    void reportsNotScannedWhenMacieIsNotEnabledForTheAccount() {
        Macie2Client macie = mock(Macie2Client.class);
        when(macie.getMacieSession(any(GetMacieSessionRequest.class)))
                .thenThrow(AccessDeniedException.builder().message("Macie is not enabled").build());

        var result = service.lookup(macie, "my-bucket");
        assertEquals("NOT_SCANNED", result.status());
    }

    @Test
    void reportsLookupFailedOnUnexpectedErrors() {
        Macie2Client macie = mock(Macie2Client.class);
        when(macie.getMacieSession(any(GetMacieSessionRequest.class)))
                .thenThrow(InternalServerException.builder().message("boom").build());

        var result = service.lookup(macie, "my-bucket");
        assertEquals("LOOKUP_FAILED", result.status());
    }

    @Test
    void reportsCleanWhenEnabledWithNoFindings() {
        Macie2Client macie = mock(Macie2Client.class);
        when(macie.getMacieSession(any(GetMacieSessionRequest.class)))
                .thenReturn(GetMacieSessionResponse.builder().status(MacieStatus.ENABLED).build());
        when(macie.listFindings(any(ListFindingsRequest.class)))
                .thenReturn(ListFindingsResponse.builder().findingIds(List.of()).build());

        var result = service.lookup(macie, "my-bucket");
        assertEquals("SCANNED_CLEAN", result.status());
        assertEquals(0, result.findingCount());
    }

    @Test
    void reportsPiiFoundWithDistinctInfoTypesAcrossFindings() {
        Macie2Client macie = mock(Macie2Client.class);
        when(macie.getMacieSession(any(GetMacieSessionRequest.class)))
                .thenReturn(GetMacieSessionResponse.builder().status(MacieStatus.ENABLED).build());
        when(macie.listFindings(any(ListFindingsRequest.class)))
                .thenReturn(ListFindingsResponse.builder().findingIds("finding-1", "finding-2").build());

        Finding finding1 = Finding.builder()
                .updatedAt(Instant.parse("2026-08-01T00:00:00Z"))
                .classificationDetails(ClassificationDetails.builder()
                        .result(ClassificationResult.builder()
                                .sensitiveData(SensitiveDataItem.builder()
                                        .detections(DefaultDetection.builder().type("EMAIL_ADDRESS").count(1L).build())
                                        .build())
                                .build())
                        .build())
                .build();
        Finding finding2 = Finding.builder()
                .updatedAt(Instant.parse("2026-08-02T00:00:00Z"))
                .classificationDetails(ClassificationDetails.builder()
                        .result(ClassificationResult.builder()
                                .sensitiveData(SensitiveDataItem.builder()
                                        .detections(DefaultDetection.builder().type("NAME").count(1L).build())
                                        .build())
                                .build())
                        .build())
                .build();
        when(macie.getFindings(any(GetFindingsRequest.class)))
                .thenReturn(GetFindingsResponse.builder().findings(finding1, finding2).build());

        var result = service.lookup(macie, "my-bucket");
        assertEquals("SCANNED_PII_FOUND", result.status());
        assertEquals("AWS_MACIE", result.source());
        assertEquals(2, result.findingCount());
        assertTrue(result.infoTypes().containsAll(List.of("EMAIL_ADDRESS", "NAME")));
        assertEquals(Instant.parse("2026-08-02T00:00:00Z"), result.lastScannedAt());
    }
}
