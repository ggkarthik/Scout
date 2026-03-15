package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class HostSoftwareNormalizationServiceTest {

    private final HostSoftwareNormalizationService service = new HostSoftwareNormalizationService();

    @Test
    void normalizeCanonicalizesVendorProductAndVersion() {
        HostSoftwareNormalizationService.NormalizedHostSoftware normalized = service.normalize(
                "Microsoft Office Professional Plus 64-bit",
                "Microsoft Corporation",
                "16.0.17726.20126 (Build 1234)",
                null,
                null,
                null,
                null
        );

        assertEquals("microsoft", normalized.normalizedPublisher());
        assertEquals("office_plus", normalized.normalizedProduct());
        assertEquals("16.0.17726.20126", normalized.normalizedVersion());
        assertEquals("microsoft:office_plus", normalized.normalizedKey());
        assertEquals("pkg:generic/microsoft/office_plus@16.0.17726.20126", normalized.purl());
        assertTrue(!normalized.needsReview());
    }

    @Test
    void normalizeLeavesMissingVersionUnsetForManualReview() {
        HostSoftwareNormalizationService.NormalizedHostSoftware normalized = service.normalize(
                "VMware Tools",
                "VMware, Inc.",
                "current",
                null,
                null,
                null,
                "{00112233-4455-6677-8899-aabbccddeeff}"
        );

        assertEquals("vmware", normalized.normalizedPublisher());
        assertEquals("tools", normalized.normalizedProduct());
        assertNull(normalized.normalizedVersion());
        assertEquals("{00112233-4455-6677-8899-aabbccddeeff}", normalized.normalizedEvidence());
        assertTrue(normalized.needsReview());
    }

    @Test
    void normalizeFallsBackWhenSourceNormalizedValuesAreUnknownPlaceholders() {
        HostSoftwareNormalizationService.NormalizedHostSoftware normalized = service.normalize(
                "Microsoft Office Professional Plus 64-bit",
                "Microsoft Corporation",
                "16.0.17726.20126 (Build 1234)",
                "unknown",
                "unmatched",
                "n/a",
                null
        );

        assertEquals("microsoft", normalized.normalizedPublisher());
        assertEquals("office_plus", normalized.normalizedProduct());
        assertEquals("16.0.17726.20126", normalized.normalizedVersion());
        assertEquals("microsoft:office_plus", normalized.normalizedKey());
    }

    @Test
    void normalizePreservesMeaningfulSourceNormalizedValues() {
        HostSoftwareNormalizationService.NormalizedHostSoftware normalized = service.normalize(
                "Something Raw",
                "Some Publisher",
                "garbled version string",
                "office",
                "microsoft",
                "16.0",
                null
        );

        assertEquals("microsoft", normalized.normalizedPublisher());
        assertEquals("office", normalized.normalizedProduct());
        assertEquals("16.0", normalized.normalizedVersion());
        assertEquals("microsoft:office", normalized.normalizedKey());
    }
}
