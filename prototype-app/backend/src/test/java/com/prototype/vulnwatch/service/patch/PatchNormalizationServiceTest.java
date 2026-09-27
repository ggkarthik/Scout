package com.prototype.vulnwatch.service.patch;

import com.prototype.vulnwatch.domain.Fix;
import com.prototype.vulnwatch.dto.patch.VendorPatchData;
import com.prototype.vulnwatch.repo.CveFixMapRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PatchNormalizationServiceTest {

    @Mock
    private CveFixMapRepository cveFixMapRepository;

    private PatchNormalizationService normalizationService;

    @BeforeEach
    void setUp() {
        normalizationService = new PatchNormalizationService(cveFixMapRepository);
    }

    @Test
    void testNormalizeWindowsKbPatch() {
        // Arrange
        VendorPatchData patch = new VendorPatchData(
            "KB5027398",
            "Windows 10 Critical Security Update",
            "Security patch for Windows 10",
            "10.0.19045.3693",
            "Windows",
            "Windows",
            "CRITICAL",
            Instant.now(),
            "Download from Microsoft Update",
            null,
            Map.of("kb_id", "KB5027398")
        );

        // Act
        PatchNormalizationService.FixNormalizationResult result =
            normalizationService.normalize(patch, "SCCM", UUID.randomUUID());

        // Assert
        Fix fix = result.fix();
        assertNotNull(fix);
        assertEquals("KB5027398", fix.getExternalId());
        assertEquals("SCCM", fix.getSourceSystem());
        assertEquals("Windows 10 Critical Security Update", fix.getTitle());
        assertEquals(Fix.FixType.PATCH, fix.getFixType());
        assertEquals(Fix.Severity.CRITICAL, fix.getSeverity());
        assertEquals("Windows", fix.getEcosystem());
        assertTrue(fix.isRequiresReboot());
        assertTrue(result.confidenceScore() > 0.5);
    }

    @Test
    void testNormalizeMissingVersion() {
        // Arrange
        VendorPatchData patch = new VendorPatchData(
            "KB5000000",
            "Windows Security Update",
            null,
            null,  // Missing fixed version
            "Windows",
            null,
            "HIGH",
            Instant.now(),
            null,
            null,
            null
        );

        // Act
        PatchNormalizationService.FixNormalizationResult result =
            normalizationService.normalize(patch, "SCCM", UUID.randomUUID());

        // Assert
        assertNotNull(result.normalizationNotes());
        assertTrue(result.normalizationNotes().contains("Fixed version not available"));
    }

    @Test
    void testNormalizeSeverityMapping() {
        // Test CRITICAL
        VendorPatchData criticalPatch = new VendorPatchData(
            "KB1", "Critical Patch", null, null, "Windows", null, "CRITICAL", Instant.now(), null, null, null
        );
        PatchNormalizationService.FixNormalizationResult criticalResult =
            normalizationService.normalize(criticalPatch, "SCCM", UUID.randomUUID());
        assertEquals(Fix.Severity.CRITICAL, criticalResult.fix().getSeverity());

        // Test HIGH
        VendorPatchData highPatch = new VendorPatchData(
            "KB2", "High Priority Patch", null, null, "Windows", null, "IMPORTANT", Instant.now(), null, null, null
        );
        PatchNormalizationService.FixNormalizationResult highResult =
            normalizationService.normalize(highPatch, "SCCM", UUID.randomUUID());
        assertEquals(Fix.Severity.HIGH, highResult.fix().getSeverity());

        // Test LOW (default)
        VendorPatchData lowPatch = new VendorPatchData(
            "KB3", "Low Priority Patch", null, null, "Windows", null, null, Instant.now(), null, null, null
        );
        PatchNormalizationService.FixNormalizationResult lowResult =
            normalizationService.normalize(lowPatch, "SCCM", UUID.randomUUID());
        assertEquals(Fix.Severity.LOW, lowResult.fix().getSeverity());
    }

    @Test
    void testFixTypeDetection() {
        // Test WORKAROUND type
        VendorPatchData workaroundPatch = new VendorPatchData(
            "KB1", "Workaround for Issue", null, null, "Windows", null, "MEDIUM", Instant.now(), null, null, null
        );
        PatchNormalizationService.FixNormalizationResult workaroundResult =
            normalizationService.normalize(workaroundPatch, "SCCM", UUID.randomUUID());
        assertEquals(Fix.FixType.WORKAROUND, workaroundResult.fix().getFixType());

        // Test PATCH type (default)
        VendorPatchData patchData = new VendorPatchData(
            "KB2", "Security Patch", null, null, "Windows", null, "MEDIUM", Instant.now(), null, null, null
        );
        PatchNormalizationService.FixNormalizationResult patchResult =
            normalizationService.normalize(patchData, "SCCM", UUID.randomUUID());
        assertEquals(Fix.FixType.PATCH, patchResult.fix().getFixType());
    }

    @Test
    void testEcosystemInference() {
        // Test Linux inference
        VendorPatchData linuxPatch = new VendorPatchData(
            "UBUNTU-2024-001", "Linux Security Update", null, null, "Linux", null, "HIGH", Instant.now(), null, null, null
        );
        PatchNormalizationService.FixNormalizationResult linuxResult =
            normalizationService.normalize(linuxPatch, "SCCM", UUID.randomUUID());
        assertEquals("Linux", linuxResult.fix().getEcosystem());
    }

    @Test
    void testRebootRequirement() {
        // Windows patches require reboot
        VendorPatchData windowsPatch = new VendorPatchData(
            "KB1", "Windows Update", null, null, "Windows", null, "MEDIUM", Instant.now(), null, null, null
        );
        PatchNormalizationService.FixNormalizationResult windowsResult =
            normalizationService.normalize(windowsPatch, "SCCM", UUID.randomUUID());
        assertTrue(windowsResult.fix().isRequiresReboot());

        // Linux patches may not require reboot
        VendorPatchData linuxPatch = new VendorPatchData(
            "LIN1", "Linux Update", null, null, "Linux", null, "MEDIUM", Instant.now(), null, null, null
        );
        PatchNormalizationService.FixNormalizationResult linuxResult =
            normalizationService.normalize(linuxPatch, "SCCM", UUID.randomUUID());
        assertFalse(linuxResult.fix().isRequiresReboot());
    }
}
