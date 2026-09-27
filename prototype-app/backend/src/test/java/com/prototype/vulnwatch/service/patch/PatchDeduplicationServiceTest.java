package com.prototype.vulnwatch.service.patch;

import com.prototype.vulnwatch.domain.Fix;
import com.prototype.vulnwatch.repo.FixRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PatchDeduplicationServiceTest {

    @Mock
    private FixRepository fixRepository;

    private PatchDeduplicationService deduplicationService;

    @BeforeEach
    void setUp() {
        deduplicationService = new PatchDeduplicationService(fixRepository);
    }

    @Test
    void testExactMatchDetection() {
        // Arrange
        String externalId = "KB5027398";
        String sourceSystem = "SCCM";

        Fix candidate = Fix.builder()
            .externalId(externalId)
            .sourceSystem(sourceSystem)
            .title("Windows Security Update")
            .ecosystem("Windows")
            .build();

        Fix existing = Fix.builder()
            .id(UUID.randomUUID())
            .externalId(externalId)
            .sourceSystem(sourceSystem)
            .title("Windows Security Update")
            .build();

        when(fixRepository.findByExternalIdAndSourceSystem(externalId, sourceSystem))
            .thenReturn(Optional.of(existing));

        // Act
        Optional<Fix> duplicate = deduplicationService.findDuplicate(candidate);

        // Assert
        assertTrue(duplicate.isPresent());
        assertEquals(existing.getId(), duplicate.get().getId());
    }

    @Test
    void testNoExactMatch() {
        // Arrange
        Fix candidate = Fix.builder()
            .externalId("KB9999999")
            .sourceSystem("SCCM")
            .title("New Unique Patch")
            .ecosystem("Windows")
            .build();

        when(fixRepository.findByExternalIdAndSourceSystem("KB9999999", "SCCM"))
            .thenReturn(Optional.empty());
        when(fixRepository.findByEcosystem("Windows"))
            .thenReturn(Collections.emptyList());

        // Act
        Optional<Fix> duplicate = deduplicationService.findDuplicate(candidate);

        // Assert
        assertFalse(duplicate.isPresent());
    }

    @Test
    void testFuzzyMatchDetection() {
        // Arrange
        Fix candidate = Fix.builder()
            .externalId("KB1000001")
            .sourceSystem("SCCM")
            .title("Windows 10 Security Update KB123")
            .ecosystem("Windows")
            .build();

        Fix similar = Fix.builder()
            .id(UUID.randomUUID())
            .externalId("KB1000000")
            .sourceSystem("SCCM")
            .title("Windows 10 Security Update KB122")
            .ecosystem("Windows")
            .build();

        when(fixRepository.findByExternalIdAndSourceSystem("KB1000001", "SCCM"))
            .thenReturn(Optional.empty());
        when(fixRepository.findByEcosystem("Windows"))
            .thenReturn(List.of(similar));

        // Act
        Optional<Fix> duplicate = deduplicationService.findDuplicate(candidate);

        // Assert - Should find fuzzy match due to high similarity
        assertTrue(duplicate.isPresent());
        assertEquals(similar.getId(), duplicate.get().getId());
    }

    @Test
    void testNoFuzzyMatchForDifferentTitles() {
        // Arrange
        Fix candidate = Fix.builder()
            .externalId("KB2000001")
            .sourceSystem("SCCM")
            .title("Windows Server 2019 Patch")
            .ecosystem("Windows")
            .build();

        Fix different = Fix.builder()
            .id(UUID.randomUUID())
            .externalId("KB3000000")
            .sourceSystem("SCCM")
            .title("Completely Different Linux Package Update")
            .ecosystem("Linux")  // Different ecosystem
            .build();

        when(fixRepository.findByExternalIdAndSourceSystem("KB2000001", "SCCM"))
            .thenReturn(Optional.empty());
        when(fixRepository.findByEcosystem("Windows"))
            .thenReturn(List.of(different));

        // Act
        Optional<Fix> duplicate = deduplicationService.findDuplicate(candidate);

        // Assert - Should not find match
        assertFalse(duplicate.isPresent());
    }

    @Test
    void testStringSimilarityCalculation() {
        // These test the internal similarity calculation
        // Test identical strings (1.0)
        Fix identical = Fix.builder()
            .title("Identical Title")
            .ecosystem("Windows")
            .build();
        Fix candidate = Fix.builder()
            .externalId("KB1")
            .sourceSystem("SCCM")
            .title("Identical Title")
            .ecosystem("Windows")
            .build();

        when(fixRepository.findByExternalIdAndSourceSystem("KB1", "SCCM"))
            .thenReturn(Optional.empty());
        when(fixRepository.findByEcosystem("Windows"))
            .thenReturn(List.of(identical));

        Optional<Fix> result = deduplicationService.findDuplicate(candidate);
        assertTrue(result.isPresent(), "Should find identical titles");
    }

    @Test
    void testNoMatchWithoutId() {
        // Arrange
        Fix candidate = Fix.builder()
            .externalId(null)  // No external ID
            .sourceSystem("SCCM")
            .title("Patch Title")
            .ecosystem("Windows")
            .build();

        // Act
        Optional<Fix> duplicate = deduplicationService.findDuplicate(candidate);

        // Assert - Should fall through to ecosystem check
        assertFalse(duplicate.isPresent());
    }
}
