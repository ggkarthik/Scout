package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.lang.reflect.Field;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

@ExtendWith(MockitoExtension.class)
class FindingUpsertServiceTest {

    @Mock
    private FindingRepository findingRepository;

    private FindingUpsertService service;
    private UUID componentId;
    private UUID vulnerabilityId;

    @BeforeEach
    void setUp() {
        service = new FindingUpsertService(findingRepository);
        componentId = UUID.randomUUID();
        vulnerabilityId = UUID.randomUUID();
    }

    @Test
    void upsertCreatesWhenExposureDoesNotExist() {
        Finding candidate = newFinding(componentId, vulnerabilityId);
        when(findingRepository.findFirstByComponent_IdAndVulnerability_Id(componentId, vulnerabilityId))
                .thenReturn(Optional.empty());
        when(findingRepository.saveAndFlush(candidate)).thenReturn(candidate);

        FindingUpsertService.UpsertResult result = service.upsert(candidate, finding -> FindingUpsertService.UpsertAction.UPDATED);

        assertSame(candidate, result.finding());
        assertEquals(FindingUpsertService.UpsertAction.CREATED, result.action());
        verify(findingRepository).saveAndFlush(candidate);
    }

    @Test
    void upsertReloadsAndMutatesExistingWhenConcurrentCreateWins() {
        Finding candidate = newFinding(componentId, vulnerabilityId);
        Finding existing = newFinding(componentId, vulnerabilityId);
        when(findingRepository.findFirstByComponent_IdAndVulnerability_Id(componentId, vulnerabilityId))
                .thenReturn(Optional.empty(), Optional.of(existing));
        when(findingRepository.saveAndFlush(candidate)).thenThrow(new DataIntegrityViolationException("duplicate"));
        when(findingRepository.save(existing)).thenReturn(existing);

        FindingUpsertService.UpsertResult result = service.upsert(candidate, finding -> {
            finding.setMatchedBy("reloaded");
            return FindingUpsertService.UpsertAction.REOPENED;
        });

        assertSame(existing, result.finding());
        assertEquals("reloaded", existing.getMatchedBy());
        assertEquals(FindingUpsertService.UpsertAction.REOPENED, result.action());
        verify(findingRepository).save(existing);
    }

    @Test
    void upsertSkipsSaveWhenExistingRemainsUnchanged() {
        Finding candidate = newFinding(componentId, vulnerabilityId);
        Finding existing = newFinding(componentId, vulnerabilityId);
        when(findingRepository.findFirstByComponent_IdAndVulnerability_Id(componentId, vulnerabilityId))
                .thenReturn(Optional.of(existing));

        FindingUpsertService.UpsertResult result = service.upsert(candidate, finding -> FindingUpsertService.UpsertAction.UNCHANGED);

        assertSame(existing, result.finding());
        assertEquals(FindingUpsertService.UpsertAction.UNCHANGED, result.action());
    }

    private Finding newFinding(UUID componentId, UUID vulnerabilityId) {
        Finding finding = new Finding();
        InventoryComponent component = new InventoryComponent();
        setId(component, componentId);
        Vulnerability vulnerability = new Vulnerability();
        setId(vulnerability, vulnerabilityId);
        finding.setComponent(component);
        finding.setVulnerability(vulnerability);
        finding.setMatchedBy("seed");
        finding.setRiskScore(1.0);
        return finding;
    }

    private void setId(Object target, UUID id) {
        try {
            Field field = target.getClass().getDeclaredField("id");
            field.setAccessible(true);
            field.set(target, id);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }
}
