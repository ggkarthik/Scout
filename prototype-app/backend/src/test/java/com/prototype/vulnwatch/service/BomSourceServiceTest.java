package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.BomSourceCompletenessAssertion;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomSourceCompletenessAssertionRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BomSourceServiceTest {

    private static final Set<String> ADMIN = Set.of("INVENTORY_ADMIN");
    private static final Set<String> ANALYST = Set.of("SECURITY_ANALYST");

    private BomSourceRepository sourceRepository;
    private BomSourceCompletenessAssertionRepository assertionRepository;
    private BomSourceService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        sourceRepository = mock(BomSourceRepository.class);
        assertionRepository = mock(BomSourceCompletenessAssertionRepository.class);
        service = new BomSourceService(sourceRepository, assertionRepository, new ObjectMapper());
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        when(sourceRepository.save(any(BomSource.class))).thenAnswer(i -> i.getArgument(0));
    }

    private BomSourceService.SourceRequest request(
            BomType bomType, UUID sourceId, String sourceKey, BomSourceCompleteness completeness) {
        return new BomSourceService.SourceRequest(
                bomType, sourceId, sourceKey, UUID.randomUUID(), "acme", "bom.json", completeness);
    }

    // The behaviour change at the heart of Milestone 1: two uploads that merely share an
    // asset and supplier are now two sources, not one silently superseding the other.
    @Test
    void omittingSourceIdCreatesAnIndependentSourceEachTime() throws Exception {
        BomSource first = service.resolve(tenant, request(BomType.SBOM, null, null, null), ADMIN);
        BomSource second = service.resolve(tenant, request(BomType.SBOM, null, null, null), ADMIN);

        assertNotSame(first, second, "an unnamed upload must not adopt an existing source");
        verify(sourceRepository, never()).findBySourceKey(any());
    }

    // Without this, the scheduled GitHub sync would create a new source on every run.
    @Test
    void deterministicKeyReusesTheSameSource() throws Exception {
        BomSource existing = new BomSource();
        existing.setId(UUID.randomUUID());
        existing.setBomType(BomType.SBOM);
        existing.setSourceKey("github-repo:SBOM:acme/widget");
        when(sourceRepository.findBySourceKey("github-repo:SBOM:acme/widget"))
                .thenReturn(Optional.of(existing));

        BomSource resolved = service.resolve(
                tenant, request(BomType.SBOM, null, "github-repo:SBOM:acme/widget", null), ADMIN);

        assertSame(existing, resolved, "an automated caller must resolve back to its own source");
    }

    @Test
    void explicitSourceIdResolvesThatSource() throws Exception {
        BomSource existing = new BomSource();
        existing.setId(UUID.randomUUID());
        existing.setBomType(BomType.SBOM);
        when(sourceRepository.findById(existing.getId())).thenReturn(Optional.of(existing));

        assertSame(existing,
                service.resolve(tenant, request(BomType.SBOM, existing.getId(), null, null), ADMIN));
    }

    @Test
    void explicitSourceIdRejectsABomTypeMismatch() {
        BomSource existing = new BomSource();
        existing.setId(UUID.randomUUID());
        existing.setBomType(BomType.SBOM);
        when(sourceRepository.findById(existing.getId())).thenReturn(Optional.of(existing));

        IOException error = assertThrows(IOException.class, () ->
                service.resolve(tenant, request(BomType.AI_BOM, existing.getId(), null, null), ADMIN));
        assertTrue(error.getMessage().contains("holds SBOM documents"), error.getMessage());
    }

    @Test
    void unknownExplicitSourceIsRejected() {
        UUID missing = UUID.randomUUID();
        when(sourceRepository.findById(missing)).thenReturn(Optional.empty());

        assertThrows(IOException.class, () ->
                service.resolve(tenant, request(BomType.SBOM, missing, null, null), ADMIN));
    }

    // A CBOM describes cryptographic assets, so it can never speak for an asset's whole
    // software inventory. Enforced here as well as by a database constraint.
    @Test
    void cbomCannotAssertSoftwareCompleteness() {
        IOException error = assertThrows(IOException.class, () -> service.resolve(
                tenant,
                request(BomType.CBOM, null, null, BomSourceCompleteness.COMPLETE_ASSET_SOFTWARE),
                ADMIN));
        assertTrue(error.getMessage().contains("cannot assert"), error.getMessage());
    }

    // Completeness is what later permits retiring components, so it is privilege-gated.
    @Test
    void completenessRequiresAnInventoryAdministrator() throws Exception {
        IOException error = assertThrows(IOException.class, () -> service.resolve(
                tenant,
                request(BomType.SBOM, null, null, BomSourceCompleteness.COMPLETE_ASSET_SOFTWARE),
                ANALYST));
        assertTrue(error.getMessage().contains("inventory administrator"), error.getMessage());

        assertEquals(BomSourceCompleteness.COMPLETE_ASSET_SOFTWARE,
                service.resolve(
                        tenant,
                        request(BomType.SBOM, null, null, BomSourceCompleteness.COMPLETE_ASSET_SOFTWARE),
                        ADMIN).getCompleteness());
    }

    // "Replacements must repeat the assertion": a silent replacement drops the claim, and
    // with it the ability to record authoritative absence.
    @Test
    void replacementThatDoesNotRepeatTheAssertionRevertsToPartial() throws Exception {
        BomSource existing = new BomSource();
        existing.setId(UUID.randomUUID());
        existing.setBomType(BomType.SBOM);
        existing.setCompleteness(BomSourceCompleteness.COMPLETE_ASSET_SOFTWARE);
        when(sourceRepository.findById(existing.getId())).thenReturn(Optional.of(existing));

        BomSource resolved =
                service.resolve(tenant, request(BomType.SBOM, existing.getId(), null, null), ADMIN);

        assertEquals(BomSourceCompleteness.PARTIAL, resolved.getCompleteness(),
                "a completeness claim must not carry over to a replacement");
    }

    @Test
    void recordCurrentVersionAdvancesTheRevision() {
        BomSource source = new BomSource();
        source.setId(UUID.randomUUID());
        UUID bomId = UUID.randomUUID();

        service.recordCurrentVersion(source, bomId);

        assertEquals(bomId, source.getCurrentBomId());
        assertEquals(1L, source.getRevision());
    }

    @Test
    void recordAssertionWritesAnAuditRowNamingTheActor() {
        BomSource source = new BomSource();
        source.setId(UUID.randomUUID());
        source.setTenantId(tenant.getId());
        source.setBomType(BomType.SBOM);
        source.setAssetId(UUID.randomUUID());
        UUID bomId = UUID.randomUUID();

        service.recordAssertion(
                source, bomId, BomSourceCompleteness.COMPLETE_ASSET_SOFTWARE, "inventory-admin@example.com");

        verify(assertionRepository).save(any(BomSourceCompletenessAssertion.class));
    }
}
