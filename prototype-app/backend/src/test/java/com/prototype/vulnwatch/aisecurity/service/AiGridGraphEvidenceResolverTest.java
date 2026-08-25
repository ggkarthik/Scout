package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

class AiGridGraphEvidenceResolverTest {
    @Test
    void distinguishesAuthoritativeAbsenceFromStaleRelationshipEvidence() {
        Instant asOf = Instant.parse("2026-08-25T12:00:00Z");
        var stale = new AiGridGraphEvidenceResolver.Relationship(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
                "USES_TOOL", asOf.minus(Duration.ofHours(25)), null);

        var staleResult = AiGridGraphEvidenceResolver.evaluate(List.of("USES_TOOL"), List.of(stale), asOf, Duration.ofHours(24));
        var absentResult = AiGridGraphEvidenceResolver.evaluate(List.of("USES_TOOL"), List.of(), asOf, Duration.ofHours(24));

        assertEquals(AiGridGraphEvidenceResolver.Status.STALE, staleResult.status());
        assertEquals(List.of("USES_TOOL"), staleResult.issues());
        assertEquals(AiGridGraphEvidenceResolver.Status.ABSENT, absentResult.status());
    }

    @Test
    void resolvesDirectEvidenceFromTheRunIndexWithoutAnotherDatabaseRead() {
        NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
        AiGridGraphEvidenceResolver resolver = new AiGridGraphEvidenceResolver(jdbc);
        Instant asOf = Instant.parse("2026-08-25T12:00:00Z");
        UUID source = UUID.randomUUID();
        var relationship = new AiGridGraphEvidenceResolver.Relationship(UUID.randomUUID(), source, UUID.randomUUID(),
                "USES_TOOL", asOf.minusSeconds(60), null);
        var index = new AiGridGraphEvidenceResolver.DirectIndex(java.util.Map.of(source, List.of(relationship)));

        var evidence = resolver.resolveDirect(index, source, List.of("USES_TOOL"), asOf);

        assertEquals(AiGridGraphEvidenceResolver.Status.READY, evidence.status());
        verifyNoInteractions(jdbc);
    }
}
