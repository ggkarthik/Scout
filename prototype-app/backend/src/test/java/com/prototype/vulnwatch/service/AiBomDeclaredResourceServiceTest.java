package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityMetadataSanitizer;
import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomDeploymentState;
import com.prototype.vulnwatch.domain.BomComponent;
import com.prototype.vulnwatch.domain.BomComponentCategory;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AiBomDeclaredResourceRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit-level coverage of the declared-inventory writer's branching, without a database. */
class AiBomDeclaredResourceServiceTest {

    private AiBomDeclaredResourceRepository repository;
    private AiSecurityMetadataSanitizer metadataSanitizer;
    private AiBomDeclaredResourceService service;

    private Tenant tenant;
    private BomSource source;
    private BomIngestionRecord record;

    @BeforeEach
    void setUp() {
        repository = mock(AiBomDeclaredResourceRepository.class);
        metadataSanitizer = mock(AiSecurityMetadataSanitizer.class);
        when(metadataSanitizer.sanitize(any(), any(), any()))
                .thenReturn(new AiSecurityMetadataSanitizer.Result(java.util.Map.of(), List.of()));

        service = new AiBomDeclaredResourceService(
                repository, new AiBomDeclaredResourceIdentityResolver(new ObjectMapper()),
                metadataSanitizer, new ObjectMapper());

        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        source = new BomSource();
        source.setId(UUID.randomUUID());

        // BomIngestionRecord's id is JPA-generated with no setter; leaving it null is fine
        // here since these tests only assert on tenant/source identity and lifecycle fields.
        record = new BomIngestionRecord();
    }

    // BomComponent's id is JPA-generated with no setter; these unit tests don't need it set
    // since the service only forwards it (as bomComponentId), never branches on it.
    private static BomComponent softwareComponent() {
        BomComponent component = new BomComponent();
        component.setCategory(BomComponentCategory.THIRD_PARTY);
        component.setComponentType("library");
        component.setName("transformers");
        component.setVersion("4.38.0");
        return component;
    }

    private static BomComponent modelComponent() {
        BomComponent component = new BomComponent();
        component.setCategory(BomComponentCategory.AI_MODEL);
        component.setComponentType("machine-learning-model");
        component.setName("llama-3");
        component.setVersion("3.1");
        component.setPurl("pkg:huggingface/llama-3@3.1");
        return component;
    }

    @Test
    void softwareComponentsAreNeverWritten() {
        when(repository.findBySourceIdAndIdentityValue(any(), any())).thenReturn(Optional.empty());

        service.recordDeclarations(record, source, tenant, List.of(softwareComponent()));

        verify(repository, times(0)).save(any());
    }

    @Test
    void aNewDeclarationStartsUnverifiedAndRecordsBothTimestamps() {
        when(repository.findBySourceIdAndIdentityValue(any(), any())).thenReturn(Optional.empty());

        service.recordDeclarations(record, source, tenant, List.of(modelComponent()));

        var captor = org.mockito.ArgumentCaptor.forClass(AiBomDeclaredResource.class);
        verify(repository).save(captor.capture());
        AiBomDeclaredResource saved = captor.getValue();

        assertEquals(AiBomDeploymentState.UNVERIFIED, saved.getDeploymentState());
        assertNotNull(saved.getFirstDeclaredAt());
        assertEquals(saved.getFirstDeclaredAt(), saved.getLastDeclaredAt());
        assertEquals(tenant.getId(), saved.getTenantId());
        assertEquals(source.getId(), saved.getSourceId());
    }

    @Test
    void anExistingDeclarationIsRefreshedWithoutTouchingDeploymentState() {
        AiBomDeclaredResource existing = new AiBomDeclaredResource();
        existing.setId(UUID.randomUUID());
        existing.setDeploymentState(AiBomDeploymentState.LINKED);
        java.time.Instant originalFirstDeclared = java.time.Instant.now().minusSeconds(3600);
        existing.setFirstDeclaredAt(originalFirstDeclared);
        existing.setLastDeclaredAt(originalFirstDeclared);
        when(repository.findBySourceIdAndIdentityValue(any(), any())).thenReturn(Optional.of(existing));

        service.recordDeclarations(record, source, tenant, List.of(modelComponent()));

        var captor = org.mockito.ArgumentCaptor.forClass(AiBomDeclaredResource.class);
        verify(repository).save(captor.capture());
        AiBomDeclaredResource saved = captor.getValue();

        assertEquals(AiBomDeploymentState.LINKED, saved.getDeploymentState(),
                "a re-upload must never be able to undo a reviewed/matched link");
        assertEquals(originalFirstDeclared, saved.getFirstDeclaredAt());
        assertNotNull(saved.getLastDeclaredAt());
    }

    @Test
    void theSanitizerIsInvokedWithTheModelNativeKindForAModelComponent() {
        when(repository.findBySourceIdAndIdentityValue(any(), any())).thenReturn(Optional.empty());

        service.recordDeclarations(record, source, tenant, List.of(modelComponent()));

        verify(metadataSanitizer).sanitize(eq("AI_BOM"), eq("AI_BOM_DECLARED_MODEL"), any());
    }

    @Test
    void theSanitizerIsInvokedWithTheDatasetNativeKindForADatasetComponent() {
        BomComponent dataset = new BomComponent();
        dataset.setCategory(BomComponentCategory.AI_MODEL);
        dataset.setComponentType("dataset");
        dataset.setName("training-corpus");
        dataset.setBomRef("corpus-ref");
        when(repository.findBySourceIdAndIdentityValue(any(), any())).thenReturn(Optional.empty());

        service.recordDeclarations(record, source, tenant, List.of(dataset));

        verify(metadataSanitizer).sanitize(eq("AI_BOM"), eq("AI_BOM_DECLARED_DATASET"), any());
    }
}
