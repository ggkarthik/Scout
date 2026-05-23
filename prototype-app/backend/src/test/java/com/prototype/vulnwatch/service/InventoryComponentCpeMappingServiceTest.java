package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.CpeDim;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentCpeMap;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class InventoryComponentCpeMappingServiceTest {

    private static final String CPE_ONE = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*";
    private static final String CPE_TWO = "cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*";

    @Mock
    private InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;

    @Mock
    private CpeDimensionService cpeDimensionService;
    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Test
    void syncComponentMappings_batchesResolutionAcrossComponents() {
        InventoryComponentCpeMappingService service = new InventoryComponentCpeMappingService(
                inventoryComponentCpeMapRepository,
                cpeDimensionService,
                tenantSchemaExecutionService
        );
        doAnswer(invocation -> invocation.getArgument(1, java.util.function.Supplier.class).get())
                .when(tenantSchemaExecutionService)
                .run(org.mockito.ArgumentMatchers.nullable(Tenant.class), org.mockito.ArgumentMatchers.<java.util.function.Supplier<Object>>any());
        Tenant tenant = tenant(UUID.randomUUID());
        InventoryComponent first = component(tenant, UUID.randomUUID(), "2.14.1", InventoryComponentStatus.ACTIVE);
        InventoryComponent second = component(tenant, UUID.randomUUID(), "1.25.3", InventoryComponentStatus.ACTIVE);

        CpeDim firstDim = cpeDim(UUID.randomUUID(), CPE_ONE);
        CpeDim secondDim = cpeDim(UUID.randomUUID(), CPE_TWO);

        when(cpeDimensionService.resolveOrCreateAllByNormalizedCpe(eq(Set.of(CPE_ONE, CPE_TWO))))
                .thenReturn(Map.of(CPE_ONE, firstDim, CPE_TWO, secondDim));
        when(inventoryComponentCpeMapRepository.findByComponent_IdIn(eq(Set.of(first.getId(), second.getId()))))
                .thenReturn(List.of());

        service.syncComponentMappings(
                List.of(first, second),
                Map.of(
                        first.getId(), List.of(CPE_ONE),
                        second.getId(), List.of(CPE_TWO)
                )
        );

        verify(cpeDimensionService).resolveOrCreateAllByNormalizedCpe(Set.of(CPE_ONE, CPE_TWO));
        verify(inventoryComponentCpeMapRepository).findByComponent_IdIn(Set.of(first.getId(), second.getId()));

        ArgumentCaptor<List<InventoryComponentCpeMap>> savedCaptor = ArgumentCaptor.forClass(List.class);
        verify(inventoryComponentCpeMapRepository).saveAll(savedCaptor.capture());
        assertEquals(2, savedCaptor.getValue().size());
        verify(inventoryComponentCpeMapRepository, never()).deleteAll(any());
    }

    @Test
    void syncComponentMappings_clearsMappingsForRetiredComponents() {
        InventoryComponentCpeMappingService service = new InventoryComponentCpeMappingService(
                inventoryComponentCpeMapRepository,
                cpeDimensionService,
                tenantSchemaExecutionService
        );
        doAnswer(invocation -> invocation.getArgument(1, java.util.function.Supplier.class).get())
                .when(tenantSchemaExecutionService)
                .run(org.mockito.ArgumentMatchers.nullable(Tenant.class), org.mockito.ArgumentMatchers.<java.util.function.Supplier<Object>>any());
        Tenant tenant = tenant(UUID.randomUUID());
        InventoryComponent retired = component(tenant, UUID.randomUUID(), "2.14.1", InventoryComponentStatus.RETIRED);
        InventoryComponentCpeMap existingRow = new InventoryComponentCpeMap();
        existingRow.setTenant(tenant);
        existingRow.setComponent(retired);
        existingRow.setCpeDim(cpeDim(UUID.randomUUID(), CPE_ONE));

        when(cpeDimensionService.resolveOrCreateAllByNormalizedCpe(Set.of())).thenReturn(Map.of());
        when(inventoryComponentCpeMapRepository.findByComponent_IdIn(Set.of(retired.getId())))
                .thenReturn(List.of(existingRow));

        service.syncComponentMappings(
                List.of(retired),
                Map.of(retired.getId(), List.of(CPE_ONE))
        );

        verify(inventoryComponentCpeMapRepository, never()).saveAll(any());
        ArgumentCaptor<List<InventoryComponentCpeMap>> deletedCaptor = ArgumentCaptor.forClass(List.class);
        verify(inventoryComponentCpeMapRepository).deleteAll(deletedCaptor.capture());
        assertEquals(List.of(existingRow), deletedCaptor.getValue());
    }

    private Tenant tenant(UUID id) {
        Tenant tenant = new Tenant();
        ReflectionTestUtils.setField(tenant, "id", id);
        return tenant;
    }

    private InventoryComponent component(Tenant tenant, UUID id, String version, InventoryComponentStatus status) {
        InventoryComponent component = new InventoryComponent();
        ReflectionTestUtils.setField(component, "id", id);
        component.setTenant(tenant);
        component.setVersion(version);
        component.setComponentStatus(status);
        return component;
    }

    private CpeDim cpeDim(UUID id, String normalizedCpe) {
        CpeDim dim = new CpeDim();
        ReflectionTestUtils.setField(dim, "id", id);
        dim.setNormalizedCpe(normalizedCpe);
        dim.setRawCpe(normalizedCpe);
        return dim;
    }
}
