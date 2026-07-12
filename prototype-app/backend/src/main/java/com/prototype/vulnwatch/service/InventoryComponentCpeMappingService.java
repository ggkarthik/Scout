package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.CpeDim;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentCpeMap;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.util.CpeUtil;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class InventoryComponentCpeMappingService {

    private final InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;
    private final CpeDimensionService cpeDimensionService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private TransactionTemplate writeTransactionTemplate;

    public InventoryComponentCpeMappingService(
            InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository,
            CpeDimensionService cpeDimensionService,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.inventoryComponentCpeMapRepository = inventoryComponentCpeMapRepository;
        this.cpeDimensionService = cpeDimensionService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        if (transactionManager == null) {
            this.writeTransactionTemplate = null;
            return;
        }
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        // Must join the caller's transaction (default REQUIRED), not open a new one: callers such as
        // SbomContentIngestionService insert brand-new InventoryComponent rows earlier in the SAME,
        // still-open outer transaction. A separate REQUIRES_NEW transaction runs on its own connection,
        // which cannot see that uncommitted row yet — the inventory_component_cpe_map insert below then
        // fails its FK check against inventory_components for any component that is new in this request.
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRED);
    }

    public void syncActiveComponentMappings(InventoryComponent component, Collection<String> rawCpes) {
        if (component == null || component.getTenant() == null || component.getId() == null) {
            return;
        }
        syncComponentMappings(List.of(component), Map.of(component.getId(), rawCpes == null ? List.of() : rawCpes));
    }

    public void syncComponentMappings(
            Collection<InventoryComponent> components,
            Map<UUID, ? extends Collection<String>> rawCpesByComponentId
    ) {
        if (components == null || components.isEmpty()) {
            return;
        }

        Map<UUID, List<InventoryComponent>> componentsByTenantId = new LinkedHashMap<>();
        Map<UUID, Tenant> tenantById = new HashMap<>();
        for (InventoryComponent component : components) {
            if (component == null || component.getTenant() == null || component.getTenant().getId() == null || component.getId() == null) {
                continue;
            }
            UUID tenantId = component.getTenant().getId();
            tenantById.putIfAbsent(tenantId, component.getTenant());
            componentsByTenantId.computeIfAbsent(tenantId, ignored -> new java.util.ArrayList<>()).add(component);
        }

        for (Map.Entry<UUID, List<InventoryComponent>> entry : componentsByTenantId.entrySet()) {
            syncTenantComponentMappings(
                    tenantById.get(entry.getKey()),
                    entry.getValue(),
                    rawCpesByComponentId == null ? Map.of() : rawCpesByComponentId
            );
        }
    }

    public void clearComponentMappings(InventoryComponent component) {
        if (component == null || component.getTenant() == null) {
            return;
        }
        tenantSchemaExecutionService.run(component.getTenant(), () -> executeWrite(() -> {
            inventoryComponentCpeMapRepository.deleteByComponent(component);
            return null;
        }));
    }

    private void syncTenantComponentMappings(
            Tenant tenant,
            List<InventoryComponent> components,
            Map<UUID, ? extends Collection<String>> rawCpesByComponentId
    ) {
        if (tenant == null || tenant.getId() == null || components.isEmpty()) {
            return;
        }

        Set<UUID> componentIds = new LinkedHashSet<>();
        Map<UUID, Set<String>> normalizedCpesByComponentId = new LinkedHashMap<>();
        Set<String> allNormalizedCpes = new LinkedHashSet<>();
        for (InventoryComponent component : components) {
            componentIds.add(component.getId());
            Set<String> normalizedCpes = component.getComponentStatus() == InventoryComponentStatus.ACTIVE
                    ? normalizeRawCpes(rawCpesByComponentId.get(component.getId()))
                    : Set.of();
            normalizedCpesByComponentId.put(component.getId(), normalizedCpes);
            allNormalizedCpes.addAll(normalizedCpes);
        }

        Map<String, CpeDim> cpeDimsByNormalized = cpeDimensionService.resolveOrCreateAllByNormalizedCpe(allNormalizedCpes);
        tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            List<InventoryComponentCpeMap> existing = inventoryComponentCpeMapRepository.findByComponent_IdIn(componentIds);

            Map<UUID, List<InventoryComponentCpeMap>> existingByComponentId = new HashMap<>();
            for (InventoryComponentCpeMap row : existing) {
                if (row.getComponent() == null || row.getComponent().getId() == null) {
                    continue;
                }
                existingByComponentId.computeIfAbsent(row.getComponent().getId(), ignored -> new java.util.ArrayList<>()).add(row);
            }

            Instant now = Instant.now();
            List<InventoryComponentCpeMap> toSave = new java.util.ArrayList<>();
            List<InventoryComponentCpeMap> toDelete = new java.util.ArrayList<>();
            for (InventoryComponent component : components) {
                List<InventoryComponentCpeMap> existingRows = existingByComponentId.getOrDefault(component.getId(), List.of());
                Map<UUID, InventoryComponentCpeMap> existingByCpeId = new HashMap<>();
                for (InventoryComponentCpeMap row : existingRows) {
                    if (row.getCpeDim() == null || row.getCpeDim().getId() == null) {
                        continue;
                    }
                    existingByCpeId.put(row.getCpeDim().getId(), row);
                }

                Set<UUID> keep = new HashSet<>();
                for (String normalizedCpe : normalizedCpesByComponentId.getOrDefault(component.getId(), Set.of())) {
                    CpeDim dim = cpeDimsByNormalized.get(normalizedCpe);
                    if (dim == null || dim.getId() == null) {
                        continue;
                    }
                    keep.add(dim.getId());
                    InventoryComponentCpeMap row = existingByCpeId.get(dim.getId());
                    if (row == null) {
                        row = new InventoryComponentCpeMap();
                        row.setTenant(component.getTenant());
                        row.setComponent(component);
                        row.setCpeDim(dim);
                        row.setFirstSeenAt(now);
                    }
                    row.setObservedVersion(component.getVersion());
                    row.setLastSeenAt(now);
                    toSave.add(row);
                }

                for (InventoryComponentCpeMap row : existingRows) {
                    UUID cpeId = row.getCpeDim() == null ? null : row.getCpeDim().getId();
                    if (cpeId == null || !keep.contains(cpeId)) {
                        toDelete.add(row);
                    }
                }
            }

            if (!toSave.isEmpty()) {
                inventoryComponentCpeMapRepository.saveAll(toSave);
            }
            if (!toDelete.isEmpty()) {
                inventoryComponentCpeMapRepository.deleteAll(toDelete);
            }
            return null;
        }));
    }

    private Set<String> normalizeRawCpes(Collection<String> rawCpes) {
        if (rawCpes == null || rawCpes.isEmpty()) {
            return Set.of();
        }
        Set<String> normalized = new LinkedHashSet<>();
        for (String rawCpe : rawCpes) {
            if (rawCpe == null || rawCpe.isBlank()) {
                continue;
            }
            String value = CpeUtil.normalizeCpe23(rawCpe);
            if (value != null) {
                normalized.add(value);
            }
        }
        return normalized;
    }

    private <T> T executeWrite(java.util.function.Supplier<T> work) {
        if (writeTransactionTemplate == null) {
            return work.get();
        }
        return writeTransactionTemplate.execute(status -> work.get());
    }
}
