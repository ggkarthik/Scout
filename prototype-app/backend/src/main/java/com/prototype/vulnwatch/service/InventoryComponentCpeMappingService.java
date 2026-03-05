package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.CpeDim;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentCpeMap;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class InventoryComponentCpeMappingService {

    private final InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;
    private final CpeDimensionService cpeDimensionService;

    public InventoryComponentCpeMappingService(
            InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository,
            CpeDimensionService cpeDimensionService
    ) {
        this.inventoryComponentCpeMapRepository = inventoryComponentCpeMapRepository;
        this.cpeDimensionService = cpeDimensionService;
    }

    @Transactional
    public void syncActiveComponentMappings(InventoryComponent component, Collection<String> rawCpes) {
        if (component == null || component.getTenant() == null) {
            return;
        }

        List<CpeDim> cpeDims = cpeDimensionService.resolveOrCreateAll(rawCpes == null ? List.of() : rawCpes);
        List<InventoryComponentCpeMap> existing = inventoryComponentCpeMapRepository
                .findByTenantAndComponent(component.getTenant(), component);

        if (cpeDims.isEmpty()) {
            if (!existing.isEmpty()) {
                inventoryComponentCpeMapRepository.deleteAll(existing);
            }
            return;
        }

        Map<UUID, InventoryComponentCpeMap> existingByCpeId = new HashMap<>();
        for (InventoryComponentCpeMap row : existing) {
            if (row.getCpeDim() == null || row.getCpeDim().getId() == null) {
                continue;
            }
            existingByCpeId.put(row.getCpeDim().getId(), row);
        }

        Instant now = Instant.now();
        Set<UUID> keep = new HashSet<>();
        List<InventoryComponentCpeMap> toSave = new java.util.ArrayList<>();
        for (CpeDim dim : cpeDims) {
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

        List<InventoryComponentCpeMap> toDelete = new java.util.ArrayList<>();
        for (InventoryComponentCpeMap row : existing) {
            UUID cpeId = row.getCpeDim() == null ? null : row.getCpeDim().getId();
            if (cpeId == null || !keep.contains(cpeId)) {
                toDelete.add(row);
            }
        }

        if (!toSave.isEmpty()) {
            inventoryComponentCpeMapRepository.saveAll(toSave);
        }
        if (!toDelete.isEmpty()) {
            inventoryComponentCpeMapRepository.deleteAll(toDelete);
        }
    }

    @Transactional
    public void clearComponentMappings(InventoryComponent component) {
        if (component == null || component.getTenant() == null) {
            return;
        }
        inventoryComponentCpeMapRepository.deleteByTenantAndComponent(component.getTenant(), component);
    }
}
