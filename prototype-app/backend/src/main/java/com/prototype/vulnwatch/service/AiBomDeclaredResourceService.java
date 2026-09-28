package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityMetadataSanitizer;
import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomDeclaredResourceKind;
import com.prototype.vulnwatch.domain.AiBomDeploymentState;
import com.prototype.vulnwatch.domain.BomComponent;
import com.prototype.vulnwatch.domain.BomComponentCategory;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AiBomDeclaredResourceRepository;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * Writes the declared AI inventory: the models and datasets an uploaded AI-BOM says exist.
 *
 * <p>A declaration is not a deployment. Every new row starts {@code UNVERIFIED} and a
 * replacement upload never touches {@code deploymentState} -- linking a declaration to a real
 * deployment is a separate, reviewed step (Milestone 2 part 4.2), and a later re-upload of the
 * same document must not be able to undo it.
 */
@Service
public class AiBomDeclaredResourceService {

    private final AiBomDeclaredResourceRepository repository;
    private final AiBomDeclaredResourceIdentityResolver identityResolver;
    private final AiSecurityMetadataSanitizer metadataSanitizer;
    private final ObjectMapper objectMapper;

    public AiBomDeclaredResourceService(
            AiBomDeclaredResourceRepository repository,
            AiBomDeclaredResourceIdentityResolver identityResolver,
            AiSecurityMetadataSanitizer metadataSanitizer,
            ObjectMapper objectMapper) {
        this.repository = repository;
        this.identityResolver = identityResolver;
        this.metadataSanitizer = metadataSanitizer;
        this.objectMapper = objectMapper;
    }

    /**
     * Records every non-software component of this ingestion as a declared AI resource,
     * scoped to its source. Only {@code source_id + identity_value} decides whether this is a
     * new declaration or a refresh of an existing one -- never the display name, and never
     * across sources.
     */
    public void recordDeclarations(
            BomIngestionRecord record, BomSource source, Tenant tenant, List<BomComponent> components) {
        if (components == null || components.isEmpty()) {
            return;
        }
        Instant now = Instant.now();
        for (BomComponent component : components) {
            if (component.getCategory() != BomComponentCategory.AI_MODEL) {
                continue;
            }
            recordOne(record, source, tenant, component, now);
        }
    }

    private void recordOne(
            BomIngestionRecord record, BomSource source, Tenant tenant, BomComponent component, Instant now) {
        AiBomDeclaredResourceKind resourceKind = identityResolver.resourceKind(component);
        AiBomDeclaredResourceIdentityResolver.Identity identity = identityResolver.resolve(component);

        AiBomDeclaredResource declared = repository
                .findBySourceIdAndIdentityValue(source.getId(), identity.value())
                .orElseGet(AiBomDeclaredResource::new);
        boolean isNew = declared.getId() == null;

        declared.setTenantId(tenant.getId());
        declared.setSourceId(source.getId());
        declared.setBomId(record.getId());
        declared.setBomComponentId(component.getId());
        declared.setResourceKind(resourceKind);
        declared.setName(component.getName());
        declared.setVersion(component.getVersion());
        declared.setIdentityKind(identity.kind());
        declared.setIdentityValue(identity.value());
        declared.setAttributesJson(sanitizedAttributes(component, resourceKind));
        declared.setLastDeclaredAt(now);
        if (isNew) {
            declared.setFirstDeclaredAt(now);
            declared.setDeploymentState(AiBomDeploymentState.UNVERIFIED);
        }
        repository.save(declared);
    }

    /**
     * attributes_json is never a public extension point (see {@code AiSecurityFieldContract}):
     * every key here is run through the same sanitizer the AWS/Azure collectors use, and a
     * field the current allowlist doesn't recognise is silently dropped rather than stored.
     */
    private String sanitizedAttributes(BomComponent component, AiBomDeclaredResourceKind resourceKind) {
        Map<String, Object> raw = new LinkedHashMap<>();
        putIfPresent(raw, "version", component.getVersion());
        putIfPresent(raw, "componentType", component.getComponentType());
        putIfPresent(raw, "purl", component.getPurl());
        putIfPresent(raw, "cpe", component.getCpe());
        putIfPresent(raw, "license", component.getLicense());
        putIfPresent(raw, "supplier", component.getSupplier());

        String nativeKind = resourceKind == AiBomDeclaredResourceKind.DATASET
                ? "AI_BOM_DECLARED_DATASET"
                : "AI_BOM_DECLARED_MODEL";
        AiSecurityMetadataSanitizer.Result result = metadataSanitizer.sanitize("AI_BOM", nativeKind, raw);
        try {
            return objectMapper.writeValueAsString(result.attributes());
        } catch (Exception e) {
            return "{}";
        }
    }

    private void putIfPresent(Map<String, Object> map, String key, String value) {
        if (value != null && !value.isBlank()) {
            map.put(key, value);
        }
    }
}
