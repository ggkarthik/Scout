package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.BomSourceCompletenessAssertion;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomSourceCompletenessAssertionRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Resolves the logical BOM source a document belongs to.
 *
 * <p>This replaces the previous implicit replacement key
 * {@code (tenant, bom_type, asset_id, lower(supplier))}, under which any document sharing a
 * supplier with an existing one silently superseded it. Replacement is now something a
 * caller asks for, by naming the source it is replacing.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BomSourceService {

    /**
     * Asserting complete software inventory is what later permits component retirement, so
     * it is restricted to the roles that already gate BOM ingestion itself.
     */
    private static final Set<String> COMPLETENESS_ROLES =
            Set.of("INVENTORY_ADMIN", "TENANT_ADMIN", "CREATOR", "PLATFORM_OWNER");

    private final BomSourceRepository sourceRepository;
    private final BomSourceCompletenessAssertionRepository assertionRepository;
    private final ObjectMapper objectMapper;

    /**
     * @param explicitSourceId caller is replacing this known source
     * @param sourceKey        deterministic identity for an automated caller, so a scheduled
     *                         run replaces its own source instead of adding another
     * @param completeness     null is treated as PARTIAL; a replacement that does not repeat
     *                         a complete assertion reverts the source to PARTIAL
     */
    public record SourceRequest(
            BomType bomType,
            UUID explicitSourceId,
            String sourceKey,
            UUID assetId,
            String supplier,
            String sourceReference,
            BomSourceCompleteness completeness
    ) {
    }

    public BomSource resolve(Tenant tenant, SourceRequest request, Set<String> actorRoles) throws IOException {
        BomSourceCompleteness completeness = request.completeness() == null
                ? BomSourceCompleteness.PARTIAL
                : request.completeness();

        if (completeness == BomSourceCompleteness.COMPLETE_ASSET_SOFTWARE) {
            if (request.bomType() == BomType.CBOM) {
                throw new IOException("A CBOM describes cryptographic assets and cannot assert "
                        + "complete software inventory for an asset");
            }
            if (actorRoles == null || actorRoles.stream().noneMatch(COMPLETENESS_ROLES::contains)) {
                throw new IOException("Asserting complete asset software inventory requires an "
                        + "inventory administrator");
            }
        }

        BomSource source = locate(tenant, request);

        // Re-applied on every version: the completeness claim does not carry over, so a
        // replacement that stays silent drops back to PARTIAL and loses the ability to
        // record authoritative absence.
        source.setCompleteness(completeness);
        if (request.assetId() != null) {
            source.setAssetId(request.assetId());
        }
        if (request.supplier() != null && !request.supplier().isBlank()) {
            source.setSupplier(request.supplier());
        }
        if (request.sourceReference() != null && !request.sourceReference().isBlank()) {
            source.setSourceReference(request.sourceReference());
        }
        return sourceRepository.save(source);
    }

    private BomSource locate(Tenant tenant, SourceRequest request) throws IOException {
        if (request.explicitSourceId() != null) {
            BomSource existing = sourceRepository.findById(request.explicitSourceId())
                    .orElseThrow(() -> new IOException(
                            "Unknown BOM source " + request.explicitSourceId()));
            if (existing.getBomType() != request.bomType()) {
                throw new IOException("BOM source " + existing.getId() + " holds "
                        + existing.getBomType() + " documents, not " + request.bomType());
            }
            return existing;
        }
        if (request.sourceKey() != null && !request.sourceKey().isBlank()) {
            return sourceRepository.findBySourceKey(request.sourceKey())
                    .orElseGet(() -> create(tenant, request));
        }
        // No source named and no deterministic key: an independent source. Deliberately not
        // matched against an existing one by asset and supplier -- that inference is what
        // made unrelated uploads supersede each other.
        return create(tenant, request);
    }

    private BomSource create(Tenant tenant, SourceRequest request) {
        BomSource source = new BomSource();
        source.setTenantId(tenant.getId());
        source.setBomType(request.bomType());
        source.setSourceKey(request.sourceKey());
        source.setAssetId(request.assetId());
        source.setSupplier(request.supplier());
        source.setSourceReference(request.sourceReference());
        return source;
    }

    /** Promotes a newly stored document version to current and advances the revision. */
    public BomSource recordCurrentVersion(BomSource source, UUID bomId) {
        source.setCurrentBomId(bomId);
        source.setRevision(source.getRevision() + 1);
        return sourceRepository.save(source);
    }

    /**
     * Writes the audit row for a completeness claim. Append-only: each version's claim is
     * recorded separately so the scope in force at any point stays reconstructable.
     */
    public void recordAssertion(
            BomSource source,
            UUID bomId,
            BomSourceCompleteness completeness,
            String assertedBy
    ) {
        Map<String, Object> scope = new LinkedHashMap<>();
        scope.put("assetId", source.getAssetId() == null ? null : source.getAssetId().toString());
        scope.put("bomType", source.getBomType().name());
        scope.put("supplier", source.getSupplier());

        BomSourceCompletenessAssertion assertion = new BomSourceCompletenessAssertion();
        assertion.setTenantId(source.getTenantId());
        assertion.setSourceId(source.getId());
        assertion.setBomId(bomId);
        assertion.setCompleteness(completeness);
        assertion.setAssertedBy(assertedBy == null || assertedBy.isBlank() ? "unknown" : assertedBy);
        assertion.setAssertedAt(Instant.now());
        try {
            assertion.setAssetScopeJson(objectMapper.writeValueAsString(scope));
        } catch (Exception ex) {
            // The scope map is built from locals here, so this cannot realistically fail;
            // an empty object still satisfies the jsonb object constraint.
            log.warn("Failed to serialise completeness assertion scope for source {}", source.getId(), ex);
            assertion.setAssetScopeJson("{}");
        }
        assertionRepository.save(assertion);
    }
}
