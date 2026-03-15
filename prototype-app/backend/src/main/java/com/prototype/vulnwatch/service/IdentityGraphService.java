package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.IdentifierType;
import com.prototype.vulnwatch.domain.IdentityLink;
import com.prototype.vulnwatch.domain.IdentityLinkType;
import com.prototype.vulnwatch.domain.SoftwareIdentifier;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.repo.IdentityLinkRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentifierRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import com.prototype.vulnwatch.util.IdentityUtil;
import com.prototype.vulnwatch.util.PurlUtil;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IdentityGraphService {

    private final SoftwareIdentityRepository softwareIdentityRepository;
    private final SoftwareIdentifierRepository softwareIdentifierRepository;
    private final IdentityLinkRepository identityLinkRepository;
    private final ConcurrentMap<String, SoftwareIdentifier> identifierCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, IdentityLink> linkCache = new ConcurrentHashMap<>();

    public IdentityGraphService(
            SoftwareIdentityRepository softwareIdentityRepository,
            SoftwareIdentifierRepository softwareIdentifierRepository,
            IdentityLinkRepository identityLinkRepository
    ) {
        this.softwareIdentityRepository = softwareIdentityRepository;
        this.softwareIdentifierRepository = softwareIdentifierRepository;
        this.identityLinkRepository = identityLinkRepository;
    }

    @Transactional
    public SoftwareIdentity resolveFromComponent(
            String ecosystem,
            String packageName,
            String purl,
            String source
    ) {
        PurlUtil.ParsedPurl parsed = PurlUtil.parse(purl);
        String resolvedEcosystem = normalizeOrFallback(parsed.ecosystem(), ecosystem, "generic");
        String resolvedNamespace = IdentityUtil.normalize(parsed.namespace());
        String resolvedPackage = normalizeOrFallback(parsed.packageName(), packageName, "unknown");
        String canonicalKey = IdentityUtil.canonicalIdentityKey(resolvedEcosystem, resolvedNamespace, resolvedPackage);
        String displayName = resolvedPackage + " (" + resolvedEcosystem + ")";

        SoftwareIdentity identity = upsertIdentity(canonicalKey, displayName);
        List<SoftwareIdentifier> identifiers = new ArrayList<>();

        String normalizedPurl = IdentityUtil.normalizePurl(purl);
        if (!normalizedPurl.isBlank()) {
            identifiers.add(upsertIdentifier(identity, IdentifierType.PURL, purl, normalizedPurl, source, true, 0.98));
        }

        String coordKey = IdentityUtil.coordKey(resolvedEcosystem, resolvedNamespace, resolvedPackage);
        if (!coordKey.equals("::")) {
            identifiers.add(upsertIdentifier(identity, IdentifierType.COORD, coordKey, coordKey, source, true, 0.95));
        }

        // BLG-015: use typed link type; PURL and COORD identifiers for the same component are equivalent
        linkIdentifiers(identifiers, IdentityLinkType.PURL_EQUIV.value(), source, 0.9, true,
                "PURL/COORD identifiers co-extracted from SBOM component");
        return identity;
    }

    @Transactional
    public Map<ComponentIdentityInput, SoftwareIdentity> resolveFromComponents(Collection<ComponentIdentityInput> components) {
        if (components == null || components.isEmpty()) {
            return Map.of();
        }

        Map<ComponentIdentityInput, ComponentIdentityDescriptor> descriptorsByInput = new LinkedHashMap<>();
        Map<String, ComponentIdentityDescriptor> descriptorsByCanonicalKey = new LinkedHashMap<>();
        for (ComponentIdentityInput input : components) {
            if (input == null) {
                continue;
            }
            ComponentIdentityDescriptor descriptor = describeComponent(input.ecosystem(), input.packageName(), input.purl());
            descriptorsByInput.put(input, descriptor);
            descriptorsByCanonicalKey.putIfAbsent(descriptor.canonicalKey(), descriptor);
        }
        if (descriptorsByCanonicalKey.isEmpty()) {
            return Map.of();
        }

        Map<String, SoftwareIdentity> identitiesByCanonicalKey = upsertIdentitiesByCanonicalKey(descriptorsByCanonicalKey);
        Map<ComponentIdentityInput, SoftwareIdentity> resolved = new LinkedHashMap<>();
        for (Map.Entry<ComponentIdentityInput, ComponentIdentityDescriptor> entry : descriptorsByInput.entrySet()) {
            SoftwareIdentity identity = identitiesByCanonicalKey.get(entry.getValue().canonicalKey());
            if (identity != null) {
                resolved.put(entry.getKey(), identity);
            }
        }
        return resolved;
    }

    @Transactional
    public SoftwareIdentity resolveFromTarget(
            String ecosystem,
            String packageName,
            String namespace,
            String purl,
            String cpe,
            String repoUrl,
            String source
    ) {
        String normalizedNamespace = IdentityUtil.normalize(namespace);
        PurlUtil.ParsedPurl parsed = PurlUtil.parse(purl);
        String resolvedEcosystem = normalizeOrFallback(parsed.ecosystem(), ecosystem, "generic");
        String resolvedPackage = normalizeOrFallback(parsed.packageName(), packageName, "unknown");
        if (!normalizedNamespace.isBlank()) {
            // explicit namespace from caller takes precedence
        } else {
            normalizedNamespace = IdentityUtil.normalize(parsed.namespace());
        }

        String canonicalKey = IdentityUtil.canonicalIdentityKey(resolvedEcosystem, normalizedNamespace, resolvedPackage);
        String displayName = resolvedPackage + " (" + resolvedEcosystem + ")";
        SoftwareIdentity identity = upsertIdentity(canonicalKey, displayName);

        List<SoftwareIdentifier> identifiers = new ArrayList<>();
        String coordKey = IdentityUtil.coordKey(resolvedEcosystem, normalizedNamespace, resolvedPackage);
        identifiers.add(upsertIdentifier(identity, IdentifierType.COORD, coordKey, coordKey, source, true, 0.92));

        String normalizedPurl = IdentityUtil.normalizePurl(purl);
        if (!normalizedPurl.isBlank()) {
            identifiers.add(upsertIdentifier(identity, IdentifierType.PURL, purl, normalizedPurl, source, false, 0.86));
        }

        String normalizedCpe = IdentityUtil.normalize(cpe);
        if (!normalizedCpe.isBlank()) {
            identifiers.add(upsertIdentifier(identity, IdentifierType.CPE, cpe, normalizedCpe, source, false, 0.82));
        }

        String normalizedRepo = IdentityUtil.normalizeRepoUrl(repoUrl);
        if (!normalizedRepo.isBlank()) {
            identifiers.add(upsertIdentifier(identity, IdentifierType.REPO_URL, repoUrl, normalizedRepo, source, false, 0.8));
        }

        // BLG-015: cross-source crosswalk links connect COORD/PURL/CPE/REPO identifiers from advisory targets
        linkIdentifiers(identifiers, IdentityLinkType.PURL_TO_COORD.value(), source, 0.8, false,
                "Cross-source identifiers co-extracted from vulnerability target");
        return identity;
    }

    @Transactional
    public SoftwareIdentifier upsertIdentifier(
            SoftwareIdentity identity,
            IdentifierType idType,
            String rawValue,
            String normalizedValue,
            String source,
            boolean verified,
            double confidence
    ) {
        String normalized = IdentityUtil.normalize(normalizedValue);
        if (identity == null || identity.getId() == null || idType == null || normalized.isBlank()) {
            return null;
        }
        String sourceValue = source == null || source.isBlank() ? "system" : source.toLowerCase(Locale.ROOT);
        String cacheKey = identifierCacheKey(identity, idType, normalized);
        SoftwareIdentifier cached = identifierCache.get(cacheKey);
        if (cached != null) {
            cached.setRawValue(rawValue);
            cached.setSource(sourceValue);
            cached.setVerified(cached.isVerified() || verified);
            cached.setConfidence(max(cached.getConfidence(), confidence));
            cached.touch();
            cached = softwareIdentifierRepository.save(cached);
            if (cached != null) {
                identifierCache.put(cacheKey, cached);
            }
            return cached;
        }
        SoftwareIdentifier identifier = softwareIdentifierRepository
                .findBySoftwareIdentityAndIdTypeAndNormalizedValue(identity, idType, normalized)
                .map(existing -> {
                    existing.setRawValue(rawValue);
                    existing.setSource(sourceValue);
                    existing.setVerified(existing.isVerified() || verified);
                    existing.setConfidence(max(existing.getConfidence(), confidence));
                    existing.touch();
                    return softwareIdentifierRepository.save(existing);
                })
                .orElseGet(() -> {
                    SoftwareIdentifier created = new SoftwareIdentifier();
                    created.setSoftwareIdentity(identity);
                    created.setIdType(idType);
                    created.setRawValue(rawValue);
                    created.setNormalizedValue(normalized);
                    created.setSource(sourceValue);
                    created.setVerified(verified);
                    created.setConfidence(confidence);
                    return softwareIdentifierRepository.save(created);
                });
        if (identifier != null) {
            identifierCache.put(cacheKey, identifier);
        }
        return identifier;
    }

    private void linkIdentifiers(
            List<SoftwareIdentifier> identifiers,
            String linkType,
            String source,
            double confidence,
            boolean verified,
            String provenanceNote
    ) {
        List<SoftwareIdentifier> filtered = identifiers.stream()
                .filter(identifier -> identifier != null)
                .toList();
        for (int i = 0; i < filtered.size(); i++) {
            for (int j = i + 1; j < filtered.size(); j++) {
                upsertLink(filtered.get(i), filtered.get(j), linkType, source, confidence, verified, provenanceNote);
                upsertLink(filtered.get(j), filtered.get(i), linkType, source, confidence, verified, provenanceNote);
            }
        }
    }

    private void upsertLink(
            SoftwareIdentifier from,
            SoftwareIdentifier to,
            String linkType,
            String source,
            double confidence,
            boolean verified,
            String provenanceNote
    ) {
        if (from == null || to == null || from.getId().equals(to.getId())) {
            return;
        }
        String sourceValue = source == null || source.isBlank() ? "system" : source.toLowerCase(Locale.ROOT);
        Instant now = Instant.now();
        String cacheKey = linkCacheKey(from, to, linkType, sourceValue);
        IdentityLink cached = linkCache.get(cacheKey);
        if (cached != null) {
            if (!cached.isVerified() && verified) {
                cached.setVerified(true);
                cached.setVerifiedAt(now);
                cached.setVerifiedBy(sourceValue);
            }
            cached.setConfidence(max(cached.getConfidence(), confidence));
            cached.setProvenanceNote(provenanceNote);
            cached = identityLinkRepository.save(cached);
            if (cached != null) {
                linkCache.put(cacheKey, cached);
            }
            return;
        }
        IdentityLink link = identityLinkRepository
                .findByFromIdentifierAndToIdentifierAndLinkTypeAndSource(from, to, linkType, sourceValue)
                .map(existing -> {
                    if (!existing.isVerified() && verified) {
                        existing.setVerified(true);
                        existing.setVerifiedAt(now);
                        existing.setVerifiedBy(sourceValue);
                    }
                    existing.setConfidence(max(existing.getConfidence(), confidence));
                    existing.setProvenanceNote(provenanceNote);
                    return identityLinkRepository.save(existing);
                })
                .orElseGet(() -> {
                    IdentityLink created = new IdentityLink();
                    created.setFromIdentifier(from);
                    created.setToIdentifier(to);
                    created.setLinkType(linkType);
                    created.setSource(sourceValue);
                    created.setVerified(verified);
                    created.setConfidence(confidence);
                    created.setProvenanceNote(provenanceNote);
                    if (verified) {
                        created.setVerifiedAt(now);
                        created.setVerifiedBy(sourceValue);
                    }
                    return identityLinkRepository.save(created);
                });
        if (link != null) {
            linkCache.put(cacheKey, link);
        }
    }

    private SoftwareIdentity upsertIdentity(String canonicalKey, String displayName) {
        String normalizedKey = IdentityUtil.normalize(canonicalKey);
        String resolvedDisplay = displayName == null || displayName.isBlank()
                ? normalizedKey
                : displayName.trim();
        return softwareIdentityRepository.findByCanonicalKey(normalizedKey)
                .map(existing -> {
                    existing.setDisplayName(resolvedDisplay);
                    existing.touch();
                    return softwareIdentityRepository.save(existing);
                })
                .orElseGet(() -> {
                    SoftwareIdentity created = new SoftwareIdentity();
                    created.setCanonicalKey(normalizedKey);
                    created.setDisplayName(resolvedDisplay);
                    return softwareIdentityRepository.save(created);
                });
    }

    private Map<String, SoftwareIdentity> upsertIdentitiesByCanonicalKey(
            Map<String, ComponentIdentityDescriptor> descriptorsByCanonicalKey
    ) {
        Map<String, SoftwareIdentity> resolved = new LinkedHashMap<>();
        List<SoftwareIdentity> existingRows = softwareIdentityRepository.findByCanonicalKeyIn(descriptorsByCanonicalKey.keySet());
        List<SoftwareIdentity> existingToSave = new ArrayList<>();
        for (SoftwareIdentity existing : existingRows) {
            String canonicalKey = existing.getCanonicalKey();
            if (canonicalKey == null || canonicalKey.isBlank()) {
                continue;
            }
            ComponentIdentityDescriptor descriptor = descriptorsByCanonicalKey.get(canonicalKey);
            if (descriptor == null) {
                continue;
            }
            existing.setDisplayName(descriptor.displayName());
            existing.touch();
            existingToSave.add(existing);
            resolved.put(canonicalKey, existing);
        }
        if (!existingToSave.isEmpty()) {
            softwareIdentityRepository.saveAll(existingToSave);
        }

        List<SoftwareIdentity> missing = new ArrayList<>();
        for (ComponentIdentityDescriptor descriptor : descriptorsByCanonicalKey.values()) {
            if (resolved.containsKey(descriptor.canonicalKey())) {
                continue;
            }
            SoftwareIdentity created = new SoftwareIdentity();
            created.setCanonicalKey(descriptor.canonicalKey());
            created.setDisplayName(descriptor.displayName());
            missing.add(created);
        }

        if (!missing.isEmpty()) {
            try {
                for (SoftwareIdentity saved : softwareIdentityRepository.saveAll(missing)) {
                    resolved.put(saved.getCanonicalKey(), saved);
                }
            } catch (DataIntegrityViolationException race) {
                for (SoftwareIdentity existing : softwareIdentityRepository.findByCanonicalKeyIn(descriptorsByCanonicalKey.keySet())) {
                    resolved.put(existing.getCanonicalKey(), existing);
                }
            }
        }

        return resolved;
    }

    private ComponentIdentityDescriptor describeComponent(String ecosystem, String packageName, String purl) {
        PurlUtil.ParsedPurl parsed = PurlUtil.parse(purl);
        String resolvedEcosystem = normalizeOrFallback(parsed.ecosystem(), ecosystem, "generic");
        String resolvedNamespace = IdentityUtil.normalize(parsed.namespace());
        String resolvedPackage = normalizeOrFallback(parsed.packageName(), packageName, "unknown");
        String canonicalKey = IdentityUtil.canonicalIdentityKey(resolvedEcosystem, resolvedNamespace, resolvedPackage);
        String displayName = resolvedPackage + " (" + resolvedEcosystem + ")";
        return new ComponentIdentityDescriptor(canonicalKey, displayName);
    }

    private String normalizeOrFallback(String preferred, String fallback, String defaultValue) {
        String normalizedPreferred = IdentityUtil.normalize(preferred);
        if (!normalizedPreferred.isBlank() && !"unknown".equals(normalizedPreferred)) {
            return normalizedPreferred;
        }
        String normalizedFallback = IdentityUtil.normalize(fallback);
        if (!normalizedFallback.isBlank()) {
            return normalizedFallback;
        }
        return defaultValue;
    }

    private double max(Double existing, double next) {
        if (existing == null) {
            return next;
        }
        return Math.max(existing, next);
    }

    private String identifierCacheKey(SoftwareIdentity identity, IdentifierType type, String normalizedValue) {
        return identity.getId() + "::" + type.name() + "::" + normalizedValue;
    }

    private String linkCacheKey(SoftwareIdentifier from, SoftwareIdentifier to, String linkType, String source) {
        return from.getId() + "::" + to.getId() + "::" + linkType + "::" + source;
    }

    public record ComponentIdentityInput(
            String ecosystem,
            String packageName,
            String purl,
            String source
    ) {
    }

    private record ComponentIdentityDescriptor(
            String canonicalKey,
            String displayName
    ) {
    }
}
