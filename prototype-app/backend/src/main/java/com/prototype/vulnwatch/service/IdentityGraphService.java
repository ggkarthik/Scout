package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.IdentifierType;
import com.prototype.vulnwatch.domain.IdentityLink;
import com.prototype.vulnwatch.domain.SoftwareIdentifier;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.repo.IdentityLinkRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentifierRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import com.prototype.vulnwatch.util.IdentityUtil;
import com.prototype.vulnwatch.util.PurlUtil;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IdentityGraphService {

    private final SoftwareIdentityRepository softwareIdentityRepository;
    private final SoftwareIdentifierRepository softwareIdentifierRepository;
    private final IdentityLinkRepository identityLinkRepository;

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

        linkIdentifiers(identifiers, "equivalent", source, 0.9, true);
        return identity;
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

        linkIdentifiers(identifiers, "crosswalk", source, 0.8, false);
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
        if (normalized.isBlank()) {
            return null;
        }
        String sourceValue = source == null || source.isBlank() ? "system" : source.toLowerCase(Locale.ROOT);
        return softwareIdentifierRepository
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
    }

    private void linkIdentifiers(
            List<SoftwareIdentifier> identifiers,
            String linkType,
            String source,
            double confidence,
            boolean verified
    ) {
        List<SoftwareIdentifier> filtered = identifiers.stream()
                .filter(identifier -> identifier != null)
                .toList();
        for (int i = 0; i < filtered.size(); i++) {
            for (int j = i + 1; j < filtered.size(); j++) {
                upsertLink(filtered.get(i), filtered.get(j), linkType, source, confidence, verified);
                upsertLink(filtered.get(j), filtered.get(i), linkType, source, confidence, verified);
            }
        }
    }

    private void upsertLink(
            SoftwareIdentifier from,
            SoftwareIdentifier to,
            String linkType,
            String source,
            double confidence,
            boolean verified
    ) {
        if (from == null || to == null || from.getId().equals(to.getId())) {
            return;
        }
        String sourceValue = source == null || source.isBlank() ? "system" : source.toLowerCase(Locale.ROOT);
        identityLinkRepository
                .findByFromIdentifierAndToIdentifierAndLinkTypeAndSource(from, to, linkType, sourceValue)
                .map(existing -> {
                    existing.setVerified(existing.isVerified() || verified);
                    existing.setConfidence(max(existing.getConfidence(), confidence));
                    return identityLinkRepository.save(existing);
                })
                .orElseGet(() -> {
                    IdentityLink link = new IdentityLink();
                    link.setFromIdentifier(from);
                    link.setToIdentifier(to);
                    link.setLinkType(linkType);
                    link.setSource(sourceValue);
                    link.setVerified(verified);
                    link.setConfidence(confidence);
                    return identityLinkRepository.save(link);
                });
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
}
