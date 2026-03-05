package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.SoftwareModel;
import com.prototype.vulnwatch.repo.SoftwareModelRepository;
import com.prototype.vulnwatch.util.CpeUtil;
import com.prototype.vulnwatch.util.PurlUtil;
import java.util.Locale;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SoftwareModelService {

    private final SoftwareModelRepository softwareModelRepository;

    public SoftwareModelService(SoftwareModelRepository softwareModelRepository) {
        this.softwareModelRepository = softwareModelRepository;
    }

    @Transactional
    public SoftwareModel resolveFromComponent(String ecosystem, String packageName, String purl) {
        PurlUtil.ParsedPurl parsed = PurlUtil.parse(purl);
        String resolvedPublisher = normalize(parsed.namespace().isBlank() ? ecosystem : parsed.namespace());
        String resolvedProduct = normalize(parsed.packageName().equals("unknown") ? packageName : parsed.packageName());
        String primaryIdentifier = purl == null || purl.isBlank()
                ? ("pkg:" + normalize(ecosystem) + "/" + resolvedProduct)
                : purl;

        return resolve(
                resolvedPublisher.isBlank() ? "generic" : resolvedPublisher,
                resolvedProduct.isBlank() ? "unknown" : resolvedProduct,
                "purl",
                primaryIdentifier);
    }

    @Transactional
    public SoftwareModel resolveFromRule(String ecosystem, String packageName, String cpe) {
        CpeUtil.ParsedCpe parsed = CpeUtil.parse(cpe);
        String publisher = normalize(parsed.vendor());
        String product = normalize(parsed.product());

        if (publisher.isBlank()) {
            publisher = normalize(ecosystem);
        }
        if (product.isBlank()) {
            product = normalize(packageName);
        }

        String primaryType = cpe == null || cpe.isBlank() ? "package" : "cpe";
        String primaryIdentifier = cpe == null || cpe.isBlank()
                ? normalize(ecosystem) + ":" + normalize(packageName)
                : cpe;

        return resolve(
                publisher.isBlank() ? "generic" : publisher,
                product.isBlank() ? "unknown" : product,
                primaryType,
                primaryIdentifier);
    }

    private SoftwareModel resolve(
            String canonicalPublisher,
            String canonicalProduct,
            String primaryIdentifierType,
            String primaryIdentifier
    ) {
        String normalizedKey = normalize(canonicalPublisher) + ":" + normalize(canonicalProduct);
        return softwareModelRepository.findByNormalizedKey(normalizedKey)
                .map(existing -> {
                    existing.setCanonicalPublisher(canonicalPublisher);
                    existing.setCanonicalProduct(canonicalProduct);
                    existing.setPrimaryIdentifierType(primaryIdentifierType);
                    existing.setPrimaryIdentifier(primaryIdentifier);
                    existing.touch();
                    return softwareModelRepository.save(existing);
                })
                .orElseGet(() -> {
                    SoftwareModel created = new SoftwareModel();
                    created.setNormalizedKey(normalizedKey);
                    created.setCanonicalPublisher(canonicalPublisher);
                    created.setCanonicalProduct(canonicalProduct);
                    created.setPrimaryIdentifierType(primaryIdentifierType);
                    created.setPrimaryIdentifier(primaryIdentifier);
                    return softwareModelRepository.save(created);
                });
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
