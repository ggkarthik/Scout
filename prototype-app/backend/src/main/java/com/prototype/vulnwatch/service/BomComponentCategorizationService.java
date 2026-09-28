package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.prototype.vulnwatch.domain.BomComponentCategory;
import com.prototype.vulnwatch.domain.BomType;
import java.util.Locale;
import org.springframework.stereotype.Service;

/**
 * Derives BomComponentCategory from raw CycloneDX / SPDX component type field
 * and the parent BOM type.
 */
@Service
public class BomComponentCategorizationService {

    /**
     * Component types that are not software and must stay out of software inventory and
     * vulnerability correlation. A model has no CPE and no CVEs; correlating one produces
     * false findings against an artifact that was never a package.
     */
    private static final java.util.Set<String> NON_SOFTWARE_TYPES = java.util.Set.of(
            "machine-learning-model", "ml-model", "ai-model", "model",
            "data", "dataset",
            "cryptographic-asset", "crypto", "certificate", "key");

    /**
     * Whether a component of this type belongs in software inventory and vulnerability
     * correlation.
     *
     * <p>Keyed on the component's own type, deliberately not on the BOM type. An AI-BOM
     * legitimately lists the software its models depend on, and a dependency CVE reported
     * against a declared model is precisely what AI-BOM ingestion is for -- so excluding
     * everything in an AI-BOM would defeat the feature. Only the component types that are
     * not software are excluded, whichever document they arrive in.
     *
     * <p>An unrecognised or absent type is treated as software. Dropping a component we
     * cannot classify would silently lose real vulnerability coverage, which is the worse
     * failure of the two.
     */
    public boolean entersSoftwareInventory(String rawComponentType) {
        if (rawComponentType == null || rawComponentType.isBlank()) {
            return true;
        }
        return !NON_SOFTWARE_TYPES.contains(rawComponentType.trim().toLowerCase(Locale.ROOT));
    }

    public BomComponentCategory categorize(String rawComponentType, BomType bomType, String supplier) {
        if (bomType == BomType.AI_BOM) {
            return BomComponentCategory.AI_MODEL;
        }
        if (bomType == BomType.CBOM) {
            return BomComponentCategory.CRYPTOGRAPHIC;
        }
        if (bomType == BomType.VENDOR) {
            return BomComponentCategory.VENDOR_SUPPLIED;
        }
        // SBOM — derive from component type
        String type = rawComponentType == null ? "" : rawComponentType.trim().toLowerCase(Locale.ROOT);
        return switch (type) {
            case "machine-learning-model", "ml-model", "ai-model", "dataset" -> BomComponentCategory.AI_MODEL;
            case "cryptographic-asset", "crypto", "certificate", "key" -> BomComponentCategory.CRYPTOGRAPHIC;
            case "container", "operating-system", "platform" -> BomComponentCategory.OS;
            case "firmware" -> BomComponentCategory.THIRD_PARTY;
            case "application" -> BomComponentCategory.APP_COMPONENT;
            default -> isVendorSupplied(supplier)
                    ? BomComponentCategory.VENDOR_SUPPLIED
                    : BomComponentCategory.THIRD_PARTY;
        };
    }

    private boolean isVendorSupplied(String supplier) {
        if (supplier == null || supplier.isBlank()) return false;
        String s = supplier.toLowerCase(Locale.ROOT);
        return s.contains("microsoft") || s.contains("redhat") || s.contains("red hat")
                || s.contains("oracle") || s.contains("google") || s.contains("amazon");
    }

    public String extractComponentType(JsonNode componentNode) {
        if (componentNode == null) return null;
        String type = componentNode.path("type").asText(null);
        return (type == null || type.isBlank()) ? null : type.trim().toLowerCase(Locale.ROOT);
    }

    public String extractLicense(JsonNode componentNode) {
        if (componentNode == null) return null;
        // CycloneDX licenses array
        JsonNode licenses = componentNode.path("licenses");
        if (licenses.isArray() && !licenses.isEmpty()) {
            JsonNode first = licenses.get(0);
            String id = first.path("license").path("id").asText(null);
            if (id != null && !id.isBlank()) return id.trim();
            String name = first.path("license").path("name").asText(null);
            if (name != null && !name.isBlank()) return name.trim();
        }
        return null;
    }

    public String extractSupplier(JsonNode componentNode) {
        if (componentNode == null) return null;
        String s = componentNode.path("supplier").path("name").asText(null);
        if (s != null && !s.isBlank()) return s.trim();
        s = componentNode.path("publisher").asText(null);
        if (s != null && !s.isBlank()) return s.trim();
        s = componentNode.path("author").asText(null);
        return (s != null && !s.isBlank()) ? s.trim() : null;
    }
}
