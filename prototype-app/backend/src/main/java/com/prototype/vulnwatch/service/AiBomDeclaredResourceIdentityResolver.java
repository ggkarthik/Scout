package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AiBomDeclaredIdentityKind;
import com.prototype.vulnwatch.domain.AiBomDeclaredResourceKind;
import com.prototype.vulnwatch.domain.BomComponent;
import com.prototype.vulnwatch.util.IdentityUtil;
import com.prototype.vulnwatch.util.PurlUtil;
import java.util.Locale;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Resolves what a declared AI-BOM component is (model vs dataset) and how it should be
 * identified, in the same descending order of trustworthiness the schema documents: an
 * immutable content digest, then a versioned purl, then a reference scoped to the declaring
 * source. A display name is never an identity -- two unrelated models are routinely both
 * called "classifier", so falling back to name alone would merge resources the document never
 * claimed were the same.
 */
@Component
public class AiBomDeclaredResourceIdentityResolver {

    private static final Set<String> MODEL_TYPES =
            Set.of("machine-learning-model", "ml-model", "ai-model", "model");
    private static final Set<String> DATASET_TYPES = Set.of("data", "dataset");

    private final ObjectMapper objectMapper;

    public AiBomDeclaredResourceIdentityResolver(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public record Identity(AiBomDeclaredIdentityKind kind, String value) {
    }

    /**
     * A dataset is not a model. Anything reaching this method was already classified
     * non-software by {@link BomComponentCategorizationService}; an unrecognised declared
     * type defaults to MODEL rather than silently discarding the declaration.
     */
    public AiBomDeclaredResourceKind resourceKind(BomComponent component) {
        String type = normalizedType(component);
        if (DATASET_TYPES.contains(type)) {
            return AiBomDeclaredResourceKind.DATASET;
        }
        return AiBomDeclaredResourceKind.MODEL;
    }

    public Identity resolve(BomComponent component) {
        String digest = extractDigest(component.getHashes());
        if (digest != null) {
            return new Identity(AiBomDeclaredIdentityKind.DIGEST, digest);
        }

        String purl = component.getPurl();
        if (purl != null && !purl.isBlank()) {
            PurlUtil.ParsedPurl parsed = PurlUtil.parse(purl);
            if (parsed != null && parsed.version() != null && !parsed.version().isBlank()) {
                return new Identity(AiBomDeclaredIdentityKind.VERSIONED_IDENTIFIER,
                        IdentityUtil.normalizePurl(purl));
            }
        }

        String bomRef = component.getBomRef();
        if (bomRef != null && !bomRef.isBlank()) {
            return new Identity(AiBomDeclaredIdentityKind.SOURCE_SCOPED_REF, "bomref:" + bomRef.trim());
        }

        String name = component.getName() == null ? "" : component.getName().trim().toLowerCase(Locale.ROOT);
        String version = component.getVersion() == null
                ? ""
                : component.getVersion().trim().toLowerCase(Locale.ROOT);
        return new Identity(AiBomDeclaredIdentityKind.SOURCE_SCOPED_REF, "nv:" + name + "|" + version);
    }

    private String normalizedType(BomComponent component) {
        String type = component.getComponentType();
        return type == null ? "" : type.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * {@code component.getHashes()} is the CycloneDX {@code hashes} array verbatim:
     * {@code [{"alg":"SHA-256","content":"..."}]}. SHA-256 is preferred when more than one
     * hash is present; otherwise the first usable entry wins.
     */
    private String extractDigest(String hashesJson) {
        if (hashesJson == null || hashesJson.isBlank()) {
            return null;
        }
        try {
            JsonNode node = objectMapper.readTree(hashesJson);
            if (!node.isArray() || node.isEmpty()) {
                return null;
            }
            JsonNode preferred = null;
            for (JsonNode entry : node) {
                String content = entry.path("content").asText("");
                if (content.isBlank()) {
                    continue;
                }
                if ("SHA-256".equalsIgnoreCase(entry.path("alg").asText(""))) {
                    preferred = entry;
                    break;
                }
                if (preferred == null) {
                    preferred = entry;
                }
            }
            if (preferred == null) {
                return null;
            }
            String alg = preferred.path("alg").asText("").trim().toLowerCase(Locale.ROOT);
            String content = preferred.path("content").asText("").trim().toLowerCase(Locale.ROOT);
            return alg.isBlank() ? content : alg + ":" + content;
        } catch (Exception ignored) {
            return null;
        }
    }
}
