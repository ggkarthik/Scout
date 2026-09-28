package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AiBomDeclaredIdentityKind;
import com.prototype.vulnwatch.domain.AiBomDeclaredResourceKind;
import com.prototype.vulnwatch.domain.BomComponent;
import org.junit.jupiter.api.Test;

class AiBomDeclaredResourceIdentityResolverTest {

    private final AiBomDeclaredResourceIdentityResolver resolver =
            new AiBomDeclaredResourceIdentityResolver(new ObjectMapper());

    private static BomComponent component(String type, String name, String version, String purl,
            String bomRef, String hashesJson) {
        BomComponent component = new BomComponent();
        component.setComponentType(type);
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setBomRef(bomRef);
        component.setHashes(hashesJson);
        return component;
    }

    @Test
    void digestWinsOverAVersionedPurlWhenBothArePresent() {
        BomComponent component = component(
                "machine-learning-model", "llama-3", "3.1", "pkg:huggingface/llama-3@3.1", null,
                "[{\"alg\":\"SHA-256\",\"content\":\"ABCDEF\"}]");

        AiBomDeclaredResourceIdentityResolver.Identity identity = resolver.resolve(component);

        assertEquals(AiBomDeclaredIdentityKind.DIGEST, identity.kind());
        assertEquals("sha-256:abcdef", identity.value());
    }

    @Test
    void prefersSha256AmongMultipleHashes() {
        BomComponent component = component(
                "model", "llama-3", "3.1", null, null,
                "[{\"alg\":\"MD5\",\"content\":\"AAAA\"},{\"alg\":\"SHA-256\",\"content\":\"BBBB\"}]");

        AiBomDeclaredResourceIdentityResolver.Identity identity = resolver.resolve(component);

        assertEquals(AiBomDeclaredIdentityKind.DIGEST, identity.kind());
        assertEquals("sha-256:bbbb", identity.value());
    }

    @Test
    void versionedPurlIsUsedWhenNoDigestIsPresent() {
        BomComponent component = component(
                "model", "llama-3", "3.1", "pkg:huggingface/llama-3@3.1", "bom-ref-1", null);

        AiBomDeclaredResourceIdentityResolver.Identity identity = resolver.resolve(component);

        assertEquals(AiBomDeclaredIdentityKind.VERSIONED_IDENTIFIER, identity.kind());
        assertEquals("pkg:huggingface/llama-3@3.1", identity.value());
    }

    @Test
    void aPurlWithoutAVersionFallsThroughToSourceScoped() {
        BomComponent component = component(
                "model", "llama-3", null, "pkg:huggingface/llama-3", "bom-ref-1", null);

        AiBomDeclaredResourceIdentityResolver.Identity identity = resolver.resolve(component);

        assertEquals(AiBomDeclaredIdentityKind.SOURCE_SCOPED_REF, identity.kind());
        assertEquals("bomref:bom-ref-1", identity.value());
    }

    @Test
    void bomRefIsUsedWhenThereIsNoPurl() {
        BomComponent component = component("data", "training-corpus", "2024.1", null, "corpus-ref", null);

        AiBomDeclaredResourceIdentityResolver.Identity identity = resolver.resolve(component);

        assertEquals(AiBomDeclaredIdentityKind.SOURCE_SCOPED_REF, identity.kind());
        assertEquals("bomref:corpus-ref", identity.value());
    }

    @Test
    void nameAndVersionAreTheLastResortWhenNothingElseIsAvailable() {
        BomComponent component = component("dataset", "Training Corpus", "2024.1", null, null, null);

        AiBomDeclaredResourceIdentityResolver.Identity identity = resolver.resolve(component);

        assertEquals(AiBomDeclaredIdentityKind.SOURCE_SCOPED_REF, identity.kind());
        assertEquals("nv:training corpus|2024.1", identity.value());
    }

    @Test
    void twoComponentsWithOnlyANameInCommonDoNotResolveToTheSameIdentityWhenDetailsDiffer() {
        BomComponent a = component("model", "classifier", "1.0", null, null, null);
        BomComponent b = component("model", "classifier", "2.0", null, null, null);

        assertNotEquals(resolver.resolve(a).value(), resolver.resolve(b).value());
    }

    @Test
    void machineLearningModelTypesResolveToModel() {
        for (String type : new String[] {"machine-learning-model", "ml-model", "ai-model", "model"}) {
            BomComponent component = component(type, "n", "1.0", null, null, null);
            assertEquals(AiBomDeclaredResourceKind.MODEL, resolver.resourceKind(component), type);
        }
    }

    @Test
    void dataAndDatasetTypesResolveToDataset() {
        for (String type : new String[] {"data", "dataset"}) {
            BomComponent component = component(type, "n", "1.0", null, null, null);
            assertEquals(AiBomDeclaredResourceKind.DATASET, resolver.resourceKind(component), type);
        }
    }

    @Test
    void anUnrecognisedDeclaredTypeDefaultsToModelRatherThanBeingDropped() {
        BomComponent component = component("some-future-ai-artifact-type", "n", "1.0", null, null, null);
        assertEquals(AiBomDeclaredResourceKind.MODEL, resolver.resourceKind(component));
    }

    @Test
    void malformedHashesJsonIsIgnoredRatherThanThrowing() {
        BomComponent component = component("model", "n", "1.0", "pkg:generic/n@1.0", null, "not json");

        AiBomDeclaredResourceIdentityResolver.Identity identity = resolver.resolve(component);

        assertEquals(AiBomDeclaredIdentityKind.VERSIONED_IDENTIFIER, identity.kind());
    }
}
