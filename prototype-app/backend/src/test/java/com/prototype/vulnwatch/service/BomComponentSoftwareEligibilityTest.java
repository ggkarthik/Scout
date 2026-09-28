package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Which component types belong in software inventory and vulnerability correlation.
 *
 * <p>The decision is per component type, not per BOM type. An AI-BOM lists the software its
 * models depend on, and surfacing a dependency CVE against a declared model is the point of
 * ingesting one -- so keying this on the document type would defeat the feature.
 */
class BomComponentSoftwareEligibilityTest {

    private final BomComponentCategorizationService service = new BomComponentCategorizationService();

    @ParameterizedTest
    @ValueSource(strings = {"library", "application", "framework", "container",
            "operating-system", "firmware", "file", "device"})
    void softwareTypesEnterInventory(String componentType) {
        assertTrue(service.entersSoftwareInventory(componentType), componentType);
    }

    // A model has no CPE and no CVEs. Correlating one produces findings against an artifact
    // that was never a package.
    @ParameterizedTest
    @ValueSource(strings = {"machine-learning-model", "ml-model", "ai-model", "model",
            "data", "dataset"})
    void modelsAndDatasetsDoNotEnterInventory(String componentType) {
        assertFalse(service.entersSoftwareInventory(componentType), componentType);
    }

    // Cryptographic assets have their own evaluator and findings store.
    @ParameterizedTest
    @ValueSource(strings = {"cryptographic-asset", "crypto", "certificate", "key"})
    void cryptographicAssetsDoNotEnterInventory(String componentType) {
        assertFalse(service.entersSoftwareInventory(componentType), componentType);
    }

    @ParameterizedTest
    @ValueSource(strings = {"MACHINE-LEARNING-MODEL", "  Dataset  ", "Cryptographic-Asset"})
    void classificationIsCaseAndWhitespaceInsensitive(String componentType) {
        assertFalse(service.entersSoftwareInventory(componentType), componentType);
    }

    /**
     * Unknown and absent types are treated as software on purpose. Dropping a component we
     * cannot classify would silently lose real vulnerability coverage, which is worse than
     * carrying an occasional non-package through correlation.
     */
    @Test
    void anUnknownOrAbsentTypeIsTreatedAsSoftware() {
        assertTrue(service.entersSoftwareInventory(null));
        assertTrue(service.entersSoftwareInventory(""));
        assertTrue(service.entersSoftwareInventory("   "));
        assertTrue(service.entersSoftwareInventory("some-future-cyclonedx-type"));
    }
}
