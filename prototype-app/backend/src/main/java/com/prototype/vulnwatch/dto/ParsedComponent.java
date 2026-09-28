package com.prototype.vulnwatch.dto;

import java.util.List;

public record ParsedComponent(
        String ecosystem,
        String packageName,
        String version,
        String purl,
        String digest,
        List<String> cpes,
        String packageGroup,
        String license,
        String scope,
        /**
         * Raw CycloneDX/SPDX component type, e.g. library, application,
         * machine-learning-model, data, cryptographic-asset. Previously discarded here, which
         * left the software-inventory path unable to tell a model from an npm package.
         */
        String componentType
) {
}
