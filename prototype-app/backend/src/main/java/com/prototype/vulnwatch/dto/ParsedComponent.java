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
        String scope
) {
}
