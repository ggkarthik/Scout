package com.prototype.vulnwatch.dto.patch;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PatchConnectorStatusResponse {
    private String connectorType;
    private String name;
    private String version;
    private List<String> supportedEcosystems;
    private boolean enabled;
}
