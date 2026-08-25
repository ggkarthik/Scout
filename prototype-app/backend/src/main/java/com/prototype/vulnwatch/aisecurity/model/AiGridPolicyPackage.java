package com.prototype.vulnwatch.aisecurity.model;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/** Immutable on-disk/package contract for the Phase 1 governed catalog. */
public record AiGridPolicyPackage(
        String policyId, String version, String name, String description, String securityIntent,
        String remediationIntent, String owner, String lifecycle, String releaseStatus,
        String controlObjectiveId, String provider, String evaluationMode,
        EvaluationDefinition evaluationDefinition, List<String> baseEvidenceTiers,
        List<String> conditionalCapabilities, String defaultSelection, String releaseFamily, String wave,
        List<String> artifactTypes, List<String> requiredCapabilities, List<String> requiredRelationships,
        List<String> requiredResourceFamilies, List<FactRequirement> requiredFacts,
        List<FrameworkMapping> frameworkMappings, List<ParameterDefinition> parameterDefinitions,
        CertificationParameterProfile certificationParameterProfile, String packageSourceRef) {
    public record EvaluationDefinition(String mode, JsonNode artifactFacts, JsonNode directRelationship,
                                       JsonNode correlationPath) {}
    public record FactRequirement(String factKey, String valueType, List<String> evidenceClasses, long maxAgeSeconds) {}
    public record FrameworkMapping(String framework, String frameworkVersion, String controlId,
                                   String mappingType, String rationale) {}
    public record ParameterDefinition(String key, String type, JsonNode defaultValue) {}
    public record CertificationParameterProfile(boolean immutable, JsonNode pass, JsonNode fail, JsonNode invalid) {}
}
