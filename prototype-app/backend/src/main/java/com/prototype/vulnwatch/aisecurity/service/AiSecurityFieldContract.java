package com.prototype.vulnwatch.aisecurity.service;

import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Independent storage/response/filter policy for metadata fields. */
public final class AiSecurityFieldContract {
    public enum Tier { STORAGE_ALLOWED, RESPONSE_ALLOWED, FILTER_ALLOWED }

    /** Internal comparison values: persisted only after the collector has HMACed the source. */
    private static final Set<String> STORAGE_ONLY = Set.of(
            "promptDigest", "toolDefinitionDigest", "digestAlgorithm", "digestKeyVersion",
            "modelDataS3Uri", "trainingDataS3Uri", "validationDataS3Uris", "principalId",
            "providerNativeId", "providerNativeVersionId");
    private static final Set<String> FILTERABLE = Set.of(
            "sourceType", "sensitivity", "publicContentAccess", "configuredAuthType", "inboundAuthType",
            "outboundAuthType", "endpointExposure", "status", "environment", "provider", "artifactType",
            "nativeKind", "accountId", "region");
    private static final Map<String, Set<String>> NESTED_PUBLIC_METADATA = Map.of(
            "contentFilters", Set.of("type", "inputStrength", "outputStrength", "inputEnabled", "outputEnabled"),
            "deniedTopics", Set.of("name", "inputAction", "outputAction"),
            "piiEntities", Set.of("type", "inputAction", "outputAction"),
            "contextualGroundingFilters", Set.of("type", "threshold", "action"),
            "evidence", Set.of("sourceApi", "field"));
    private static final Set<String> DYNAMIC_PUBLIC_METADATA = Set.of("tags");
    private static final Pattern SENSITIVE_DYNAMIC_FIELD = Pattern.compile(
            "(?i)(secret|password|credential|authorization|token|api[_-]?key|private[_-]?key|"
                    + "prompt|completion|input[_-]?text|output[_-]?text|document[_-]?body|raw[_-]?trace|"
                    + "tool[_-]?arguments?|request[_-]?body|response[_-]?body|connection[_-]?string|headers?)");
    /**
     * Closed, response-safe metadata contract.  Adding a collector field requires an explicit
     * review here as well as in {@link AiSecurityMetadataSanitizer}; attributes_json is never a
     * public extension point.
     */
    private static final Set<String> PUBLIC_METADATA = Set.of(
            "actionGroupId", "agentCoreRootQualified", "agentId", "aliasId", "aliasName", "architecture", "assignmentScope", "authMode", "authoritativeWorkloadBoundaryObserved", "azureResourceType", "backingStore", "baseModelArn",
            "botPasswordAuthWithoutManagedIdentity", "capacity", "codeInterpreterEnabled", "classification", "componentType",
            "commitmentDuration", "commitmentExpirationTime", "conditionVersion", "configurationSubtype",
            "bodyStored", "browserId", "codeInterpreterId", "configuredAuthType", "confidence", "contentFilterCount", "contentFilters", "creationMode",
            "contextualGroundingFilterCount", "contextualGroundingFilters", "createdAt", "customWordFilterCount",
            "customerManagedKey", "customizationType", "customizationsSupported", "dataSourceAccessCount",
            "dataSourceCount", "datastoreId", "deletionPolicy", "deniedTopicCount", "deniedTopics",
            "deployedArtifact", "definitionBodyStored", "diagnosticLoggingEnabled", "disableLocalAuth", "domainId", "endpointComputeType", "endpointExposure",
            "endpointHost", "environment", "evidence", "evidenceSource", "executionRoleArn", "experimentName", "foundationModel",
            "functionUrlAuthType", "guardrailAttached", "guardrailId", "guardrailMinimumStrength", "hasDestination",
            "crossAccountTrust", "iamEvidenceAvailable", "iamNotAction", "iamNotResource", "iamPassRole",
            "iamWildcardActions", "iamWildcardResources", "identityType", "inboundAuthType", "inferenceTypesSupported",
            "ingestionConfigurationPresent", "inputModalities", "instanceType", "instructSupported",
            "invocationLoggingEnabled", "invocationState", "jobName", "jobType", "kind", "kmsKeyArn", "lambdaArn", "lambdaUrlAuthType",
            "lastSynchronizedAt", "localAuthEnabled", "location", "managed", "managedIdentityAssigned",
            "minimumStrength", "mlLocalAuthEnabled", "model", "modelArn", "modelDeployment", "modelFormat",
            "modelKmsKeyArn", "modelLifecycleStatus", "modelName", "modelPublisher", "modelType", "modelVersion",
            "msaAppType", "nativeKind", "networkDefaultAction", "originalArmId", "outboundAuthType", "outputModalities",
            "memoryId", "ownerAccountId", "permissionBoundaryAttached", "piiEntities", "piiEntityCount", "principalType", "privateEndpoint", "privateEndpointCount",
            "productionVariants", "profanityFilterEnabled", "protocol", "provider", "providerName", "provisioningState",
            "public", "publicContentAccess", "publicNetworkAccess", "publicNetworkUnrestricted", "publiclyAccessible",
            "publicEndpoint", "raiBasePolicyName", "raiCustomBlocklistCount", "raiFilterCount", "raiFilterEvidenceComplete",
            "raiNonBlockingFilterCount", "raiNonBlockingFilterObserved", "raiPolicyMode", "raiPolicyName", "referenceOnly",
            "referencedBy", "region", "resourceGroup", "retrievalMode", "roleDefinitionId", "s3Buckets", "s3Public",
            "promptLength", "promptType", "roleArn", "routedVersions", "runtimeId", "scaleType", "scopeKey", "searchLocalAuthEnabled", "sensitivity", "sensitiveRegexCount", "signature", "source", "state", "trustConditionsPresent", "type",
            "sourceType", "stableMembershipObserved", "stableRuntimeArnObserved", "status", "storeType", "tags", "toolType", "traffic", "updatedAt", "version",
            "versionUpgradeOption", "vpcId", "aclSupport");

    private AiSecurityFieldContract() { }

    public static boolean allows(String field, Tier tier) {
        if (field == null) return false;
        if (STORAGE_ONLY.contains(field)) return tier == Tier.STORAGE_ALLOWED;
        if (tier == Tier.FILTER_ALLOWED) return FILTERABLE.contains(field);
        // Explicitly reviewed public names win over broad deny-list substrings.  For example,
        // publicContentAccess and contentFilterCount are safe booleans/counts, not raw content.
        if (PUBLIC_METADATA.contains(field)) return true;
        return false;
    }

    public static Map<String, Object> responseSafe(Map<String, Object> attributes) {
        return filter(attributes, Tier.RESPONSE_ALLOWED);
    }

    public static Map<String, Object> storageSafe(Map<String, Object> attributes) {
        return filter(attributes, Tier.STORAGE_ALLOWED);
    }

    static boolean allowsNested(String parentPath, String field, Tier tier) {
        if (parentPath == null || field == null || tier == Tier.FILTER_ALLOWED) return false;
        int bracket = parentPath.indexOf('[');
        int dot = parentPath.indexOf('.');
        int separator = bracket < 0 ? dot : dot < 0 ? bracket : Math.min(bracket, dot);
        String root = separator < 0 ? parentPath : parentPath.substring(0, separator);
        if (DYNAMIC_PUBLIC_METADATA.contains(root)) {
            return !field.isBlank() && field.length() <= 128 && !SENSITIVE_DYNAMIC_FIELD.matcher(field).find();
        }
        return NESTED_PUBLIC_METADATA.getOrDefault(root, Set.of()).contains(field);
    }

    private static Map<String, Object> filter(Map<String, Object> attributes, Tier tier) {
        Map<String, Object> clean = new LinkedHashMap<>();
        if (attributes == null) return clean;
        attributes.forEach((key, value) -> {
            if (!allows(key, tier)) return;
            clean.put(key, filterValue(value, tier, key));
        });
        return clean;
    }

    private static Object filterValue(Object value, Tier tier, String path) {
        if (value instanceof Map<?, ?> nested) {
            Map<String, Object> child = new LinkedHashMap<>();
            nested.forEach((nestedKey, nestedValue) -> {
                String key = String.valueOf(nestedKey);
                if (allowsNested(path, key, tier)) {
                    child.put(key, filterValue(nestedValue, tier, path + "." + key));
                }
            });
            return child;
        }
        if (value instanceof List<?> list) {
            List<Object> child = new ArrayList<>();
            list.forEach(item -> child.add(filterValue(item, tier, path)));
            return child;
        }
        return value;
    }
}
