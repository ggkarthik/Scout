package com.prototype.vulnwatch.aisecurity.service;

import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
    /**
     * Closed, response-safe metadata contract.  Adding a collector field requires an explicit
     * review here as well as in {@link AiSecurityMetadataSanitizer}; attributes_json is never a
     * public extension point.
     */
    private static final Set<String> PUBLIC_METADATA = Set.of(
            "agentId", "architecture", "assignmentScope", "authMode", "azureResourceType", "baseModelArn",
            "botPasswordAuthWithoutManagedIdentity", "capacity", "codeInterpreterEnabled", "classification", "componentType",
            "commitmentDuration", "commitmentExpirationTime", "conditionVersion", "configurationSubtype",
            "configuredAuthType", "confidence", "contentFilterCount", "contentFilters",
            "contextualGroundingFilterCount", "contextualGroundingFilters", "createdAt", "customWordFilterCount",
            "customerManagedKey", "customizationType", "customizationsSupported", "dataSourceAccessCount",
            "dataSourceCount", "datastoreId", "deletionPolicy", "deniedTopicCount", "deniedTopics",
            "diagnosticLoggingEnabled", "disableLocalAuth", "domainId", "endpointComputeType", "endpointExposure",
            "endpointHost", "environment", "evidence", "executionRoleArn", "experimentName", "field", "foundationModel",
            "functionUrlAuthType", "guardrailAttached", "guardrailId", "guardrailMinimumStrength", "hasDestination",
            "iamEvidenceAvailable", "iamWildcardActions", "identityType", "inboundAuthType", "inferenceTypesSupported",
            "ingestionConfigurationPresent", "inputModalities", "instanceType", "instructSupported",
            "invocationLoggingEnabled", "jobName", "jobType", "kind", "kmsKeyArn", "lambdaUrlAuthType",
            "lastSynchronizedAt", "localAuthEnabled", "location", "managed", "managedIdentityAssigned",
            "minimumStrength", "mlLocalAuthEnabled", "model", "modelArn", "modelDeployment", "modelFormat",
            "modelKmsKeyArn", "modelLifecycleStatus", "modelName", "modelPublisher", "modelType", "modelVersion",
            "msaAppType", "nativeKind", "networkDefaultAction", "originalArmId", "outboundAuthType", "outputModalities",
            "ownerAccountId", "piiEntities", "piiEntityCount", "principalType", "privateEndpoint", "privateEndpointCount",
            "productionVariants", "profanityFilterEnabled", "protocol", "provider", "providerName", "provisioningState",
            "public", "publicContentAccess", "publicNetworkAccess", "publicNetworkUnrestricted", "publiclyAccessible",
            "publicEndpoint", "raiBasePolicyName", "raiCustomBlocklistCount", "raiFilterCount", "raiFilterEvidenceComplete",
            "raiNonBlockingFilterCount", "raiNonBlockingFilterObserved", "raiPolicyMode", "raiPolicyName", "referenceOnly",
            "referencedBy", "region", "resourceGroup", "retrievalMode", "roleDefinitionId", "s3Buckets", "s3Public",
            "scaleType", "scopeKey", "searchLocalAuthEnabled", "sensitivity", "sensitiveRegexCount", "source",
            "sourceApi", "sourceType", "status", "storeType", "tags", "toolType", "traffic", "updatedAt", "version",
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

    private static Map<String, Object> filter(Map<String, Object> attributes, Tier tier) {
        Map<String, Object> clean = new LinkedHashMap<>();
        if (attributes == null) return clean;
        attributes.forEach((key, value) -> {
            if (!allows(key, tier)) return;
            clean.put(key, filterValue(value, tier));
        });
        return clean;
    }

    private static Object filterValue(Object value, Tier tier) {
        if (value instanceof Map<?, ?> nested) {
            Map<String, Object> child = new LinkedHashMap<>();
            nested.forEach((nestedKey, nestedValue) -> {
                String key = String.valueOf(nestedKey);
                if (allows(key, tier)) child.put(key, filterValue(nestedValue, tier));
            });
            return child;
        }
        if (value instanceof List<?> list) {
            List<Object> child = new ArrayList<>();
            list.forEach(item -> child.add(filterValue(item, tier)));
            return child;
        }
        return value;
    }
}
