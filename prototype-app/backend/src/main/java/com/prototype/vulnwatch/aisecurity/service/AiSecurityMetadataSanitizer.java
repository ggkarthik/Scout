package com.prototype.vulnwatch.aisecurity.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Boundary sanitizer for collector metadata.  Discovery is intentionally metadata-only: text
 * payloads, credentials and request/response material are never allowed into a tenant schema.
 * The limits also make a malformed provider response unable to turn an observation into an
 * unbounded JSON document.  Callers retain the observation when a field is rejected.
 */
@Component
public class AiSecurityMetadataSanitizer {
    static final int MAX_DEPTH = 4;
    static final int MAX_FIELDS = 64;
    static final int MAX_LIST_ITEMS = 100;
    static final int MAX_STRING_LENGTH = 2_048;
    static final int MAX_SERIALIZED_SIZE = 32 * 1024;
    private static final Pattern PROHIBITED = Pattern.compile(
            "(?i)(secret|password|credential|authorization|token|api[_-]?key|private[_-]?key|"
                    + "prompt|completion|input[_-]?text|output[_-]?text|document[_-]?body|raw[_-]?trace|"
                    + "tool[_-]?arguments?|request[_-]?body|response[_-]?body|connection[_-]?string|"
                    + "headers?|openapi|smithy|schema|parameter[_-]?defaults?)");
    /** Version 1 registry: every native kind emitted by the current AWS/Azure collectors. */
    private static final Set<String> REGISTERED_NATIVE_KINDS = Set.of(
            "AWS_BEDROCK_AGENT", "AWS_BEDROCK_CUSTOM_MODEL", "AWS_BEDROCK_FLOW", "AWS_BEDROCK_GUARDRAIL",
            "AWS_BEDROCK_IMPORTED_MODEL", "AWS_BEDROCK_INFERENCE_PROFILE", "AWS_BEDROCK_INVOCATION_LOGGING",
            "AWS_BEDROCK_KNOWLEDGE_BASE", "AWS_BEDROCK_MODEL", "AWS_BEDROCK_MODEL_CUSTOMIZATION_JOB",
            "AWS_BEDROCK_PROMPT", "AWS_BEDROCK_PROVISIONED_MODEL", "AWS_BEDROCK_DATA_SOURCE", "AWS_LAMBDA_FUNCTION", "AWS_S3_BUCKET",
            "AWS_AGENTCORE_GATEWAY", "AWS_AGENTCORE_GATEWAY_TARGET", "AWS_AGENTCORE_MCP_SERVER",
            "AWS_SAGEMAKER_DOMAIN", "AWS_SAGEMAKER_ENDPOINT", "AWS_SAGEMAKER_ENDPOINT_CONFIGURATION",
            "AWS_SAGEMAKER_EXECUTION_ROLE", "AWS_SAGEMAKER_MODEL_PACKAGE", "AWS_SAGEMAKER_MODEL_PACKAGE_GROUP",
            "AWS_SAGEMAKER_MODEL_REFERENCE", "AWS_SAGEMAKER_NETWORK", "AWS_SAGEMAKER_NOTEBOOK_INSTANCE",
            "AWS_SAGEMAKER_PIPELINE", "AWS_SAGEMAKER_PROCESSING_JOB", "AWS_SAGEMAKER_SPACE",
            "AWS_SAGEMAKER_TRAINING_JOB", "AWS_SAGEMAKER_TRANSFORM_JOB", "AZURE_AI_ACCOUNTS", "AZURE_BOT",
            "AZURE_BOT_CHANNELS", "AZURE_BOT_IDENTITIES", "AZURE_BOT_SERVICES", "AZURE_DIAGNOSTIC_SETTINGS",
            "AZURE_FOUNDRY_AGENTS", "AZURE_FOUNDRY_AGENT_TOOLS", "AZURE_FOUNDRY_CONNECTIONS",
            "AZURE_FOUNDRY_DEPLOYMENTS", "AZURE_FOUNDRY_PROJECTS", "AZURE_ML_COMPUTE", "AZURE_ML_DEPLOYMENTS",
            "AZURE_ML_ENDPOINTS", "AZURE_ML_JOBS", "AZURE_ML_MODELS", "AZURE_ML_PIPELINES", "AZURE_ML_WORKSPACES",
            "AZURE_RAI_POLICIES", "AZURE_SEARCH_DATA_SOURCES", "AZURE_SEARCH_INDEXERS", "AZURE_SEARCH_INDEXES",
            "AZURE_SEARCH_KNOWLEDGE_BASES", "AZURE_SEARCH_KNOWLEDGE_SOURCES", "AZURE_SEARCH_MCP_SERVER",
            "AZURE_FOUNDRY_MCP_SERVER",
            "AZURE_SEARCH_SERVICES", "AZURE_SEARCH_SKILLSETS", "AZURE_STORAGE_ACCOUNTS", "AZURE_FABRIC_CAPACITIES");

    /**
     * Versioned top-level metadata schema. Provider-returned objects may contain new fields at any
     * time; those fields are rejected until Scout deliberately adds them here. Free-form content
     * fields such as descriptions, messages, instructions and provider error text are omitted.
     */
    private static final Set<String> ALLOWED_TOP_LEVEL_FIELDS = Set.of(
            "agentId", "architecture", "assignmentScope", "authMode", "azureResourceType",
            "baseModelArn", "botPasswordAuthWithoutManagedIdentity", "capacity", "codeInterpreterEnabled",
            "commitmentDuration", "commitmentExpirationTime", "conditionVersion", "configurationSubtype",
            "configuredAuthType", "contentFilterCount", "contentFilters", "contextualGroundingFilterCount",
            "contextualGroundingFilters", "createdAt", "customWordFilterCount", "customerManagedKey",
            "customizationType", "customizationsSupported", "dataSourceAccessCount", "dataSourceCount",
            "datastoreId", "deletionPolicy", "deniedTopicCount", "deniedTopics", "diagnosticLoggingEnabled",
            "disableLocalAuth", "domainId", "endpointComputeType", "endpointExposure", "endpointHost",
            "executionRoleArn", "experimentName", "foundationModel", "functionUrlAuthType", "guardrailAttached",
            "guardrailId", "guardrailMinimumStrength", "hasDestination", "iamEvidenceAvailable", "identityType",
            "inboundAuthType", "inferenceTypesSupported", "ingestionConfigurationPresent", "inputModalities",
            "instanceType", "instructSupported", "invocationLoggingEnabled", "jobName", "jobType", "kind",
            "kmsKeyArn", "lambdaUrlAuthType", "lastSynchronizedAt", "localAuthEnabled", "location", "managed",
            "managedIdentityAssigned", "minimumStrength", "mlLocalAuthEnabled", "model", "modelArn",
            "modelDataS3Uri", "modelDeployment", "modelFormat", "modelKmsKeyArn", "modelLifecycleStatus",
            "modelName", "modelPublisher", "modelType", "modelVersion", "msaAppType", "networkDefaultAction",
            "originalArmId", "outboundAuthType", "outputModalities", "ownerAccountId", "piiEntities",
            "piiEntityCount", "principalId", "principalType", "privateEndpoint", "privateEndpointCount",
            "productionVariants", "profanityFilterEnabled", "protocol", "providerName", "provisioningState",
            "public", "publicContentAccess", "publicNetworkAccess", "publicNetworkUnrestricted",
            "raiBasePolicyName", "raiCustomBlocklistCount", "raiFilterCount", "raiFilterEvidenceComplete",
            "raiNonBlockingFilterCount", "raiNonBlockingFilterObserved", "raiPolicyMode", "raiPolicyName",
            "referenceOnly", "referencedBy", "resourceGroup", "retrievalMode", "roleDefinitionId", "s3Buckets",
            "s3Public", "scaleType", "searchLocalAuthEnabled", "sensitiveRegexCount", "sourceType", "status",
            "storeType", "tags", "toolType", "traffic", "trainingDataS3Uri", "updatedAt",
            "validationDataS3Uris", "version", "versionUpgradeOption", "vpcId", "aclSupport");

    public Result sanitize(String provider, String nativeKind, Map<String, Object> attributes) {
        // Native kinds emitted by the AWS and Azure collectors are registered families. A newly
        // introduced provider/kind must be explicitly registered before metadata can be retained.
        if (!knownProviderKind(provider, nativeKind)) {
            return new Result(Map.of(), List.of("nativeKind"));
        }
        Limits limits = new Limits();
        Map<String, Object> clean = map(attributes, 1, "", limits, true);
        while (estimateSize(clean) > MAX_SERIALIZED_SIZE && !clean.isEmpty()) {
            String last = clean.keySet().stream().reduce((first, second) -> second).orElseThrow();
            clean.remove(last);
            limits.rejected.add(last);
        }
        return new Result(java.util.Collections.unmodifiableMap(new LinkedHashMap<>(clean)), List.copyOf(limits.rejected));
    }

    private boolean knownProviderKind(String provider, String nativeKind) {
        if (provider == null || nativeKind == null) return false;
        String normalizedProvider = provider.toUpperCase(Locale.ROOT);
        return REGISTERED_NATIVE_KINDS.contains(nativeKind)
                && (("AWS".equals(normalizedProvider) && nativeKind.startsWith("AWS_"))
                || ("AZURE".equals(normalizedProvider) && nativeKind.startsWith("AZURE_")));
    }

    private Map<String, Object> map(Map<?, ?> source, int depth, String prefix, Limits limits, boolean topLevel) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (source == null || depth > MAX_DEPTH) {
            if (source != null) limits.reject(prefix);
            return result;
        }
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            String key = String.valueOf(entry.getKey());
            String path = prefix.isEmpty() ? key : prefix + "." + key;
            if (limits.fields >= MAX_FIELDS || PROHIBITED.matcher(key).find()
                    || (topLevel && !ALLOWED_TOP_LEVEL_FIELDS.contains(key))) {
                limits.reject(path);
                continue;
            }
            Object value = value(entry.getValue(), depth + 1, path, limits);
            if (value != Rejected.VALUE) {
                result.put(key, value);
                limits.fields++;
            }
        }
        return result;
    }

    private Object value(Object value, int depth, String path, Limits limits) {
        if (value == null || value instanceof Boolean || value instanceof Number) return value;
        if (value instanceof String string) {
            if (string.length() > MAX_STRING_LENGTH) {
                limits.reject(path);
                return Rejected.VALUE;
            }
            return string;
        }
        if (value instanceof Map<?, ?> nested) {
            if (depth > MAX_DEPTH) { limits.reject(path); return Rejected.VALUE; }
            return map(nested, depth, path, limits, false);
        }
        if (value instanceof Collection<?> collection) {
            if (depth > MAX_DEPTH || collection.size() > MAX_LIST_ITEMS) { limits.reject(path); return Rejected.VALUE; }
            List<Object> values = new ArrayList<>();
            int index = 0;
            for (Object item : collection) {
                Object clean = value(item, depth + 1, path + "[" + index++ + "]", limits);
                if (clean != Rejected.VALUE) values.add(clean);
            }
            return values;
        }
        limits.reject(path);
        return Rejected.VALUE;
    }

    private int estimateSize(Map<String, Object> attributes) {
        return attributes.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
    }

    private enum Rejected { VALUE }
    private static final class Limits {
        private int fields;
        private final Set<String> rejected = new LinkedHashSet<>();
        void reject(String path) { rejected.add(path.isBlank() ? "attributes" : path); }
    }
    public record Result(Map<String, Object> attributes, List<String> rejectedFieldNames) { }
}
