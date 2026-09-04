package com.prototype.vulnwatch.aisecurity.service;

import java.util.List;
import org.springframework.stereotype.Component;

/** AWS connector fields owned by Bedrock, IAM, Lambda, AgentCore, and SageMaker adapters. */
@Component
public class AwsAiGridFactProducer implements AiGridFactProducer {
    @Override
    public List<ProducedFact> produce(FactInput input) {
        if (!"AWS".equalsIgnoreCase(input.provider())) return List.of();
        List<ProducedFact> facts = AiGridFactProducerSupport.facts();
        AiGridFactProducerSupport.copy(input, "status", "resource.status_observed", facts);
        AiGridFactProducerSupport.copy(input, "guardrailAttached", "bedrock.agent.guardrail_attached_configured", facts);
        // Bedrock discovery exposes this as guardrailMinimumStrength.  Keep the
        // normalized minimumStrength alias for package-driven inputs, but prefer
        // the connector field so existing observations remain evaluable.
        if (input.attributes().hasNonNull("guardrailMinimumStrength")) {
            AiGridFactProducerSupport.copy(input, "guardrailMinimumStrength",
                    "bedrock.guardrail.minimum_strength_configured", facts);
        } else {
            AiGridFactProducerSupport.copy(input, "minimumStrength",
                    "bedrock.guardrail.minimum_strength_configured", facts);
        }
        AiGridFactProducerSupport.copy(input, "publicNetworkUnrestricted", "network.public_access_configured", facts);
        AiGridFactProducerSupport.copy(input, "s3Public", "data.s3_public_access_configured", facts);
        if (input.attributes().hasNonNull("functionUrlAuthType")) {
            AiGridFactProducerSupport.copy(input, "functionUrlAuthType", "compute.lambda_url_auth_type_configured", facts);
        } else {
            AiGridFactProducerSupport.copy(input, "lambdaUrlAuthType", "compute.lambda_url_auth_type_configured", facts);
        }
        AiGridFactProducerSupport.copy(input, "foundationModel", "model.foundation_identifier_configured", facts);
        AiGridFactProducerSupport.copy(input, "lambdaArn", "compute.lambda_target_arn_configured", facts);
        AiGridFactProducerSupport.copy(input, "iamWildcardActions", "identity.wildcard_permission_observed", facts);
        AiGridFactProducerSupport.copy(input, "invocationLoggingEnabled", "logging.model_invocation_enabled_configured", facts);
        AiGridFactProducerSupport.copy(input, "customerManagedKey", "data.customer_managed_key_configured", facts);
        AiGridFactProducerSupport.copy(input, "privateEndpointCount", "network.private_endpoint_count_configured", facts);
        AiGridFactProducerSupport.copy(input, "sourceType", "data.source_type", facts);
        AiGridFactProducerSupport.copy(input, "dataSourceCount", "data.source_count_configured", facts);
        AiGridFactProducerSupport.copy(input, "contentFilterCount", "guardrail.content_filter_count_configured", facts);
        AiGridFactProducerSupport.copy(input, "piiEntityCount", "guardrail.pii_entity_count_configured", facts);
        AiGridFactProducerSupport.copy(input, "contextualGroundingFilterCount", "guardrail.contextual_grounding_filter_count_configured", facts);
        AiGridFactProducerSupport.copy(input, "deniedTopicCount", "guardrail.denied_topic_count_configured", facts);
        AiGridFactProducerSupport.copy(input, "updatedAt", "guardrail.updated_at_observed", facts);
        AiGridFactProducerSupport.copy(input, "deletionPolicy", "data.deletion_policy_configured", facts);
        AiGridFactProducerSupport.copy(input, "providerName", "model.provider_name_observed", facts);
        AiGridFactProducerSupport.copy(input, "modelLifecycleStatus", "model.lifecycle_status_observed", facts);
        AiGridFactProducerSupport.copy(input, "configurationSubtype", "mcp.target_subtype_configured", facts);
        AiGridFactProducerSupport.copy(input, "endpointHost", "mcp.server_hostname_configured", facts);
        if ("AWS_AGENTCORE_GATEWAY_TARGET".equals(input.nativeKind())
                && !input.attributes().hasNonNull("endpointHost")) {
            facts.add(AiGridFactProducerSupport.known("mcp.server_hostname_configured",
                    com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.textNode("NOT_APPLICABLE"),
                    "nativeKind"));
        }
        if ("AWS_AGENTCORE_MCP_SERVER".equals(input.nativeKind())
                && !input.attributes().hasNonNull("configurationSubtype")) {
            facts.add(AiGridFactProducerSupport.known("mcp.target_subtype_configured",
                    com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.textNode("NOT_APPLICABLE"),
                    "nativeKind"));
        }
        AiGridFactProducerSupport.copy(input, "vpcId", "network.vpc_id_configured", facts);
        AiGridFactProducerSupport.copy(input, "instanceType", "compute.instance_type_configured", facts);
        AiGridFactProducerSupport.copy(input, "aclSupport", "data.source_acl_enforced", facts);
        AiGridFactProducerSupport.copy(input, "retrievalMode", "data.retrieval_mode", facts);
        AiGridFactProducerSupport.copy(input, "publicContentAccess", "data.source_public_content_access", facts);
        AiGridFactProducerSupport.copy(input, "privateEndpoint", "mcp.private_endpoint", facts);
        AiGridFactProducerSupport.copy(input, "lastSynchronizedAt", "mcp.last_synchronized_at", facts);
        if ("PUBLIC_NETWORK_REACHABLE".equals(input.attributes().path("endpointExposure").asText())) {
            AiGridFactProducerSupport.copy(input, "endpointExposure", "mcp.endpoint_exposure", facts);
        }
        AiGridFactProducerSupport.copy(input, "configuredAuthType", "mcp.configured_auth_type", facts);
        AiGridFactProducerSupport.copy(input, "inboundAuthType", "mcp.inbound_auth_type", facts);
        AiGridFactProducerSupport.copy(input, "outboundAuthType", "mcp.outbound_auth_type", facts);
        AiGridFactProducerSupport.copy(input, "status", "mcp.target_status", facts);
        // Phase 2 normalized facts are deliberately scalar classifications.  The
        // connector may derive them from bounded IAM, S3, telemetry, registry, or
        // SageMaker calls; this producer never persists provider policy bodies.
        String[][] phase2Attributes = {
                {"effectiveAccessExceedsApprovedMatrix", "identity.effective_access_exceeds_approved_matrix"},
                {"crossAccountSensitiveAccess", "identity.cross_account_sensitive_access_observed"},
                {"unapprovedPrivilegedRoleAccess", "identity.unapproved_privileged_role_access"},
                {"restrictionControlsIncomplete", "identity.restriction_controls_incomplete"},
                {"s3EffectiveBlockPublicAccessIncomplete", "data.s3_effective_block_public_access_incomplete"},
                {"s3DefaultEncryptionConfigured", "data.s3_default_encryption_configured"},
                {"s3CustomerManagedKeyConfigured", "data.s3_customer_managed_key_configured"},
                {"s3UnapprovedCrossAccountPrincipal", "data.s3_unapproved_cross_account_principal"},
                {"s3TlsEnforced", "data.s3_tls_enforced"},
                {"vectorStorePublicNetworkAccess", "data.vector_store_public_network_access"},
                {"vectorStoreEncryptionConfigured", "data.vector_store_encryption_configured"},
                {"vectorStorePrincipalBoundaryConfigured", "data.vector_store_principal_boundary_configured"},
                {"bedrockBudgetConfigured", "consumption.bedrock_budget_configured"},
                {"bedrockQuotaAlarmConfigured", "consumption.bedrock_quota_alarm_configured"},
                {"bedrockQuotaUtilizationExceedsThreshold", "consumption.bedrock_quota_utilization_exceeds_threshold"},
                {"bedrockThrottlingAlarmEffective", "consumption.bedrock_throttling_alarm_effective"},
                {"bedrockUsageExceedsThreshold", "consumption.bedrock_usage_exceeds_threshold"},
                {"modelSignatureAttestationPresent", "provenance.model_signature_attestation_present"},
                {"modelApprovedRegistryLineage", "provenance.model_approved_registry_lineage"},
                {"modelSbomCoveragePresent", "provenance.model_sbom_coverage_present"},
                {"modelVulnerabilityBaselinePass", "provenance.model_vulnerability_baseline_pass"},
                {"datasetVersionChecksumPinned", "provenance.dataset_version_checksum_pinned"},
                {"datasetLineagePresent", "provenance.dataset_lineage_present"},
                {"datasetChangedAfterApproval", "provenance.dataset_changed_after_approval"},
                {"endpointPublicWithoutAdequateAuth", "mcp.endpoint_public_without_adequate_auth"},
                {"endpointTlsBaselinePass", "mcp.endpoint_tls_baseline_pass"},
                {"sagemakerNetworkIsolationEnabled", "model.sagemaker_network_isolation_enabled"},
                {"sagemakerStorageCustomerManagedKey", "model.sagemaker_storage_customer_managed_key"},
                {"sagemakerRootAccessEnabled", "model.sagemaker_root_access_enabled"},
                {"sagemakerImageBaselinePass", "model.sagemaker_image_baseline_pass"},
                {"effectivePublicAccess", "data.s3_effective_public_access"},
                {"effectivePublicContentAccess", "data.s3_effective_public_content_access"},
                {"inboundAuthAuthoritative", "mcp.inbound_auth_authoritative"},
                {"outboundAuthAuthoritative", "mcp.outbound_auth_authoritative"},
        };
        for (String[] mapping : phase2Attributes) AiGridFactProducerSupport.copy(input, mapping[0], mapping[1], facts);
        String kmsKey = input.attributes().path("kmsKeyArn").asText("");
        if (kmsKey.isBlank()) kmsKey = input.attributes().path("modelKmsKeyArn").asText("");
        if (input.attributes().has("kmsKeyArn") || input.attributes().has("modelKmsKeyArn")) {
            facts.add(AiGridFactProducerSupport.known("data.customer_managed_key_configured",
                    com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.booleanNode(!kmsKey.isBlank()),
                    input.attributes().has("kmsKeyArn") ? "kmsKeyArn" : "modelKmsKeyArn"));
        }
        if ("AI_AGENT".equals(input.artifactType())) {
            AiGridFactProducerSupport.copy(input, "status", "agent.status_observed", facts);
            if (input.attributes().has("executionRoleArn")) {
                boolean present = !input.attributes().path("executionRoleArn").asText("").isBlank();
                facts.add(AiGridFactProducerSupport.known("identity.execution_role_present_configured",
                        com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.booleanNode(present), "executionRoleArn"));
            }
        }
        return List.copyOf(facts);
    }
}
