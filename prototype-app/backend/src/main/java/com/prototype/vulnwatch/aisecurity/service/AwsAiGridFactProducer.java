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
