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
        AiGridFactProducerSupport.copy(input, "minimumStrength", "bedrock.guardrail.minimum_strength_configured", facts);
        AiGridFactProducerSupport.copy(input, "publicNetworkUnrestricted", "network.public_access_configured", facts);
        AiGridFactProducerSupport.copy(input, "s3Public", "data.s3_public_access_configured", facts);
        AiGridFactProducerSupport.copy(input, "lambdaUrlAuthType", "compute.lambda_url_auth_type_configured", facts);
        AiGridFactProducerSupport.copy(input, "iamWildcardActions", "identity.wildcard_permission_observed", facts);
        AiGridFactProducerSupport.copy(input, "invocationLoggingEnabled", "logging.model_invocation_enabled_configured", facts);
        AiGridFactProducerSupport.copy(input, "customerManagedKey", "data.customer_managed_key_configured", facts);
        AiGridFactProducerSupport.copy(input, "privateEndpointCount", "network.private_endpoint_count_configured", facts);
        AiGridFactProducerSupport.copy(input, "sourceType", "data.source_type", facts);
        AiGridFactProducerSupport.copy(input, "dataSourceCount", "data.source_count_configured", facts);
        AiGridFactProducerSupport.copy(input, "contentFilterCount", "guardrail.content_filter_count_configured", facts);
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
