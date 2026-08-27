package com.prototype.vulnwatch.aisecurity.service;

import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

/** Azure connector fields owned by AI Services, Foundry, ML, Search, Bot, and RBAC adapters. */
@Component
public class AzureAiGridFactProducer implements AiGridFactProducer {
    @Override
    public List<ProducedFact> produce(FactInput input) {
        if (!"AZURE".equalsIgnoreCase(input.provider())) return List.of();
        List<ProducedFact> facts = AiGridFactProducerSupport.facts();
        AiGridFactProducerSupport.copy(input, "provisioningState", "resource.provisioning_state_observed", facts);
        AiGridFactProducerSupport.copy(input, "status", "resource.status_observed", facts);
        AiGridFactProducerSupport.copy(input, "publicNetworkUnrestricted", "network.public_access_configured", facts);
        AiGridFactProducerSupport.copy(input, "localAuthEnabled", "identity.local_auth_enabled_configured", facts);
        AiGridFactProducerSupport.copy(input, "diagnosticLoggingEnabled", "logging.diagnostic_enabled_configured", facts);
        AiGridFactProducerSupport.copy(input, "hasDestination", "logging.diagnostic_destination_configured", facts);
        AiGridFactProducerSupport.copy(input, "codeInterpreterEnabled", "agent.code_interpreter_enabled_configured", facts);
        AiGridFactProducerSupport.copy(input, "modelDeployment", "agent.model_deployment_configured", facts);
        AiGridFactProducerSupport.copy(input, "managedIdentityAssigned", "identity.managed_identity_assigned_configured", facts);
        AiGridFactProducerSupport.copy(input, "mlLocalAuthEnabled", "identity.ml_endpoint_local_auth_enabled_configured", facts);
        AiGridFactProducerSupport.copy(input, "searchLocalAuthEnabled", "identity.search_local_admin_auth_enabled_configured", facts);
        AiGridFactProducerSupport.copy(input, "authoritativeNonIdentityAuthentication", "identity.search_data_source_non_identity_auth_observed", facts);
        AiGridFactProducerSupport.copy(input, "botPasswordAuthWithoutManagedIdentity", "identity.bot_password_without_managed_identity_observed", facts);
        AiGridFactProducerSupport.copy(input, "customerManagedKey", "data.customer_managed_key_configured", facts);
        AiGridFactProducerSupport.copy(input, "privateEndpointCount", "network.private_endpoint_count_configured", facts);
        AiGridFactProducerSupport.copy(input, "sourceType", "data.source_type", facts);
        AiGridFactProducerSupport.copy(input, "aclSupport", "data.source_acl_enforced", facts);
        AiGridFactProducerSupport.copy(input, "retrievalMode", "data.retrieval_mode", facts);
        AiGridFactProducerSupport.copy(input, "publicContentAccess", "data.source_public_content_access", facts);
        if (input.attributes().path("raiFilterEvidenceComplete").asBoolean(false)) {
            AiGridFactProducerSupport.copy(input, "raiNonBlockingFilterObserved", "guardrail.rai_non_blocking_filter_observed", facts);
        }
        AiGridFactProducerSupport.copy(input, "raiFilterCount", "guardrail.rai_filter_count_configured", facts);
        AiGridFactProducerSupport.copy(input, "raiCustomBlocklistCount", "guardrail.rai_custom_blocklist_count_configured", facts);
        AiGridFactProducerSupport.copy(input, "raiPolicyMode", "guardrail.rai_mode_configured", facts);
        AiGridFactProducerSupport.copy(input, "raiBasePolicyName", "guardrail.rai_base_policy_configured", facts);
        AiGridFactProducerSupport.copy(input, "modelName", "model.name_configured", facts);
        AiGridFactProducerSupport.copy(input, "modelPublisher", "model.publisher_configured", facts);
        AiGridFactProducerSupport.copy(input, "modelVersion", "model.version_configured", facts);
        AiGridFactProducerSupport.copy(input, "versionUpgradeOption", "model.version_upgrade_option_configured", facts);
        AiGridFactProducerSupport.copy(input, "endpointHost", "mcp.server_hostname_configured", facts);
        AiGridFactProducerSupport.copy(input, "toolType", "agent.tool_type_configured", facts);
        AiGridFactProducerSupport.copy(input, "traffic", "ml.endpoint_traffic_configured", facts);
        AiGridFactProducerSupport.copy(input, "instanceType", "compute.instance_type_configured", facts);
        AiGridFactProducerSupport.copy(input, "model", "ml.model_reference_configured", facts);
        AiGridFactProducerSupport.copy(input, "assignmentScope", "identity.assignment_scope_configured", facts);
        AiGridFactProducerSupport.copy(input, "principalType", "identity.principal_type_configured", facts);
        AiGridFactProducerSupport.copy(input, "conditionVersion", "identity.assignment_condition_version_configured", facts);
        if ("AZURE_BOT_CHANNELS".equals(input.resourceFamily())) {
            AiGridFactProducerSupport.copy(input, "channelName", "bot.channel_type_configured", facts);
            if (!input.attributes().hasNonNull("channelName")) {
                AiGridFactProducerSupport.copy(input, "kind", "bot.channel_type_configured", facts);
            }
        }
        if (input.attributes().path("tags").isObject()) {
            boolean hasOwner = false;
            boolean hasEnvironment = false;
            boolean hasCriticality = false;
            var fields = input.attributes().path("tags").fieldNames();
            while (fields.hasNext()) {
                String tag = fields.next();
                if ("owner".equals(tag.toLowerCase(Locale.ROOT))
                        && !input.attributes().path("tags").path(tag).asText("").isBlank()) {
                    hasOwner = true;
                }
                if ("environment".equals(tag.toLowerCase(Locale.ROOT))
                        && !input.attributes().path("tags").path(tag).asText("").isBlank()) hasEnvironment = true;
                if ("criticality".equals(tag.toLowerCase(Locale.ROOT))
                        && !input.attributes().path("tags").path(tag).asText("").isBlank()) hasCriticality = true;
            }
            facts.add(AiGridFactProducerSupport.known("owner.owner_tag_present_configured",
                    com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.booleanNode(hasOwner), "tags.owner"));
            facts.add(AiGridFactProducerSupport.known("resource.required_tags_present_configured",
                    com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.booleanNode(hasEnvironment && hasCriticality),
                    "tags.environment+tags.criticality"));
        }
        AiGridFactProducerSupport.copy(input, "raiPolicyName", "guardrail.rai_policy_reference_configured", facts);
        return List.copyOf(facts);
    }
}
