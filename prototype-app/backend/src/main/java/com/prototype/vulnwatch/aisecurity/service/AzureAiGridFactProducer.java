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
        String[][] phase2Attributes = {
                {"effectiveAccessExceedsApprovedMatrix", "identity.effective_access_exceeds_approved_matrix"},
                {"sensitiveAccessOutsideApprovedScope", "identity.sensitive_access_outside_approved_scope"},
                {"canElevateAccess", "identity.can_elevate_access"},
                {"highImpactWildcardPermission", "identity.high_impact_wildcard_permission"},
                {"roleAssignmentStale", "identity.role_assignment_stale"},
                {"pimActivationRequiredMissing", "identity.pim_activation_required_missing"},
                {"accessReviewMissingOrStale", "identity.access_review_missing_or_stale"},
                {"dataSourceSecretAuthentication", "search.data_source_secret_authentication"},
                {"connectionCustomerManagedKey", "search.connection_customer_managed_key"},
                {"permissionFilteringConfigured", "search.permission_filtering_configured"},
                {"documentAuthorizationConfigured", "search.document_authorization_configured"},
                {"tenantPartitioningConfigured", "search.tenant_partitioning_configured"},
                {"retrievalModeApproved", "search.retrieval_mode_approved"},
                {"encryptionCustomerManagedKey", "search.encryption_customer_managed_key"},
                {"outboundSharedPrivateLinkConfigured", "search.outbound_shared_private_link_configured"},
                {"storagePublicBlobAccess", "data.storage_public_blob_access"},
                {"storageSharedKeyAccess", "data.storage_shared_key_access"},
                {"storageSecureTransferTlsBaseline", "data.storage_secure_transfer_tls_baseline"},
                {"storageCustomerManagedKey", "data.storage_customer_managed_key"},
                {"storagePrivateNetworkBoundary", "data.storage_private_network_boundary"},
                {"azureBudgetConfigured", "consumption.azure_budget_configured"},
                {"azureQuotaAlertConfigured", "consumption.azure_quota_alert_configured"},
                {"azureQuotaUtilizationExceedsThreshold", "consumption.azure_quota_utilization_exceeds_threshold"},
                {"azureThrottlingCapacityExceedsThreshold", "consumption.azure_throttling_capacity_exceeds_threshold"},
                {"azureUsageExceedsThreshold", "consumption.azure_usage_exceeds_threshold"},
                {"modelSignatureAttestationPresent", "provenance.model_signature_attestation_present"},
                {"modelApprovedRegistryLineage", "provenance.model_approved_registry_lineage"},
                {"modelSbomCoveragePresent", "provenance.model_sbom_coverage_present"},
                {"deploymentImageVulnerabilityBaselinePass", "provenance.deployment_image_vulnerability_baseline_pass"},
                {"datasetVersionChecksumPinned", "provenance.dataset_version_checksum_pinned"},
                {"mlflowDatasetLineagePresent", "provenance.mlflow_dataset_lineage_present"},
                {"azureMlManagedNetworkEnabled", "model.azure_ml_managed_network_enabled"},
                {"azureMlOutboundEgressRestricted", "model.azure_ml_outbound_egress_restricted"},
                {"botPublicWithoutStrongAuth", "mcp.bot_public_without_strong_auth"},
                {"botManagedIdentityConfigured", "mcp.bot_managed_identity_configured"},
                {"botTlsBaselinePass", "mcp.bot_tls_baseline_pass"},
                {"foundryPrivateEndpointConfigured", "mcp.foundry_private_endpoint_configured"},
                {"effectivePublicNetworkExposure", "network.effective_public_network_exposure"},
                {"effectivePrivateEndpointRequirement", "network.effective_private_endpoint_requirement"},
                {"foundryAuthAuthoritative", "mcp.foundry_auth_authoritative"},
                {"effectivePrivilegedScope", "identity.effective_privileged_scope"},
                {"effectiveRoleConstraints", "identity.effective_role_constraints"},
                {"authoritativeSensitivityState", "data.authoritative_sensitivity_state"},
        };
        for (String[] mapping : phase2Attributes) AiGridFactProducerSupport.copy(input, mapping[0], mapping[1], facts);
        return List.copyOf(facts);
    }
}
