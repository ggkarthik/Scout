package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureKillSwitchService;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry.PolicyDefinition;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityResourceFamilyCatalogue;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.EvaluationOutcome;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;

class AiSecurityPolicyEvaluationServiceTest {

    private final NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
    private final AiSecurityPolicyEvaluationService service = new AiSecurityPolicyEvaluationService(
            jdbc,
            new ObjectMapper(),
            new AiSecurityPolicyRegistry(),
            new AiSecurityResourceFamilyCatalogue(),
            new AiSecurityAzureKillSwitchService("", "", "", ""));

    @Test
    void accountGlobalEvidenceRequiresTheGlobalScope() {
        when(jdbc.queryForObject(anyString(), any(SqlParameterSource.class), eq(Integer.class)))
                .thenAnswer(invocation -> {
                    MapSqlParameterSource params = invocation.getArgument(1);
                    String family = String.valueOf(params.getValue("family"));
                    String region = String.valueOf(params.getValue("region"));
                    if ("BEDROCK_AGENTS".equals(family) && "us-east-1".equals(region)) {
                        return 1;
                    }
                    // Deliberately model incorrectly tagged regional IAM evidence.
                    if ("IAM_GLOBAL".equals(family) && "us-east-1".equals(region)) {
                        return 1;
                    }
                    return 0;
                });

        assertFalse(service.hasCompleteEvidence(
                UUID.randomUUID(),
                "123456789012",
                "us-east-1",
                policy(List.of("BEDROCK_AGENTS", "IAM_GLOBAL"))));
    }

    @Test
    void regionalAndGlobalFamiliesUseTheirExactSemanticScopes() {
        when(jdbc.queryForObject(anyString(), any(SqlParameterSource.class), eq(Integer.class)))
                .thenAnswer(invocation -> {
                    MapSqlParameterSource params = invocation.getArgument(1);
                    String family = String.valueOf(params.getValue("family"));
                    String region = String.valueOf(params.getValue("region"));
                    return switch (family) {
                        case "BEDROCK_AGENTS" -> "us-east-1".equals(region) ? 1 : 0;
                        case "IAM_GLOBAL" -> "GLOBAL".equals(region) ? 1 : 0;
                        default -> 0;
                    };
                });

        assertTrue(service.hasCompleteEvidence(
                UUID.randomUUID(),
                "123456789012",
                "us-east-1",
                policy(List.of("BEDROCK_AGENTS", "IAM_GLOBAL"))));
    }

    @Test
    void unknownResourceFamilyFailsClosedWithoutQueryingStorage() {
        assertFalse(service.hasCompleteEvidence(
                UUID.randomUUID(),
                "123456789012",
                "us-east-1",
                policy(List.of("FUTURE_UNCATALOGUED_FAMILY"))));

        verifyNoInteractions(jdbc);
    }

    @Test
    void azureRegionalAndSubscriptionGlobalEvidenceMustBothBeComplete() {
        when(jdbc.queryForObject(anyString(), any(SqlParameterSource.class), eq(Integer.class)))
                .thenAnswer(invocation -> {
                    MapSqlParameterSource params = invocation.getArgument(1);
                    String family = String.valueOf(params.getValue("family"));
                    String region = String.valueOf(params.getValue("region"));
                    return switch (family) {
                        case "AZURE_BOT_SERVICES" -> "GLOBAL".equals(region) ? 1 : 0;
                        case "AZURE_BOT_IDENTITIES" -> "GLOBAL".equals(region) ? 1 : 0;
                        default -> 0;
                    };
                });

        assertTrue(service.hasCompleteEvidence(
                UUID.randomUUID(),
                "subscription-id",
                "eastus",
                policy(List.of("AZURE_BOT_SERVICES", "AZURE_BOT_IDENTITIES"))));
    }

    @Test
    void azureRulesUseOnlyTypedNormalizedFacts() {
        assertEquals(
                EvaluationOutcome.FAIL,
                service.evaluate(
                        "AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS",
                        Map.of("publicNetworkUnrestricted", true)).outcome());
        assertEquals(
                EvaluationOutcome.PASS,
                service.evaluate(
                        "AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED",
                        Map.of("mlLocalAuthEnabled", false)).outcome());
        assertEquals(
                EvaluationOutcome.NO_DECISION,
                service.evaluate("AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED", Map.of()).outcome());
        assertFalse(service.isApplicable("AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED", Map.of()));
    }

    @Test
    void registryContainsEveryAzurePilotPolicy() {
        AiSecurityPolicyRegistry registry = new AiSecurityPolicyRegistry();
        assertEquals(8, registry.all().stream().filter(policy -> policy.id().startsWith("AZURE_")).count());
    }

    @Test
    void sharedAzurePosturePolicyUsesTheArtifactProviderFamily() {
        var policy = new AiSecurityPolicyRegistry().find("AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS").orElseThrow();

        assertEquals(List.of("AZURE_ML_WORKSPACES"), service.requiredFamilies(policy, "AZURE_ML_WORKSPACES"));
        assertEquals(List.of("AZURE_SEARCH_SERVICES"), service.requiredFamilies(policy, "AZURE_SEARCH_SERVICES"));
        assertEquals(List.of("AZURE_AI_ACCOUNTS"), service.requiredFamilies(policy, "AZURE_AI_ACCOUNTS"));
    }

    @Test
    void sharedAzureLoggingPolicyRequiresMatchingPostureAndDiagnosticsScopes() {
        var policy = new AiSecurityPolicyRegistry().find("AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED").orElseThrow();

        assertEquals(
                List.of("AZURE_SEARCH_SERVICES", "AZURE_DIAGNOSTIC_SETTINGS"),
                service.requiredFamilies(policy, "AZURE_SEARCH_SERVICES"));
    }

    private PolicyDefinition policy(List<String> families) {
        return new PolicyDefinition(
                "TEST_POLICY",
                "1.0.0",
                "Test policy",
                "HIGH",
                List.of("AI_AGENT"),
                families,
                "Test",
                "Test",
                Map.of());
    }
}
