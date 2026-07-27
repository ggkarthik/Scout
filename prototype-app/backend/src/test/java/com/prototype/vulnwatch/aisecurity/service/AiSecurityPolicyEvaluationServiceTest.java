package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry.PolicyDefinition;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityResourceFamilyCatalogue;
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
            new AiSecurityResourceFamilyCatalogue());

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
