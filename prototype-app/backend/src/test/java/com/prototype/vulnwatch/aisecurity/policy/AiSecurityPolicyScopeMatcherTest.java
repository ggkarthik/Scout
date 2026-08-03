package com.prototype.vulnwatch.aisecurity.policy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher.ArtifactScopeFacts;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher.ScopeCondition;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher.ScopeConfig;
import java.util.List;
import org.junit.jupiter.api.Test;

class AiSecurityPolicyScopeMatcherTest {

    private static final ArtifactScopeFacts AGENT = new ArtifactScopeFacts(
            "AWS", "us-east-1", "123456789012", "AI_AGENT", "BEDROCK_AGENT", "fraud-triage-agent");

    @Test
    void allModeIsInScopeRegardlessOfConditions() {
        assertTrue(AiSecurityPolicyScopeMatcher.isInScope(ScopeConfig.all(), AGENT, null));
    }

    @Test
    void customListModeExcludesEverythingWithoutAnExplicitInclude() {
        ScopeConfig scope = new ScopeConfig(AiSecurityPolicyScopeMatcher.MODE_CUSTOM_LIST, "AND", List.of());
        assertFalse(AiSecurityPolicyScopeMatcher.isInScope(scope, AGENT, null));
        assertTrue(AiSecurityPolicyScopeMatcher.isInScope(scope, AGENT, AiSecurityPolicyScopeMatcher.OVERRIDE_INCLUDED));
    }

    @Test
    void explicitExcludeOverridesAnyMode() {
        assertFalse(AiSecurityPolicyScopeMatcher.isInScope(
                ScopeConfig.all(), AGENT, AiSecurityPolicyScopeMatcher.OVERRIDE_EXCLUDED));
    }

    @Test
    void matchRulesWithNoConditionsMatchesNothing() {
        ScopeConfig scope = new ScopeConfig(AiSecurityPolicyScopeMatcher.MODE_MATCH_RULES, "AND", List.of());
        assertFalse(AiSecurityPolicyScopeMatcher.isInScope(scope, AGENT, null));
    }

    @Test
    void andLogicRequiresEveryConditionToMatch() {
        ScopeConfig scope = new ScopeConfig(AiSecurityPolicyScopeMatcher.MODE_MATCH_RULES, "AND", List.of(
                new ScopeCondition("ARTIFACT_TYPE", "EQUALS", "AI_AGENT"),
                new ScopeCondition("PROVIDER", "EQUALS", "AZURE")));
        assertFalse(AiSecurityPolicyScopeMatcher.isInScope(scope, AGENT, null));
    }

    @Test
    void orLogicMatchesIfAnyConditionMatches() {
        ScopeConfig scope = new ScopeConfig(AiSecurityPolicyScopeMatcher.MODE_MATCH_RULES, "OR", List.of(
                new ScopeCondition("ARTIFACT_TYPE", "EQUALS", "AI_MODEL"),
                new ScopeCondition("PROVIDER", "EQUALS", "AWS")));
        assertTrue(AiSecurityPolicyScopeMatcher.isInScope(scope, AGENT, null));
    }

    @Test
    void nameNotContainsExcludesMatchingArtifacts() {
        ScopeConfig scope = new ScopeConfig(AiSecurityPolicyScopeMatcher.MODE_MATCH_RULES, "AND", List.of(
                new ScopeCondition("NAME", "NOT_CONTAINS", "sandbox")));
        assertTrue(AiSecurityPolicyScopeMatcher.isInScope(scope, AGENT, null));

        ArtifactScopeFacts sandboxAgent = new ArtifactScopeFacts(
                "AWS", "us-east-1", "123456789012", "AI_AGENT", "BEDROCK_AGENT", "sandbox-triage-agent");
        assertFalse(AiSecurityPolicyScopeMatcher.isInScope(scope, sandboxAgent, null));
    }

    @Test
    void explicitIncludeWinsEvenWhenRulesWouldExclude() {
        ScopeConfig scope = new ScopeConfig(AiSecurityPolicyScopeMatcher.MODE_MATCH_RULES, "AND", List.of(
                new ScopeCondition("PROVIDER", "EQUALS", "AZURE")));
        assertTrue(AiSecurityPolicyScopeMatcher.isInScope(
                scope, AGENT, AiSecurityPolicyScopeMatcher.OVERRIDE_INCLUDED));
    }
}
