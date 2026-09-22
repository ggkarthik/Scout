package com.prototype.vulnwatch.aisecurity.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.aisecurity.service.AiGridCapabilityService;
import com.prototype.vulnwatch.aisecurity.service.AiGridRelationshipSemantics;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityMetadataSanitizer;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Fails the build when the AWS collector registration manifest drifts across its owners. */
class AiGridCollectorRegistrationCertificationTest {

    private final AwsPolicyPermissionMatrix permissions = new AwsPolicyPermissionMatrix();

    @Test
    void everyCollectorFamilyHasPermissionsCapabilitiesAndABoundedProbe() {
        Set<String> collectorFamilies = Set.copyOf(AwsBedrockDiscoveryService.collectorFamilies());
        assertEquals(collectorFamilies, permissions.resourceFamilies());
        assertEquals(collectorFamilies.size(), new HashSet<>(AwsBedrockDiscoveryService.collectorFamilies()).size());

        for (String family : collectorFamilies) {
            var registration = permissions.family(family);
            assertFalse(registration.requiredActions().isEmpty(), family + " must declare required permissions");
            assertFalse(registration.verificationProbe().isBlank(), family + " must declare a bounded probe");
            assertEquals(Set.copyOf(AiGridCapabilityService.declaredCapabilities("AWS", family)),
                    Set.copyOf(registration.capabilities()), family + " capability registration drifted");
            assertFalse(registration.capabilities().isEmpty(), family + " must declare capabilities");
            if (registration.capabilities().stream().anyMatch(AiGridCollectorRegistrationCertificationTest::hasGovernedPolicies)) {
                assertFalse(registration.policies().isEmpty(), family + " must declare its governed policies");
            }
            assertTrue(registration.requiredActions().stream().allMatch(AiGridCollectorRegistrationCertificationTest::isReadOnly),
                    family + " contains a mutation-shaped action");
        }
    }

    @Test
    void relationshipAndAttachmentContractsStayCanonicalAndSanitizable() {
        assertTrue(AiGridRelationshipSemantics.ALLOWED_RELATIONSHIPS.containsAll(Set.of(
                "HAS_COMPONENT", "SERVES_VERSION", "USES_TOOL", "IMPLEMENTED_BY")));
        assertFalse(AiGridRelationshipSemantics.ALLOWED_RELATIONSHIPS.contains("INVOKES_LAMBDA"));
        assertFalse(AiGridRelationshipSemantics.SYSTEM_MEMBERSHIP_RELATIONSHIPS.contains("VERSION_OF"));
        assertEquals(AiGridRelationshipSemantics.AttachmentContract.REQUIRED,
                AiGridRelationshipSemantics.attachmentContract("AI_COMPONENT", "AWS_AGENTCORE_RUNTIME"));
        assertEquals(AiGridRelationshipSemantics.AttachmentContract.ROOT,
                AiGridRelationshipSemantics.attachmentContract("AI_COMPONENT", "AWS_AGENTCORE_RUNTIME",
                        Map.of("agentCoreRootQualified", true)));
        assertTrue(AiSecurityMetadataSanitizer.registeredNativeKinds()
                .containsAll(AiGridRelationshipSemantics.registeredAttachmentNativeKinds()));
    }

    private static boolean isReadOnly(String action) {
        String operation = action.substring(action.indexOf(':') + 1).toLowerCase();
        return operation.startsWith("get") || operation.startsWith("list")
                || operation.startsWith("describe") || operation.startsWith("batchget");
    }

    private static boolean hasGovernedPolicies(String capability) {
        return Set.of("BEDROCK_AGENTS", "BEDROCK_GUARDRAILS", "BEDROCK_KNOWLEDGE_BASES",
                "BEDROCK_MODELS_JOBS", "LAMBDA_URLS", "IAM_ROLE_POLICIES", "AGENTCORE_GATEWAYS_TARGETS",
                "SAGEMAKER_DOMAINS_MODELS_ENDPOINTS").contains(capability);
    }
}
