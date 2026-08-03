package com.prototype.vulnwatch.aisecurity.policy;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

@Component
public class AiSecurityPolicyRegistry {

    private final List<PolicyDefinition> definitions = List.of(
            new PolicyDefinition(
                    "AWS_BEDROCK_PUBLIC_KB_S3", "1.0.0", "Public knowledge-base S3 source",
                    "CRITICAL", List.of("KNOWLEDGE_BASE"), List.of("BEDROCK_KNOWLEDGE_BASES", "S3_EXPOSURE"),
                    "A Bedrock knowledge base uses an S3 data source that is publicly accessible.",
                    "Block public access and restrict the bucket policy to the knowledge-base execution role.",
                    Map.of("CIS", "AWS-S3-PUBLIC-ACCESS")),
            new PolicyDefinition(
                    "AWS_BEDROCK_UNAUTH_LAMBDA_URL", "1.0.0", "Unauthenticated action-group Lambda URL",
                    "CRITICAL", List.of("AI_AGENT"), List.of("BEDROCK_AGENTS", "LAMBDA_URLS"),
                    "An agent action group can invoke a Lambda function URL without AWS IAM authentication.",
                    "Set the function URL AuthType to AWS_IAM or remove the public function URL.",
                    Map.of("AWS", "LAMBDA-FUNCTION-URL-AUTH")),
            new PolicyDefinition(
                    "AWS_BEDROCK_WILDCARD_AGENT_ROLE", "1.0.0", "Wildcard agent execution-role actions",
                    "HIGH", List.of("AI_AGENT"), List.of("BEDROCK_AGENTS", "IAM_GLOBAL"),
                    "A Bedrock agent execution role grants wildcard actions.",
                    "Replace wildcard actions with the minimum actions and resources required by the agent.",
                    Map.of("CIS", "IAM-LEAST-PRIVILEGE")),
            new PolicyDefinition(
                    "AWS_BEDROCK_WEAK_GUARDRAIL", "1.0.0", "Weak attached guardrail content filters",
                    "HIGH", List.of("AI_AGENT"), List.of("BEDROCK_AGENTS", "BEDROCK_GUARDRAILS"),
                    "An attached guardrail has a required content-filter strength below MEDIUM.",
                    "Configure at least MEDIUM input and output strength for required harmful-content categories.",
                    Map.of("NIST-AI-RMF", "MAP-2.3")),
            new PolicyDefinition(
                    "AWS_BEDROCK_INVOCATION_LOGGING_DISABLED", "1.0.0", "Bedrock invocation logging disabled",
                    "MEDIUM", List.of("ACCOUNT_CONFIGURATION"), List.of("BEDROCK_INVOCATION_LOGGING"),
                    "Model invocation logging is disabled for an applicable AWS account and region.",
                    "Enable Bedrock model invocation logging to an encrypted CloudWatch Logs or S3 destination.",
                    Map.of("AWS", "BEDROCK-LOGGING")),
            new PolicyDefinition(
                    "AZURE_RAI_POLICY_NON_BLOCKING_FILTER", "1.0.0",
                    "Azure RAI policy contains a non-blocking filter",
                    "HIGH", List.of("AI_GUARDRAIL"), List.of("AZURE_RAI_POLICIES"),
                    "An Azure RAI policy explicitly disables a content filter or configures it as non-blocking.",
                    "Enable blocking for every explicitly configured RAI content filter.",
                    Map.of("OWASP-LLM", "LLM01")),
            new PolicyDefinition(
                    "AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS", "1.0.0", "Unrestricted Azure AI public access",
                    "CRITICAL", List.of("OTHER_AI_ARTIFACT"), List.of("AZURE_AI_ACCOUNTS"),
                    "An Azure AI account permits unrestricted public network access.",
                    "Disable public access or restrict network ACLs and use approved private endpoints.",
                    Map.of("AZURE", "AI-NETWORK-ACCESS")),
            new PolicyDefinition(
                    "AZURE_AI_LOCAL_AUTH_ENABLED", "1.0.0", "Azure AI local authentication enabled",
                    "HIGH", List.of("OTHER_AI_ARTIFACT"), List.of("AZURE_AI_ACCOUNTS"),
                    "An Azure AI account permits key-based local authentication.",
                    "Disable local authentication and require Microsoft Entra identities.",
                    Map.of("AZURE", "AI-LOCAL-AUTH")),
            new PolicyDefinition(
                    "AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED", "1.0.0", "Azure AI diagnostic logging disabled",
                    "MEDIUM", List.of("OTHER_AI_ARTIFACT"),
                    List.of("AZURE_AI_ACCOUNTS", "AZURE_DIAGNOSTIC_SETTINGS"),
                    "An Azure AI account has no enabled diagnostic-log destination.",
                    "Enable diagnostic logs to an approved Log Analytics workspace, storage account, or event hub.",
                    Map.of("AZURE", "AI-DIAGNOSTIC-LOGGING")),
            new PolicyDefinition(
                    "AZURE_FOUNDRY_AGENT_CODE_INTERPRETER_ENABLED", "1.0.0",
                    "Foundry agent Code Interpreter enabled",
                    "HIGH", List.of("AI_AGENT"),
                    List.of("AZURE_FOUNDRY_AGENTS", "AZURE_FOUNDRY_AGENT_TOOLS"),
                    "A Foundry agent enables Code Interpreter.",
                    "Disable Code Interpreter unless the use case and data boundary are explicitly approved.",
                    Map.of("NIST-AI-RMF", "GOVERN-1.7")),
            new PolicyDefinition(
                    "AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED", "1.0.0",
                    "Azure ML endpoint local authentication enabled",
                    "HIGH", List.of("OTHER_AI_ARTIFACT"), List.of("AZURE_ML_ENDPOINTS"),
                    "An Azure ML online endpoint permits local token authentication.",
                    "Require Microsoft Entra authentication for the endpoint.",
                    Map.of("AZURE", "ML-ENDPOINT-AUTH")),
            new PolicyDefinition(
                    "AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED", "1.0.0",
                    "Azure AI Search local admin authentication enabled",
                    "HIGH", List.of("OTHER_AI_ARTIFACT"), List.of("AZURE_SEARCH_SERVICES"),
                    "An Azure AI Search service permits local admin-key authentication.",
                    "Disable local authentication and use Microsoft Entra role-based access.",
                    Map.of("AZURE", "SEARCH-LOCAL-AUTH")),
            new PolicyDefinition(
                    "AZURE_SEARCH_DATA_SOURCE_NON_IDENTITY_AUTH", "1.0.0",
                    "Azure AI Search data source does not use identity authentication",
                    "HIGH", List.of("OTHER_AI_ARTIFACT"), List.of("AZURE_SEARCH_DATA_SOURCES"),
                    "An Azure AI Search data source uses authoritative non-identity authentication evidence.",
                    "Use a managed identity for the Search data-source connection.",
                    Map.of("AZURE", "SEARCH-DATA-SOURCE-AUTH")),
            new PolicyDefinition(
                    "AZURE_BOT_PASSWORD_AUTH_WITHOUT_MANAGED_IDENTITY", "1.0.0",
                    "Azure Bot password authentication without managed identity",
                    "HIGH", List.of("AI_AGENT"),
                    List.of("AZURE_BOT_SERVICES", "AZURE_BOT_IDENTITIES"),
                    "An Azure Bot uses password authentication without an assigned managed identity.",
                    "Use a user-assigned managed identity and remove password-based application credentials.",
                    Map.of("AZURE", "BOT-MANAGED-IDENTITY"))
    );

    private static final Map<String, List<PolicyParameterSpec>> PARAMETER_SPECS = Map.of(
            "AWS_BEDROCK_WEAK_GUARDRAIL", List.of(new PolicyParameterSpec(
                    "minimumGuardrailStrength",
                    "Minimum guardrail strength",
                    "ENUM",
                    List.of("NONE", "LOW", "MEDIUM", "HIGH"),
                    "MEDIUM",
                    "Agents in scope must have a guardrail at or above this strength attached."))
    );

    public List<PolicyDefinition> all() {
        return definitions;
    }

    public Optional<PolicyDefinition> find(String policyId) {
        return definitions.stream().filter(definition -> definition.id().equals(policyId)).findFirst();
    }

    public List<PolicyParameterSpec> parameterSpecs(String policyId) {
        return PARAMETER_SPECS.getOrDefault(policyId, List.of());
    }

    public record PolicyDefinition(
            String id,
            String version,
            String name,
            String severity,
            List<String> artifactTypes,
            List<String> requiredResourceFamilies,
            String description,
            String remediation,
            Map<String, String> controlMappings
    ) {
    }

    public record PolicyParameterSpec(
            String key,
            String label,
            String type,
            List<String> options,
            String defaultValue,
            String helpText
    ) {
    }
}
