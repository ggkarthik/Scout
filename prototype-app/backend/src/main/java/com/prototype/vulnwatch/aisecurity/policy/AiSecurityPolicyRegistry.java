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
                    Map.of("AWS", "BEDROCK-LOGGING"))
    );

    public List<PolicyDefinition> all() {
        return definitions;
    }

    public Optional<PolicyDefinition> find(String policyId) {
        return definitions.stream().filter(definition -> definition.id().equals(policyId)).findFirst();
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
}
