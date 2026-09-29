package com.prototype.vulnwatch.aisecurity.aws;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.stereotype.Component;

/** Governed read-only AWS permission, capability and probe contract. */
@Component
public class AwsPolicyPermissionMatrix {

    public static final int VERSION = 1;
    public static final List<String> PROHIBITED_MUTATION_ACTIONS = List.of(
            "iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:DeleteAccessKey",
            "iam:PassRole", "cloudformation:*", "cloudtrail:PutEventSelectors",
            "logs:Put*", "s3:Put*", "s3:Delete*", "xray:Put*");
    private static final Map<String, List<String>> POLICIES_BY_CAPABILITY = Map.ofEntries(
            Map.entry("BEDROCK_GUARDRAILS", List.of("AGCF-AWS-001", "AGCF-AWS-002", "AGCF-AWS-010",
                    "AGCF-AWS-011", "AGCF-AWS-012", "AGCF-AWS-013", "AGCF-AWS-016")),
            Map.entry("BEDROCK_AGENTS", List.of("AGCF-AWS-003", "AGCF-AWS-004", "AGCF-AWS-005",
                    "AGCF-AWS-014", "AGCF-AWS-015", "AGCF-AWS-020", "AGCF-AWS-021", "AGCF-AWS-022",
                    "AGCF-AWS-038")),
            Map.entry("IAM_ROLE_POLICIES", List.of("AGCF-AWS-004", "AGCF-AWS-005")),
            Map.entry("LAMBDA_URLS", List.of("AGCF-AWS-006", "AGCF-AWS-008")),
            Map.entry("BEDROCK_MODELS_JOBS", List.of("AGCF-AWS-007", "AGCF-AWS-009", "AGCF-AWS-025",
                    "AGCF-AWS-026", "AGCF-AWS-027", "AGCF-AWS-028", "AGCF-AWS-029", "AGCF-AWS-030")),
            Map.entry("BEDROCK_KNOWLEDGE_BASES", List.of("AGCF-AWS-017", "AGCF-AWS-018", "AGCF-AWS-019",
                    "AGCF-AWS-023", "AGCF-AWS-024")),
            Map.entry("AGENTCORE_GATEWAYS_TARGETS", List.of("AGCF-AWS-031", "AGCF-AWS-032", "AGCF-AWS-033",
                    "AGCF-AWS-034")),
            Map.entry("SAGEMAKER_DOMAINS_MODELS_ENDPOINTS", List.of("AGCF-AWS-035", "AGCF-AWS-036",
                    "AGCF-AWS-037")));

    private final Map<String, FamilyPermission> families = build();

    public Set<String> resourceFamilies() {
        return families.keySet();
    }

    public FamilyPermission family(String resourceFamily) {
        FamilyPermission value = families.get(resourceFamily);
        if (value == null) throw new IllegalArgumentException("Unsupported AWS resource family");
        return value;
    }

    public RequirementsReport requirementsReport() {
        return new RequirementsReport(VERSION, "AWS", List.copyOf(families.values()),
                PROHIBITED_MUTATION_ACTIONS);
    }

    private Map<String, FamilyPermission> build() {
        Map<String, FamilyPermission> result = new LinkedHashMap<>();
        add(result, "BEDROCK_AGENTS", "REGIONAL", "BEDROCK_AGENTS", List.of("bedrock:ListAgents", "bedrock:GetAgent"),
                List.of(), List.of("BEDROCK_AGENTS"));
        add(result, "BEDROCK_AGENT_VERSIONS", "REGIONAL", "BEDROCK_AGENTS", List.of(
                "bedrock:ListAgents", "bedrock:ListAgentVersions", "bedrock:GetAgentVersion", "bedrock:ListAgentAliases"),
                List.of(), List.of("BEDROCK_AGENT_VERSIONS_ALIASES"));
        add(result, "BEDROCK_AGENT_DEFINITIONS", "REGIONAL", "BEDROCK_AGENTS", List.of(
                "bedrock:ListAgentActionGroups", "bedrock:GetAgentActionGroup", "bedrock:ListAgentKnowledgeBases"),
                List.of(), List.of("BEDROCK_PROMPTS_TOOLS"));
        add(result, "BEDROCK_KNOWLEDGE_BASES", "REGIONAL", "BEDROCK_KNOWLEDGE_BASES",
                List.of("bedrock:ListKnowledgeBases", "bedrock:GetKnowledgeBase"), List.of(),
                List.of("BEDROCK_KNOWLEDGE_BASES"));
        add(result, "BEDROCK_DATA_SOURCES", "REGIONAL", "BEDROCK_KNOWLEDGE_BASES",
                List.of("bedrock:ListDataSources", "bedrock:GetDataSource"), List.of(),
                List.of("BEDROCK_KNOWLEDGE_BASES"));
        add(result, "BEDROCK_DATA_STORES", "REGIONAL", "BEDROCK_KNOWLEDGE_BASES",
                List.of("bedrock:GetKnowledgeBase", "bedrock:GetDataSource"), List.of(),
                List.of("BEDROCK_KNOWLEDGE_BASES"));
        add(result, "BEDROCK_GUARDRAILS", "REGIONAL", "BEDROCK_MODELS", List.of("bedrock:ListGuardrails", "bedrock:GetGuardrail"),
                List.of(), List.of("BEDROCK_GUARDRAILS"));
        add(result, "BEDROCK_INVOCATION_LOGGING", "REGIONAL", "BEDROCK_MODELS",
                List.of("bedrock:GetModelInvocationLoggingConfiguration"), List.of(), List.of("BEDROCK_INVOCATION_LOGGING"));
        add(result, "BEDROCK_DEPLOYABLE_MODELS", "REGIONAL", "BEDROCK_MODELS", List.of(
                "bedrock:ListFoundationModels", "bedrock:ListCustomModels", "bedrock:ListImportedModels", "bedrock:ListProvisionedModelThroughputs"),
                List.of(), List.of("BEDROCK_MODELS_JOBS"));
        add(result, "BEDROCK_INFERENCE_PROFILES", "REGIONAL", "BEDROCK_MODELS",
                List.of("bedrock:ListInferenceProfiles"), List.of(), List.of("BEDROCK_MODELS_JOBS"));
        add(result, "BEDROCK_MODEL_CUSTOMIZATION_JOBS", "REGIONAL", "BEDROCK_MODELS",
                List.of("bedrock:ListModelCustomizationJobs"), List.of(), List.of("BEDROCK_MODELS_JOBS"));
        add(result, "BEDROCK_PROMPTS", "REGIONAL", "BEDROCK_AGENTS", List.of("bedrock:ListPrompts"), List.of(),
                List.of("BEDROCK_PROMPTS_TOOLS"));
        add(result, "BEDROCK_FLOWS", "REGIONAL", "BEDROCK_AGENTS", List.of("bedrock:ListFlows"), List.of(),
                List.of("BEDROCK_PROMPTS_TOOLS"));

        addAgentCore(result, "AWS_AGENTCORE_GATEWAYS", "AGENTCORE_GATEWAYS", "AGENTCORE_GATEWAYS_TARGETS",
                List.of("bedrock-agentcore:ListGateways", "bedrock-agentcore:GetGateway"));
        addAgentCore(result, "AWS_AGENTCORE_GATEWAY_TARGETS", "AGENTCORE_GATEWAYS", "AGENTCORE_GATEWAYS_TARGETS",
                List.of("bedrock-agentcore:ListGatewayTargets", "bedrock-agentcore:GetGatewayTarget"));
        addAgentCore(result, "AWS_AGENTCORE_RUNTIMES", "AGENTCORE_RUNTIMES", "AGENTCORE_RUNTIME_TOOLS", List.of(
                "bedrock-agentcore:ListAgentRuntimes", "bedrock-agentcore:GetAgentRuntime",
                "bedrock-agentcore:ListAgentRuntimeVersions", "bedrock-agentcore:ListAgentRuntimeEndpoints"));
        addAgentCore(result, "AWS_AGENTCORE_BROWSERS", "AGENTCORE_BROWSERS", "AGENTCORE_RUNTIME_TOOLS", List.of("bedrock-agentcore:ListBrowsers"));
        addAgentCore(result, "AWS_AGENTCORE_CODE_INTERPRETERS", "AGENTCORE_CODE_INTERPRETERS", "AGENTCORE_RUNTIME_TOOLS",
                List.of("bedrock-agentcore:ListCodeInterpreters"));
        addAgentCore(result, "AWS_AGENTCORE_MEMORIES", "AGENTCORE_MEMORIES", "AGENTCORE_RUNTIME_TOOLS", List.of("bedrock-agentcore:ListMemories"));

        add(result, "IAM_GLOBAL", "GLOBAL", "IAM", List.of(
                "iam:ListRoles", "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
                "iam:GetPolicy", "iam:GetPolicyVersion"), List.of("access-analyzer:ListFindings"),
                List.of("IAM_ROLE_POLICIES", "AWS_EFFECTIVE_ACCESS"));
        add(result, "LAMBDA_URLS", "REGIONAL", "LAMBDA", List.of("lambda:ListFunctions", "lambda:GetFunctionUrlConfig"),
                List.of("lambda:GetPolicy"), List.of("LAMBDA_URLS"));
        add(result, "S3_EXPOSURE", "REGIONAL", "S3", List.of("s3:ListAllMyBuckets", "s3:GetBucketPolicyStatus"),
                List.of("s3:GetPublicAccessBlock"), List.of("AWS_LINKED_DATA_STORES"));
        add(result, "AWS_MACIE_PII", "REGIONAL", "MACIE", List.of(
                "macie2:GetMacieSession", "macie2:ListFindings", "macie2:GetFindings"), List.of(), List.of("MACIE_CLASSIFICATION"));

        addSageMaker(result, "SAGEMAKER_DOMAINS", "sagemaker:ListDomains", "SAGEMAKER_DOMAINS_MODELS_ENDPOINTS");
        addSageMaker(result, "SAGEMAKER_SPACES", "sagemaker:ListSpaces", "SAGEMAKER_DOMAINS_MODELS_ENDPOINTS");
        addSageMaker(result, "SAGEMAKER_MODEL_REGISTRY", "sagemaker:ListModelPackages", "SAGEMAKER_DOMAINS_MODELS_ENDPOINTS");
        addSageMaker(result, "SAGEMAKER_ENDPOINTS", "sagemaker:ListEndpoints", "SAGEMAKER_DOMAINS_MODELS_ENDPOINTS");
        addSageMaker(result, "SAGEMAKER_ENDPOINT_CONFIGURATIONS", "sagemaker:ListEndpointConfigs", "SAGEMAKER_DOMAINS_MODELS_ENDPOINTS");
        addSageMaker(result, "SAGEMAKER_JOBS", "sagemaker:ListTrainingJobs", "SAGEMAKER_DOMAINS_MODELS_ENDPOINTS");
        addSageMaker(result, "SAGEMAKER_PIPELINES", "sagemaker:ListPipelines", "SAGEMAKER_DOMAINS_MODELS_ENDPOINTS");
        addSageMaker(result, "SAGEMAKER_COMPUTE", "sagemaker:ListNotebookInstances", "SAGEMAKER_DOMAINS_MODELS_ENDPOINTS");
        addSageMaker(result, "SAGEMAKER_EXECUTION_ROLES", "sagemaker:ListDomains", "SAGEMAKER_DOMAINS_MODELS_ENDPOINTS");
        addSageMaker(result, "SAGEMAKER_NETWORKING", "sagemaker:ListDomains", "SAGEMAKER_DOMAINS_MODELS_ENDPOINTS");
        return Map.copyOf(result);
    }

    private void addAgentCore(Map<String, FamilyPermission> target, String family, String probe,
                              String capability, List<String> actions) {
        add(target, family, "REGIONAL", probe, actions, List.of(), List.of(capability));
    }

    private void addSageMaker(Map<String, FamilyPermission> target, String family, String action, String capability) {
        add(target, family, "REGIONAL", "SAGEMAKER", List.of(action), List.of(), List.of(capability));
    }

    private void add(Map<String, FamilyPermission> target, String family, String scope, String probe,
                     List<String> required, List<String> optional, List<String> capabilities) {
        target.put(family, new FamilyPermission(family, scope, required, optional, probe,
                capabilities, policies(capabilities), "Grant only the listed read actions for " + family + "."));
    }

    private List<String> policies(List<String> capabilities) {
        Set<String> policies = new TreeSet<>();
        capabilities.forEach(capability -> policies.addAll(POLICIES_BY_CAPABILITY.getOrDefault(capability, List.of())));
        return List.copyOf(policies);
    }

    public record FamilyPermission(String resourceFamily, String scope, List<String> requiredActions,
                                   List<String> optionalEnrichmentActions, String verificationProbe,
                                   List<String> capabilities, List<String> policies,
                                   String customerRemediation) { }

    public record RequirementsReport(int matrixVersion, String provider,
                                     List<FamilyPermission> resourceFamilies,
                                     List<String> prohibitedMutationActions) { }
}
