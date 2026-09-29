package com.prototype.vulnwatch.aisecurity.aws;

import com.prototype.vulnwatch.aisecurity.service.AiGridProviderCallCounter;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.ConnectorSecret;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.CredentialsHandle;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.bedrock.BedrockClient;
import software.amazon.awssdk.services.bedrock.model.ListFoundationModelsRequest;
import software.amazon.awssdk.services.bedrockagent.BedrockAgentClient;
import software.amazon.awssdk.services.bedrockagent.model.ListAgentsRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListKnowledgeBasesRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.BedrockAgentCoreControlClient;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListAgentRuntimesRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListBrowsersRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListCodeInterpretersRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListGatewaysRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListMemoriesRequest;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.ListRolesRequest;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.ListFunctionsRequest;
import software.amazon.awssdk.services.macie2.Macie2Client;
import software.amazon.awssdk.services.macie2.model.GetMacieSessionRequest;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.sagemaker.SageMakerClient;
import software.amazon.awssdk.services.sagemaker.model.ListDomainsRequest;
import software.amazon.awssdk.services.sts.StsClient;

/** Explicit, user-triggered, bounded AWS permission verification. Never invoked by save/discovery. */
@Service
public class AwsPermissionPreflightService {
    private final AiSecurityAwsConnectorService connectors;
    private final AwsPolicyPermissionMatrix matrix;
    private final AiGridProviderCallCounter calls;
    private final long ceiling;
    private final boolean maciePiiEnabled;
    private final ExecutionInterceptor counter = new ExecutionInterceptor() {
        @Override public void beforeTransmission(Context.BeforeTransmission context, ExecutionAttributes attributes) {
            calls.increment();
        }
    };

    public AwsPermissionPreflightService(AiSecurityAwsConnectorService connectors,
                                         AwsPolicyPermissionMatrix matrix,
                                         AiGridProviderCallCounter calls,
                                         @Value("${app.ai-security.provider-call-ceiling:10000}") long ceiling,
                                         @Value("${app.ai-security.aws.macie-pii.enabled:false}") boolean maciePiiEnabled) {
        this.connectors = connectors;
        this.matrix = matrix;
        this.calls = calls;
        this.ceiling = ceiling;
        this.maciePiiEnabled = maciePiiEnabled;
    }

    public PreflightReport run(Tenant tenant) {
        ConnectorSecret config = connectors.secret(tenant);
        List<FamilyResult> families = new ArrayList<>();
        Identity identity = null;
        if (!config.enabled()) {
            return new PreflightReport(null, disabledFamilies(config, "Connector collection is disabled"), 0, true);
        }
        try (var measurement = calls.begin(ceiling); CredentialsHandle credentials = connectors.credentials(config)) {
            try (StsClient sts = StsClient.builder().region(Region.US_EAST_1)
                    .credentialsProvider(credentials.provider())
                    .overrideConfiguration(c -> c.addExecutionInterceptor(counter)).build()) {
                var caller = sts.getCallerIdentity();
                identity = new Identity(caller.account(), caller.arn(), caller.userId());
            }
            Map<String, ProbeOutcome> cache = new LinkedHashMap<>();
            for (AwsPolicyPermissionMatrix.FamilyPermission family : matrix.requirementsReport().resourceFamilies()) {
                List<String> regions = "GLOBAL".equals(family.scope())
                        ? List.of("GLOBAL") : config.regions();
                for (String region : regions) {
                    if ("AWS_MACIE_PII".equals(family.resourceFamily()) && !maciePiiEnabled) {
                        families.add(disabled(family, region, "Cost-sensitive Macie collection is disabled"));
                        continue;
                    }
                    String key = region + "|" + family.verificationProbe();
                    ProbeOutcome outcome = cache.computeIfAbsent(key,
                            ignored -> probe(credentials, region, family.verificationProbe()));
                    families.add(result(family, region, outcome));
                }
            }
            return new PreflightReport(identity, families, measurement.count(), true);
        }
    }

    private List<FamilyResult> disabledFamilies(ConnectorSecret config, String detail) {
        List<FamilyResult> results = new ArrayList<>();
        for (AwsPolicyPermissionMatrix.FamilyPermission family : matrix.requirementsReport().resourceFamilies()) {
            List<String> regions = "GLOBAL".equals(family.scope()) ? List.of("GLOBAL") : config.regions();
            regions.forEach(region -> results.add(disabled(family, region, detail)));
        }
        return List.copyOf(results);
    }

    private FamilyResult disabled(AwsPolicyPermissionMatrix.FamilyPermission family, String region, String detail) {
        List<ActionResult> actions = new ArrayList<>();
        family.requiredActions().forEach(action -> actions.add(new ActionResult(action, "DISABLED", detail)));
        family.optionalEnrichmentActions().forEach(action -> actions.add(new ActionResult(action, "DISABLED", detail)));
        return new FamilyResult(family.resourceFamily(), region, "DISABLED", List.copyOf(actions),
                family.customerRemediation());
    }

    private FamilyResult result(AwsPolicyPermissionMatrix.FamilyPermission family, String region,
                                ProbeOutcome outcome) {
        List<ActionResult> actions = new ArrayList<>();
        for (int index = 0; index < family.requiredActions().size(); index++) {
            String status;
            if (!"COMPLETE".equals(outcome.familyStatus())) status = outcome.actionStatus();
            else if (index == 0) status = outcome.empty() ? "VERIFIED_EMPTY" : "VERIFIED_ALLOWED";
            else status = outcome.empty() ? "NOT_VERIFIED_EMPTY" : "VERIFIED_ALLOWED";
            actions.add(new ActionResult(family.requiredActions().get(index), status, outcome.detail()));
        }
        family.optionalEnrichmentActions().forEach(action -> actions.add(new ActionResult(action,
                "COMPLETE".equals(outcome.familyStatus())
                        ? (outcome.empty() ? "NOT_VERIFIED_EMPTY" : "VERIFIED_ALLOWED")
                        : outcome.actionStatus(), outcome.detail())));
        return new FamilyResult(family.resourceFamily(), region, outcome.familyStatus(), actions,
                family.customerRemediation());
    }

    private ProbeOutcome probe(CredentialsHandle credentials, String regionName, String probe) {
        Region region = "GLOBAL".equals(regionName) ? Region.AWS_GLOBAL : Region.of(regionName);
        try {
            boolean empty = switch (probe) {
                case "BEDROCK_AGENTS" -> probeBedrockAgents(credentials, region);
                case "BEDROCK_KNOWLEDGE_BASES" -> probeKnowledgeBases(credentials, region);
                case "BEDROCK_MODELS" -> probeBedrockModels(credentials, region);
                case "AGENTCORE_GATEWAYS" -> probeAgentCore(credentials, region, probe);
                case "AGENTCORE_RUNTIMES" -> probeAgentCore(credentials, region, probe);
                case "AGENTCORE_BROWSERS" -> probeAgentCore(credentials, region, probe);
                case "AGENTCORE_CODE_INTERPRETERS" -> probeAgentCore(credentials, region, probe);
                case "AGENTCORE_MEMORIES" -> probeAgentCore(credentials, region, probe);
                case "IAM" -> probeIam(credentials);
                case "LAMBDA" -> probeLambda(credentials, region);
                case "S3" -> probeS3(credentials, region);
                case "MACIE" -> probeMacie(credentials, region);
                case "SAGEMAKER" -> probeSageMaker(credentials, region);
                default -> throw new IllegalArgumentException("Unknown AWS preflight probe: " + probe);
            };
            return new ProbeOutcome("COMPLETE", empty, "VERIFIED_ALLOWED", empty
                    ? "Authoritative list probe returned no resources" : "Bounded provider probe succeeded");
        } catch (AiGridProviderCallCounter.ProviderCallBudgetExceededException exception) {
            return new ProbeOutcome("PARTIAL", false, "ERROR", "PROVIDER_CALL_BUDGET_EXHAUSTED");
        } catch (AwsServiceException exception) {
            String code = exception.awsErrorDetails() == null ? "" : exception.awsErrorDetails().errorCode();
            if (code.toLowerCase().contains("accessdenied") || code.toLowerCase().contains("unauthorized")) {
                return new ProbeOutcome("UNAUTHORIZED", false, "UNAUTHORIZED", "AWS denied the bounded verification probe");
            }
            if (Set.of("UnknownOperationException", "UnsupportedOperation", "InvalidAction").contains(code)) {
                return new ProbeOutcome("UNSUPPORTED_API", false, "UNSUPPORTED_API", "API is unavailable in this scope");
            }
            return new ProbeOutcome("ERROR", false, "ERROR", "AWS verification probe failed");
        } catch (RuntimeException exception) {
            return new ProbeOutcome("ERROR", false, "ERROR", "AWS verification probe failed");
        }
    }

    private boolean probeBedrockAgents(CredentialsHandle credentials, Region region) {
        try (BedrockAgentClient client = BedrockAgentClient.builder().region(region).credentialsProvider(credentials.provider())
                .overrideConfiguration(c -> c.addExecutionInterceptor(counter)).build()) {
            return client.listAgents(ListAgentsRequest.builder().maxResults(1).build()).agentSummaries().isEmpty();
        }
    }
    private boolean probeKnowledgeBases(CredentialsHandle credentials, Region region) {
        try (BedrockAgentClient client = BedrockAgentClient.builder().region(region).credentialsProvider(credentials.provider())
                .overrideConfiguration(c -> c.addExecutionInterceptor(counter)).build()) {
            return client.listKnowledgeBases(ListKnowledgeBasesRequest.builder().maxResults(1).build()).knowledgeBaseSummaries().isEmpty();
        }
    }
    private boolean probeBedrockModels(CredentialsHandle credentials, Region region) {
        try (BedrockClient client = BedrockClient.builder().region(region).credentialsProvider(credentials.provider())
                .overrideConfiguration(c -> c.addExecutionInterceptor(counter)).build()) {
            return client.listFoundationModels(ListFoundationModelsRequest.builder().build()).modelSummaries().isEmpty();
        }
    }
    private boolean probeAgentCore(CredentialsHandle credentials, Region region, String probe) {
        try (BedrockAgentCoreControlClient client = BedrockAgentCoreControlClient.builder().region(region)
                .credentialsProvider(credentials.provider()).overrideConfiguration(c -> c.addExecutionInterceptor(counter)).build()) {
            return switch (probe) {
                case "AGENTCORE_GATEWAYS" -> client.listGateways(ListGatewaysRequest.builder().maxResults(1).build()).items().isEmpty();
                case "AGENTCORE_RUNTIMES" -> client.listAgentRuntimes(ListAgentRuntimesRequest.builder().maxResults(1).build()).agentRuntimes().isEmpty();
                case "AGENTCORE_BROWSERS" -> client.listBrowsers(ListBrowsersRequest.builder().maxResults(1).build()).browserSummaries().isEmpty();
                case "AGENTCORE_CODE_INTERPRETERS" -> client.listCodeInterpreters(ListCodeInterpretersRequest.builder().maxResults(1).build()).codeInterpreterSummaries().isEmpty();
                case "AGENTCORE_MEMORIES" -> client.listMemories(ListMemoriesRequest.builder().maxResults(1).build()).memories().isEmpty();
                default -> throw new IllegalArgumentException("Unknown AgentCore preflight probe");
            };
        }
    }
    private boolean probeIam(CredentialsHandle credentials) {
        try (IamClient client = IamClient.builder().region(Region.AWS_GLOBAL).credentialsProvider(credentials.provider())
                .overrideConfiguration(c -> c.addExecutionInterceptor(counter)).build()) {
            return client.listRoles(ListRolesRequest.builder().maxItems(1).build()).roles().isEmpty();
        }
    }
    private boolean probeLambda(CredentialsHandle credentials, Region region) {
        try (LambdaClient client = LambdaClient.builder().region(region).credentialsProvider(credentials.provider())
                .overrideConfiguration(c -> c.addExecutionInterceptor(counter)).build()) {
            return client.listFunctions(ListFunctionsRequest.builder().maxItems(1).build()).functions().isEmpty();
        }
    }
    private boolean probeS3(CredentialsHandle credentials, Region region) {
        try (S3Client client = S3Client.builder().region(region).credentialsProvider(credentials.provider())
                .overrideConfiguration(c -> c.addExecutionInterceptor(counter)).build()) {
            return client.listBuckets().buckets().isEmpty();
        }
    }
    private boolean probeMacie(CredentialsHandle credentials, Region region) {
        try (Macie2Client client = Macie2Client.builder().region(region).credentialsProvider(credentials.provider())
                .overrideConfiguration(c -> c.addExecutionInterceptor(counter)).build()) {
            client.getMacieSession(GetMacieSessionRequest.builder().build());
            return false;
        }
    }
    private boolean probeSageMaker(CredentialsHandle credentials, Region region) {
        try (SageMakerClient client = SageMakerClient.builder().region(region).credentialsProvider(credentials.provider())
                .overrideConfiguration(c -> c.addExecutionInterceptor(counter)).build()) {
            return client.listDomains(ListDomainsRequest.builder().maxResults(1).build()).domains().isEmpty();
        }
    }

    private record ProbeOutcome(String familyStatus, boolean empty, String actionStatus, String detail) { }
    public record Identity(String accountId, String arn, String principalId) { }
    public record ActionResult(String action, String status, String detail) { }
    public record FamilyResult(String resourceFamily, String region, String status,
                               List<ActionResult> actions, String customerRemediation) { }
    public record PreflightReport(Identity identity, List<FamilyResult> resourceFamilies,
                                  long providerApiCalls, boolean explicitlyRequested) { }
}
