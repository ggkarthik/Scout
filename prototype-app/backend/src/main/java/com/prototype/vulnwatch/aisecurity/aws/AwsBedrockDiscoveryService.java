package com.prototype.vulnwatch.aisecurity.aws;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.Diagnostic;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.RelationshipObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.ConnectorSecret;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.CredentialsHandle;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityObservationService;
import com.prototype.vulnwatch.aisecurity.service.AiSecuritySyncRunFacade;
import com.prototype.vulnwatch.aisecurity.service.AiGridBudgetService;
import com.prototype.vulnwatch.aisecurity.service.AiGridProviderCallCounter;
import com.prototype.vulnwatch.aisecurity.service.AiGridRunMetricsService;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.bedrock.BedrockClient;
import software.amazon.awssdk.services.bedrock.model.GetGuardrailRequest;
import software.amazon.awssdk.services.bedrock.model.GetModelInvocationLoggingConfigurationRequest;
import software.amazon.awssdk.services.bedrock.model.GuardrailContentFilter;
import software.amazon.awssdk.services.bedrock.model.ListGuardrailsRequest;
import software.amazon.awssdk.services.bedrockagent.BedrockAgentClient;
import software.amazon.awssdk.services.bedrockagent.model.GetAgentActionGroupRequest;
import software.amazon.awssdk.services.bedrockagent.model.GetAgentRequest;
import software.amazon.awssdk.services.bedrockagent.model.GetDataSourceRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListAgentActionGroupsRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListAgentKnowledgeBasesRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListAgentsRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListDataSourcesRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListKnowledgeBasesRequest;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.GetPolicyRequest;
import software.amazon.awssdk.services.iam.model.GetPolicyVersionRequest;
import software.amazon.awssdk.services.iam.model.GetRolePolicyRequest;
import software.amazon.awssdk.services.iam.model.ListAttachedRolePoliciesRequest;
import software.amazon.awssdk.services.iam.model.ListRolePoliciesRequest;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.GetFunctionUrlConfigRequest;
import software.amazon.awssdk.services.lambda.model.ResourceNotFoundException;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetBucketPolicyStatusRequest;

@Service
public class AwsBedrockDiscoveryService {

    private final AiSecurityAwsConnectorService connectorService;
    private final AiSecurityObservationService observationService;
    private final AiSecuritySyncRunFacade syncRunFacade;
    private final ObjectMapper objectMapper;
    private final AiSecurityAwsAdmissionService admissionService;
    private final AiGridBudgetService budgets;
    private final AiGridProviderCallCounter providerCalls;
    private final AiGridRunMetricsService runMetrics;
    private final ExecutionInterceptor providerCallInterceptor = new ExecutionInterceptor() {
        @Override
        public void beforeTransmission(Context.BeforeTransmission context, ExecutionAttributes executionAttributes) {
            providerCalls.increment();
        }
    };

    public AwsBedrockDiscoveryService(
            AiSecurityAwsConnectorService connectorService,
            AiSecurityObservationService observationService,
            AiSecuritySyncRunFacade syncRunFacade,
            ObjectMapper objectMapper,
            AiSecurityAwsAdmissionService admissionService,
            AiGridBudgetService budgets,
            AiGridProviderCallCounter providerCalls,
            AiGridRunMetricsService runMetrics
    ) {
        this.connectorService = connectorService;
        this.observationService = observationService;
        this.syncRunFacade = syncRunFacade;
        this.objectMapper = objectMapper;
        this.admissionService = admissionService;
        this.budgets = budgets;
        this.providerCalls = providerCalls;
        this.runMetrics = runMetrics;
    }

    public DiscoveryResult discover(Tenant tenant, UUID connectorId) {
        ConnectorSecret config = connectorService.secret(tenant);
        if (!config.id().equals(connectorId)) {
            throw new IllegalArgumentException("AI Security connector does not match claimed job");
        }
        SyncRun run = syncRunFacade.start(tenant, AiSecuritySyncRunFacade.AWS_SYNC_TYPE, json(Map.of(
                "provider", "AWS",
                "connectorId", connectorId,
                "accountId", config.accountId(),
                "regions", config.regions())));
        int artifacts = 0;
        int failedScopes = 0;
        try (var measurement = providerCalls.begin()) {
            try {
                budgets.admit(tenant, run.getId(), "AWS", List.of(
                        "BEDROCK_AGENTS", "IAM_GLOBAL", "LAMBDA_URLS", "BEDROCK_KNOWLEDGE_BASES",
                        "S3_EXPOSURE", "BEDROCK_GUARDRAILS", "BEDROCK_INVOCATION_LOGGING"), "*", "*");
                try (CredentialsHandle credentials = connectorService.credentials(config)) {
                    Set<String> ingestedScopeKeys = new java.util.HashSet<>();
                    for (String regionName : config.regions()) {
                        Region region = Region.of(regionName);
                        try (var permit = admissionService.acquire(config.accountId(), regionName)) {
                            RegionContext context = discoverRegion(config, credentials.provider(), region);
                            for (ScopePayload scope : context.scopes()) {
                                // Global scopes are collected during each regional pass, but
                                // the receipt contract permits one global scope per run.
                                String scopeKey = "AWS:" + config.accountId() + ":"
                                        + (scope.global() ? "GLOBAL" : regionName) + ":" + scope.family();
                                if (!ingestedScopeKeys.add(scopeKey)) {
                                    continue;
                                }
                                observationService.ingest(tenant, envelope(tenant, config, run.getId(), regionName, scope));
                                artifacts += scope.artifacts().size();
                                if (scope.status() != ScopeStatus.COMPLETE) {
                                    failedScopes++;
                                }
                            }
                        }
                    }
                }
                int persistedArtifacts = observationService.countPersistedArtifacts(tenant, run.getId());
                runMetrics.recordProviderCalls(tenant, run.getId(), "AWS", measurement.count());
                budgets.reconcile(tenant, run.getId(), "AWS");
                syncRunFacade.complete(
                        tenant.getId(), run.getId(), persistedArtifacts, failedScopes,
                        json(Map.of(
                                "provider", "AWS",
                                "connectorId", connectorId,
                                "accountId", config.accountId(),
                                "regions", config.regions(),
                                "providerApiCalls", measurement.count())));
                return new DiscoveryResult(run.getId(), persistedArtifacts, failedScopes);
            } catch (Exception ex) {
                runMetrics.recordProviderCalls(tenant, run.getId(), "AWS", measurement.count());
                budgets.reconcile(tenant, run.getId(), "AWS");
                syncRunFacade.fail(tenant.getId(), run.getId(), "AWS Bedrock discovery failed");
                throw ex;
            }
        }
    }

    private RegionContext discoverRegion(
            ConnectorSecret config, AwsCredentialsProvider credentials, Region region) {
        List<ScopePayload> scopes = new ArrayList<>();
        AgentContext agents = collectAgents(config, credentials, region, scopes);
        collectIam(config, credentials, region, agents, scopes);
        collectLambdaUrls(config, credentials, region, agents, scopes);
        collectKnowledgeBases(config, credentials, region, agents, scopes);
        collectGuardrails(config, credentials, region, agents, scopes);
        collectInvocationLogging(config, credentials, region, scopes);
        return new RegionContext(scopes);
    }

    private AgentContext collectAgents(
            ConnectorSecret config,
            AwsCredentialsProvider credentials,
            Region region,
            List<ScopePayload> scopes
    ) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        List<RelationshipObservation> relationships = new ArrayList<>();
        Map<String, AgentFact> facts = new LinkedHashMap<>();
        try (BedrockAgentClient client = BedrockAgentClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            String token = null;
            do {
                var response = client.listAgents(ListAgentsRequest.builder().nextToken(token).build());
                for (var summary : response.agentSummaries()) {
                    var agent = client.getAgent(GetAgentRequest.builder().agentId(summary.agentId()).build()).agent();
                    String agentArn = arn(config, region, "agent/" + summary.agentId());
                    Map<String, Object> attributes = new LinkedHashMap<>();
                    attributes.put("agentId", summary.agentId());
                    attributes.put("status", summary.agentStatusAsString());
                    attributes.put("executionRoleArn", agent.agentResourceRoleArn());
                    attributes.put("foundationModel", agent.foundationModel());
                    boolean guardrailAttached = agent.guardrailConfiguration() != null
                            && hasText(agent.guardrailConfiguration().guardrailIdentifier());
                    attributes.put("guardrailAttached", guardrailAttached);
                    if (guardrailAttached) {
                        attributes.put("guardrailId", agent.guardrailConfiguration().guardrailIdentifier());
                    }
                    artifacts.add(new ArtifactObservation(
                            agentArn, "AI_AGENT", "AWS_BEDROCK_AGENT", summary.agentName(), attributes));
                    facts.put(summary.agentId(), new AgentFact(
                            summary.agentId(), agentArn, agent.agentResourceRoleArn(), agent.foundationModel(),
                            guardrailAttached ? agent.guardrailConfiguration().guardrailIdentifier() : null));

                    if (hasText(agent.foundationModel())) {
                        String modelId = agent.foundationModel();
                        String modelResourceId = modelId.startsWith("arn:")
                                ? modelId
                                : "bedrock:model:" + region.id() + ":" + modelId;
                        artifacts.add(new ArtifactObservation(
                                modelResourceId, "AI_MODEL", "AWS_BEDROCK_MODEL", modelId,
                                Map.of("referencedByAgent", true)));
                        relationships.add(new RelationshipObservation(
                                agentArn, modelResourceId, "USES_MODEL", Map.of()));
                    }
                }
                token = response.nextToken();
            } while (hasText(token));
            scopes.add(complete("BEDROCK_AGENTS", artifacts, relationships));
        } catch (Exception ex) {
            scopes.add(failed("BEDROCK_AGENTS", ex, List.of(
                    "bedrock:ListAgents", "bedrock:GetAgent")));
        }
        return new AgentContext(facts);
    }

    private void collectIam(
            ConnectorSecret config,
            AwsCredentialsProvider credentials,
            Region region,
            AgentContext agents,
            List<ScopePayload> scopes
    ) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        try (IamClient iam = IamClient.builder().region(Region.AWS_GLOBAL).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            for (AgentFact agent : agents.facts().values()) {
                if (!hasText(agent.roleArn())) {
                    artifacts.add(agentUpdate(agent, Map.of("iamEvidenceAvailable", false)));
                    continue;
                }
                artifacts.add(agentUpdate(agent, Map.of(
                        "iamEvidenceAvailable", true,
                        "iamWildcardActions", hasWildcardActions(iam, agent.roleArn()))));
            }
            scopes.add(completeGlobal("IAM_GLOBAL", artifacts));
        } catch (Exception ex) {
            scopes.add(failedGlobal("IAM_GLOBAL", ex, List.of(
                    "iam:GetRole", "iam:ListAttachedRolePolicies", "iam:GetPolicy",
                    "iam:GetPolicyVersion", "iam:ListRolePolicies", "iam:GetRolePolicy")));
        }
    }

    private void collectLambdaUrls(
            ConnectorSecret config,
            AwsCredentialsProvider credentials,
            Region region,
            AgentContext agents,
            List<ScopePayload> scopes
    ) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        List<RelationshipObservation> relationships = new ArrayList<>();
        try (BedrockAgentClient bedrock = BedrockAgentClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build();
             LambdaClient lambda = LambdaClient.builder()
                     .region(region).credentialsProvider(credentials)
                     .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            for (AgentFact agent : agents.facts().values()) {
                List<String> lambdaArns = actionGroupLambdas(bedrock, agent.id());
                String effectiveAuth = "ABSENT";
                for (String lambdaArn : lambdaArns) {
                    String authType;
                    try {
                        authType = lambda.getFunctionUrlConfig(GetFunctionUrlConfigRequest.builder()
                                .functionName(functionName(lambdaArn)).build()).authTypeAsString();
                    } catch (ResourceNotFoundException ex) {
                        authType = "ABSENT";
                    }
                    if ("NONE".equals(authType)) {
                        effectiveAuth = "NONE";
                    } else if (!"NONE".equals(effectiveAuth) && !"ABSENT".equals(authType)) {
                        effectiveAuth = authType;
                    }
                    artifacts.add(new ArtifactObservation(
                            lambdaArn, "SUPPORTING_RESOURCE", "AWS_LAMBDA_FUNCTION", functionName(lambdaArn),
                            Map.of("functionUrlAuthType", authType)));
                    relationships.add(new RelationshipObservation(
                            agent.arn(), lambdaArn, "INVOKES_LAMBDA", Map.of()));
                }
                artifacts.add(agentUpdate(agent, Map.of("lambdaUrlAuthType", effectiveAuth)));
            }
            scopes.add(complete("LAMBDA_URLS", artifacts, relationships));
        } catch (Exception ex) {
            scopes.add(failed("LAMBDA_URLS", ex, List.of(
                    "bedrock:ListAgentActionGroups", "bedrock:GetAgentActionGroup",
                    "lambda:GetFunctionUrlConfig")));
        }
    }

    private void collectKnowledgeBases(
            ConnectorSecret config,
            AwsCredentialsProvider credentials,
            Region region,
            AgentContext agents,
            List<ScopePayload> scopes
    ) {
        List<ArtifactObservation> kbArtifacts = new ArrayList<>();
        List<ArtifactObservation> exposureArtifacts = new ArrayList<>();
        List<RelationshipObservation> relationships = new ArrayList<>();
        try (BedrockAgentClient bedrock = BedrockAgentClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build();
             S3Client s3 = S3Client.builder().region(region).credentialsProvider(credentials)
                     .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            String token = null;
            do {
                var response = bedrock.listKnowledgeBases(ListKnowledgeBasesRequest.builder().nextToken(token).build());
                for (var summary : response.knowledgeBaseSummaries()) {
                    String kbArn = arn(config, region, "knowledge-base/" + summary.knowledgeBaseId());
                    boolean anyPublic = false;
                    List<String> buckets = new ArrayList<>();
                    String dataToken = null;
                    do {
                        var dataSources = bedrock.listDataSources(ListDataSourcesRequest.builder()
                                .knowledgeBaseId(summary.knowledgeBaseId()).nextToken(dataToken).build());
                        for (var source : dataSources.dataSourceSummaries()) {
                            var detail = bedrock.getDataSource(GetDataSourceRequest.builder()
                                    .knowledgeBaseId(summary.knowledgeBaseId())
                                    .dataSourceId(source.dataSourceId()).build()).dataSource();
                            if (detail.dataSourceConfiguration() != null
                                    && detail.dataSourceConfiguration().s3Configuration() != null) {
                                String bucketArn = detail.dataSourceConfiguration().s3Configuration().bucketArn();
                                String bucketName = bucketArn.substring(bucketArn.lastIndexOf(':') + 1);
                                boolean isPublic = isBucketPublic(s3, bucketName);
                                anyPublic |= isPublic;
                                buckets.add(bucketArn);
                                exposureArtifacts.add(new ArtifactObservation(
                                        bucketArn, "SUPPORTING_RESOURCE", "AWS_S3_BUCKET", bucketName,
                                        Map.of("public", isPublic)));
                                relationships.add(new RelationshipObservation(
                                        kbArn, bucketArn, "READS_FROM_S3", Map.of("dataSourceId", source.dataSourceId())));
                            }
                        }
                        dataToken = dataSources.nextToken();
                    } while (hasText(dataToken));
                    Map<String, Object> attributes = new LinkedHashMap<>();
                    attributes.put("status", summary.statusAsString());
                    attributes.put("s3Public", anyPublic);
                    attributes.put("s3Buckets", buckets);
                    kbArtifacts.add(new ArtifactObservation(
                            kbArn, "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", summary.name(), attributes));
                }
                token = response.nextToken();
            } while (hasText(token));

            for (AgentFact agent : agents.facts().values()) {
                var attached = bedrock.listAgentKnowledgeBases(ListAgentKnowledgeBasesRequest.builder()
                        .agentId(agent.id()).agentVersion("DRAFT").build());
                for (var kb : attached.agentKnowledgeBaseSummaries()) {
                    relationships.add(new RelationshipObservation(
                            agent.arn(), arn(config, region, "knowledge-base/" + kb.knowledgeBaseId()),
                            "USES_KNOWLEDGE_BASE", Map.of()));
                }
            }
            scopes.add(complete("BEDROCK_KNOWLEDGE_BASES", kbArtifacts, relationships));
            scopes.add(complete("S3_EXPOSURE", exposureArtifacts, List.of()));
        } catch (Exception ex) {
            scopes.add(failed("BEDROCK_KNOWLEDGE_BASES", ex, List.of(
                    "bedrock:ListKnowledgeBases", "bedrock:ListDataSources", "bedrock:GetDataSource")));
            scopes.add(failed("S3_EXPOSURE", ex, List.of("s3:GetBucketPolicyStatus")));
        }
    }

    private void collectGuardrails(
            ConnectorSecret config,
            AwsCredentialsProvider credentials,
            Region region,
            AgentContext agents,
            List<ScopePayload> scopes
    ) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        List<RelationshipObservation> relationships = new ArrayList<>();
        Map<String, String> minimumStrength = new HashMap<>();
        try (BedrockClient bedrock = BedrockClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            String token = null;
            do {
                var response = bedrock.listGuardrails(ListGuardrailsRequest.builder().nextToken(token).build());
                for (var summary : response.guardrails()) {
                    var detail = bedrock.getGuardrail(GetGuardrailRequest.builder()
                            .guardrailIdentifier(summary.id()).guardrailVersion("DRAFT").build());
                    String strength = minimumStrength(detail.contentPolicy() == null
                            ? List.of()
                            : detail.contentPolicy().filters());
                    minimumStrength.put(summary.id(), strength);
                    artifacts.add(new ArtifactObservation(
                            summary.arn(), "OTHER_AI_ARTIFACT", "AWS_BEDROCK_GUARDRAIL", summary.name(),
                            Map.of("minimumStrength", strength, "status", summary.statusAsString())));
                }
                token = response.nextToken();
            } while (hasText(token));
            for (AgentFact agent : agents.facts().values()) {
                if (hasText(agent.guardrailId())) {
                    String strength = minimumStrength.get(agent.guardrailId());
                    Map<String, Object> attributes = new LinkedHashMap<>();
                    attributes.put("guardrailAttached", true);
                    if (strength != null) {
                        attributes.put("guardrailMinimumStrength", strength);
                    }
                    artifacts.add(agentUpdate(agent, attributes));
                    String guardrailArn = arn(config, region, "guardrail/" + agent.guardrailId());
                    relationships.add(new RelationshipObservation(
                            agent.arn(), guardrailArn, "USES_GUARDRAIL", Map.of()));
                }
            }
            scopes.add(complete("BEDROCK_GUARDRAILS", artifacts, relationships));
        } catch (Exception ex) {
            scopes.add(failed("BEDROCK_GUARDRAILS", ex, List.of(
                    "bedrock:ListGuardrails", "bedrock:GetGuardrail")));
        }
    }

    private void collectInvocationLogging(
            ConnectorSecret config,
            AwsCredentialsProvider credentials,
            Region region,
            List<ScopePayload> scopes
    ) {
        try (BedrockClient bedrock = BedrockClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            var response = bedrock.getModelInvocationLoggingConfiguration(
                    GetModelInvocationLoggingConfigurationRequest.builder().build());
            boolean enabled = response.loggingConfig() != null;
            String id = "bedrock:logging:" + config.accountId() + ":" + region.id();
            scopes.add(complete("BEDROCK_INVOCATION_LOGGING", List.of(new ArtifactObservation(
                    id, "ACCOUNT_CONFIGURATION", "AWS_BEDROCK_INVOCATION_LOGGING",
                    "Bedrock invocation logging", Map.of("invocationLoggingEnabled", enabled))), List.of()));
        } catch (Exception ex) {
            scopes.add(failed("BEDROCK_INVOCATION_LOGGING", ex, List.of(
                    "bedrock:GetModelInvocationLoggingConfiguration")));
        }
    }

    private List<String> actionGroupLambdas(BedrockAgentClient client, String agentId) {
        List<String> arns = new ArrayList<>();
        String token = null;
        do {
            var groups = client.listAgentActionGroups(ListAgentActionGroupsRequest.builder()
                    .agentId(agentId).agentVersion("DRAFT").nextToken(token).build());
            for (var group : groups.actionGroupSummaries()) {
                var detail = client.getAgentActionGroup(GetAgentActionGroupRequest.builder()
                        .agentId(agentId).agentVersion("DRAFT")
                        .actionGroupId(group.actionGroupId()).build()).agentActionGroup();
                if (detail.actionGroupExecutor() != null && hasText(detail.actionGroupExecutor().lambda())) {
                    arns.add(detail.actionGroupExecutor().lambda());
                }
            }
            token = groups.nextToken();
        } while (hasText(token));
        return arns;
    }

    private boolean hasWildcardActions(IamClient iam, String roleArn) {
        String roleName = roleArn.substring(roleArn.lastIndexOf('/') + 1);
        List<String> documents = new ArrayList<>();
        String token = null;
        do {
            var attached = iam.listAttachedRolePolicies(ListAttachedRolePoliciesRequest.builder()
                    .roleName(roleName).marker(token).build());
            for (var policyRef : attached.attachedPolicies()) {
                var policy = iam.getPolicy(GetPolicyRequest.builder().policyArn(policyRef.policyArn()).build()).policy();
                documents.add(iam.getPolicyVersion(GetPolicyVersionRequest.builder()
                        .policyArn(policyRef.policyArn()).versionId(policy.defaultVersionId()).build())
                        .policyVersion().document());
            }
            token = attached.marker();
        } while (attachedHasMore(iam, roleName, token));

        String inlineToken = null;
        do {
            var inline = iam.listRolePolicies(ListRolePoliciesRequest.builder()
                    .roleName(roleName).marker(inlineToken).build());
            for (String policyName : inline.policyNames()) {
                documents.add(iam.getRolePolicy(GetRolePolicyRequest.builder()
                        .roleName(roleName).policyName(policyName).build()).policyDocument());
            }
            inlineToken = inline.marker();
            if (!inline.isTruncated()) {
                break;
            }
        } while (hasText(inlineToken));
        return documents.stream().anyMatch(this::documentHasWildcardAction);
    }

    private boolean attachedHasMore(IamClient iam, String roleName, String marker) {
        return hasText(marker);
    }

    private boolean documentHasWildcardAction(String encoded) {
        try {
            JsonNode document = objectMapper.readTree(URLDecoder.decode(encoded, StandardCharsets.UTF_8));
            JsonNode statements = document.path("Statement");
            List<JsonNode> values = statements.isArray()
                    ? toList(statements)
                    : List.of(statements);
            for (JsonNode statement : values) {
                if (!"Allow".equalsIgnoreCase(statement.path("Effect").asText())) {
                    continue;
                }
                JsonNode actions = statement.path("Action");
                for (JsonNode action : actions.isArray() ? toList(actions) : List.of(actions)) {
                    String value = action.asText();
                    if ("*".equals(value) || value.endsWith(":*")) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to resolve IAM policy evidence", ex);
        }
    }

    private boolean isBucketPublic(S3Client s3, String bucketName) {
        try {
            return Boolean.TRUE.equals(s3.getBucketPolicyStatus(GetBucketPolicyStatusRequest.builder()
                    .bucket(bucketName).build()).policyStatus().isPublic());
        } catch (software.amazon.awssdk.services.s3.model.S3Exception ex) {
            String code = ex.awsErrorDetails() == null ? "" : ex.awsErrorDetails().errorCode();
            if (ex.statusCode() == 404 || "NoSuchBucketPolicy".equals(code)) {
                return false;
            }
            throw ex;
        }
    }

    private String minimumStrength(List<GuardrailContentFilter> filters) {
        List<String> order = List.of("NONE", "LOW", "MEDIUM", "HIGH");
        int minimum = order.indexOf("HIGH");
        if (filters == null || filters.isEmpty()) {
            return "NONE";
        }
        for (GuardrailContentFilter filter : filters) {
            minimum = Math.min(minimum, order.indexOf(filter.inputStrengthAsString()));
            minimum = Math.min(minimum, order.indexOf(filter.outputStrengthAsString()));
        }
        return minimum < 0 ? "NONE" : order.get(minimum);
    }

    private ObservationEnvelopeV1 envelope(
            Tenant tenant,
            ConnectorSecret config,
            UUID runId,
            String region,
            ScopePayload scope
    ) {
        String scopeRegion = scope.global() ? "GLOBAL" : region;
        String scopeKey = "AWS:" + config.accountId() + ":" + scopeRegion + ":" + scope.family();
        String content = json(Map.of("artifacts", scope.artifacts(), "relationships", scope.relationships()));
        return new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION,
                runId,
                config.id(),
                tenant.getId(),
                "AWS",
                config.accountId(),
                scopeRegion,
                scope.family(),
                scopeKey,
                0,
                1,
                runId + ":" + scopeKey + ":0",
                sha256(content),
                Instant.now(),
                scope.status(),
                scope.artifacts(),
                scope.relationships(),
                scope.diagnostics());
    }

    private ScopePayload complete(
            String family, List<ArtifactObservation> artifacts, List<RelationshipObservation> relationships) {
        return new ScopePayload(family, false, ScopeStatus.COMPLETE, artifacts, relationships, List.of());
    }

    private ScopePayload completeGlobal(String family, List<ArtifactObservation> artifacts) {
        return new ScopePayload(family, true, ScopeStatus.COMPLETE, artifacts, List.of(), List.of());
    }

    private ScopePayload failed(String family, Exception ex, List<String> permissions) {
        return failed(family, false, ex, permissions);
    }

    private ScopePayload failedGlobal(String family, Exception ex, List<String> permissions) {
        return failed(family, true, ex, permissions);
    }

    private ScopePayload failed(String family, boolean global, Exception ex, List<String> permissions) {
        String code = diagnosticCode(ex);
        return new ScopePayload(
                family, global, ScopeStatus.FAILED, List.of(), List.of(),
                List.of(new Diagnostic(
                        code,
                        safeMessage(code),
                        "THROTTLED".equals(code) || "TIMEOUT".equals(code) || "PROVIDER_UNAVAILABLE".equals(code),
                        "ACCESS_DENIED".equals(code) ? permissions : List.of(),
                        UUID.randomUUID().toString())));
    }

    private String diagnosticCode(Exception ex) {
        if (ex instanceof AwsServiceException aws) {
            String code = aws.awsErrorDetails() == null ? "" : aws.awsErrorDetails().errorCode();
            if ("AccessDenied".equalsIgnoreCase(code) || "AccessDeniedException".equalsIgnoreCase(code)) {
                return "ACCESS_DENIED";
            }
            if ("ThrottlingException".equalsIgnoreCase(code) || aws.statusCode() == 429) {
                return "THROTTLED";
            }
        }
        if (ex instanceof java.net.SocketTimeoutException) {
            return "TIMEOUT";
        }
        return "PROVIDER_UNAVAILABLE";
    }

    private String safeMessage(String code) {
        return switch (code) {
            case "ACCESS_DENIED" -> "AWS permissions are insufficient for this discovery scope";
            case "THROTTLED" -> "AWS temporarily throttled this discovery scope";
            case "TIMEOUT" -> "AWS did not respond before the discovery timeout";
            default -> "AWS discovery could not complete this scope";
        };
    }

    private ArtifactObservation agentUpdate(AgentFact agent, Map<String, Object> attributes) {
        return new ArtifactObservation(agent.arn(), "AI_AGENT", "AWS_BEDROCK_AGENT", agent.id(), attributes);
    }

    private String arn(ConnectorSecret config, Region region, String resource) {
        return "arn:aws:bedrock:" + region.id() + ":" + config.accountId() + ":" + resource;
    }

    private String functionName(String arn) {
        return arn.substring(arn.lastIndexOf(':') + 1);
    }

    private List<JsonNode> toList(JsonNode node) {
        List<JsonNode> result = new ArrayList<>();
        node.forEach(result::add);
        return result;
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to serialize AI Security discovery result", ex);
        }
    }

    private String sha256(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(bytes);
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to hash AI Security observation", ex);
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private record AgentFact(
            String id,
            String arn,
            String roleArn,
            String modelId,
            String guardrailId
    ) {
    }

    private record AgentContext(Map<String, AgentFact> facts) {
    }

    private record RegionContext(List<ScopePayload> scopes) {
    }

    private record ScopePayload(
            String family,
            boolean global,
            ScopeStatus status,
            List<ArtifactObservation> artifacts,
            List<RelationshipObservation> relationships,
            List<Diagnostic> diagnostics
    ) {
    }

    public record DiscoveryResult(UUID runId, int artifactsObserved, int failedScopes) {
    }
}
