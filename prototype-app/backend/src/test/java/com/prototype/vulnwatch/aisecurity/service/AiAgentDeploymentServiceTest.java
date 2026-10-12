package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.service.AiAgentDeploymentService.*;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AiAgentDeploymentServiceTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final UUID agentId = UUID.randomUUID(), routeId = UUID.randomUUID(), versionId = UUID.randomUUID(), runId = UUID.randomUUID();
    private final Instant observed = Instant.parse("2026-10-05T00:00:00Z");
    private final Duration ttl = Duration.ofHours(24);
    private Agent agent(String kind) { return new Agent(agentId, kind); }
    private Scope scope(String state, String diagnostic) {
        return new Scope(agentId, UUID.randomUUID(), runId, "ROUTING", state, diagnostic, observed, true);
    }
    private Resource resource(UUID id, String kind, String json) throws Exception {
        return new Resource(runId, id, kind, mapper.readTree(json));
    }
    private List<Edge> edges() { return List.of(new Edge(runId, agentId, routeId, "HAS_DEPLOYMENT"),
            new Edge(runId, routeId, versionId, "SERVES_VERSION"), new Edge(runId, versionId, agentId, "VERSION_OF")); }
    private List<Resource> resources(String kind, String state) throws Exception {
        return List.of(resource(agentId, "AWS_BEDROCK_AGENT", "{}"), resource(versionId, "AWS_BEDROCK_AGENT_VERSION", "{}"),
                resource(routeId, kind, "{\"status\":\"" + state + "\",\"aliasId\":\"prod\",\"invocationState\":\"ACCEPT_INVOCATIONS\"}"));
    }
    private Metadata evaluate(String kind, List<Edge> edges, List<Resource> resources) {
        return AiAgentDeploymentService.evaluate(agent(kind), scope("COMPLETE", null), edges, resources, observed, ttl);
    }
    @Test void readyResolvedEndpointsServeExactlyOneLogicalAgent() throws Exception {
        Metadata result = evaluate("AWS_AGENTCORE_RUNTIME", edges(), resources("AWS_AGENTCORE_RUNTIME_ENDPOINT", "READY"));
        assertEquals(Status.SERVED, result.status());
        assertEquals(Reason.VERIFIED_SERVING_ROUTE, result.reasonCode());
        assertEquals(List.of(routeId), result.evidenceReferences().get(0).routeIds());
    }
    @Test void preparedBedrockAliasNeedsAnAcceptedResolvedTarget() throws Exception {
        assertEquals(Status.SERVED, evaluate("AWS_BEDROCK_AGENT", edges(), resources("AWS_BEDROCK_AGENT_ALIAS", "PREPARED")).status());
        assertEquals(Reason.UNRESOLVED_VERSION, evaluate("AWS_BEDROCK_AGENT", edges().subList(0, 2), resources("AWS_BEDROCK_AGENT_ALIAS", "PREPARED")).reasonCode());
        assertEquals(Reason.UNRESOLVED_IDENTITY, evaluate("AWS_BEDROCK_AGENT", edges(), resources("AWS_BEDROCK_AGENT_ALIAS", "PREPARED").subList(0, 1)).reasonCode());
    }
    @Test void completeEmptyRoutingSupersedesEarlierRoutes() throws Exception {
        List<Resource> onlyAgent = List.of(resource(agentId, "AWS_BEDROCK_AGENT", "{}"));
        Metadata result = evaluate("AWS_BEDROCK_AGENT", List.of(new Edge(UUID.randomUUID(), agentId, routeId, "HAS_COMPONENT")), onlyAgent);
        assertEquals(Status.NOT_CURRENTLY_SERVED, result.status());
        assertEquals(Reason.NO_ALIAS_ROUTE, result.reasonCode());
        assertEquals(Reason.NO_SERVING_ENDPOINT, evaluate("AWS_AGENTCORE_RUNTIME", List.of(), onlyAgent).reasonCode());
    }
    @Test void draftLineageAndProvisioningNeverProveServing() throws Exception {
        List<Resource> onlyAgent = List.of(resource(agentId, "AWS_BEDROCK_AGENT", "{\"status\":\"PREPARED\"}"));
        assertEquals(Status.NOT_CURRENTLY_SERVED, evaluate("AWS_BEDROCK_AGENT", List.of(new Edge(runId, agentId, versionId, "ACTIVE_VERSION")), onlyAgent).status());
        assertEquals(Reason.AMBIGUOUS_ROUTE_STATE, evaluate("AWS_AGENTCORE_RUNTIME", edges(), resources("AWS_AGENTCORE_RUNTIME_ENDPOINT", "CREATING")).reasonCode());
    }
    @Test void expiryIsInclusiveAndUsesRequestTime() throws Exception {
        var resources = resources("AWS_BEDROCK_AGENT_ALIAS", "PREPARED");
        assertEquals(Status.SERVED, AiAgentDeploymentService.evaluate(agent("AWS_BEDROCK_AGENT"), scope("COMPLETE", null), edges(), resources, observed.plus(ttl).minusNanos(1), ttl).status());
        assertEquals(Reason.STALE_EVIDENCE, AiAgentDeploymentService.evaluate(agent("AWS_BEDROCK_AGENT"), scope("COMPLETE", null), edges(), resources, observed.plus(ttl), ttl).reasonCode());
    }
    @Test void latestFailuresDoNotReuseEarlierServingRoutes() throws Exception {
        for (var pair : List.of(new String[]{"UNAUTHORIZED", "ACCESS_DENIED", "PERMISSION_DENIED"},
                new String[]{"PARTIAL", "PROVIDER_CALL_BUDGET_EXHAUSTED", "BUDGET_EXHAUSTED"},
                new String[]{"ERROR", "TIMEOUT", "PROVIDER_ERROR"},
                new String[]{"UNSUPPORTED_API", "UNSUPPORTED_API_VERSION", "UNSUPPORTED_API"},
                new String[]{"PARTIAL", "FEATURE_DISABLED", "COLLECTION_DISABLED"})) {
            Metadata result = AiAgentDeploymentService.evaluate(agent("AWS_BEDROCK_AGENT"), scope(pair[0], pair[1]), edges(), resources("AWS_BEDROCK_AGENT_ALIAS", "PREPARED"), observed, ttl);
            assertEquals(Status.UNVERIFIED, result.status());
            assertEquals(Reason.valueOf(pair[2]), result.reasonCode());
        }
    }
    @Test void completePaginationIsRequired() {
        Scope partial = new Scope(agentId, UUID.randomUUID(), runId, "ROUTING", "COMPLETE", null, observed, false);
        assertEquals(Reason.INCOMPLETE_SCOPE, AiAgentDeploymentService.evaluate(agent("AWS_BEDROCK_AGENT"), partial, List.of(), List.of(), observed, ttl).reasonCode());
    }
    @Test void publicationAloneCannotProveCopilotServingOrAbsence() throws Exception {
        Metadata result = evaluate("MICROSOFT_COPILOT", List.of(), List.of(resource(agentId, "MICROSOFT_COPILOT", "{\"published\":true}")));
        assertEquals(Status.UNVERIFIED, result.status());
        assertEquals(Reason.UNSUPPORTED_CHANNEL_EVIDENCE, result.reasonCode());
    }
    @Test void aTransitionalEndpointMakesMultipleEndpointsUnverifiedRegardlessOfOrder() throws Exception {
        UUID second = UUID.randomUUID();
        var resources = new java.util.ArrayList<>(resources("AWS_AGENTCORE_RUNTIME_ENDPOINT", "READY"));
        resources.add(resource(second, "AWS_AGENTCORE_RUNTIME_ENDPOINT", "{\"status\":\"UPDATING\"}"));
        var edges = new java.util.ArrayList<>(edges());
        edges.add(new Edge(runId, agentId, second, "HAS_DEPLOYMENT"));
        assertEquals(Reason.AMBIGUOUS_ROUTE_STATE, evaluate("AWS_AGENTCORE_RUNTIME", edges, resources).reasonCode());
        java.util.Collections.reverse(edges);
        assertEquals(Reason.AMBIGUOUS_ROUTE_STATE, evaluate("AWS_AGENTCORE_RUNTIME", edges, resources).reasonCode());
    }
    @Test void draftNeverBecomesAServingTargetEvenWithAnAlias() throws Exception {
        var resources = new java.util.ArrayList<>(resources("AWS_BEDROCK_AGENT_ALIAS", "PREPARED"));
        resources.set(1,resource(versionId,"AWS_BEDROCK_AGENT_VERSION","{\"version\":\"DRAFT\"}"));
        assertEquals(Reason.UNRESOLVED_VERSION,evaluate("AWS_BEDROCK_AGENT",edges(),resources).reasonCode());
    }
    @Test void everyStatusReasonPairIsCheckedAgainstTheClosedContract() {
        for (Status status : Status.values()) for (Reason reason : Reason.values()) {
            Status expected = reason == Reason.VERIFIED_SERVING_ROUTE ? Status.SERVED
                    : List.of(Reason.NO_ALIAS_ROUTE,Reason.NO_SERVING_ENDPOINT,Reason.NO_ACTIVE_DEPLOYMENT,
                        Reason.ZERO_TRAFFIC_ALLOCATION,Reason.NOT_PUBLISHED,Reason.NO_ENABLED_CHANNEL,Reason.NO_SERVING_ROUTE)
                        .contains(reason) ? Status.NOT_CURRENTLY_SERVED : Status.UNVERIFIED;
            if (status == expected) assertDoesNotThrow(() -> new Metadata(status,reason,null,null,List.of(),null));
            else assertThrows(IllegalArgumentException.class,() -> new Metadata(status,reason,null,null,List.of(),null));
        }
    }
    @Test void multipleNegativeFoundryMechanismsUseTheGenericReasonRegardlessOfOrder() throws Exception {
        UUID second = UUID.randomUUID();
        var resources = new java.util.ArrayList<>(resources("AZURE_FOUNDRY_AGENT_ROUTES","ZERO_TRAFFIC_ALLOCATION"));
        resources.add(resource(second,"AZURE_FOUNDRY_AGENT_ROUTES","{\"status\":\"NO_ACTIVE_DEPLOYMENT\"}"));
        var edges = new java.util.ArrayList<>(edges());
        edges.add(new Edge(runId,agentId,second,"HAS_DEPLOYMENT"));
        assertEquals(Reason.NO_SERVING_ROUTE,evaluate("AZURE_FOUNDRY_AGENTS",edges,resources).reasonCode());
        java.util.Collections.reverse(edges);
        assertEquals(Reason.NO_SERVING_ROUTE,evaluate("AZURE_FOUNDRY_AGENTS",edges,resources).reasonCode());
    }
    @Test void inventoryClassificationDoesNotCountVersionsBotsOrRoutesAsAgents() {
        assertTrue(AiAgentInventoryClassification.isAgent("AWS_AGENTCORE_RUNTIME"));
        assertFalse(AiAgentInventoryClassification.isAgent("AZURE_BOT_SERVICES"));
        assertFalse(AiAgentInventoryClassification.isAgent("AWS_BEDROCK_AGENT_ALIAS"));
        for (String kind : AiAgentInventoryClassification.VERSION_KINDS) assertFalse(AiAgentInventoryClassification.isAgent(kind));
    }
}
