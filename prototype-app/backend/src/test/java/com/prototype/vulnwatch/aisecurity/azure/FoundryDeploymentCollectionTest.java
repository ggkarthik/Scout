package com.prototype.vulnwatch.aisecurity.azure;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.service.AiGridProviderCallCounter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import reactor.core.publisher.Mono;

/** Mock the java.net.http transport used by this adapter; no provider credentials or calls. */
class FoundryDeploymentCollectionTest {
    private static final String ACCOUNT = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct";
    private static final String PROJECT = ACCOUNT + "/projects/project";
    private final TokenCredential credential = request -> Mono.just(new AccessToken("test-only",OffsetDateTime.now().plusHours(1)));
    private final List<HttpRequest> requests = new ArrayList<>();
    private AzureAiManagementClient client(int appStatus) throws Exception {
        AzureAiManagementClient client = new AzureAiManagementClient(new ObjectMapper(),new AzurePolicyPermissionMatrix());
        HttpClient http = mock(HttpClient.class);
        ReflectionTestUtils.setField(client,"http",http);
        when(http.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any())).thenAnswer(call -> {
            HttpRequest request = call.getArgument(0); requests.add(request);
            String path = request.uri().getPath();
            String body;
            int status = 200;
            if (path.equals("/subscriptions/sub/resources")) body = "{\"value\":[" + node(ACCOUNT,"Microsoft.CognitiveServices/accounts","{}") + "]}";
            else if (path.equalsIgnoreCase(ACCOUNT)) body = node(ACCOUNT,"Microsoft.CognitiveServices/accounts","{}");
            else if (path.equalsIgnoreCase(ACCOUNT + "/projects")) body = "{\"value\":[" + node(PROJECT,"Microsoft.CognitiveServices/accounts/projects","{}") + "]}";
            else if (path.endsWith("/applications")) {
                status = appStatus;
                body = status == 200 ? "{\"value\":[" + node(PROJECT + "/applications/app","Microsoft.CognitiveServices/accounts/projects/applications","{\"agents\":[{\"agentName\":\"support\"}]}") + "]}" : "{\"error\":{\"code\":\"Forbidden\"}}";
            } else if (path.endsWith("/agentdeployments")) body = "{\"value\":[" + node(PROJECT + "/applications/app/agentdeployments/deploy","Microsoft.CognitiveServices/accounts/projects/applications/agentdeployments","{\"state\":\"Running\",\"protocols\":[{\"protocol\":\"Responses\"}],\"agents\":[{\"agentName\":\"support\",\"agentVersion\":\"1\"}]}") + "]}";
            else if (path.endsWith("/agents")) body = "{\"data\":[{\"name\":\"support\",\"versions\":{\"latest\":{\"version\":\"1\",\"definition\":{\"type\":\"prompt\"}}}}],\"has_more\":false}";
            else if (path.endsWith("/versions")) body = "{\"data\":[{\"version\":\"1\",\"definition\":{\"type\":\"prompt\"}}],\"has_more\":false}";
            else throw new AssertionError("Unexpected metadata URL " + request.uri());
            return response(request,status,body);
        });
        return client;
    }
    @Test void readsLegacyApplicationsAndDeploymentsWithoutInvokingOrPublishing() throws Exception {
        var result = client(200).discover(credential,"sub",Set.of("AZURE_FOUNDRY_AGENT_ROUTES"),true);
        assertEquals(1,result.resources().get("AZURE_FOUNDRY_AGENTS").size());
        assertEquals("READY",result.resources().get("AZURE_FOUNDRY_AGENT_ROUTES").get(0).properties().path("status").asText());
        assertTrue(requests.stream().allMatch(r -> r.method().equals("GET")));
        assertTrue(requests.stream().anyMatch(r -> r.uri().getPath().endsWith("/applications") && r.uri().getQuery().equals("api-version=2026-07-01")));
        assertTrue(requests.stream().anyMatch(r -> r.uri().getPath().endsWith("/agentdeployments")));
    }
    @Test void legacyPermissionFailureKeepsAgentsAndProducesAnExplicitGap() throws Exception {
        var result = client(403).discover(credential,"sub",Set.of("AZURE_FOUNDRY_AGENT_ROUTES"),true);
        assertEquals(1,result.resources().get("AZURE_FOUNDRY_AGENTS").size());
        assertFalse(result.failures().containsKey("AZURE_FOUNDRY_AGENTS"));
        assertEquals("PERMISSION_DENIED",result.resources().get("AZURE_FOUNDRY_AGENT_ROUTES").get(0).properties().path("deploymentEvidenceReason").asText());
    }
    @Test void exhaustionStopsAtTheSameReadBoundaryWithoutRetryingTheExhaustedBudget() throws Exception {
        var client = client(200);
        AiGridProviderCallCounter counter = new AiGridProviderCallCounter();
        ReflectionTestUtils.setField(client,"providerCalls",counter);
        try (var measurement = counter.begin(5)) {
            var result = client.discover(credential,"sub",Set.of("AZURE_FOUNDRY_AGENT_ROUTES"),true);
            assertEquals(5,measurement.count());
            assertEquals(5,requests.size());
            assertEquals("PROVIDER_CALL_BUDGET_EXHAUSTED",result.failures().get("AZURE_FOUNDRY_AGENT_ROUTES").code());
        }
    }
    private static String node(String id,String type,String properties) {
        return "{\"id\":\"" + id + "\",\"name\":\"resource\",\"type\":\"" + type + "\",\"location\":\"eastus\",\"properties\":" + properties + "}";
    }
    private static HttpResponse<String> response(HttpRequest request,int status,String body) {
        return new HttpResponse<>() {
            public int statusCode() { return status; }
            public HttpRequest request() { return request; }
            public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            public HttpHeaders headers() { return HttpHeaders.of(Map.of(),(key,value) -> true); }
            public String body() { return body; }
            public Optional<SSLSession> sslSession() { return Optional.empty(); }
            public URI uri() { return request.uri(); }
            public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }
}
