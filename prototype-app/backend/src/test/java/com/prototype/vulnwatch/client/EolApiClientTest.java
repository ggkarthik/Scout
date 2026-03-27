package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class EolApiClientTest {

    private final RestTemplate restTemplate = new RestTemplate();
    private final OutboundHttpClient outboundHttpClient = new OutboundHttpClient(restTemplate);
    private final OutboundPolicyFactory outboundPolicyFactory = new OutboundPolicyFactory(
            new OutboundPolicyDefaults(0L, 1, 1L, 60000L, true, true)
    );
    private final EolApiClient client = new EolApiClient(outboundHttpClient, outboundPolicyFactory, new ObjectMapper());
    private MockRestServiceServer server;

    @BeforeEach
    void setUp() {
        server = MockRestServiceServer.createServer(restTemplate);
        ReflectionTestUtils.setField(client, "baseUrl", "https://endoflife.date/api/v1");
        ReflectionTestUtils.setField(client, "minRequestIntervalMs", 0L);
        ReflectionTestUtils.setField(client, "maxRetries", 1);
        ReflectionTestUtils.setField(client, "retryBaseBackoffMs", 1L);
    }

    @Test
    void fetchProductReleasesConditionalTreats304AsNotModified() {
        server.expect(requestTo("https://endoflife.date/api/v1/products/nginx"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("If-Modified-Since", "Wed, 01 Jan 2025 00:00:00 GMT"))
                .andRespond(withStatus(HttpStatus.NOT_MODIFIED));

        EolApiClient.EolReleaseFetchResult result = client.fetchProductReleasesConditional(
                "nginx",
                "Wed, 01 Jan 2025 00:00:00 GMT"
        );

        assertTrue(result.notModified());
        assertTrue(result.cycles().isEmpty());
        server.verify();
    }

    @Test
    void fetchProductReleasesConditionalTreats404AsSkipped() {
        server.expect(requestTo("https://endoflife.date/api/v1/products/missing-slug"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        EolApiClient.EolReleaseFetchResult result = client.fetchProductReleasesConditional("missing-slug", null);

        assertTrue(result.notModified());
        assertTrue(result.cycles().isEmpty());
        server.verify();
    }
}
