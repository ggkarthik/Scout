package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class EuvdApiClientTest {

    private final RestTemplate restTemplate = new RestTemplate();
    private final OutboundHttpClient outboundHttpClient = new OutboundHttpClient(restTemplate);
    private final OutboundPolicyFactory outboundPolicyFactory = new OutboundPolicyFactory(
            new OutboundPolicyDefaults(0L, 1, 1L, 60000L, true, true)
    );
    private final EuvdApiClient client = new EuvdApiClient(new ObjectMapper(), outboundHttpClient, outboundPolicyFactory);
    private MockRestServiceServer server;

    @BeforeEach
    void setUp() {
        server = MockRestServiceServer.createServer(restTemplate);
        ReflectionTestUtils.setField(client, "apiUrl", "https://euvdservices.enisa.europa.eu/api/search");
        ReflectionTestUtils.setField(client, "perPage", 50);
        ReflectionTestUtils.setField(client, "minRequestIntervalMs", 0L);
        ReflectionTestUtils.setField(client, "maxRetries", 1);
        ReflectionTestUtils.setField(client, "retryBaseBackoffMs", 1L);
    }

    @Test
    void fetchPageSendsBrowserFriendlyJsonHeaders() {
        String responseBody = """
                {
                  "page": 0,
                  "size": 50,
                  "total": 0,
                  "items": []
                }
                """;

        server.expect(requestTo("https://euvdservices.enisa.europa.eu/api/search?fromScore=0&toScore=10&page=0&size=50"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Accept", "application/json, text/plain, */*"))
                .andExpect(header("User-Agent", "Mozilla/5.0 (compatible; VulnWatch/1.0; +https://euvd.enisa.europa.eu)"))
                .andExpect(header("Accept-Language", "en-US,en;q=0.9"))
                .andExpect(header("Origin", "https://euvd.enisa.europa.eu"))
                .andExpect(header("Referer", "https://euvd.enisa.europa.eu/apidoc"))
                .andRespond(withSuccess(responseBody, MediaType.APPLICATION_JSON));

        EuvdApiClient.EuvdPage page = client.fetchPage(0);

        assertEquals(0, page.records().size());
        assertEquals(0, page.totalResults());
        assertEquals(0, page.pageNumber());
        assertEquals(50, page.pageSize());
        server.verify();
    }
}
