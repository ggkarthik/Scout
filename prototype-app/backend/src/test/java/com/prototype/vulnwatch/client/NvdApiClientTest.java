package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class NvdApiClientTest {

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final NvdApiClient client = new NvdApiClient(objectMapper, restTemplate);
    private MockRestServiceServer server;

    @BeforeEach
    void setUp() {
        server = MockRestServiceServer.createServer(restTemplate);
        ReflectionTestUtils.setField(client, "baseUrl", "https://services.nvd.nist.gov/rest/json/cves/2.0");
        ReflectionTestUtils.setField(client, "apiKey", "");
        ReflectionTestUtils.setField(client, "apiKeyFile", "");
        ReflectionTestUtils.setField(client, "resultsPerPage", 2000);
        ReflectionTestUtils.setField(client, "minRequestIntervalMs", 0L);
        ReflectionTestUtils.setField(client, "maxRetries", 1);
        ReflectionTestUtils.setField(client, "retryBaseBackoffMs", 1L);
        client.init();
    }

    @Test
    void hasApiKey_acceptsFullSyncUiOverrideWhenBackendConfigIsBlank() {
        assertTrue(client.hasApiKey("ui-provided-token"));
    }

    @Test
    void fetchPage_prefersFullSyncUiOverrideApiKeyHeader() {
        server.expect(requestTo("https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0&resultsPerPage=2000"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("apiKey", "ui-provided-token"))
                .andRespond(withSuccess("""
                        {
                          "resultsPerPage": 1,
                          "startIndex": 0,
                          "totalResults": 1,
                          "vulnerabilities": [
                            {
                              "cve": {
                                "id": "CVE-2024-0001",
                                "descriptions": [
                                  {
                                    "lang": "en",
                                    "value": "Test NVD record"
                                  }
                                ]
                              }
                            }
                          ]
                        }
                        """, MediaType.APPLICATION_JSON));

        NvdApiClient.NvdPage page = client.fetchPage(0, null, null, "ui-provided-token");

        assertEquals(1, page.records().size());
        assertEquals("CVE-2024-0001", page.records().get(0).cveId());
        server.verify();
    }

    @Test
    void fetchPage_appendsConfiguredQueryFilters() {
        server.expect(requestTo(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0&resultsPerPage=2000"
                                + "&cpeName=cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
                                + "&isVulnerable&hasKev&cvssV3Severity=CRITICAL"
                ))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("""
                        {
                          "resultsPerPage": 0,
                          "startIndex": 0,
                          "totalResults": 0,
                          "vulnerabilities": []
                        }
                        """, MediaType.APPLICATION_JSON));

        NvdApiClient.NvdPage page = client.fetchPage(
                0,
                null,
                null,
                new NvdApiClient.NvdQueryFilters(
                        "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                        true,
                        true,
                        "CRITICAL",
                        null
                ),
                null
        );

        assertEquals(0, page.records().size());
        server.verify();
    }
}
