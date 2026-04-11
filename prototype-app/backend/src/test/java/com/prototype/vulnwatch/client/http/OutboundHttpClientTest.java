package com.prototype.vulnwatch.client.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class OutboundHttpClientTest {

    private final RestTemplate restTemplate = new RestTemplate();
    private final AtomicLong now = new AtomicLong();
    private final List<Long> sleeps = new ArrayList<>();
    private final OutboundHttpClient client = new OutboundHttpClient(
            restTemplate,
            now::get,
            millis -> {
                sleeps.add(millis);
                now.addAndGet(millis);
            }
    );
    private MockRestServiceServer server;

    @BeforeEach
    void setUp() {
        server = MockRestServiceServer.createServer(restTemplate);
        now.set(0L);
        sleeps.clear();
    }

    @Test
    void retriesOnRetryableHttpStatusThenSucceeds() {
        server.expect(requestTo("https://example.test/retry"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS));
        server.expect(requestTo("https://example.test/retry"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("ok", MediaType.TEXT_PLAIN));

        ResponseEntity<String> response = exchange(policy("test", 0L, 2, 0L), "https://example.test/retry");

        assertEquals("ok", response.getBody());
        server.verify();
    }

    @Test
    void doesNotRetryOnNonRetryableHttpStatus() {
        server.expect(requestTo("https://example.test/not-found"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        assertThrows(RuntimeException.class, () -> exchange(policy("test", 0L, 2, 0L), "https://example.test/not-found"));
        assertTrue(sleeps.isEmpty());
        server.verify();
    }

    @Test
    void honorsRetryAfterHeaderWhenPresent() {
        server.expect(requestTo("https://example.test/retry-after"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS).header("Retry-After", "2"));
        server.expect(requestTo("https://example.test/retry-after"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("ok", MediaType.TEXT_PLAIN));

        exchange(policy("test", 0L, 2, 25L), "https://example.test/retry-after");

        assertEquals(List.of(2000L), sleeps);
        server.verify();
    }

    @Test
    void appliesBackoffWhenRetryAfterIsAbsent() {
        server.expect(requestTo("https://example.test/backoff"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
        server.expect(requestTo("https://example.test/backoff"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("ok", MediaType.TEXT_PLAIN));

        exchange(policy("test", 0L, 2, 10L), "https://example.test/backoff");

        assertEquals(1, sleeps.size());
        assertTrue(sleeps.get(0) >= 10L);
        assertTrue(sleeps.get(0) <= 35L);
        server.verify();
    }

    @Test
    void retriesNetworkErrorsWhenEnabled() {
        server.expect(requestTo("https://example.test/network"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withException(new java.net.SocketTimeoutException("timed out")));
        server.expect(requestTo("https://example.test/network"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("ok", MediaType.TEXT_PLAIN));

        ResponseEntity<String> response = exchange(policy("test", 0L, 2, 0L), "https://example.test/network");

        assertEquals("ok", response.getBody());
        server.verify();
    }

    @Test
    void enforcesProviderScopedMinimumRequestIntervalAcrossSequentialCalls() {
        server.expect(requestTo("https://example.test/paced"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("first", MediaType.TEXT_PLAIN));
        server.expect(requestTo("https://example.test/paced"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("second", MediaType.TEXT_PLAIN));

        OutboundPolicy policy = policy("paced", 100L, 1, 0L);
        exchange(policy, "https://example.test/paced");
        exchange(policy, "https://example.test/paced");

        assertEquals(List.of(100L), sleeps);
        server.verify();
    }

    @Test
    void preservesPreEncodedQueryValues() {
        server.expect(requestTo("https://example.test/advisories?after=Y3Vyc29y%3D%3D"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("ok", MediaType.TEXT_PLAIN));

        ResponseEntity<String> response = exchange(
                policy("github", 0L, 1, 0L),
                "https://example.test/advisories?after=Y3Vyc29y%3D%3D"
        );

        assertEquals("ok", response.getBody());
        server.verify();
    }

    private ResponseEntity<String> exchange(OutboundPolicy policy, String endpoint) {
        try {
            return client.exchange(
                    endpoint,
                    HttpMethod.GET,
                    HttpEntity.EMPTY,
                    String.class,
                    "test operation",
                    policy,
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            new RuntimeException("terminal failure", context.error())
                    )
            );
        } catch (RuntimeException runtimeException) {
            throw runtimeException;
        } catch (Exception checkedException) {
            throw new RuntimeException(checkedException);
        }
    }

    private OutboundPolicy policy(String providerKey, long minRequestIntervalMs, int maxRetries, long retryBaseBackoffMs) {
        return new OutboundPolicy(
                providerKey,
                minRequestIntervalMs,
                maxRetries,
                retryBaseBackoffMs,
                1000L,
                Set.of(408, 429, 500, 502, 503, 504),
                true,
                true
        );
    }
}
