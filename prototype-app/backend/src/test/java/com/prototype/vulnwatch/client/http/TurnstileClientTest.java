package com.prototype.vulnwatch.client.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class TurnstileClientTest {

    @Test
    void postsSecretAndTokenToSiteverify() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server = MockRestServiceServer.bindTo(restTemplate).build();
        server.expect(requestTo(TurnstileClient.SITEVERIFY_URL))
                .andExpect(content().contentType("application/x-www-form-urlencoded;charset=UTF-8"))
                .andExpect(content().string("secret=secret&response=valid-token"))
                .andRespond(withSuccess(
                        """
                        {"success":true,"hostname":"scoutgrid.io","action":"demo_request","error-codes":[]}
                        """,
                        MediaType.APPLICATION_JSON));

        TurnstileClient.VerificationResult result = new TurnstileClient(restTemplate)
                .verify("secret", "valid-token");

        assertThat(result.success()).isTrue();
        assertThat(result.hostname()).isEqualTo("scoutgrid.io");
        assertThat(result.action()).isEqualTo("demo_request");
        server.verify();
    }
}
