package com.prototype.vulnwatch.client.http;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

@Component
public class TurnstileClient {

    static final String SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    private final RestTemplate restTemplate;

    public TurnstileClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public VerificationResult verify(String secretKey, String token) {
        return verify(secretKey, token, null);
    }

    public VerificationResult verify(String secretKey, String token, String remoteIp) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("secret", secretKey);
        body.add("response", token);
        if (remoteIp != null && !remoteIp.isBlank() && !"unknown".equals(remoteIp)) {
            body.add("remoteip", remoteIp);
        }
        body.add("idempotency_key", UUID.randomUUID().toString());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        try {
            return restTemplate.postForObject(
                    SITEVERIFY_URL,
                    new HttpEntity<>(body, headers),
                    VerificationResult.class);
        } catch (RestClientException verificationFailure) {
            throw new TurnstileClientException("Turnstile Siteverify request failed", verificationFailure);
        }
    }

    public record VerificationResult(
            boolean success,
            String hostname,
            String action,
            @JsonProperty("error-codes") List<String> errorCodes
    ) {
    }

    public static final class TurnstileClientException extends RuntimeException {
        public TurnstileClientException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
