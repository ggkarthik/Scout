package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.http.TurnstileClient;
import com.prototype.vulnwatch.client.http.TurnstileClient.TurnstileClientException;
import com.prototype.vulnwatch.client.http.TurnstileClient.VerificationResult;
import java.util.List;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class TurnstileVerificationService {

    private static final Logger LOG = LoggerFactory.getLogger(TurnstileVerificationService.class);
    private static final String DEMO_REQUEST_ACTION = "demo_request";

    private final TurnstileClient turnstileClient;
    private final boolean enabled;
    private final String secretKey;
    private final String expectedHostname;

    public TurnstileVerificationService(
            TurnstileClient turnstileClient,
            @Value("${app.security.turnstile.enabled:false}") boolean enabled,
            @Value("${app.security.turnstile.secret-key:}") String secretKey,
            @Value("${app.security.turnstile.expected-hostname:}") String expectedHostname
    ) {
        this.turnstileClient = turnstileClient;
        this.enabled = enabled;
        this.secretKey = secretKey == null ? "" : secretKey.trim();
        this.expectedHostname = expectedHostname == null ? "" : expectedHostname.trim().toLowerCase(Locale.ROOT);
    }

    public void verifyDemoRequest(String token) {
        verifyDemoRequest(token, null);
    }

    public void verifyDemoRequest(String token, String remoteIp) {
        if (!enabled) {
            return;
        }
        if (secretKey.isBlank()) {
            LOG.error("Turnstile validation is enabled but no secret key is configured");
            throw new DemoAccessException(
                    "CAPTCHA_UNAVAILABLE",
                    "CAPTCHA verification is temporarily unavailable. Please try again later.",
                    HttpStatus.SERVICE_UNAVAILABLE);
        }
        if (token == null || token.isBlank() || token.length() > 2048) {
            throw invalidCaptcha();
        }

        VerificationResult response;
        try {
            response = turnstileClient.verify(secretKey, token.trim(), remoteIp);
        } catch (TurnstileClientException verificationFailure) {
            LOG.warn("Turnstile Siteverify request failed", verificationFailure);
            throw new DemoAccessException(
                    "CAPTCHA_UNAVAILABLE",
                    "CAPTCHA verification is temporarily unavailable. Please try again later.",
                    HttpStatus.SERVICE_UNAVAILABLE);
        }

        boolean hostnameMatches = expectedHostname.isBlank()
                || (response != null && expectedHostname.equalsIgnoreCase(response.hostname()));
        boolean actionMatches = response != null && DEMO_REQUEST_ACTION.equals(response.action());
        if (response == null || !response.success() || !hostnameMatches || !actionMatches) {
            LOG.info(
                    "Turnstile rejected demo request hostname={} action={} errors={}",
                    response == null ? null : response.hostname(),
                    response == null ? null : response.action(),
                    response == null ? List.of("empty-response") : response.errorCodes());
            throw invalidCaptcha();
        }
    }

    private DemoAccessException invalidCaptcha() {
        return new DemoAccessException(
                "CAPTCHA_INVALID",
                "Complete the CAPTCHA verification and try again.",
                HttpStatus.BAD_REQUEST);
    }

}
