package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.DemoInvite;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class ResendEmailService {
    private static final Logger log = LoggerFactory.getLogger(ResendEmailService.class);

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final boolean enabled;
    private final String apiKey;
    private final String apiBaseUrl;
    private final String emailFrom;
    private final String emailReplyTo;
    private final String appBaseUrl;

    public ResendEmailService(
            @Value("${app.email.enabled:false}") boolean enabled,
            @Value("${app.email.resend.api-key:}") String apiKey,
            @Value("${app.email.resend.base-url:https://api.resend.com}") String apiBaseUrl,
            @Value("${app.email.from:}") String emailFrom,
            @Value("${app.email.reply-to:}") String emailReplyTo,
            @Value("${app.public.base-url:${app.demo.app-base-url:http://localhost:5173}}") String appBaseUrl
    ) {
        this.enabled = enabled;
        this.apiKey = apiKey == null ? "" : apiKey.trim();
        this.apiBaseUrl = apiBaseUrl == null || apiBaseUrl.isBlank() ? "https://api.resend.com" : apiBaseUrl.replaceAll("/+$", "");
        this.emailFrom = emailFrom == null ? "" : emailFrom.trim();
        this.emailReplyTo = emailReplyTo == null ? "" : emailReplyTo.trim();
        this.appBaseUrl = appBaseUrl == null || appBaseUrl.isBlank() ? "http://localhost:5173" : appBaseUrl.replaceAll("/+$", "");
    }

    public void sendDemoInvite(DemoInvite invite) {
        if (!enabled) {
            throw new IllegalStateException("Invite email delivery is disabled. Set APP_EMAIL_ENABLED=true to send demo invites.");
        }
        if (apiKey.isBlank() || emailFrom.isBlank()) {
            throw new IllegalStateException("Resend email delivery is not fully configured. Set RESEND_API_KEY and APP_EMAIL_FROM.");
        }
        String inviteUrl = appBaseUrl + "/invite.html?token=" + invite.getToken();
        String subject = "Your Scout.ai validation workspace is ready";
        String text = "Your Scout.ai validation workspace is ready.\n\n"
                + "Workspace: " + invite.getTenant().getName() + "\n"
                + "Invite expires: " + invite.getExpiresAt() + "\n"
                + "Open invite: " + inviteUrl + "\n";
        String html = """
                <div style="font-family:Arial,sans-serif;line-height:1.5;color:#111827">
                  <h2>Your Scout.ai validation workspace is ready</h2>
                  <p><strong>Workspace:</strong> %s</p>
                  <p><strong>Invite expires:</strong> %s</p>
                  <p><a href="%s">Open your invite</a></p>
                </div>
                """.formatted(escapeHtml(invite.getTenant().getName()), invite.getExpiresAt(), inviteUrl);
        send(invite.getEmail(), subject, text, html);
    }

    private void send(String to, String subject, String text, String html) {
        String payload = """
                {
                  "from": %s,
                  "to": [%s],
                  "subject": %s,
                  "text": %s,
                  "html": %s%s
                }
                """.formatted(
                json(emailFrom),
                json(to),
                json(subject),
                json(text),
                json(html),
                emailReplyTo.isBlank() ? "" : ",\n  \"reply_to\": [" + json(emailReplyTo) + "]"
        );
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(apiBaseUrl + "/emails"))
                .timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IllegalStateException("Resend email request failed with status " + response.statusCode() + ": " + response.body());
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Failed to send Resend email", ex);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to send Resend email", ex);
        }
    }

    private String json(String value) {
        String escaped = value == null ? "" : value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n");
        return "\"" + escaped + "\"";
    }

    private String escapeHtml(String value) {
        return value == null ? "" : value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }
}
