package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.DemoInvite;
import com.prototype.vulnwatch.domain.DemoRequest;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class DemoInviteEmailService {

    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("MMM d, yyyy 'at' h:mm a 'UTC'").withZone(ZoneOffset.UTC);

    private final ResendEmailClient resendEmailClient;
    private final String appBaseUrl;

    public DemoInviteEmailService(
            ResendEmailClient resendEmailClient,
            @Value("${app.demo.app-base-url:http://localhost:5173}") String appBaseUrl
    ) {
        this.resendEmailClient = resendEmailClient;
        this.appBaseUrl = appBaseUrl == null || appBaseUrl.isBlank() ? "http://localhost:5173" : appBaseUrl.replaceAll("/+$", "");
    }

    public ResendEmailClient.DeliveryResult sendInvite(DemoRequest request, DemoInvite invite) {
        Tenant tenant = invite.getTenant();
        String inviteUrl = appBaseUrl + "/invite/" + invite.getToken();
        String loginUrl = appBaseUrl + "/login";
        String displayName = request.getFullName() == null || request.getFullName().isBlank() ? request.getEmail() : request.getFullName().trim();
        String tenantName = tenant.getName();
        String subject = "Your Scout.ai validation workspace for " + tenantName + " is ready";
        String validationAuthOption = "For the validation phase, use the one-time activation link below to set your initial password. "
                + "After that, sign in from the shared login portal with your email and password.";

        Map<String, String> tags = new LinkedHashMap<>();
        tags.put("flow", "demo_validation");
        tags.put("tenant_id", tenant.getId().toString());
        if (request.getId() != null) {
            tags.put("request_id", request.getId().toString());
        }

        return resendEmailClient.send(new ResendEmailClient.EmailMessage(
                invite.getEmail(),
                subject,
                htmlBody(displayName, tenantName, inviteUrl, loginUrl, invite.getExpiresAt(), tenant.getDemoExpiresAt(), validationAuthOption),
                textBody(displayName, tenantName, inviteUrl, loginUrl, invite.getExpiresAt(), tenant.getDemoExpiresAt(), validationAuthOption),
                tags,
                null
        ));
    }

    private String htmlBody(
            String displayName,
            String tenantName,
            String inviteUrl,
            String loginUrl,
            Instant inviteExpiresAt,
            Instant demoExpiresAt,
            String validationAuthOption
    ) {
        StringBuilder body = new StringBuilder();
        body.append("<p>Hi ").append(escape(displayName)).append(",</p>");
        body.append("<p>Your Scout.ai validation workspace for <strong>").append(escape(tenantName)).append("</strong> is ready.</p>");
        body.append("<p>").append(escape(validationAuthOption)).append("</p>");
        body.append("<p><a href=\"").append(inviteUrl).append("\">Activate your workspace</a></p>");
        body.append("<ul>");
        body.append("<li><strong>Shared login portal:</strong> <a href=\"").append(loginUrl).append("\">").append(loginUrl).append("</a></li>");
        body.append("<li><strong>Invite expires:</strong> ").append(formatInstant(inviteExpiresAt)).append("</li>");
        body.append("<li><strong>Validation workspace access through:</strong> ").append(formatInstant(demoExpiresAt)).append("</li>");
        body.append("</ul>");
        body.append("<p>What to expect in this validation environment:</p>");
        body.append("<ul>");
        body.append("<li>Dedicated tenant workspace for your company</li>");
        body.append("<li>Tenant-owner access only to your validation tenant</li>");
        body.append("<li>Limited demo quotas and no live connectors</li>");
        body.append("</ul>");
        body.append("<p>If the invite link expires, reply to this email and we can resend access.</p>");
        return body.toString();
    }

    private String textBody(
            String displayName,
            String tenantName,
            String inviteUrl,
            String loginUrl,
            Instant inviteExpiresAt,
            Instant demoExpiresAt,
            String validationAuthOption
    ) {
        return "Hi " + displayName + ",\n\n"
                + "Your Scout.ai validation workspace for " + tenantName + " is ready.\n\n"
                + validationAuthOption + "\n\n"
                + "Activate your workspace: " + inviteUrl + "\n"
                + "Shared login portal: " + loginUrl + "\n"
                + "Invite expires: " + formatInstant(inviteExpiresAt) + "\n"
                + "Validation workspace access through: " + formatInstant(demoExpiresAt) + "\n\n"
                + "What to expect in this validation environment:\n"
                + "- Dedicated tenant workspace for your company\n"
                + "- Tenant-owner access only to your validation tenant\n"
                + "- Limited demo quotas and no live connectors\n\n"
                + "If the invite link expires, reply to this email and we can resend access.\n";
    }

    private String formatInstant(Instant value) {
        return value == null ? "Not set" : DATE_TIME_FORMATTER.format(value);
    }

    private String escape(String value) {
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }
}
