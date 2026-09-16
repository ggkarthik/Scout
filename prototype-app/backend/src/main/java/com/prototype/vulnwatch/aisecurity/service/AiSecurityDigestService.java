package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Tenant-scoped, versioned HMAC identity digests; plaintext definitions never enter this API. */
@Component
public class AiSecurityDigestService {
    private final byte[] masterKey;
    private final String keyVersion;

    public AiSecurityDigestService(
            @Value("${app.ai-security.identity-hmac-key:}") String identityHmacKey,
            @Value("${app.ai-security.identity-hmac-key-version:v1}") String keyVersion) {
        this.masterKey = identityHmacKey == null ? new byte[0] : identityHmacKey.getBytes(StandardCharsets.UTF_8);
        this.keyVersion = keyVersion;
    }

    public Digest digest(Tenant tenant, String purpose, String value) {
        if (tenant == null || tenant.getId() == null) throw new IllegalArgumentException("Tenant is required");
        if (masterKey.length < 32) throw new IllegalStateException("AI identity HMAC key must be at least 32 bytes");
        if (value == null) throw new IllegalArgumentException("Digest input is required");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(masterKey, "HmacSHA256"));
            String scoped = keyVersion + "|" + tenant.getId() + "|" + purpose + "|" + value;
            return new Digest("HMAC-SHA-256", keyVersion,
                    HexFormat.of().formatHex(mac.doFinal(scoped.getBytes(StandardCharsets.UTF_8))));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to compute AI identity digest", exception);
        }
    }

    public record Digest(String algorithm, String keyVersion, String value) { }
}
