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
    private final byte[] previousMasterKey;
    private final String previousKeyVersion;
    private final byte[] runtimeMasterKey;
    private final String runtimeKeyVersion;
    private final byte[] previousRuntimeMasterKey;
    private final String previousRuntimeKeyVersion;

    @org.springframework.beans.factory.annotation.Autowired
    public AiSecurityDigestService(
            @Value("${app.ai-security.identity-hmac-key:}") String identityHmacKey,
            @Value("${app.ai-security.identity-hmac-key-version:v1}") String keyVersion,
            @Value("${app.ai-security.identity-hmac-previous-key:}") String previousIdentityHmacKey,
            @Value("${app.ai-security.identity-hmac-previous-key-version:}") String previousKeyVersion,
            @Value("${app.ai-security.runtime-identity-hmac-key:}") String runtimeIdentityHmacKey,
            @Value("${app.ai-security.runtime-identity-hmac-key-version:v1}") String runtimeKeyVersion,
            @Value("${app.ai-security.runtime-identity-hmac-previous-key:}") String previousRuntimeIdentityHmacKey,
            @Value("${app.ai-security.runtime-identity-hmac-previous-key-version:}") String previousRuntimeKeyVersion) {
        this.masterKey = identityHmacKey == null ? new byte[0] : identityHmacKey.getBytes(StandardCharsets.UTF_8);
        this.keyVersion = keyVersion;
        this.previousMasterKey = previousIdentityHmacKey == null ? new byte[0]
                : previousIdentityHmacKey.getBytes(StandardCharsets.UTF_8);
        this.previousKeyVersion = previousKeyVersion;
        this.runtimeMasterKey = bytes(runtimeIdentityHmacKey);
        this.runtimeKeyVersion = runtimeKeyVersion;
        this.previousRuntimeMasterKey = bytes(previousRuntimeIdentityHmacKey);
        this.previousRuntimeKeyVersion = previousRuntimeKeyVersion;
    }

    /** Test and migration compatibility constructor; production wiring uses separate key families. */
    public AiSecurityDigestService(String identityHmacKey, String keyVersion,
                                   String previousIdentityHmacKey, String previousKeyVersion) {
        this(identityHmacKey, keyVersion, previousIdentityHmacKey, previousKeyVersion,
                identityHmacKey, keyVersion, previousIdentityHmacKey, previousKeyVersion);
    }

    public Digest digest(Tenant tenant, String purpose, String value) {
        if (tenant == null || tenant.getId() == null) throw new IllegalArgumentException("Tenant is required");
        if (masterKey.length < 32) throw new IllegalStateException("AI identity HMAC key must be at least 32 bytes");
        if (value == null) throw new IllegalArgumentException("Digest input is required");
        return digest(masterKey, keyVersion, tenant, purpose, value);
    }

    /** Returns current and (only during a configured overlap) previous candidate identifiers. */
    public java.util.List<Digest> identityCandidates(Tenant tenant, String purpose, String value) {
        Digest current = identityDigest(tenant, purpose, value);
        if (previousRuntimeMasterKey.length < 32 || previousRuntimeKeyVersion == null || previousRuntimeKeyVersion.isBlank()) {
            return java.util.List.of(current);
        }
        return java.util.List.of(current, digest(previousRuntimeMasterKey, previousRuntimeKeyVersion, tenant, purpose, value));
    }

    public Digest identityDigest(Tenant tenant, String purpose, String value) {
        if (tenant == null || tenant.getId() == null) throw new IllegalArgumentException("Tenant is required");
        if (runtimeMasterKey.length < 32) throw new IllegalStateException("AI runtime identity HMAC key must be at least 32 bytes");
        if (value == null) throw new IllegalArgumentException("Digest input is required");
        return digest(runtimeMasterKey, runtimeKeyVersion, tenant, purpose, value);
    }

    /** Content digests from different key generations cannot be compared after plaintext is discarded. */
    public Comparison compare(Digest left, Digest right) {
        if (left == null || right == null || !left.keyVersion().equals(right.keyVersion())) {
            return Comparison.BASELINE_UNKNOWN_REAPPROVAL_REQUIRED;
        }
        return left.value().equals(right.value()) ? Comparison.UNCHANGED : Comparison.CHANGED;
    }

    private static Digest digest(byte[] key, String version, Tenant tenant, String purpose, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            String scoped = version + "|" + tenant.getId() + "|" + purpose + "|" + value;
            return new Digest("HMAC-SHA-256", version,
                    HexFormat.of().formatHex(mac.doFinal(scoped.getBytes(StandardCharsets.UTF_8))));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to compute AI identity digest", exception);
        }
    }

    private static byte[] bytes(String value) {
        return value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8);
    }

    public record Digest(String algorithm, String keyVersion, String value) { }
    public enum Comparison { UNCHANGED, CHANGED, BASELINE_UNKNOWN_REAPPROVAL_REQUIRED }
}
