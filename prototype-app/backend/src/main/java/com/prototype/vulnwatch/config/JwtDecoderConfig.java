package com.prototype.vulnwatch.config;

import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class JwtDecoderConfig {

    @Bean
    @ConditionalOnExpression("'${app.security.jwt.issuer-uri:}' != '' || '${app.security.jwt.jwk-set-uri:}' != '' || '${app.security.jwt.hmac-secret:}' != ''")
    public JwtDecoder jwtDecoder(
            @Value("${app.security.jwt.issuer-uri:}") String issuerUri,
            @Value("${app.security.jwt.jwk-set-uri:}") String jwkSetUri,
            @Value("${app.security.jwt.hmac-secret:}") String hmacSecret
    ) {
        if (hasText(issuerUri)) {
            return JwtDecoders.fromIssuerLocation(issuerUri.trim());
        }
        if (hasText(jwkSetUri)) {
            return NimbusJwtDecoder.withJwkSetUri(jwkSetUri.trim()).build();
        }
        if (hasText(hmacSecret)) {
            SecretKeySpec key = new SecretKeySpec(hmacSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256");
            return NimbusJwtDecoder.withSecretKey(key).build();
        }
        throw new IllegalStateException("JWT authentication is enabled but no decoder setting was provided.");
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
