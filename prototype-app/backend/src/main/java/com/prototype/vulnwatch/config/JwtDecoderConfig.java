package com.prototype.vulnwatch.config;

import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class JwtDecoderConfig {

    @Bean
    @ConditionalOnExpression("'${app.security.jwt.issuer-uri:}' != '' || '${app.security.jwt.jwk-set-uri:}' != '' || '${app.security.jwt.hmac-secret:}' != ''")
    public JwtDecoder jwtDecoder(
            @Value("${app.security.jwt.issuer-uri:}") String issuerUri,
            @Value("${app.security.jwt.jwk-set-uri:}") String jwkSetUri,
            @Value("${app.security.jwt.hmac-secret:}") String hmacSecret,
            @Value("${app.security.jwt.audience:}") String audience
    ) {
        if (hasText(issuerUri)) {
            NimbusJwtDecoder decoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(issuerUri.trim());
            configureAudienceValidator(decoder, issuerUri.trim(), audience);
            return decoder;
        }
        if (hasText(jwkSetUri)) {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri.trim()).build();
            configureAudienceValidator(decoder, null, audience);
            return decoder;
        }
        if (hasText(hmacSecret)) {
            SecretKeySpec key = new SecretKeySpec(hmacSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256");
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key).build();
            configureAudienceValidator(decoder, null, audience);
            return decoder;
        }
        throw new IllegalStateException("JWT authentication is enabled but no decoder setting was provided.");
    }

    private void configureAudienceValidator(NimbusJwtDecoder decoder, String issuerUri, String audience) {
        OAuth2TokenValidator<org.springframework.security.oauth2.jwt.Jwt> validator =
                hasText(issuerUri) ? JwtValidators.createDefaultWithIssuer(issuerUri) : JwtValidators.createDefault();
        if (hasText(audience)) {
            validator = new DelegatingOAuth2TokenValidator<>(validator, jwt -> {
                if (jwt.getAudience().contains(audience.trim())) {
                    return OAuth2TokenValidatorResult.success();
                }
                return OAuth2TokenValidatorResult.failure(
                        new OAuth2Error("invalid_token", "JWT audience is invalid", null)
                );
            });
        }
        decoder.setJwtValidator(validator);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
