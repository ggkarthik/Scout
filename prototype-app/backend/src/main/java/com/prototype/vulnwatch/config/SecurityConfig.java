package com.prototype.vulnwatch.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            ApiKeyAuthenticationFilter apiKeyAuthenticationFilter,
            RequestCorrelationFilter requestCorrelationFilter,
            TenantStatusFilter tenantStatusFilter,
            @Value("${app.security.headers.content-security-policy:default-src 'none'; frame-ancestors 'none'}") String contentSecurityPolicy,
            @Value("${app.security.headers.permissions-policy:camera=(), microphone=(), geolocation=(), payment=()}") String permissionsPolicy
    ) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                        .headers(headers -> headers
                        .contentTypeOptions(contentType -> {})
                        .frameOptions(frame -> frame.deny())
                        .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                        .contentSecurityPolicy(csp -> csp.policyDirectives(contentSecurityPolicy))
                        .addHeaderWriter(new StaticHeadersWriter("Permissions-Policy", permissionsPolicy)))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/readiness", "/actuator/health/liveness", "/actuator/info").permitAll()
                        .requestMatchers("/actuator/**").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/auth/login", "/api/auth/setup-password").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/demo-requests").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/demo-invites/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/demo-invites/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/tenant-invites/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/tenant-invites/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/operations/quality/**", "/api/operations/software-identities/search")
                        .hasAnyRole("PLATFORM_OWNER", "TENANT_ADMIN", "INVENTORY_ADMIN", "SECURITY_ANALYST", "READ_ONLY_AUDITOR")
                        .requestMatchers("/api/platform/**").hasRole("PLATFORM_OWNER")
                        .requestMatchers("/api/operations/**").hasRole("PLATFORM_OWNER")
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().permitAll())
                .addFilterBefore(apiKeyAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(requestCorrelationFilter, ApiKeyAuthenticationFilter.class)
                .addFilterAfter(tenantStatusFilter, RequestCorrelationFilter.class);

        return http.build();
    }
}
