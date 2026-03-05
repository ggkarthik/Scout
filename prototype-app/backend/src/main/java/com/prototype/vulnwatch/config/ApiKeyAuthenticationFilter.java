package com.prototype.vulnwatch.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    @Value("${app.security.api-key:}")
    private String configuredApiKey;
    @Value("${app.security.creator-key:}")
    private String configuredCreatorKey;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String providedApiKey = request.getHeader("X-API-Key");
        if (configuredApiKey == null || configuredApiKey.isBlank()) {
            reject(response, "API key is not configured");
            return;
        }

        if (!constantTimeEquals(configuredApiKey, providedApiKey)) {
            reject(response, "Unauthorized");
            return;
        }

        // If creator key is not configured, keep operations workspace available in local/dev mode.
        // When a creator key is configured, callers must provide matching X-Creator-Key.
        boolean creator = !hasText(configuredCreatorKey)
                || constantTimeEquals(configuredCreatorKey, request.getHeader("X-Creator-Key"));
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        if (creator) {
            authorities.add(new SimpleGrantedAuthority("ROLE_CREATOR"));
        }
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                creator ? "creator-client" : "api-key-client",
                null,
                authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }

    private boolean constantTimeEquals(String left, String right) {
        if (left == null || right == null) {
            return false;
        }
        return MessageDigest.isEqual(
                left.getBytes(StandardCharsets.UTF_8),
                right.getBytes(StandardCharsets.UTF_8));
    }

    private void reject(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
