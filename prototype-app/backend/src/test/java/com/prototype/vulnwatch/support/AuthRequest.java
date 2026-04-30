package com.prototype.vulnwatch.support;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder;

/**
 * Authenticated request helpers for controller integration tests. Avoids the
 * boilerplate of repeating {@code .header("X-API-Key", ...)} on every
 * MockMvc call. Combine with {@link PostgresITSupport} constants.
 *
 * <p>Examples:
 * <pre>{@code
 *   mockMvc.perform(authedGet("/api/findings"))
 *          .andExpect(status().isOk());
 *
 *   mockMvc.perform(asPlatformOwner(authedPost("/api/demo/seed")))
 *          .andExpect(status().isOk());
 *
 *   mockMvc.perform(asAnalyst(authedPost("/api/cve-detail/{id}/suppress", cveId))
 *                       .contentType(MediaType.APPLICATION_JSON)
 *                       .content(body))
 *          .andExpect(status().isOk());
 * }</pre>
 */
public final class AuthRequest {

    private AuthRequest() {
    }

    public static MockHttpServletRequestBuilder authedGet(String url, Object... uriVars) {
        return withApiKey(get(url, uriVars));
    }

    public static MockHttpServletRequestBuilder authedPost(String url, Object... uriVars) {
        return withApiKey(post(url, uriVars));
    }

    public static MockHttpServletRequestBuilder authedPut(String url, Object... uriVars) {
        return withApiKey(put(url, uriVars));
    }

    public static MockHttpServletRequestBuilder authedDelete(String url, Object... uriVars) {
        return withApiKey(delete(url, uriVars));
    }

    public static MockMultipartHttpServletRequestBuilder authedMultipart(String url, Object... uriVars) {
        MockMultipartHttpServletRequestBuilder builder = multipart(url, uriVars);
        builder.header("X-API-Key", PostgresITSupport.API_KEY);
        return builder;
    }

    public static MockHttpServletRequestBuilder withApiKey(MockHttpServletRequestBuilder builder) {
        return builder.header("X-API-Key", PostgresITSupport.API_KEY);
    }

    public static MockHttpServletRequestBuilder withCreator(MockHttpServletRequestBuilder builder) {
        return builder.header("X-Creator-Key", PostgresITSupport.CREATOR_KEY);
    }

    public static MockHttpServletRequestBuilder withUser(MockHttpServletRequestBuilder builder, String userId) {
        return builder.header("X-User-ID", userId);
    }

    public static MockHttpServletRequestBuilder withTenant(MockHttpServletRequestBuilder builder, String tenantId) {
        return builder.header("X-Tenant-ID", tenantId);
    }

    /** Adds creator-role headers (operations endpoints, demo seed, etc.). */
    public static MockHttpServletRequestBuilder asPlatformOwner(MockHttpServletRequestBuilder builder) {
        return withCreator(builder);
    }

    /** Adds default analyst user header (for endpoints that read X-User-ID). */
    public static MockHttpServletRequestBuilder asAnalyst(MockHttpServletRequestBuilder builder) {
        return withUser(builder, PostgresITSupport.DEFAULT_USER_ID);
    }

    /** Adds default analyst + tenant headers (for tenant-scoped workflow endpoints). */
    public static MockHttpServletRequestBuilder asTenantAnalyst(MockHttpServletRequestBuilder builder) {
        return withTenant(withUser(builder, PostgresITSupport.DEFAULT_USER_ID), PostgresITSupport.DEFAULT_TENANT_ID);
    }
}
