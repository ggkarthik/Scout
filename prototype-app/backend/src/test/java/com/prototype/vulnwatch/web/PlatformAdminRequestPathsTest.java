package com.prototype.vulnwatch.web;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PlatformAdminRequestPathsTest {

    @Test
    void detectsPlatformAdminEndpoints() {
        assertTrue(PlatformAdminRequestPaths.isPlatformAdminPath("/api/ingestion/nvd-sync"));
        assertTrue(PlatformAdminRequestPaths.isPlatformAdminPath("/api/connectors/vulnerability-sources/nvd"));
        assertTrue(PlatformAdminRequestPaths.isPlatformAdminPath("/api/platform/tenants"));
        assertTrue(PlatformAdminRequestPaths.isPlatformAdminPath("/api/platform/tenants/123/quotas"));
        assertTrue(PlatformAdminRequestPaths.isPlatformAdminPath("/api/operations/dashboard"));
        assertTrue(PlatformAdminRequestPaths.isPlatformAdminPath("/api/eol/admin/refresh/catalog"));
        assertTrue(PlatformAdminRequestPaths.isPlatformAdminPath("/api/eol/admin/refresh/full"));
        assertFalse(PlatformAdminRequestPaths.isPlatformAdminPath("/api/eol/status/summary"));
        assertFalse(PlatformAdminRequestPaths.isPlatformAdminPath("/api/eol/mappings/confirm"));
        assertFalse(PlatformAdminRequestPaths.isPlatformAdminPath("/api/dashboard"));
    }
}
