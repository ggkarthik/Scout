package com.prototype.vulnwatch.web;

public final class PlatformAdminRequestPaths {

    private PlatformAdminRequestPaths() {
    }

    public static boolean isPlatformAdminPath(String uri) {
        return uri != null && (
                uri.startsWith("/api/platform/")
                        || uri.startsWith("/api/operations/")
                        || uri.startsWith("/api/ingestion/")
                        || uri.startsWith("/api/eol/admin/")
                        || uri.startsWith("/api/connectors/vulnerability-sources"));
    }
}
