package com.prototype.vulnwatch.service;

import java.util.UUID;

/**
 * BLG-007: Thread-local tenant identity carrier.
 *
 * Set by TenantResolutionFilter at request start; used by TenantAwareDataSource
 * to set the PostgreSQL session variable app.current_tenant_id on each acquired
 * connection, enabling Row-Level Security policies.
 *
 * Always call clear() in a finally block to prevent context bleed between
 * pooled threads.
 */
public final class TenantContext {

    private static final ThreadLocal<UUID> CURRENT = new ThreadLocal<>();
    private static final ThreadLocal<String> CURRENT_SCHEMA = new ThreadLocal<>();

    private TenantContext() {
    }

    public static UUID getCurrentTenantId() {
        return CURRENT.get();
    }

    public static void setCurrentTenantId(UUID tenantId) {
        CURRENT.set(tenantId);
    }

    public static String getCurrentSchemaName() {
        return CURRENT_SCHEMA.get();
    }

    public static void setCurrentSchemaName(String schemaName) {
        CURRENT_SCHEMA.set(schemaName);
    }

    public static void clear() {
        CURRENT.remove();
        CURRENT_SCHEMA.remove();
    }
}
