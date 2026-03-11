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

    private TenantContext() {
    }

    public static UUID getCurrentTenantId() {
        return CURRENT.get();
    }

    public static void setCurrentTenantId(UUID tenantId) {
        CURRENT.set(tenantId);
    }

    public static void clear() {
        CURRENT.remove();
    }
}
