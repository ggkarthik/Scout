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
    private static final ThreadLocal<Boolean> PLATFORM_CONTEXT = ThreadLocal.withInitial(() -> false);

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

    public static boolean isPlatformContext() {
        return Boolean.TRUE.equals(PLATFORM_CONTEXT.get());
    }

    public static <T> T runAsPlatform(java.util.function.Supplier<T> supplier) {
        UUID previousTenantId = CURRENT.get();
        String previousSchema = CURRENT_SCHEMA.get();
        boolean previousPlatform = isPlatformContext();
        try {
            CURRENT.remove();
            CURRENT_SCHEMA.remove();
            PLATFORM_CONTEXT.set(true);
            return supplier.get();
        } finally {
            restore(previousTenantId, previousSchema, previousPlatform);
        }
    }

    public static void runAsPlatform(Runnable runnable) {
        runAsPlatform(() -> {
            runnable.run();
            return null;
        });
    }

    public static Snapshot capture() {
        return new Snapshot(CURRENT.get(), CURRENT_SCHEMA.get(), isPlatformContext());
    }

    public static void restore(Snapshot snapshot) {
        if (snapshot == null) {
            clear();
            return;
        }
        restore(snapshot.tenantId(), snapshot.schemaName(), snapshot.platformContext());
    }

    public static void clear() {
        CURRENT.remove();
        CURRENT_SCHEMA.remove();
        PLATFORM_CONTEXT.remove();
    }

    private static void restore(UUID tenantId, String schemaName, boolean platformContext) {
        if (tenantId == null) {
            CURRENT.remove();
        } else {
            CURRENT.set(tenantId);
        }
        if (schemaName == null) {
            CURRENT_SCHEMA.remove();
        } else {
            CURRENT_SCHEMA.set(schemaName);
        }
        if (platformContext) {
            PLATFORM_CONTEXT.set(true);
        } else {
            PLATFORM_CONTEXT.remove();
        }
    }

    public record Snapshot(UUID tenantId, String schemaName, boolean platformContext) {
    }
}
