package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantContext;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import org.springframework.jdbc.datasource.DelegatingDataSource;

/**
 * BLG-007: DataSource decorator that sets the PostgreSQL session variable
 * app.current_tenant_id on every connection acquired from the underlying pool,
 * and resets it when the connection is returned (on close()).
 *
 * This allows PostgreSQL Row-Level Security policies to enforce tenant isolation
 * at the database layer, complementing application-layer tenant filtering.
 *
 * set_config(name, value, FALSE) sets a session-level variable that persists for
 * the life of the connection. The reset on close() restores it to an empty string,
 * which the RLS policies treat as "no tenant constraint" (allowing unrestricted
 * access for background jobs and Flyway migrations).
 */
public class TenantAwareDataSource extends DelegatingDataSource {

    public TenantAwareDataSource(javax.sql.DataSource targetDataSource) {
        super(targetDataSource);
    }

    @Override
    public Connection getConnection() throws SQLException {
        Connection conn = super.getConnection();
        applyTenantContext(conn);
        return wrapWithReset(conn);
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        Connection conn = super.getConnection(username, password);
        applyTenantContext(conn);
        return wrapWithReset(conn);
    }

    private void applyTenantContext(Connection conn) throws SQLException {
        UUID tenantId = TenantContext.getCurrentTenantId();
        String value = tenantId != null ? tenantId.toString() : "";
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT set_config('app.current_tenant_id', ?, FALSE)")) {
            ps.setString(1, value);
            ps.execute();
        }
    }

    /**
     * Wraps the connection in a JDK proxy that resets app.current_tenant_id before
     * close(), ensuring the pool connection is clean for the next request.
     * ConnectionWrapper was removed in Spring 6; Proxy is the portable alternative.
     */
    private Connection wrapWithReset(Connection target) {
        return (Connection) Proxy.newProxyInstance(
                target.getClass().getClassLoader(),
                new Class[]{Connection.class},
                (proxy, method, args) -> {
                    if ("close".equals(method.getName())) {
                        try (Statement stmt = target.createStatement()) {
                            stmt.execute("RESET app.current_tenant_id");
                        } catch (SQLException ignored) {
                            // Best-effort: connection still returned to pool.
                        }
                    }
                    return method.invoke(target, args);
                });
    }
}
