package com.prototype.vulnwatch.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.service.TenantContext;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class TenantAwareDataSourceTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void classifiesPlatformAndMissingContextSeparately() throws Exception {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        TenantAwareDataSource dataSource = new TenantAwareDataSource(targetConnection(), true, "tenant_default", registry);

        TenantContext.runAsPlatform(() -> {
            try {
                dataSource.getConnection().close();
            } catch (SQLException ex) {
                throw new IllegalStateException(ex);
            }
        });
        dataSource.getConnection().close();

        assertThat(registry.counter("tenant.context.missing", "classification", "platform").count()).isEqualTo(1.0);
        assertThat(registry.counter("tenant.context.missing", "classification", "missing_unclassified").count()).isEqualTo(1.0);
    }

    @Test
    void classifiesBootstrapConnectionsSeparatelyWithoutRuntimeWarningBucket() throws Exception {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        TenantAwareDataSource dataSource = new TenantAwareDataSource(
                targetConnection(),
                true,
                "tenant_default",
                registry,
                () -> false
        );

        dataSource.getConnection().close();

        assertThat(registry.counter("tenant.context.missing", "classification", "bootstrap_default_tenant").count()).isEqualTo(1.0);
        assertThat(registry.find("tenant.context.missing").tags("classification", "missing_unclassified").counter()).isNull();
    }

    @Test
    void tenantContextSetsTenantSchemaWithPlatformFallback() throws Exception {
        DataSource target = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        PreparedStatement statement = mock(PreparedStatement.class);
        Statement resetStatement = mock(Statement.class);
        when(target.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(connection.createStatement()).thenReturn(resetStatement);
        TenantAwareDataSource dataSource = new TenantAwareDataSource(target, true, "tenant_default", new SimpleMeterRegistry());
        UUID tenantId = UUID.randomUUID();
        TenantContext.setCurrentTenantId(tenantId);
        TenantContext.setCurrentSchemaName("tenant_acme");

        dataSource.getConnection().close();

        ArgumentCaptor<String> values = ArgumentCaptor.forClass(String.class);
        verify(statement, times(2)).setString(org.mockito.ArgumentMatchers.eq(1), values.capture());
        assertThat(values.getAllValues()).containsExactly(tenantId.toString(), "tenant_acme,platform");
    }

    @Test
    void platformContextSetsPlatformOnlySearchPath() throws Exception {
        DataSource target = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        PreparedStatement statement = mock(PreparedStatement.class);
        Statement resetStatement = mock(Statement.class);
        when(target.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(connection.createStatement()).thenReturn(resetStatement);
        TenantAwareDataSource dataSource = new TenantAwareDataSource(target, true, "tenant_default", new SimpleMeterRegistry());

        TenantContext.runAsPlatform(() -> {
            try {
                dataSource.getConnection().close();
            } catch (SQLException ex) {
                throw new IllegalStateException(ex);
            }
        });

        ArgumentCaptor<String> values = ArgumentCaptor.forClass(String.class);
        verify(statement, times(2)).setString(org.mockito.ArgumentMatchers.eq(1), values.capture());
        assertThat(values.getAllValues()).containsExactly("", "platform,public");
    }

    @Test
    void closesBorrowedConnectionWhenApplyingContextFails() throws Exception {
        DataSource target = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        when(target.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenThrow(new SQLException("nope"));
        TenantAwareDataSource dataSource = new TenantAwareDataSource(target, true, "tenant_default", new SimpleMeterRegistry());

        assertThatThrownBy(dataSource::getConnection)
                .isInstanceOf(SQLException.class)
                .hasMessageContaining("nope");

        verify(connection).close();
    }

    private DataSource targetConnection() throws Exception {
        DataSource target = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        PreparedStatement statement = mock(PreparedStatement.class);
        Statement resetStatement = mock(Statement.class);
        when(target.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(connection.createStatement()).thenReturn(resetStatement);
        return target;
    }
}
