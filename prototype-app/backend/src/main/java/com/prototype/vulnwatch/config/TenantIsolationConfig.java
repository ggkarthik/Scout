package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.WorkspaceService;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.servlet.Filter;
import jakarta.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * BLG-007: Replaces Spring Boot's auto-configured DataSource with a
 * TenantAwareDataSource wrapper that sets app.current_tenant_id on every
 * connection, enabling PostgreSQL Row-Level Security policies.
 *
 * Spring Boot's DataSourceAutoConfiguration backs off when a DataSource bean
 * named "dataSource" is defined here. HikariCP settings from
 * spring.datasource.hikari.* are still applied via @ConfigurationProperties.
 */
@Configuration
public class TenantIsolationConfig {

    /**
     * Raw HikariCP pool — not exposed to the application directly.
     * Receives all spring.datasource.hikari.* bindings.
     */
    @Bean(name = "hikariDataSource")
    @ConfigurationProperties(prefix = "spring.datasource.hikari")
    public HikariDataSource hikariDataSource(DataSourceProperties properties) {
        return properties.initializeDataSourceBuilder()
                .type(HikariDataSource.class)
                .build();
    }

    /**
     * Primary DataSource bean — wraps the HikariCP pool with tenant context injection.
     * All JPA, Flyway, and JdbcTemplate beans will use this bean.
     */
    @Bean
    @Primary
    public DataSource dataSource(HikariDataSource hikariDataSource) {
        return new TenantAwareDataSource(hikariDataSource);
    }

    /**
     * Unscoped JdbcTemplate for admin-only flows that must clear data across
     * all tenants and global tables.
     */
    @Bean(name = "prototypeResetJdbcTemplate")
    public JdbcTemplate prototypeResetJdbcTemplate(HikariDataSource hikariDataSource) {
        return new JdbcTemplate(hikariDataSource);
    }

    /**
     * Dedicated transaction manager for prototype reset operations that should
     * bypass the tenant-aware datasource wrapper.
     */
    @Bean(name = "prototypeResetTransactionManager")
    public PlatformTransactionManager prototypeResetTransactionManager(HikariDataSource hikariDataSource) {
        return new DataSourceTransactionManager(hikariDataSource);
    }

    /**
     * Keep the application's default JPA transaction manager available under the
     * conventional bean name expected by the rest of the service layer.
     */
    @Bean(name = "transactionManager")
    @Primary
    public PlatformTransactionManager transactionManager(EntityManagerFactory entityManagerFactory) {
        return new JpaTransactionManager(entityManagerFactory);
    }

    /**
     * Registers TenantResolutionFilter explicitly (not via @Component) so that
     * @WebMvcTest slice tests do not try to load it without JPA context available.
     */
    @Bean
    public FilterRegistrationBean<Filter> tenantResolutionFilter(WorkspaceService workspaceService) {
        FilterRegistrationBean<Filter> reg = new FilterRegistrationBean<>(
                new TenantResolutionFilter(workspaceService));
        reg.addUrlPatterns("/*");
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        reg.setName("tenantResolutionFilter");
        return reg;
    }
}
