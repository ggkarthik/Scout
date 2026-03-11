package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantService;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.servlet.Filter;
import javax.sql.DataSource;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;

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
     * Registers TenantResolutionFilter explicitly (not via @Component) so that
     * @WebMvcTest slice tests do not try to load it without JPA context available.
     */
    @Bean
    public FilterRegistrationBean<Filter> tenantResolutionFilter(TenantService tenantService) {
        FilterRegistrationBean<Filter> reg = new FilterRegistrationBean<>(
                new TenantResolutionFilter(tenantService));
        reg.addUrlPatterns("/*");
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        reg.setName("tenantResolutionFilter");
        return reg;
    }
}
