package com.prototype.vulnwatch.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.service.TenantContext;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.TaskDecorator;

class HttpClientConfigTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void tenantContextTaskDecoratorCopiesAndRestoresContext() {
        UUID tenantId = UUID.randomUUID();
        TenantContext.setCurrentTenantId(tenantId);
        TenantContext.setCurrentSchemaName("tenant_acme");
        TaskDecorator decorator = HttpClientConfig.tenantContextTaskDecorator();
        Runnable decorated = decorator.decorate(() -> {
            assertThat(TenantContext.getCurrentTenantId()).isEqualTo(tenantId);
            assertThat(TenantContext.getCurrentSchemaName()).isEqualTo("tenant_acme");
        });

        TenantContext.clear();
        decorated.run();

        assertThat(TenantContext.getCurrentTenantId()).isNull();
        assertThat(TenantContext.getCurrentSchemaName()).isNull();
    }

    @Test
    void tenantContextTaskDecoratorCopiesPlatformContext() {
        TaskDecorator decorator = HttpClientConfig.tenantContextTaskDecorator();
        Runnable decorated = TenantContext.runAsPlatform(
                () -> decorator.decorate(() -> assertThat(TenantContext.isPlatformContext()).isTrue())
        );

        decorated.run();

        assertThat(TenantContext.isPlatformContext()).isFalse();
    }
}
