package com.prototype.vulnwatch.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class SensitiveTenantActionInterceptorTest {

    @Mock
    private RequestActorService requestActorService;

    @Mock
    private AuditEventService auditEventService;

    @Test
    void nonPlatformActorsDoNotNeedConfirmation() throws Exception {
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "tenant-owner",
                false,
                UUID.randomUUID(),
                "Example Co",
                Set.of("TENANT_ADMIN")));

        SensitiveTenantActionInterceptor interceptor = new SensitiveTenantActionInterceptor(
                requestActorService,
                emptyProvider()
        );

        assertTrue(interceptor.preHandle(request(), new MockHttpServletResponse(), sensitiveMethod()));
    }

    @Test
    void platformOwnersInTenantContextNeedConfirmationHeaders() throws Exception {
        UUID tenantId = UUID.randomUUID();
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "platform-owner",
                true,
                tenantId,
                "Example Co",
                Set.of("PLATFORM_OWNER")));

        SensitiveTenantActionInterceptor interceptor = new SensitiveTenantActionInterceptor(
                requestActorService,
                emptyProvider()
        );

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> interceptor.preHandle(request(), new MockHttpServletResponse(), sensitiveMethod())
        );

        assertEquals(428, error.getStatusCode().value());
    }

    @Test
    void validConfirmationHeadersAllowSensitiveActionAndAudit() throws Exception {
        UUID tenantId = UUID.randomUUID();
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "platform-owner",
                true,
                tenantId,
                "Example Co",
                Set.of("PLATFORM_OWNER")));

        SensitiveTenantActionInterceptor interceptor = new SensitiveTenantActionInterceptor(
                requestActorService,
                providerWithAudit()
        );
        MockHttpServletRequest request = request();
        request.addHeader("X-Platform-Action-Confirm", "true");
        request.addHeader("X-Platform-Action-Tenant", tenantId.toString());
        request.addHeader("X-Platform-Action-Time", Instant.now().toString());

        assertTrue(interceptor.preHandle(request, new MockHttpServletResponse(), sensitiveMethod()));
        verify(auditEventService).record(
                eq("platform.tenant_action.confirmed"),
                eq("tenant"),
                eq(tenantId.toString()),
                contains("/api/test/sensitive"));
    }

    private MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/test/sensitive");
        request.setRequestURI("/api/test/sensitive");
        return request;
    }

    private HandlerMethod sensitiveMethod() throws NoSuchMethodException {
        Method method = TestController.class.getDeclaredMethod("sensitive");
        return new HandlerMethod(new TestController(), method);
    }

    private ObjectProvider<AuditEventService> emptyProvider() {
        return new StaticListableBeanFactory().getBeanProvider(AuditEventService.class);
    }

    private ObjectProvider<AuditEventService> providerWithAudit() {
        StaticListableBeanFactory beanFactory = new StaticListableBeanFactory();
        beanFactory.addBean("auditEventService", auditEventService);
        return beanFactory.getBeanProvider(AuditEventService.class);
    }

    private static final class TestController {
        @SensitiveTenantAction
        public void sensitive() {
        }
    }
}
