package com.prototype.vulnwatch.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import java.lang.reflect.Method;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class SensitiveTenantActionInterceptorTest {

    @Mock
    private RequestActorService requestActorService;

    @Test
    void nonPlatformActorsDoNotNeedConfirmation() throws Exception {
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "tenant-owner",
                false,
                UUID.randomUUID(),
                "Example Co",
                Set.of("TENANT_ADMIN")));

        SensitiveTenantActionInterceptor interceptor = new SensitiveTenantActionInterceptor(
                requestActorService
        );

        assertTrue(interceptor.preHandle(request(), new MockHttpServletResponse(), sensitiveMethod()));
    }

    @Test
    void platformOwnersCannotPerformTenantScopedActions() throws Exception {
        UUID tenantId = UUID.randomUUID();
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "platform-owner",
                true,
                tenantId,
                "Example Co",
                Set.of("PLATFORM_OWNER")));

        SensitiveTenantActionInterceptor interceptor = new SensitiveTenantActionInterceptor(
                requestActorService
        );

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> interceptor.preHandle(request(), new MockHttpServletResponse(), sensitiveMethod())
        );

        assertEquals(403, error.getStatusCode().value());
    }

    @Test
    void platformOwnedIngestionPathsBypassTenantSupportChecks() throws Exception {
        UUID tenantId = UUID.randomUUID();
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "platform-owner",
                true,
                tenantId,
                "Example Co",
                Set.of("PLATFORM_OWNER")));

        SensitiveTenantActionInterceptor interceptor = new SensitiveTenantActionInterceptor(
                requestActorService
        );

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/ingestion/nvd-sync");
        request.setRequestURI("/api/ingestion/nvd-sync");

        assertTrue(interceptor.preHandle(request, new MockHttpServletResponse(), sensitiveMethod()));
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

    private static final class TestController {
        @SensitiveTenantAction
        public void sensitive() {
        }
    }
}
