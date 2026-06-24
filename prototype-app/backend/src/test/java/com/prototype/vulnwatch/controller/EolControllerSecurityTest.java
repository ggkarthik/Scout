package com.prototype.vulnwatch.controller;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.dto.EolMappingConfirmRequest;
import java.lang.reflect.Method;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;

class EolControllerSecurityTest {

    @Test
    void mutationEndpointsRequirePlatformOwnerRole() throws Exception {
        for (Method method : platformOwnerMethods()) {
            PreAuthorize preAuthorize = method.getAnnotation(PreAuthorize.class);
            assertThat(preAuthorize)
                    .as(method.getName())
                    .isNotNull();
            assertThat(preAuthorize.value()).isEqualTo("hasRole('PLATFORM_OWNER')");
        }
    }

    private List<Method> platformOwnerMethods() throws NoSuchMethodException {
        return List.of(
                EolController.class.getDeclaredMethod("confirmMapping", EolMappingConfirmRequest.class),
                EolController.class.getDeclaredMethod("triggerCatalogRefresh"),
                EolController.class.getDeclaredMethod("triggerReleaseRefresh"),
                EolController.class.getDeclaredMethod("triggerMappingResolve"),
                EolController.class.getDeclaredMethod("triggerDenormalize"),
                EolController.class.getDeclaredMethod("triggerFullRefresh")
        );
    }
}
