package com.prototype.vulnwatch.aisecurity.controller;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.prototype.vulnwatch.aisecurity.service.AiGridApiService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.security.Principal;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

class AiGridEvidenceIngestionControllerTest {
    @Test
    void rejectsServiceAccountWhoseSubjectDoesNotMatchProducer() {
        WorkspaceService workspaces = mock(WorkspaceService.class);
        AiGridApiService api = mock(AiGridApiService.class);
        AiSecurityAccessService access = mock(AiSecurityAccessService.class);
        AiGridEvidenceIngestionController controller = new AiGridEvidenceIngestionController(workspaces, api, access);
        Principal principal = () -> "SCOUT_DATA_SECURITY";

        assertThatThrownBy(() -> controller.ingest("SCOUT_RUNTIME_CONTROL",
                new AiGridEvidenceIngestionController.EvidenceBatch(List.of()), principal))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("not authorized");
        verifyNoInteractions(workspaces, api, access);
    }
}
