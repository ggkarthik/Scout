package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.lenient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.GithubTokenProvider;
import com.prototype.vulnwatch.domain.GithubSbomSource;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.GithubSbomSourceRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.task.TaskExecutor;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class GithubSbomSourceServiceTest {

    @Mock
    private GithubSbomSourceRepository githubSbomSourceRepository;

    @Mock
    private SyncRunRepository syncRunRepository;

    @Mock
    private SbomIngestionService sbomIngestionService;

    @Mock
    private WorkspaceService workspaceService;

    @Mock
    private TenantService tenantService;

    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Mock
    private TaskExecutor ingestionExecutor;

    @Mock
    private TransactionTemplate transactionTemplate;

    @Mock
    private GithubTokenProvider githubTokenProvider;

    private GithubSbomSourceService githubSbomSourceService;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        when(githubTokenProvider.hasToken()).thenReturn(false);
        when(githubTokenProvider.configurationHint()).thenReturn(
                "Configure GITHUB_API_TOKEN_FILE, backend/secrets/github-api-token, or GITHUB_API_TOKEN for the backend."
        );
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Tenant A");
        lenient().when(workspaceService.getWorkspace()).thenReturn(tenant);
        lenient().when(tenantService.listTenants()).thenReturn(java.util.List.of(tenant));
        lenient().when(tenantSchemaExecutionService.run(org.mockito.ArgumentMatchers.any(Tenant.class), org.mockito.ArgumentMatchers.<Supplier<?>>any()))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());
        lenient().when(tenantSchemaExecutionService.run(org.mockito.ArgumentMatchers.any(UUID.class), org.mockito.ArgumentMatchers.<Supplier<?>>any()))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());
        githubSbomSourceService = new GithubSbomSourceService(
                githubSbomSourceRepository,
                syncRunRepository,
                sbomIngestionService,
                workspaceService,
                githubTokenProvider,
                ingestionExecutor,
                transactionTemplate,
                new ObjectMapper(),
                tenantService,
                tenantSchemaExecutionService
        );
    }

    @Test
    void triggerGhcrRunOnceFailsFastWithoutConfiguredToken() {
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> githubSbomSourceService.triggerGhcrRunOnce("openai")
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("read:packages"));
        verifyNoInteractions(syncRunRepository, transactionTemplate, ingestionExecutor);
    }

    @Test
    void triggerSavedGhcrSourceFailsFastWithoutConfiguredToken() {
        UUID sourceId = UUID.randomUUID();
        GithubSbomSource source = new GithubSbomSource();
        source.setTenant(tenant);
        source.setPath(GithubSbomSourceService.PATH_GHCR_ATTESTATIONS);
        when(githubSbomSourceRepository.findById(sourceId)).thenReturn(Optional.of(source));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> githubSbomSourceService.trigger(sourceId)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("backend/secrets/github-api-token"));
        verify(githubSbomSourceRepository).findById(sourceId);
        verifyNoInteractions(syncRunRepository, transactionTemplate, ingestionExecutor);
    }
}
