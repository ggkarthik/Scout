package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.GithubGhcrSbomIngestionRequest;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.GithubSbomSourceRequest;
import com.prototype.vulnwatch.dto.GithubSbomSourceResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.GithubSbomSourceService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/github-sbom-sources")
public class GithubSbomSourceController {

    private final GithubSbomSourceService githubSbomSourceService;

    public GithubSbomSourceController(GithubSbomSourceService githubSbomSourceService) {
        this.githubSbomSourceService = githubSbomSourceService;
    }

    @GetMapping
    public List<GithubSbomSourceResponse> list() {
        return githubSbomSourceService.list();
    }

    @PostMapping
    public GithubSbomSourceResponse create(@Valid @RequestBody GithubSbomSourceRequest request) {
        return githubSbomSourceService.create(request);
    }

    @PutMapping("/{id}")
    public GithubSbomSourceResponse update(@PathVariable UUID id, @Valid @RequestBody GithubSbomSourceRequest request) {
        return githubSbomSourceService.update(id, request);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable UUID id) {
        githubSbomSourceService.delete(id);
    }

    @PostMapping("/ghcr/run")
    public SyncTriggerResponse runGhcrOnce(@Valid @RequestBody GithubGhcrSbomIngestionRequest request) {
        return githubSbomSourceService.triggerGhcrRunOnce(request.owner());
    }

    @PostMapping("/repository/run")
    public SyncTriggerResponse runRepositoryOnce(@Valid @RequestBody GithubSbomIngestionRequest request) {
        return githubSbomSourceService.triggerRepositoryRunOnce(request);
    }

    @PostMapping("/{id}/run")
    public SyncTriggerResponse run(@PathVariable UUID id) {
        return githubSbomSourceService.trigger(id);
    }
}
