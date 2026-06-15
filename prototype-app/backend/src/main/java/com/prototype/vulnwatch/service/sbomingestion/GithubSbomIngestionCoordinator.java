package com.prototype.vulnwatch.service.sbomingestion;

import com.prototype.vulnwatch.client.GithubApiClient;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GithubRepoIngestionResult;
import com.prototype.vulnwatch.dto.GithubSbomIngestionBatchResponse;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.SbomIngestionResponse;
import com.prototype.vulnwatch.service.SbomIngestionService;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class GithubSbomIngestionCoordinator {

    private final GithubApiClient githubApiClient;
    private final SbomFetchGuardService sbomFetchGuardService;
    private final SbomUploadSupportService sbomUploadSupportService;
    private final SbomContentIngestionService sbomContentIngestionService;

    public GithubSbomIngestionCoordinator(
            GithubApiClient githubApiClient,
            SbomFetchGuardService sbomFetchGuardService,
            SbomUploadSupportService sbomUploadSupportService,
            SbomContentIngestionService sbomContentIngestionService
    ) {
        this.githubApiClient = githubApiClient;
        this.sbomFetchGuardService = sbomFetchGuardService;
        this.sbomUploadSupportService = sbomUploadSupportService;
        this.sbomContentIngestionService = sbomContentIngestionService;
    }

    public GithubSbomIngestionBatchResponse ingestFromGithub(Tenant tenant, GithubSbomIngestionRequest request) throws IOException {
        String owner = normalize(request.owner());
        if (owner.isBlank()) {
            throw new IOException("GitHub owner/account is required");
        }

        boolean includeAllRepos = shouldIncludeAllRepos(request);
        AssetType assetType = request.assetType() == null ? AssetType.APPLICATION : request.assetType();

        List<GithubApiClient.GithubRepositoryRef> repositories;
        if (includeAllRepos) {
            repositories = githubApiClient.listAccountRepositories(owner);
        } else {
            String repo = normalize(request.repo());
            if (repo.isBlank()) {
                throw new IOException("GitHub repo is required for single-repository mode");
            }
            repositories = List.of(new GithubApiClient.GithubRepositoryRef(
                    owner,
                    repo,
                    owner + "/" + repo,
                    null,
                    false,
                    null));
        }

        if (repositories.isEmpty()) {
            throw new IOException("No GitHub repositories were discovered for account: " + owner);
        }

        int componentsIngested = 0;
        int findingsGenerated = 0;
        int repositoriesSucceeded = 0;
        int repositoriesFailed = 0;
        List<GithubRepoIngestionResult> results = new ArrayList<>();

        for (GithubApiClient.GithubRepositoryRef repository : repositories) {
            String repoOwner = normalize(repository.owner());
            String repoName = normalize(repository.repo());
            if (repoOwner.isBlank() || repoName.isBlank()) {
                continue;
            }

            String assetName = includeAllRepos
                    ? defaultGithubAssetName(repoOwner, repoName)
                    : resolveSingleGithubAssetName(repoOwner, repoName, request.assetName());
            String assetIdentifier = includeAllRepos
                    ? defaultGithubAssetIdentifier(repoOwner, repoName)
                    : resolveSingleGithubAssetIdentifier(repoOwner, repoName, request.assetIdentifier());

            try {
                SbomIngestionResponse response = ingestFromGithubRepository(
                        tenant,
                        repoOwner,
                        repoName,
                        assetType,
                        assetName,
                        assetIdentifier
                );
                componentsIngested += response.componentsIngested();
                findingsGenerated += response.findingsGenerated();
                repositoriesSucceeded++;
                results.add(new GithubRepoIngestionResult(
                        repoOwner,
                        repoName,
                        assetIdentifier,
                        "SUCCESS",
                        response.componentsIngested(),
                        response.findingsGenerated(),
                        "Ingested successfully"
                ));
            } catch (IOException ex) {
                repositoriesFailed++;
                results.add(new GithubRepoIngestionResult(
                        repoOwner,
                        repoName,
                        assetIdentifier,
                        "FAILURE",
                        null,
                        null,
                        ex.getMessage()
                ));
            }
        }

        if (repositoriesSucceeded == 0) {
            String errorMessage = results.isEmpty()
                    ? "GitHub SBOM ingestion failed for all repositories"
                    : "GitHub SBOM ingestion failed for all repositories. Last error: "
                    + results.get(results.size() - 1).message();
            throw new IOException(errorMessage);
        }

        return new GithubSbomIngestionBatchResponse(
                repositories.size(),
                results.size(),
                repositoriesSucceeded,
                repositoriesFailed,
                componentsIngested,
                findingsGenerated,
                results
        );
    }

    public SbomIngestionService.GithubGhcrIngestionSummary ingestAllFromGithubContainerRegistry(
            Tenant tenant,
            String owner
    ) throws IOException {
        String normalizedOwner = normalize(owner);
        if (normalizedOwner.isBlank()) {
            throw new IOException("GitHub owner/account is required");
        }

        List<GithubApiClient.GithubContainerPackageRef> packages = githubApiClient.listContainerPackages(normalizedOwner);
        if (packages.isEmpty()) {
            throw new IOException("No GHCR container packages were discovered for account: " + normalizedOwner);
        }

        Map<String, DiscoveredGhcrImage> imagesByAssetIdentifier = new LinkedHashMap<>();
        for (GithubApiClient.GithubContainerPackageRef pkg : packages) {
            List<GithubApiClient.GithubContainerImageVersionRef> versions =
                    githubApiClient.listContainerImageVersions(normalizedOwner, pkg.packageName());
            for (GithubApiClient.GithubContainerImageVersionRef version : versions) {
                String digest = normalizeDigestToken(version.digest());
                if (digest.isBlank()) {
                    continue;
                }
                String imageRepository = sbomUploadSupportService.normalizeContainerRepository(version.imageRepository());
                if (imageRepository.isBlank()) {
                    continue;
                }
                String assetIdentifier = imageRepository + "@" + digest;
                imagesByAssetIdentifier.compute(assetIdentifier, (key, existing) -> {
                    if (existing == null) {
                        return new DiscoveredGhcrImage(
                                imageRepository,
                                digest,
                                selectPrimaryImageTag(version.tags())
                        );
                    }
                    return existing.mergeTags(version.tags());
                });
            }
        }

        if (imagesByAssetIdentifier.isEmpty()) {
            throw new IOException("No GHCR image digests with attestation candidates were discovered for account: " + normalizedOwner);
        }

        int componentsIngested = 0;
        int findingsGenerated = 0;
        int imagesSucceeded = 0;
        int imagesFailed = 0;
        List<SbomIngestionService.GithubGhcrImageIngestionResult> results = new ArrayList<>();
        Map<String, GithubApiClient.GithubAttestedSbomResponse> bulkAttestationsByAssetIdentifier = Map.of();

        try {
            bulkAttestationsByAssetIdentifier = githubApiClient.fetchAttestedSbomsForOwnerBulk(
                    normalizedOwner,
                    imagesByAssetIdentifier.values().stream()
                            .map(image -> new GithubApiClient.GithubAttestationLookup(image.imageRepository(), image.digest()))
                            .toList()
            );
        } catch (IOException ignored) {
            bulkAttestationsByAssetIdentifier = Map.of();
        }

        for (DiscoveredGhcrImage image : imagesByAssetIdentifier.values()) {
            String assetName = sbomUploadSupportService.defaultContainerAssetName(image.imageRepository());
            String assetIdentifier = image.imageRepository() + "@" + image.digest();
            try {
                GithubApiClient.GithubAttestedSbomResponse attestedSbom = bulkAttestationsByAssetIdentifier.get(assetIdentifier);
                SbomIngestionResponse response = attestedSbom == null
                        ? ingestGithubAttestation(
                                tenant,
                                normalizedOwner,
                                "",
                                image.imageRepository(),
                                image.digest(),
                                image.primaryTag(),
                                assetName,
                                assetIdentifier
                        )
                        : ingestGithubAttestedSbom(
                                tenant,
                                normalizedOwner,
                                "",
                                image.imageRepository(),
                                image.digest(),
                                image.primaryTag(),
                                assetName,
                                assetIdentifier,
                                attestedSbom
                        );
                componentsIngested += response.componentsIngested();
                findingsGenerated += response.findingsGenerated();
                imagesSucceeded++;
                results.add(new SbomIngestionService.GithubGhcrImageIngestionResult(
                        image.imageRepository(),
                        assetIdentifier,
                        "SUCCESS",
                        response.componentsIngested(),
                        response.findingsGenerated(),
                        "Ingested successfully"
                ));
            } catch (IOException ex) {
                imagesFailed++;
                sbomUploadSupportService.recordGithubAttestationFailureEvidence(
                        tenant,
                        normalizedOwner,
                        "",
                        image.imageRepository(),
                        image.primaryTag(),
                        image.digest(),
                        assetName,
                        assetIdentifier,
                        ex.getMessage()
                );
                results.add(new SbomIngestionService.GithubGhcrImageIngestionResult(
                        image.imageRepository(),
                        assetIdentifier,
                        "FAILURE",
                        null,
                        null,
                        ex.getMessage()
                ));
            }
        }

        String failureSummary = summarizeGhcrFailures(results);
        int imagesProcessed = imagesSucceeded + imagesFailed;

        if (imagesSucceeded == 0) {
            throw new IOException(failureSummary == null
                    ? "GitHub GHCR SBOM ingestion failed for all discovered images"
                    : "GitHub GHCR SBOM ingestion failed for all discovered images. " + failureSummary);
        }

        return new SbomIngestionService.GithubGhcrIngestionSummary(
                imagesByAssetIdentifier.size(),
                imagesProcessed,
                imagesSucceeded,
                imagesFailed,
                componentsIngested,
                findingsGenerated,
                failureSummary,
                results
        );
    }

    private SbomIngestionResponse ingestFromGithubRepository(
            Tenant tenant,
            String owner,
            String repo,
            AssetType assetType,
            String assetName,
            String assetIdentifier
    ) throws IOException {
        String endpoint = githubApiClient.buildGeneratedSbomEndpoint(owner, repo);
        GithubApiClient.GithubSbomResponse response;
        try {
            response = githubApiClient.fetchGeneratedSbom(owner, repo);
        } catch (IOException ex) {
            sbomUploadSupportService.recordGithubFetchFailureEvidence(
                    tenant,
                    assetType,
                    assetName,
                    assetIdentifier,
                    owner,
                    repo,
                    endpoint,
                    ex.getMessage()
            );
            throw ex;
        }

        byte[] content = response.payload();
        sbomFetchGuardService.ensurePayloadWithinLimit(content.length);

        String reference = owner + "/" + repo;
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("ingestionMode", "github-generated");
        evidence.put("owner", owner);
        evidence.put("repo", repo);
        evidence.put("apiUrl", response.endpoint());
        evidence.put("statusCode", response.statusCode());
        evidence.put("fetchedAt", Instant.now());

        SbomIngestionSourceMetadata metadata = new SbomIngestionSourceMetadata(
                "GITHUB_GENERATED",
                "github",
                reference,
                response.endpoint(),
                response.statusCode(),
                response.contentType(),
                response.contentLength(),
                sbomUploadSupportService.toJson(evidence)
        );

        return sbomContentIngestionService.ingestBytes(
                tenant,
                assetType,
                assetName,
                assetIdentifier,
                content,
                "github-generated-sbom.json",
                metadata,
                null
        );
    }

    private SbomIngestionResponse ingestGithubAttestation(
            Tenant tenant,
            String owner,
            String repo,
            String imageRepository,
            String normalizedDigest,
            String imageTag,
            String assetName,
            String assetIdentifier
    ) throws IOException {
        GithubApiClient.GithubAttestedSbomResponse response = repo == null || repo.isBlank()
                ? githubApiClient.fetchAttestedSbomForOwner(owner, normalizedDigest, imageRepository)
                : githubApiClient.fetchAttestedSbom(owner, repo, normalizedDigest, imageRepository);
        return ingestGithubAttestedSbom(
                tenant,
                owner,
                repo,
                imageRepository,
                normalizedDigest,
                imageTag,
                assetName,
                assetIdentifier,
                response
        );
    }

    private SbomIngestionResponse ingestGithubAttestedSbom(
            Tenant tenant,
            String owner,
            String repo,
            String imageRepository,
            String normalizedDigest,
            String imageTag,
            String assetName,
            String assetIdentifier,
            GithubApiClient.GithubAttestedSbomResponse response
    ) throws IOException {
        byte[] content = response.payload();
        sbomFetchGuardService.ensurePayloadWithinLimit(content.length);

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("ingestionMode", "github-attestation");
        evidence.put("owner", owner);
        if (repo != null && !repo.isBlank()) {
            evidence.put("repo", repo);
        }
        evidence.put("imageRepository", imageRepository);
        evidence.put("imageTag", imageTag);
        evidence.put("subjectDigest", normalizedDigest);
        evidence.put("predicateType", response.predicateType());
        evidence.put("subjectName", response.subjectName());
        evidence.put("attestationCount", response.attestationCount());
        evidence.put("apiUrl", response.endpoint());
        evidence.put("statusCode", response.statusCode());
        evidence.put("fetchedAt", Instant.now());
        evidence.put("signatureVerified", false);
        evidence.put("verificationMode", "unverified-dsse-subject-match");

        SbomIngestionSourceMetadata metadata = new SbomIngestionSourceMetadata(
                "GITHUB_ATTESTATION",
                "github",
                imageRepository,
                response.endpoint(),
                response.statusCode(),
                response.contentType(),
                response.contentLength(),
                sbomUploadSupportService.toJson(evidence)
        );

        return sbomContentIngestionService.ingestBytes(
                tenant,
                AssetType.CONTAINER_IMAGE,
                assetName,
                assetIdentifier,
                content,
                "github-attested-sbom.json",
                metadata,
                asset -> sbomUploadSupportService.applyContainerImageMetadata(
                        asset,
                        imageRepository,
                        imageTag,
                        normalizedDigest
                )
        );
    }

    private boolean shouldIncludeAllRepos(GithubSbomIngestionRequest request) {
        if (request.includeAllRepos() != null) {
            return request.includeAllRepos();
        }
        return request.repo() == null || request.repo().isBlank();
    }

    private String summarizeGhcrFailures(List<SbomIngestionService.GithubGhcrImageIngestionResult> results) {
        if (results == null || results.isEmpty()) {
            return null;
        }
        List<String> failures = results.stream()
                .filter(result -> "FAILURE".equalsIgnoreCase(result.status()))
                .map(result -> {
                    String repository = result.imageRepository() == null || result.imageRepository().isBlank()
                            ? result.assetIdentifier()
                            : result.imageRepository();
                    String message = result.message() == null || result.message().isBlank()
                            ? "Unknown error"
                            : result.message().trim();
                    return repository + ": " + message;
                })
                .toList();
        if (failures.isEmpty()) {
            return null;
        }
        int previewCount = Math.min(3, failures.size());
        String preview = String.join(" | ", failures.subList(0, previewCount));
        if (failures.size() == previewCount) {
            return preview;
        }
        return preview + " | +" + (failures.size() - previewCount) + " more failures";
    }

    private String defaultGithubAssetName(String owner, String repo) {
        return owner + "/" + repo;
    }

    private String defaultGithubAssetIdentifier(String owner, String repo) {
        return "github:" + owner.toLowerCase(Locale.ROOT) + "/" + repo.toLowerCase(Locale.ROOT);
    }

    private String resolveSingleGithubAssetName(String owner, String repo, String override) {
        if (override == null || override.isBlank()) {
            return defaultGithubAssetName(owner, repo);
        }
        return override.trim();
    }

    private String resolveSingleGithubAssetIdentifier(String owner, String repo, String override) {
        if (override == null || override.isBlank()) {
            return defaultGithubAssetIdentifier(owner, repo);
        }
        return override.trim();
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String selectPrimaryImageTag(List<String> tags) {
        if (tags == null || tags.isEmpty()) {
            return null;
        }
        for (String tag : tags) {
            String normalizedTag = normalize(tag);
            if (!normalizedTag.isBlank() && !"latest".equals(normalizedTag)) {
                return normalizedTag;
            }
        }
        String fallback = normalize(tags.get(0));
        return fallback.isBlank() ? null : fallback;
    }

    private String normalizeDigestToken(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (!normalized.startsWith("sha256:")) {
            normalized = "sha256:" + normalized;
        }
        String hex = normalized.substring("sha256:".length());
        if (hex.length() != 64) {
            return "";
        }
        for (int i = 0; i < hex.length(); i++) {
            char ch = hex.charAt(i);
            boolean digit = ch >= '0' && ch <= '9';
            boolean lowerHex = ch >= 'a' && ch <= 'f';
            if (!digit && !lowerHex) {
                return "";
            }
        }
        return normalized;
    }

    private record DiscoveredGhcrImage(
            String imageRepository,
            String digest,
            String primaryTag
    ) {
        private DiscoveredGhcrImage mergeTags(List<String> tags) {
            if (primaryTag != null && !primaryTag.isBlank()) {
                return this;
            }
            if (tags == null || tags.isEmpty()) {
                return this;
            }
            for (String tag : tags) {
                if (tag != null && !tag.isBlank()) {
                    return new DiscoveredGhcrImage(imageRepository, digest, tag.trim());
                }
            }
            return this;
        }
    }
}
