package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.GithubApiClient;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GithubRepoIngestionResult;
import com.prototype.vulnwatch.dto.GithubSbomIngestionBatchResponse;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.ParsedComponent;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.dto.SbomIngestionResponse;
import com.prototype.vulnwatch.dto.SbomUploadEvidenceResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.util.PurlUtil;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

@Service
public class SbomIngestionService {

    private final SbomParserService sbomParserService;
    private final AssetRepository assetRepository;
    private final SbomUploadRepository sbomUploadRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final IdentityGraphService identityGraphService;
    private final InventoryComponentCpeMappingService inventoryComponentCpeMappingService;
    private final SoftwareInventorySyncService softwareInventorySyncService;
    private final FindingService findingService;
    private final AssetLifecycleService assetLifecycleService;
    private final SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService;
    private final OperationalQualityProjectionService operationalQualityProjectionService;
    private final GithubApiClient githubApiClient;
    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;
    private final long maxPayloadBytes;
    private final boolean allowUserAuthHeader;
    private final String allowedHostsCsv;
    private final ConcurrentMap<String, ReentrantLock> ingestionLocks = new ConcurrentHashMap<>();
    @PersistenceContext
    private EntityManager entityManager;

    public SbomIngestionService(
            SbomParserService sbomParserService,
            AssetRepository assetRepository,
            SbomUploadRepository sbomUploadRepository,
            InventoryComponentRepository inventoryComponentRepository,
            IdentityGraphService identityGraphService,
            InventoryComponentCpeMappingService inventoryComponentCpeMappingService,
            SoftwareInventorySyncService softwareInventorySyncService,
            FindingService findingService,
            AssetLifecycleService assetLifecycleService,
            SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService,
            OperationalQualityProjectionService operationalQualityProjectionService,
            GithubApiClient githubApiClient,
            ObjectMapper objectMapper,
            RestTemplate restTemplate,
            @Value("${app.sbom-fetch.max-payload-bytes:5242880}") long maxPayloadBytes,
            @Value("${app.sbom-fetch.allow-user-auth-header:false}") boolean allowUserAuthHeader,
            @Value("${app.sbom-fetch.allowed-hosts:}") String allowedHostsCsv
    ) {
        this.sbomParserService = sbomParserService;
        this.assetRepository = assetRepository;
        this.sbomUploadRepository = sbomUploadRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.identityGraphService = identityGraphService;
        this.inventoryComponentCpeMappingService = inventoryComponentCpeMappingService;
        this.softwareInventorySyncService = softwareInventorySyncService;
        this.findingService = findingService;
        this.assetLifecycleService = assetLifecycleService;
        this.softwareIdentitySummaryProjectionService = softwareIdentitySummaryProjectionService;
        this.operationalQualityProjectionService = operationalQualityProjectionService;
        this.githubApiClient = githubApiClient;
        this.objectMapper = objectMapper;
        this.restTemplate = restTemplate;
        this.maxPayloadBytes = maxPayloadBytes;
        this.allowUserAuthHeader = allowUserAuthHeader;
        this.allowedHostsCsv = allowedHostsCsv;
    }

    @Transactional
    public SbomIngestionResponse ingestFromEndpoint(Tenant tenant, SbomEndpointIngestionRequest request) throws IOException {
        String url = request.sourceUrl().trim();
        validateRemoteSourceUrl(url);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN, MediaType.ALL));
        if (request.authorizationHeader() != null && !request.authorizationHeader().isBlank()) {
            if (!allowUserAuthHeader) {
                throw new IOException("Custom authorization headers are disabled for remote SBOM fetch");
            }
            headers.set(HttpHeaders.AUTHORIZATION, request.authorizationHeader().trim());
        }

        ResponseEntity<byte[]> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                byte[].class);
        long declaredLength = response.getHeaders().getContentLength();
        if (declaredLength > maxPayloadBytes) {
            throw new IOException("Remote endpoint payload exceeds max allowed size");
        }
        byte[] content = response.getBody();
        if (content == null || content.length == 0) {
            throw new IOException("Remote endpoint returned empty SBOM payload");
        }
        ensurePayloadWithinLimit(content.length);

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("ingestionMode", "remote-endpoint");
        evidence.put("sourceUrl", url);
        evidence.put("statusCode", response.getStatusCode().value());
        evidence.put("responseContentType", response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE));

        IngestionSourceMetadata metadata = new IngestionSourceMetadata(
                "REMOTE_ENDPOINT",
                "api",
                request.sourceLabel() == null || request.sourceLabel().isBlank() ? url : request.sourceLabel().trim(),
                url,
                response.getStatusCode().value(),
                response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE),
                response.getHeaders().getContentLength() >= 0
                        ? response.getHeaders().getContentLength()
                        : (long) content.length,
                toJson(evidence));

        return withIngestionLock(lockKey(tenant, request.assetIdentifier()), () -> ingestBytes(
                tenant,
                request.assetType(),
                request.assetName(),
                request.assetIdentifier(),
                content,
                "endpoint-sbom.json",
                metadata,
                null));
    }

    @Transactional
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
                        assetIdentifier);
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
                        "Ingested successfully"));
            } catch (IOException ex) {
                repositoriesFailed++;
                results.add(new GithubRepoIngestionResult(
                        repoOwner,
                        repoName,
                        assetIdentifier,
                        "FAILURE",
                        null,
                        null,
                        ex.getMessage()));
            }
        }

        if (repositoriesSucceeded == 0) {
            String errorMessage = results.isEmpty()
                    ? "GitHub SBOM ingestion failed for all repositories"
                    : "GitHub SBOM ingestion failed for all repositories. Last error: " + results.get(results.size() - 1).message();
            throw new IOException(errorMessage);
        }

        return new GithubSbomIngestionBatchResponse(
                repositories.size(),
                results.size(),
                repositoriesSucceeded,
                repositoriesFailed,
                componentsIngested,
                findingsGenerated,
                results);
    }

    @Transactional
    public GithubGhcrIngestionSummary ingestAllFromGithubContainerRegistry(
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
                String imageRepository = normalizeContainerRepository(version.imageRepository());
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
        List<GithubGhcrImageIngestionResult> results = new ArrayList<>();
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
            String assetName = defaultContainerAssetName(image.imageRepository());
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
                results.add(new GithubGhcrImageIngestionResult(
                        image.imageRepository(),
                        assetIdentifier,
                        "SUCCESS",
                        response.componentsIngested(),
                        response.findingsGenerated(),
                        "Ingested successfully"
                ));
            } catch (IOException ex) {
                imagesFailed++;
                recordGithubAttestationFailureEvidence(
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
                results.add(new GithubGhcrImageIngestionResult(
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

        return new GithubGhcrIngestionSummary(
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

    private String summarizeGhcrFailures(List<GithubGhcrImageIngestionResult> results) {
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

    @Transactional(readOnly = true)
    public List<SbomUploadEvidenceResponse> listUploads(Tenant tenant, String sourceSystem) {
        List<SbomUpload> uploads = sourceSystem == null || sourceSystem.isBlank()
                ? sbomUploadRepository.findByTenantOrderByUploadedAtDesc(tenant)
                : sbomUploadRepository.findByTenantAndIngestionSourceSystemIgnoreCaseOrderByUploadedAtDesc(
                        tenant,
                        sourceSystem.trim());
        return uploads.stream()
                .map(upload -> new SbomUploadEvidenceResponse(
                        upload.getId(),
                        upload.getAsset().getId(),
                        upload.getAsset().getName(),
                        upload.getAsset().getIdentifier(),
                        upload.getAsset().getType().name(),
                        upload.getStatus().name(),
                        upload.getFormat().name(),
                        upload.getUploadedAt(),
                        upload.getOriginalFilename(),
                        upload.getIngestionSourceType(),
                        upload.getIngestionSourceSystem(),
                        upload.getSourceReference(),
                        upload.getSourceEndpoint(),
                        upload.getFetchStatusCode(),
                        upload.getContentType(),
                        upload.getContentLengthBytes(),
                        upload.getContentSha256(),
                        upload.getComponentCount(),
                        upload.getFindingsGenerated(),
                        upload.getEvidenceJson()))
                .toList();
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
            recordGithubFetchFailureEvidence(tenant, assetType, assetName, assetIdentifier, owner, repo, endpoint, ex.getMessage());
            throw ex;
        }

        byte[] content = response.payload();
        ensurePayloadWithinLimit(content.length);

        String reference = owner + "/" + repo;
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("ingestionMode", "github-generated");
        evidence.put("owner", owner);
        evidence.put("repo", repo);
        evidence.put("apiUrl", response.endpoint());
        evidence.put("statusCode", response.statusCode());
        evidence.put("fetchedAt", Instant.now());

        IngestionSourceMetadata metadata = new IngestionSourceMetadata(
                "GITHUB_GENERATED",
                "github",
                reference,
                response.endpoint(),
                response.statusCode(),
                response.contentType(),
                response.contentLength(),
                toJson(evidence));

        return withIngestionLock(lockKey(tenant, assetIdentifier), () -> ingestBytes(
                tenant,
                assetType,
                assetName,
                assetIdentifier,
                content,
                "github-generated-sbom.json",
                metadata,
                null));
    }

    private void recordGithubFetchFailureEvidence(
            Tenant tenant,
            AssetType assetType,
            String assetName,
            String assetIdentifier,
            String owner,
            String repo,
            String endpoint,
            String errorMessage
    ) {
        Asset asset = resolveAsset(tenant, assetType, assetName, assetIdentifier);
        asset.setName(assetName);
        asset.setType(assetType);
        assetRepository.save(asset);

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("ingestionMode", "github-generated");
        evidence.put("owner", owner);
        evidence.put("repo", repo);
        evidence.put("apiUrl", endpoint);
        evidence.put("ingestionStatus", "FAILURE");
        evidence.put("failedAt", Instant.now());
        evidence.put("errorMessage", errorMessage == null ? "Failed to fetch generated SBOM from GitHub" : errorMessage);

        SbomUpload upload = new SbomUpload();
        upload.setTenant(tenant);
        upload.setAsset(asset);
        upload.setFormat(SbomFormat.UNKNOWN);
        upload.setStatus(SbomIngestionStatus.FAILURE);
        upload.setOriginalFilename("github-generated-sbom.json");
        upload.setIngestionSourceType("GITHUB_GENERATED");
        upload.setIngestionSourceSystem("github");
        upload.setSourceReference(owner + "/" + repo);
        upload.setSourceEndpoint(endpoint);
        upload.setContentLengthBytes(0L);
        upload.setComponentCount(0);
        upload.setFindingsGenerated(0);
        upload.setEvidenceJson(toJson(evidence));
        sbomUploadRepository.save(upload);
    }

    private boolean shouldIncludeAllRepos(GithubSbomIngestionRequest request) {
        if (request.includeAllRepos() != null) {
            return request.includeAllRepos();
        }
        return request.repo() == null || request.repo().isBlank();
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
        ensurePayloadWithinLimit(content.length);

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

        IngestionSourceMetadata metadata = new IngestionSourceMetadata(
                "GITHUB_ATTESTATION",
                "github",
                imageRepository,
                response.endpoint(),
                response.statusCode(),
                response.contentType(),
                response.contentLength(),
                toJson(evidence));

        return withIngestionLock(lockKey(tenant, assetIdentifier), () -> ingestBytes(
                tenant,
                AssetType.CONTAINER_IMAGE,
                assetName,
                assetIdentifier,
                content,
                "github-attested-sbom.json",
                metadata,
                asset -> applyContainerImageMetadata(asset, imageRepository, imageTag, normalizedDigest)
        ));
    }

    private void recordGithubAttestationFailureEvidence(
            Tenant tenant,
            String owner,
            String repo,
            String imageRepository,
            String imageTag,
            String normalizedDigest,
            String assetName,
            String assetIdentifier,
            String errorMessage
    ) {
        Asset asset = resolveAsset(tenant, AssetType.CONTAINER_IMAGE, assetName, assetIdentifier);
        asset.setName(assetName);
        asset.setType(AssetType.CONTAINER_IMAGE);
        applyContainerImageMetadata(asset, imageRepository, imageTag, normalizedDigest);
        assetRepository.save(asset);

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("ingestionMode", "github-attestation");
        evidence.put("owner", owner);
        if (repo != null && !repo.isBlank()) {
            evidence.put("repo", repo);
        }
        evidence.put("imageRepository", imageRepository);
        evidence.put("imageTag", imageTag);
        evidence.put("subjectDigest", normalizedDigest);
        evidence.put("ingestionStatus", "FAILURE");
        evidence.put("failedAt", Instant.now());
        evidence.put("errorMessage", errorMessage == null ? "Failed to fetch attested SBOM from GitHub" : errorMessage);

        SbomUpload upload = new SbomUpload();
        upload.setTenant(tenant);
        upload.setAsset(asset);
        upload.setFormat(SbomFormat.UNKNOWN);
        upload.setStatus(SbomIngestionStatus.FAILURE);
        upload.setOriginalFilename("github-attested-sbom.json");
        upload.setIngestionSourceType("GITHUB_ATTESTATION");
        upload.setIngestionSourceSystem("github");
        upload.setSourceReference(imageRepository);
        upload.setContentLengthBytes(0L);
        upload.setComponentCount(0);
        upload.setFindingsGenerated(0);
        upload.setEvidenceJson(toJson(evidence));
        sbomUploadRepository.save(upload);
    }

    private SbomIngestionResponse ingestBytes(
            Tenant tenant,
            AssetType assetType,
            String assetName,
            String assetIdentifier,
            byte[] content,
            String originalFilename,
            IngestionSourceMetadata metadata,
            java.util.function.Consumer<Asset> assetCustomizer
    ) throws IOException {
        ensurePayloadWithinLimit(content.length);
        Asset asset = resolveAsset(tenant, assetType, assetName, assetIdentifier);

        asset.setName(assetName);
        asset.setType(assetType);
        if (assetCustomizer != null) {
            assetCustomizer.accept(asset);
        }
        assetRepository.save(asset);
        assetLifecycleService.markInventoryIngested(asset);

        SbomUpload upload = new SbomUpload();
        upload.setTenant(tenant);
        upload.setAsset(asset);
        upload.setFormat(SbomFormat.UNKNOWN);
        upload.setStatus(SbomIngestionStatus.IN_PROGRESS);
        upload.setOriginalFilename(originalFilename);
        upload.setIngestionSourceType(metadata.sourceType());
        upload.setIngestionSourceSystem(metadata.sourceSystem());
        upload.setSourceReference(metadata.sourceReference());
        upload.setSourceEndpoint(metadata.sourceEndpoint());
        upload.setFetchStatusCode(metadata.fetchStatusCode());
        upload.setContentType(metadata.contentType());
        upload.setContentLengthBytes(metadata.contentLengthBytes() == null ? (long) content.length : metadata.contentLengthBytes());
        upload.setContentSha256(sha256(content));
        upload.setComponentCount(0);
        upload.setFindingsGenerated(0);
        upload.setEvidenceJson(metadata.evidenceJson());
        upload = sbomUploadRepository.save(upload);

        try {
            SbomFormat format = sbomParserService.detectFormat(content);
            List<ParsedComponent> components = sbomParserService.parse(content);

            Map<String, ParsedComponent> parsedByKey = new LinkedHashMap<>();
            for (ParsedComponent parsed : components) {
                parsedByKey.put(componentKey(parsed.ecosystem(), parsed.packageName(), parsed.version(), parsed.purl()), parsed);
            }

            Map<IdentityGraphService.ComponentIdentityInput, String> componentKeyByIdentityInput = new LinkedHashMap<>();
            for (ParsedComponent parsed : parsedByKey.values()) {
                componentKeyByIdentityInput.put(
                        new IdentityGraphService.ComponentIdentityInput(
                                parsed.ecosystem(),
                                parsed.packageName(),
                                parsed.purl(),
                                "sbom"
                        ),
                        componentKey(parsed.ecosystem(), parsed.packageName(), parsed.version(), parsed.purl())
                );
            }
            Map<String, SoftwareIdentity> softwareIdentityByComponentKey = new HashMap<>();
            Map<IdentityGraphService.ComponentIdentityInput, SoftwareIdentity> resolvedIdentities =
                    identityGraphService.resolveFromComponents(componentKeyByIdentityInput.keySet());
            for (Map.Entry<IdentityGraphService.ComponentIdentityInput, String> entry : componentKeyByIdentityInput.entrySet()) {
                SoftwareIdentity softwareIdentity = resolvedIdentities.get(entry.getKey());
                if (softwareIdentity != null) {
                    softwareIdentityByComponentKey.put(entry.getValue(), softwareIdentity);
                }
            }

            List<InventoryComponent> existingComponents = inventoryComponentRepository.findByAsset(asset);
            Map<String, InventoryComponent> existingByKey = new HashMap<>();
            for (InventoryComponent existing : existingComponents) {
                existingByKey.put(componentKey(existing.getEcosystem(), existing.getPackageName(), existing.getVersion(), existing.getPurl()), existing);
            }

            Instant now = Instant.now();
            List<InventoryComponent> toPersist = new ArrayList<>();
            for (ParsedComponent parsed : parsedByKey.values()) {
                String key = componentKey(parsed.ecosystem(), parsed.packageName(), parsed.version(), parsed.purl());
                InventoryComponent component = existingByKey.remove(key);
                if (component == null) {
                    component = new InventoryComponent();
                    component.setTenant(tenant);
                    component.setAsset(asset);
                    component.setIngestedAt(now);
                }
                component.setSbomUpload(upload);
                component.setEcosystem(parsed.ecosystem().toLowerCase(Locale.ROOT));
                component.setPackageName(parsed.packageName().toLowerCase(Locale.ROOT));
                component.setVersion(parsed.version());
                component.setPurl(parsed.purl());
                component.setComponentDigest(parsed.digest());
                component.setComponentStatus(InventoryComponentStatus.ACTIVE);
                component.setRetiredAt(null);
                component.setLastObservedAt(now);

                SoftwareIdentity softwareIdentity = softwareIdentityByComponentKey.get(key);
                component.setSoftwareIdentity(softwareIdentity);
                component.setNormalizedName(resolveNormalizedName(parsed));
                component.setNormalizedVersion(resolveNormalizedVersion(parsed.version()));
                toPersist.add(component);
            }

            for (InventoryComponent component : existingByKey.values()) {
                if (component.getComponentStatus() != InventoryComponentStatus.RETIRED) {
                    component.setComponentStatus(InventoryComponentStatus.RETIRED);
                    component.setRetiredAt(now);
                    toPersist.add(component);
                }
            }
            if (!toPersist.isEmpty()) {
                inventoryComponentRepository.saveAll(toPersist);
            }

            if (!toPersist.isEmpty()) {
                Map<java.util.UUID, List<String>> componentCpesById = new LinkedHashMap<>();
                for (InventoryComponent component : toPersist) {
                    if (component.getId() == null || component.getComponentStatus() != InventoryComponentStatus.ACTIVE) {
                        componentCpesById.put(component.getId(), List.of());
                        continue;
                    }
                    ParsedComponent parsed = parsedByKey.get(componentKey(
                            component.getEcosystem(),
                            component.getPackageName(),
                            component.getVersion(),
                            component.getPurl()
                    ));
                    componentCpesById.put(component.getId(), parsed == null ? List.of() : parsed.cpes());
                }
                inventoryComponentCpeMappingService.syncComponentMappings(toPersist, componentCpesById);
            }
            softwareInventorySyncService.syncFromInventoryDelta(tenant, toPersist, now);
            entityManager.flush();
            entityManager.clear();

            Set<java.util.UUID> recomputedComponentIds = new LinkedHashSet<>();
            for (InventoryComponent component : toPersist) {
                if (component.getId() == null || !recomputedComponentIds.add(component.getId())) {
                    continue;
                }
            }
            int findingsGenerated = findingService.recomputeOnSoftwareDeltaBatch(tenant.getId(), recomputedComponentIds);
            softwareIdentitySummaryProjectionService.refreshTenant(tenant);
            operationalQualityProjectionService.refreshTenant(tenant);
            upload.setFormat(format);
            upload.setComponentCount(components.size());
            upload.setFindingsGenerated(findingsGenerated);
            upload.setStatus(SbomIngestionStatus.SUCCESS);
            sbomUploadRepository.save(upload);

            return new SbomIngestionResponse(asset.getId(), upload.getId(), components.size(), findingsGenerated);
        } catch (IOException ex) {
            markUploadFailed(upload, ex.getMessage());
            throw ex;
        } catch (RuntimeException ex) {
            markUploadFailed(upload, ex.getMessage());
            throw ex;
        }
    }

    private String componentKey(String ecosystem, String packageName, String version, String purl) {
        String normalizedPurl = normalize(purl);
        if (!normalizedPurl.isBlank()) {
            return "purl:" + normalizedPurl;
        }
        return "coord:"
                + normalize(ecosystem)
                + ":"
                + normalize(packageName)
                + "@"
                + normalize(version);
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String resolveNormalizedName(ParsedComponent parsed) {
        PurlUtil.ParsedPurl parsedPurl = PurlUtil.parse(parsed.purl());
        String namespace = normalize(parsedPurl.namespace());
        String packageName = normalize(parsedPurl.packageName());
        if (!packageName.isBlank() && !"unknown".equals(packageName)) {
            return namespace.isBlank() ? packageName : namespace + "/" + packageName;
        }

        String fallbackPackage = normalize(parsed.packageName());
        if (!fallbackPackage.isBlank()) {
            return fallbackPackage;
        }
        return "unknown";
    }

    private String resolveNormalizedVersion(String version) {
        String normalized = normalize(version);
        if (normalized.isBlank()) {
            return "unknown";
        }
        if (normalized.startsWith("v") && normalized.length() > 1 && Character.isDigit(normalized.charAt(1))) {
            return normalized.substring(1);
        }
        return normalized;
    }

    private String sha256(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private void markUploadFailed(SbomUpload upload, String message) {
        Map<String, Object> failureEvidence = new LinkedHashMap<>();
        failureEvidence.put("ingestionStatus", "FAILURE");
        failureEvidence.put("failedAt", Instant.now());
        failureEvidence.put("errorMessage", message == null ? "Unknown ingestion failure" : message);
        failureEvidence.put("previousEvidence", upload.getEvidenceJson());
        upload.setStatus(SbomIngestionStatus.FAILURE);
        upload.setEvidenceJson(toJson(failureEvidence));
        sbomUploadRepository.save(upload);
    }

    private void validateRemoteSourceUrl(String value) throws IOException {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (Exception e) {
            throw new IOException("Invalid source URL");
        }

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IOException("Only HTTPS source URLs are allowed");
        }
        if (uri.getUserInfo() != null && !uri.getUserInfo().isBlank()) {
            throw new IOException("URL user info is not allowed");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IOException("Source URL host is required");
        }

        String normalizedHost = host.trim().toLowerCase(Locale.ROOT);
        if (allowedHosts().contains(normalizedHost)) {
            return;
        }

        InetAddress[] addresses = InetAddress.getAllByName(normalizedHost);
        if (addresses.length == 0) {
            throw new IOException("Unable to resolve source URL host");
        }
        for (InetAddress address : addresses) {
            if (isBlockedAddress(address)) {
                throw new IOException("Source URL resolves to a blocked internal address");
            }
        }
    }

    private Set<String> allowedHosts() {
        if (allowedHostsCsv == null || allowedHostsCsv.isBlank()) {
            return Set.of();
        }
        Set<String> values = new HashSet<>();
        for (String host : allowedHostsCsv.split(",")) {
            if (host != null && !host.isBlank()) {
                values.add(host.trim().toLowerCase(Locale.ROOT));
            }
        }
        return values;
    }

    private boolean isBlockedAddress(InetAddress address) {
        return address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress();
    }

    private void ensurePayloadWithinLimit(long bytes) throws IOException {
        if (bytes > maxPayloadBytes) {
            throw new IOException("SBOM payload exceeds max allowed size");
        }
    }

    private String lockKey(Tenant tenant, String assetIdentifier) {
        return tenant.getId() + ":" + normalize(assetIdentifier);
    }

    private SbomIngestionResponse withIngestionLock(
            String key,
            ThrowingIoSupplier<SbomIngestionResponse> supplier
    ) throws IOException {
        ReentrantLock lock = ingestionLocks.computeIfAbsent(key, ignored -> new ReentrantLock());
        if (!lock.tryLock()) {
            throw new IOException("An SBOM ingestion is already in progress for this asset. Please retry shortly.");
        }
        try {
            return supplier.get();
        } finally {
            lock.unlock();
            ingestionLocks.remove(key, lock);
        }
    }

    private void applyContainerImageMetadata(
            Asset asset,
            String imageRepository,
            String imageTag,
            String imageDigest
    ) {
        if (asset == null) {
            return;
        }
        asset.setImageRepository(imageRepository);
        asset.setImageTag(imageTag);
        asset.setImageDigest(imageDigest);
    }

    private String normalizeContainerRepository(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
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

    private String defaultContainerAssetName(String imageRepository) {
        if (imageRepository == null || imageRepository.isBlank()) {
            return "container-image";
        }
        int slash = imageRepository.lastIndexOf('/');
        return slash >= 0 && slash < imageRepository.length() - 1
                ? imageRepository.substring(slash + 1)
                : imageRepository;
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

    private Asset resolveAsset(Tenant tenant, AssetType assetType, String assetName, String assetIdentifier) {
        return assetRepository.findByTenantAndIdentifier(tenant, assetIdentifier)
                .orElseGet(() -> {
                    Asset created = new Asset();
                    created.setTenant(tenant);
                    created.setType(assetType);
                    created.setName(assetName);
                    created.setIdentifier(assetIdentifier);
                    try {
                        return assetRepository.save(created);
                    } catch (DataIntegrityViolationException e) {
                        return assetRepository.findByTenantAndIdentifier(tenant, assetIdentifier)
                                .orElseThrow(() -> e);
                    }
                });
    }

    private record IngestionSourceMetadata(
            String sourceType,
            String sourceSystem,
            String sourceReference,
            String sourceEndpoint,
            Integer fetchStatusCode,
            String contentType,
            Long contentLengthBytes,
            String evidenceJson
    ) {
    }

    public record GithubGhcrIngestionSummary(
            int imagesDiscovered,
            int imagesProcessed,
            int imagesSucceeded,
            int imagesFailed,
            int componentsIngested,
            int findingsGenerated,
            String failureSummary,
            List<GithubGhcrImageIngestionResult> results
    ) {
    }

    public record GithubGhcrImageIngestionResult(
            String imageRepository,
            String assetIdentifier,
            String status,
            Integer componentsIngested,
            Integer findingsGenerated,
            String message
    ) {
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

    @FunctionalInterface
    private interface ThrowingIoSupplier<T> {
        T get() throws IOException;
    }
}
