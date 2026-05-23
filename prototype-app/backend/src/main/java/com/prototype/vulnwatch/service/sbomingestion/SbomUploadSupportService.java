package com.prototype.vulnwatch.service.sbomingestion;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SbomUploadEvidenceResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

@Service
public class SbomUploadSupportService {

    private final AssetRepository assetRepository;
    private final SbomUploadRepository sbomUploadRepository;
    private final ObjectMapper objectMapper;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public SbomUploadSupportService(
            AssetRepository assetRepository,
            SbomUploadRepository sbomUploadRepository,
            ObjectMapper objectMapper,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.assetRepository = assetRepository;
        this.sbomUploadRepository = sbomUploadRepository;
        this.objectMapper = objectMapper;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    public List<SbomUploadEvidenceResponse> listUploads(Tenant tenant, String sourceSystem) {
        List<SbomUpload> uploads = tenantSchemaExecutionService.run(tenant, () ->
                sourceSystem == null || sourceSystem.isBlank()
                        ? sbomUploadRepository.findAllByOrderByUploadedAtDesc()
                        : sbomUploadRepository.findByIngestionSourceSystemIgnoreCaseOrderByUploadedAtDesc(sourceSystem.trim()));
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

    public Asset resolveAsset(Tenant tenant, AssetType assetType, String assetName, String assetIdentifier) {
        return tenantSchemaExecutionService.run(tenant, () -> assetRepository.findByIdentifier(assetIdentifier)
                .orElseGet(() -> {
                    Asset created = new Asset();
                    created.setTenant(tenant);
                    created.setType(assetType);
                    created.setName(assetName);
                    created.setIdentifier(assetIdentifier);
                    try {
                        return assetRepository.save(created);
                    } catch (DataIntegrityViolationException e) {
                        return assetRepository.findByIdentifier(assetIdentifier)
                                .orElseThrow(() -> e);
                    }
                }));
    }

    public Asset saveAsset(Asset asset) {
        return assetRepository.save(asset);
    }

    public void markUploadFailed(SbomUpload upload, String message) {
        Map<String, Object> failureEvidence = new LinkedHashMap<>();
        failureEvidence.put("ingestionStatus", "FAILURE");
        failureEvidence.put("failedAt", Instant.now());
        failureEvidence.put("errorMessage", message == null ? "Unknown ingestion failure" : message);
        failureEvidence.put("previousEvidence", upload.getEvidenceJson());
        upload.setStatus(SbomIngestionStatus.FAILURE);
        upload.setEvidenceJson(toJson(failureEvidence));
        sbomUploadRepository.save(upload);
    }

    public void recordGithubFetchFailureEvidence(
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
        saveAsset(asset);

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

    public void recordGithubAttestationFailureEvidence(
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
        saveAsset(asset);

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

    public void applyContainerImageMetadata(
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

    public String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    public String defaultContainerAssetName(String imageRepository) {
        if (imageRepository == null || imageRepository.isBlank()) {
            return "container-image";
        }
        int slash = imageRepository.lastIndexOf('/');
        return slash >= 0 && slash < imageRepository.length() - 1
                ? imageRepository.substring(slash + 1)
                : imageRepository;
    }

    public String normalizeContainerRepository(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }
}
