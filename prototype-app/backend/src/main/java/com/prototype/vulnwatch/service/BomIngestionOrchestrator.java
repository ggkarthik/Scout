package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BomComponent;
import com.prototype.vulnwatch.domain.BomComponentCategory;
import com.prototype.vulnwatch.domain.BomComponentEvidence;
import com.prototype.vulnwatch.domain.BomComponentVulnerabilityLink;
import com.prototype.vulnwatch.domain.BomComponentWorkflow;
import com.prototype.vulnwatch.domain.BomDocumentFormat;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSourceType;
import com.prototype.vulnwatch.domain.BomSpecificationFamily;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.BomVulnerabilityRelationType;
import com.prototype.vulnwatch.domain.BomWorkflowStatus;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.BomFetchRequest;
import com.prototype.vulnwatch.dto.BomInspectionResponse;
import com.prototype.vulnwatch.dto.BomIngestionResultResponse;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.dto.SbomIngestionResponse;
import com.prototype.vulnwatch.repo.BomComponentRepository;
import com.prototype.vulnwatch.repo.BomComponentEvidenceRepository;
import com.prototype.vulnwatch.repo.BomComponentVulnerabilityLinkRepository;
import com.prototype.vulnwatch.repo.BomComponentWorkflowRepository;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.service.sbomingestion.SbomEndpointFetchResult;
import com.prototype.vulnwatch.service.sbomingestion.SbomEndpointFetchService;
import com.prototype.vulnwatch.service.sbomingestion.SbomIngestionLockService;
import com.prototype.vulnwatch.service.sbomingestion.SbomIngestionSourceMetadata;
import com.prototype.vulnwatch.service.sbomingestion.SbomContentIngestionService;
import com.prototype.vulnwatch.service.sbomingestion.SbomUploadSupportService;
import com.prototype.vulnwatch.util.IdentityUtil;
import com.prototype.vulnwatch.util.PurlUtil;
import java.io.IOException;
import java.math.BigDecimal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

@Service
public class BomIngestionOrchestrator {

    private static final int MAX_COMPONENTS = 100_000;
    public static final long MAX_BOM_BYTES = 50L * 1024 * 1024;

    private final SbomEndpointFetchService sbomEndpointFetchService;
    private final SbomContentIngestionService sbomContentIngestionService;
    private final SbomIngestionLockService sbomIngestionLockService;
    private final SbomUploadSupportService sbomUploadSupportService;
    private final SbomParserService sbomParserService;
    private final BomComponentCategorizationService categorizationService;
    private final BomIngestionRecordRepository bomRecordRepository;
    private final BomComponentRepository bomComponentRepository;
    private final BomComponentEvidenceRepository bomComponentEvidenceRepository;
    private final BomComponentVulnerabilityLinkRepository bomComponentVulnerabilityLinkRepository;
    private final BomComponentWorkflowRepository bomComponentWorkflowRepository;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final FindingRepository findingRepository;
    private final CpeDimensionService cpeDimensionService;
    private final ObjectMapper objectMapper;

    public BomIngestionOrchestrator(
            SbomEndpointFetchService sbomEndpointFetchService,
            SbomContentIngestionService sbomContentIngestionService,
            SbomIngestionLockService sbomIngestionLockService,
            SbomUploadSupportService sbomUploadSupportService,
            SbomParserService sbomParserService,
            BomComponentCategorizationService categorizationService,
            BomIngestionRecordRepository bomRecordRepository,
            BomComponentRepository bomComponentRepository,
            BomComponentEvidenceRepository bomComponentEvidenceRepository,
            BomComponentVulnerabilityLinkRepository bomComponentVulnerabilityLinkRepository,
            BomComponentWorkflowRepository bomComponentWorkflowRepository,
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            InventoryComponentRepository inventoryComponentRepository,
            FindingRepository findingRepository,
            CpeDimensionService cpeDimensionService,
            ObjectMapper objectMapper
    ) {
        this.sbomEndpointFetchService = sbomEndpointFetchService;
        this.sbomContentIngestionService = sbomContentIngestionService;
        this.sbomIngestionLockService = sbomIngestionLockService;
        this.sbomUploadSupportService = sbomUploadSupportService;
        this.sbomParserService = sbomParserService;
        this.categorizationService = categorizationService;
        this.bomRecordRepository = bomRecordRepository;
        this.bomComponentRepository = bomComponentRepository;
        this.bomComponentEvidenceRepository = bomComponentEvidenceRepository;
        this.bomComponentVulnerabilityLinkRepository = bomComponentVulnerabilityLinkRepository;
        this.bomComponentWorkflowRepository = bomComponentWorkflowRepository;
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.findingRepository = findingRepository;
        this.cpeDimensionService = cpeDimensionService;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public BomIngestionResultResponse ingestFromUrl(Tenant tenant, BomFetchRequest request) throws IOException {
        SbomEndpointIngestionRequest legacyRequest = new SbomEndpointIngestionRequest(
                request.assetType(),
                request.assetName(),
                request.assetIdentifier(),
                request.sourceUrl(),
                request.sourceLabel(),
                request.authorizationHeader()
        );
        SbomEndpointFetchResult fetchResult = sbomEndpointFetchService.fetch(legacyRequest);
        return sbomIngestionLockService.withAssetLock(tenant, request.assetIdentifier(), () ->
                ingestBytes(
                        tenant,
                        request.bomType(),
                        request.supplier(),
                        request.sourceUrl(),
                        "URL",
                        fetchResult.content(),
                        legacyRequest,
                        fetchResult.metadata(),
                        null
                )
        );
    }

    @Transactional
    public BomIngestionResultResponse ingestFromUpload(
            Tenant tenant,
            BomType bomType,
            com.prototype.vulnwatch.domain.AssetType assetType,
            String assetName,
            String assetIdentifier,
            String supplier,
            byte[] content,
            String originalFilename
    ) throws IOException {
        SbomEndpointIngestionRequest legacyRequest = new SbomEndpointIngestionRequest(
                assetType, assetName, assetIdentifier, null, originalFilename, null
        );
        SbomIngestionSourceMetadata metadata = new SbomIngestionSourceMetadata(
                "UPLOAD", "bom-upload", originalFilename, null, null, null,
                (long) content.length, null
        );
        return sbomIngestionLockService.withAssetLock(tenant, assetIdentifier, () ->
                ingestBytes(tenant, bomType, supplier, null, "UPLOAD", content, legacyRequest, metadata, null)
        );
    }

    @Transactional
    public BomIngestionResultResponse ingestFetchedContent(
            Tenant tenant,
            BomType bomType,
            com.prototype.vulnwatch.domain.AssetType assetType,
            String assetName,
            String assetIdentifier,
            String supplier,
            String sourceUrl,
            String sourceMethod,
            byte[] content,
            String originalFilename,
            SbomIngestionSourceMetadata metadata,
            Consumer<Asset> assetCustomizer
    ) throws IOException {
        SbomEndpointIngestionRequest legacyRequest = new SbomEndpointIngestionRequest(
                assetType,
                assetName,
                assetIdentifier,
                sourceUrl == null ? originalFilename : sourceUrl,
                originalFilename,
                null
        );
        return sbomIngestionLockService.withAssetLock(tenant, assetIdentifier, () ->
                ingestBytes(tenant, bomType, supplier, sourceUrl, sourceMethod, content, legacyRequest, metadata, assetCustomizer)
        );
    }

    @Transactional
    public BomIngestionResultResponse ingestGithubRepository(
            Tenant tenant,
            GithubSbomIngestionRequest request,
            byte[] content,
            SbomIngestionSourceMetadata metadata
    ) throws IOException {
        return ingestFetchedContent(
                tenant,
                BomType.SBOM,
                request.assetType() == null ? com.prototype.vulnwatch.domain.AssetType.APPLICATION : request.assetType(),
                request.assetName(),
                request.assetIdentifier(),
                null,
                metadata.sourceEndpoint(),
                "GITHUB_REPOSITORY",
                content,
                "github-generated-sbom.json",
                metadata,
                null
        );
    }

    @Transactional
    public BomIngestionResultResponse ingestGithubContainerImage(
            Tenant tenant,
            String assetName,
            String assetIdentifier,
            byte[] content,
            SbomIngestionSourceMetadata metadata,
            Consumer<Asset> assetCustomizer
    ) throws IOException {
        return ingestFetchedContent(
                tenant,
                BomType.SBOM,
                com.prototype.vulnwatch.domain.AssetType.CONTAINER_IMAGE,
                assetName,
                assetIdentifier,
                null,
                metadata.sourceEndpoint(),
                "GITHUB_GHCR",
                content,
                "github-attested-sbom.json",
                metadata,
                assetCustomizer
        );
    }

    private BomIngestionResultResponse ingestBytes(
            Tenant tenant,
            BomType bomType,
            String supplier,
            String sourceUrl,
            String sourceMethod,
            byte[] content,
            SbomEndpointIngestionRequest legacyRequest,
            SbomIngestionSourceMetadata metadata,
            Consumer<Asset> assetCustomizer
    ) throws IOException {
        if (content.length > MAX_BOM_BYTES) {
            throw new IOException("BOM payload is too large (max 50 MB)");
        }

        Asset resolvedAsset = sbomUploadSupportService.resolveAsset(
                tenant,
                legacyRequest.assetType(),
                legacyRequest.assetName(),
                legacyRequest.assetIdentifier()
        );
        if (assetCustomizer != null) {
            assetCustomizer.accept(resolvedAsset);
            sbomUploadSupportService.saveAsset(resolvedAsset);
        }

        boolean isXml = isXmlContent(content);
        SbomFormat format = sbomParserService.detectFormat(content);
        if (format == SbomFormat.UNKNOWN) {
            throw new IOException("Unsupported or unrecognized BOM format");
        }
        String serialNumber;
        String formatVersion;
        JsonNode root;
        if (isXml) {
            String[] xmlMeta = extractXmlBomAttributes(content);
            serialNumber = xmlMeta[0];
            formatVersion = xmlMeta[1];
            root = objectMapper.createObjectNode();
        } else {
            root = parseRoot(content);
            serialNumber = extractSerialNumber(root);
            formatVersion = extractFormatVersion(root, format);
        }

        String supplierKey = supplier == null ? null : supplier.trim().toLowerCase(Locale.ROOT);
        String sourceIdentity = normalizeSourceIdentity(metadata);
        Optional<BomIngestionRecord> existingOpt = resolvedAsset.getId() != null
                ? bomRecordRepository.findActiveForAsset(tenant.getId(), bomType, resolvedAsset.getId(), supplierKey)
                : bomRecordRepository.findActiveWithoutAsset(tenant.getId(), bomType, supplierKey, sourceIdentity);
        String contentChecksum = sha256(content);

        if (existingOpt.isPresent()) {
            BomIngestionRecord existing = existingOpt.get();
            if ((serialNumber != null && serialNumber.equals(existing.getSerialNumber()))
                    || (contentChecksum.equals(existing.getChecksumSha256()) && contentChecksum != null && !contentChecksum.isBlank())) {
                throw new IOException("This BOM serial number has already been ingested");
            }
        }

        // Delegate inventory + CVE correlation path (JSON and CycloneDX XML both supported)
        String defaultFilename = isXml ? "bom.xml" : "bom.json";
        String originalFilename = metadata.sourceReference() != null ? metadata.sourceReference() : defaultFilename;
        SbomIngestionResponse inventoryResult = sbomContentIngestionService.ingestBytes(
                tenant,
                legacyRequest.assetType(),
                legacyRequest.assetName(),
                legacyRequest.assetIdentifier(),
                content,
                originalFilename,
                metadata,
                assetCustomizer
        );

        UUID previousBomId = null;
        // Supersede existing BOM record if present
        if (existingOpt.isPresent()) {
            BomIngestionRecord old = existingOpt.get();
            bomComponentRepository.softDeleteByBomId(old.getId());
            old.setStatus(BomStatus.SUPERSEDED);
            bomRecordRepository.save(old);
            previousBomId = old.getId();
        }

        // Persist new BomIngestionRecord
        BomIngestionRecord record = new BomIngestionRecord();
        record.setTenant(tenant);
        record.setSbomUploadId(inventoryResult.sbomUploadId());
        record.setAssetId(inventoryResult.assetId());
        record.setBomType(bomType);
        record.setFormat(format);
        record.setFormatVersion(formatVersion);
        record.setSerialNumber(serialNumber);
        record.setSupplier(supplier == null || supplier.isBlank() ? null : supplier.trim().toLowerCase(Locale.ROOT));
        record.setSourceMethod(sourceMethod);
        record.setSourceType(resolveSourceType(metadata));
        record.setSourceSystem(metadata.sourceSystem());
        record.setSourceReference(metadata.sourceReference());
        record.setSourceEndpoint(metadata.sourceEndpoint());
        record.setSourceLabel(legacyRequest.sourceLabel());
        record.setSourceUrl(sourceUrl);
        record.setSpecFamily(resolveSpecFamily(format, bomType));
        record.setDocumentFormat(resolveDocumentFormat(format, content));
        record.setDocumentName(metadata.sourceReference() != null ? metadata.sourceReference() : originalFilenameFor(sourceMethod));
        record.setContentType(metadata.contentType());
        record.setContentLengthBytes(metadata.contentLengthBytes());
        record.setChecksumSha256(contentChecksum);
        record.setPreviousBomId(previousBomId);
        record.setStatus(BomStatus.ACTIVE);
        record.setIngestedAt(Instant.now());
        record = bomRecordRepository.save(record);

        // Supersede link after save
        if (existingOpt.isPresent()) {
            BomIngestionRecord old = existingOpt.get();
            old.setSupersededBy(record.getId());
            bomRecordRepository.save(old);
        }

        // Persist BomComponents with category
        List<BomComponent> components = isXml
                ? extractAndCategorizeXmlComponents(content, record, tenant, bomType, supplier)
                : extractAndCategorizeComponents(root, record, tenant, bomType, supplier);
        if (components.isEmpty()) {
            record.setStatus(BomStatus.FAILED);
            bomRecordRepository.save(record);
            throw new IOException("No BOM components could be extracted from the submitted document");
        }
        persistEvidenceAndCorrelations(record, tenant, components);
        record.setComponentCount(components.size());
        bomRecordRepository.save(record);

        String action = existingOpt.isPresent() ? "REPLACED" : "CREATED";
        BomInspectionResponse inspection = sbomParserService.inspectResolved(
                format.name(),
                formatVersion,
                record.getSpecFamily() != null ? record.getSpecFamily().name() : null,
                record.getDocumentFormat() != null ? record.getDocumentFormat().name() : null
        );
        return new BomIngestionResultResponse(
                record.getId(),
                inventoryResult.assetId(),
                bomType.name(),
                format.name(),
                formatVersion,
                record.getSpecFamily() != null ? record.getSpecFamily().name() : null,
                record.getDocumentFormat() != null ? record.getDocumentFormat().name() : null,
                inspection.supportLevel(),
                inspection.supported(),
                inspection.warnings(),
                components.size(),
                inventoryResult.findingsGenerated(),
                record.getStatus().name(),
                action
        );
    }

    private String normalizeSourceIdentity(SbomIngestionSourceMetadata metadata) {
        if (metadata == null || metadata.sourceReference() == null) {
            return null;
        }
        String normalized = metadata.sourceReference().trim();
        return normalized.isBlank() ? null : normalized;
    }

    private BomSourceType resolveSourceType(SbomIngestionSourceMetadata metadata) {
        if (metadata == null || metadata.sourceType() == null) {
            return BomSourceType.URL;
        }
        return switch (metadata.sourceType().toUpperCase(Locale.ROOT)) {
            case "UPLOAD" -> BomSourceType.UPLOAD;
            case "FILE" -> BomSourceType.FILE;
            case "GITHUB_REPOSITORY" -> BomSourceType.GITHUB_REPOSITORY;
            case "GITHUB_GHCR" -> BomSourceType.GITHUB_GHCR;
            case "API" -> BomSourceType.API;
            case "VENDOR_PORTAL" -> BomSourceType.VENDOR_PORTAL;
            default -> BomSourceType.URL;
        };
    }

    private BomSpecificationFamily resolveSpecFamily(SbomFormat format, BomType bomType) {
        if (format == SbomFormat.CYCLONEDX) {
            return BomSpecificationFamily.CYCLONEDX;
        }
        if (format == SbomFormat.SPDX) {
            return BomSpecificationFamily.SPDX;
        }
        if (bomType == BomType.VENDOR) {
            return BomSpecificationFamily.VENDOR;
        }
        return BomSpecificationFamily.UNKNOWN;
    }

    private BomDocumentFormat resolveDocumentFormat(SbomFormat format, byte[] content) {
        if (isXmlContent(content)) {
            return BomDocumentFormat.XML;
        }
        if (format == SbomFormat.CYCLONEDX || format == SbomFormat.SPDX) {
            return BomDocumentFormat.JSON;
        }
        return BomDocumentFormat.UNKNOWN;
    }

    private String originalFilenameFor(String sourceMethod) {
        return "UPLOAD".equalsIgnoreCase(sourceMethod) ? "bom-upload" : "bom-endpoint";
    }

    private String sha256(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private List<BomComponent> extractAndCategorizeComponents(
            JsonNode root, BomIngestionRecord record, Tenant tenant, BomType bomType, String supplierOverride
    ) {
        List<BomComponent> result = new ArrayList<>();
        JsonNode componentsNode = root.path("components");
        if (!componentsNode.isArray()) {
            componentsNode = root.path("packages"); // SPDX
        }
        if (!componentsNode.isArray()) {
            return result;
        }
        for (JsonNode node : componentsNode) {
            if (result.size() >= MAX_COMPONENTS) break;

            String name = node.path("name").asText(null);
            if (name == null || name.isBlank()) continue;

            String rawType = categorizationService.extractComponentType(node);
            String license = categorizationService.extractLicense(node);
            String compSupplier = categorizationService.extractSupplier(node);
            if (compSupplier == null) compSupplier = supplierOverride;

            BomComponentCategory category = categorizationService.categorize(rawType, bomType, compSupplier);

            BomComponent comp = new BomComponent();
            comp.setBomId(record.getId());
            comp.setTenant(tenant);
            comp.setName(name.trim());
            comp.setVersion(blankToNull(node.path("version").asText(null)));
            comp.setPurl(blankToNull(node.path("purl").asText(null)));
            comp.setCpe(resolvePrimaryCpe(node));
            comp.setLicense(license);
            comp.setSupplier(compSupplier);
            comp.setComponentType(rawType);
            comp.setBomRef(blankToNull(node.path("bom-ref").asText(null)));
            comp.setGroupName(resolveGroupName(node, comp.getPurl()));
            comp.setScope(blankToNull(node.path("scope").asText(null)));
            comp.setSwid(resolveSwid(node));
            comp.setHashes(writeJson(node.path("hashes")));
            comp.setProperties(writeJson(node.path("properties")));
            comp.setExternalReferences(resolveExternalReferences(node));
            comp.setCategory(category);
            comp.setActive(true);
            result.add(comp);
        }
        bomComponentRepository.saveAll(result);
        return result;
    }

    private List<BomComponent> extractAndCategorizeXmlComponents(
            byte[] content, BomIngestionRecord record, Tenant tenant, BomType bomType, String supplierOverride
    ) throws IOException {
        List<BomComponent> result = new ArrayList<>();
        try {
            Document doc = sbomParserService.buildXmlDocument(content);
            Element bom = doc.getDocumentElement();
            // Use direct-child search to find the top-level <components> element.
            // getElementsByTagNameNS would return nested <components> (e.g. inside
            // <metadata><tools>) before the real dependency list.
            Element componentsEl = sbomParserService.xmlFirstChild(bom, "components");
            if (componentsEl == null) {
                return result;
            }
            NodeList children = componentsEl.getChildNodes();
            for (int i = 0; i < children.getLength() && result.size() < MAX_COMPONENTS; i++) {
                Node node = children.item(i);
                if (node.getNodeType() != Node.ELEMENT_NODE) continue;
                Element comp = (Element) node;
                // Accept any element whose local name is "component"
                String compLocal = comp.getLocalName();
                if (compLocal == null) {
                    String n2 = comp.getNodeName();
                    int c = n2.lastIndexOf(':');
                    compLocal = c >= 0 ? n2.substring(c + 1) : n2;
                }
                if (!"component".equals(compLocal)) continue;

                String name = sbomParserService.xmlChildText(comp, "name");
                if (name == null || name.isBlank()) continue;

                String rawType = blankToNull(comp.getAttribute("type"));
                String purl = sbomParserService.xmlChildText(comp, "purl");
                String version = sbomParserService.xmlChildText(comp, "version");
                String license = null;
                Element licensesEl = sbomParserService.xmlFirstChild(comp, "licenses");
                if (licensesEl != null) {
                    Element licenseEl = sbomParserService.xmlFirstChild(licensesEl, "license");
                    if (licenseEl != null) {
                        license = sbomParserService.xmlChildText(licenseEl, "id");
                        if (license == null) license = sbomParserService.xmlChildText(licenseEl, "name");
                    }
                }
                String compSupplier = null;
                Element supplierEl = sbomParserService.xmlFirstChild(comp, "supplier");
                if (supplierEl != null) {
                    compSupplier = sbomParserService.xmlChildText(supplierEl, "name");
                }
                if (compSupplier == null) compSupplier = supplierOverride;

                BomComponentCategory category = categorizationService.categorize(rawType, bomType, compSupplier);

                BomComponent bomComp = new BomComponent();
                bomComp.setBomId(record.getId());
                bomComp.setTenant(tenant);
                bomComp.setName(name.trim());
                bomComp.setVersion(blankToNull(version));
                bomComp.setPurl(blankToNull(purl));
                bomComp.setCpe(resolvePrimaryXmlCpe(comp));
                bomComp.setLicense(license);
                bomComp.setSupplier(compSupplier);
                bomComp.setComponentType(rawType);
                bomComp.setBomRef(blankToNull(comp.getAttribute("bom-ref")));
                bomComp.setGroupName(resolveXmlGroupName(comp, bomComp.getPurl()));
                bomComp.setScope(blankToNull(comp.getAttribute("scope")));
                bomComp.setSwid(resolveXmlSwid(comp));
                bomComp.setHashes(extractXmlHashes(comp));
                bomComp.setExternalReferences(extractXmlExternalReferences(comp));
                bomComp.setCategory(category);
                bomComp.setActive(true);
                result.add(bomComp);
            }
        } catch (Exception e) {
            throw new IOException("Failed to parse XML BOM components", e);
        }
        bomComponentRepository.saveAll(result);
        return result;
    }

    private JsonNode parseRoot(byte[] content) {
        try {
            JsonNode root = objectMapper.readTree(content);
            JsonNode nested = root.path("sbom");
            return nested.isObject() ? nested : root;
        } catch (Exception e) {
            return objectMapper.createObjectNode();
        }
    }

    private String extractSerialNumber(JsonNode root) {
        String serial = root.path("serialNumber").asText(null);
        if (serial == null) serial = root.path("SPDXID").asText(null);
        return blankToNull(serial);
    }

    private String extractFormatVersion(JsonNode root, SbomFormat format) {
        if (format == SbomFormat.CYCLONEDX) {
            return blankToNull(root.path("specVersion").asText(null));
        }
        if (format == SbomFormat.SPDX) {
            String v = root.path("spdxVersion").asText(null);
            if (v != null) {
                // "SPDX-2.3" → "2.3"
                return blankToNull(v.replace("SPDX-", "").trim());
            }
        }
        return null;
    }

    private String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s.trim();
    }

    private void persistEvidenceAndCorrelations(BomIngestionRecord record, Tenant tenant, List<BomComponent> components) {
        if (record == null || tenant == null || components == null || components.isEmpty()) {
            return;
        }
        List<BomComponentEvidence> evidenceRows = new ArrayList<>();
        List<BomComponentVulnerabilityLink> vulnerabilityLinks = new ArrayList<>();
        List<BomComponentWorkflow> workflows = new ArrayList<>();
        Map<UUID, List<InventoryComponent>> inventoryMatchesByComponentId = new LinkedHashMap<>();

        Map<String, List<VulnerabilityTarget>> purlTargetsByKey = loadPurlTargets(components);
        Map<String, List<VulnerabilityTarget>> coordTargetsByKey = loadCoordTargets(components);
        Map<String, UUID> cpeDimIdsByNormalizedCpe = loadCpeDimIds(components);
        Map<UUID, List<VulnerabilityTarget>> cpeTargetsByCpeId = loadCpeTargets(cpeDimIdsByNormalizedCpe.values());

        for (BomComponent component : components) {
            if (component.getId() == null) {
                continue;
            }
            evidenceRows.addAll(buildEvidenceRows(record, tenant, component));
            List<BomComponentVulnerabilityLink> componentLinks = buildVulnerabilityLinks(
                    record,
                    tenant,
                    component,
                    purlTargetsByKey,
                    coordTargetsByKey,
                    cpeDimIdsByNormalizedCpe,
                    cpeTargetsByCpeId
            );
            vulnerabilityLinks.addAll(componentLinks);
            List<InventoryComponent> inventoryMatches = resolveInventoryMatches(record, tenant, component);
            inventoryMatchesByComponentId.put(component.getId(), inventoryMatches);
            if (componentLinks.isEmpty()) {
                workflows.add(buildDiscoveredWorkflow(tenant, component));
                component.setWorkflowStatus(BomWorkflowStatus.DISCOVERED);
            } else {
                for (BomComponentVulnerabilityLink link : componentLinks) {
                    workflows.add(buildProgressedWorkflow(tenant, component, link, inventoryMatches));
                }
                component.setWorkflowStatus(deriveComponentWorkflowStatus(workflows, component.getId()));
            }
        }

        if (!evidenceRows.isEmpty()) {
            bomComponentEvidenceRepository.saveAll(evidenceRows);
        }
        if (!vulnerabilityLinks.isEmpty()) {
            bomComponentVulnerabilityLinkRepository.saveAll(vulnerabilityLinks);
        }
        if (!workflows.isEmpty()) {
            for (BomComponentWorkflow workflow : workflows) {
                if (workflow.getVulnerabilityLinkId() == null) {
                    continue;
                }
                for (BomComponentVulnerabilityLink link : vulnerabilityLinks) {
                    if (link.getId() != null
                            && link.getBomComponentId().equals(workflow.getBomComponentId())
                            && link.getVulnerabilityKey().equals(workflow.getInvestigationKey())) {
                        workflow.setVulnerabilityLinkId(link.getId());
                        break;
                    }
                }
            }
            bomComponentWorkflowRepository.saveAll(workflows);
        }
        bomComponentRepository.saveAll(components);
    }

    private List<InventoryComponent> resolveInventoryMatches(BomIngestionRecord record, Tenant tenant, BomComponent component) {
        if (record.getAssetId() == null || component.getName() == null || component.getName().isBlank()) {
            return List.of();
        }
        return inventoryComponentRepository.findActiveByTenantAssetAndComponentNameVersion(
                tenant.getId(),
                record.getAssetId(),
                InventoryComponentStatus.ACTIVE,
                component.getName().trim(),
                blankToNull(component.getVersion())
        );
    }

    private List<BomComponentEvidence> buildEvidenceRows(BomIngestionRecord record, Tenant tenant, BomComponent component) {
        List<BomComponentEvidence> rows = new ArrayList<>();
        addEvidence(rows, record, tenant, component, "NAME", "name", component.getName());
        addEvidence(rows, record, tenant, component, "VERSION", "version", component.getVersion());
        addEvidence(rows, record, tenant, component, "PURL", "purl", component.getPurl());
        addEvidence(rows, record, tenant, component, "CPE", "cpe", component.getCpe());
        addEvidence(rows, record, tenant, component, "LICENSE", "license", component.getLicense());
        addEvidence(rows, record, tenant, component, "SUPPLIER", "supplier", component.getSupplier());
        addEvidence(rows, record, tenant, component, "GROUP", "group", component.getGroupName());
        addEvidence(rows, record, tenant, component, "SCOPE", "scope", component.getScope());
        addEvidence(rows, record, tenant, component, "BOM_REF", "bomRef", component.getBomRef());
        addEvidence(rows, record, tenant, component, "SWID", "swid", component.getSwid());
        addEvidence(rows, record, tenant, component, "HASHES", "hashes", component.getHashes());
        addEvidence(rows, record, tenant, component, "PROPERTIES", "properties", component.getProperties());
        addEvidence(rows, record, tenant, component, "EXTERNAL_REFERENCES", "externalReferences", component.getExternalReferences());
        return rows;
    }

    private void addEvidence(
            List<BomComponentEvidence> rows,
            BomIngestionRecord record,
            Tenant tenant,
            BomComponent component,
            String type,
            String key,
            String value
    ) {
        if (value == null || value.isBlank()) {
            return;
        }
        BomComponentEvidence evidence = new BomComponentEvidence();
        evidence.setTenant(tenant);
        evidence.setBomId(record.getId());
        evidence.setBomComponentId(component.getId());
        evidence.setEvidenceType(type);
        evidence.setEvidenceKey(key);
        evidence.setEvidenceValue(value);
        evidence.setSourceSystem(record.getSourceSystem());
        evidence.setSourceReference(record.getSourceReference());
        rows.add(evidence);
    }

    private List<BomComponentVulnerabilityLink> buildVulnerabilityLinks(
            BomIngestionRecord record,
            Tenant tenant,
            BomComponent component,
            Map<String, List<VulnerabilityTarget>> purlTargetsByKey,
            Map<String, List<VulnerabilityTarget>> coordTargetsByKey,
            Map<String, UUID> cpeDimIdsByNormalizedCpe,
            Map<UUID, List<VulnerabilityTarget>> cpeTargetsByCpeId
    ) {
        Map<String, BomComponentVulnerabilityLink> linksByKey = new LinkedHashMap<>();
        String normalizedPurl = normalizePurl(component.getPurl());
        if (!normalizedPurl.isBlank()) {
            appendVulnerabilityLinks(
                    linksByKey,
                    record,
                    tenant,
                    component,
                    purlTargetsByKey.getOrDefault(normalizedPurl, List.of()),
                    "purl-indexed-exact",
                    true,
                    new BigDecimal("0.95")
            );
        }

        String coordKey = deriveCoordKey(component);
        if (!coordKey.isBlank()) {
            appendVulnerabilityLinks(
                    linksByKey,
                    record,
                    tenant,
                    component,
                    coordTargetsByKey.getOrDefault(coordKey, List.of()),
                    "coord-indexed-exact",
                    false,
                    new BigDecimal("0.82")
            );
        }

        String normalizedCpe = normalizeCpe(component.getCpe());
        UUID cpeId = normalizedCpe.isBlank() ? null : cpeDimIdsByNormalizedCpe.get(normalizedCpe);
        if (cpeId != null) {
            appendVulnerabilityLinks(
                    linksByKey,
                    record,
                    tenant,
                    component,
                    cpeTargetsByCpeId.getOrDefault(cpeId, List.of()),
                    "cpe-indexed-direct",
                    true,
                    new BigDecimal("0.98")
            );
        }
        return new ArrayList<>(linksByKey.values());
    }

    private void appendVulnerabilityLinks(
            Map<String, BomComponentVulnerabilityLink> linksByKey,
            BomIngestionRecord record,
            Tenant tenant,
            BomComponent component,
            Collection<VulnerabilityTarget> targets,
            String matchSource,
            boolean directMatch,
            BigDecimal confidence
    ) {
        if (targets == null || targets.isEmpty()) {
            return;
        }
        for (VulnerabilityTarget target : targets) {
            if (target == null || target.getVulnerability() == null || target.getVulnerability().getExternalId() == null) {
                continue;
            }
            String vulnerabilityKey = target.getVulnerability().getExternalId();
            BomComponentVulnerabilityLink existing = linksByKey.get(vulnerabilityKey);
            if (existing != null && existing.isDirectMatch()) {
                continue;
            }
            BomComponentVulnerabilityLink link = new BomComponentVulnerabilityLink();
            link.setTenant(tenant);
            link.setBomId(record.getId());
            link.setBomComponentId(component.getId());
            link.setVulnerabilityKey(vulnerabilityKey);
            link.setVulnerabilitySource(target.getVulnerability().getSource().name());
            link.setRelationType(BomVulnerabilityRelationType.CVE);
            link.setMatchSource(matchSource);
            link.setDirectMatch(directMatch);
            link.setMatchConfidence(confidence);
            link.setCorrelationEvidenceJson(buildCorrelationEvidenceJson(component, target, matchSource));
            linksByKey.put(vulnerabilityKey, link);
        }
    }

    private BomComponentWorkflow buildDiscoveredWorkflow(Tenant tenant, BomComponent component) {
        BomComponentWorkflow workflow = new BomComponentWorkflow();
        workflow.setTenant(tenant);
        workflow.setBomComponentId(component.getId());
        workflow.setWorkflowStatus(BomWorkflowStatus.DISCOVERED);
        workflow.setWorkflowReason("No direct vulnerability correlation found during BOM ingest");
        workflow.setInvestigationKey(component.getId().toString());
        return workflow;
    }

    private BomComponentWorkflow buildProgressedWorkflow(
            Tenant tenant,
            BomComponent component,
            BomComponentVulnerabilityLink link,
            List<InventoryComponent> inventoryMatches
    ) {
        BomComponentWorkflow workflow = new BomComponentWorkflow();
        workflow.setTenant(tenant);
        workflow.setBomComponentId(component.getId());
        workflow.setInvestigationKey(link.getVulnerabilityKey());
        workflow.setWorkflowStatus(BomWorkflowStatus.CORRELATED);
        workflow.setWorkflowReason("Direct vulnerability correlation derived from BOM evidence");
        if (inventoryMatches != null && !inventoryMatches.isEmpty()) {
            List<Finding> findings = findingRepository.findByComponent_IdIn(
                    inventoryMatches.stream().map(InventoryComponent::getId).toList()
            );
            String vulnerabilityKey = link.getVulnerabilityKey();
            List<Finding> matchingFindings = findings.stream()
                    .filter(finding -> finding.getVulnerability() != null
                            && vulnerabilityKey.equalsIgnoreCase(finding.getVulnerability().getExternalId()))
                    .toList();
            if (!matchingFindings.isEmpty()) {
                boolean hasOpen = matchingFindings.stream().anyMatch(finding -> finding.getStatus() == FindingStatus.OPEN);
                boolean allResolved = matchingFindings.stream().allMatch(finding -> finding.getStatus() != FindingStatus.OPEN);
                if (hasOpen) {
                    workflow.setWorkflowStatus(BomWorkflowStatus.REMEDIATION_OPEN);
                    workflow.setFindingId(matchingFindings.get(0).getId());
                    workflow.setWorkflowReason("BOM evidence correlates to inventory and has open remediation findings");
                } else if (allResolved) {
                    workflow.setWorkflowStatus(BomWorkflowStatus.RESOLVED);
                    workflow.setFindingId(matchingFindings.get(0).getId());
                    workflow.setWorkflowReason("BOM evidence correlates to inventory and all linked findings are resolved");
                } else {
                    workflow.setWorkflowStatus(BomWorkflowStatus.UNDER_INVESTIGATION);
                    workflow.setWorkflowReason("BOM evidence correlates to inventory and findings are not yet open");
                }
            } else {
                workflow.setWorkflowStatus(BomWorkflowStatus.UNDER_INVESTIGATION);
                workflow.setWorkflowReason("BOM evidence correlates to inventory and is ready for analyst investigation");
            }
        }
        return workflow;
    }

    private BomWorkflowStatus deriveComponentWorkflowStatus(List<BomComponentWorkflow> workflows, UUID componentId) {
        return workflows.stream()
                .filter(workflow -> componentId.equals(workflow.getBomComponentId()))
                .map(BomComponentWorkflow::getWorkflowStatus)
                .max(java.util.Comparator.comparingInt(this::workflowRank))
                .orElse(BomWorkflowStatus.DISCOVERED);
    }

    private int workflowRank(BomWorkflowStatus status) {
        return switch (status) {
            case REMEDIATION_OPEN -> 6;
            case RESOLVED -> 5;
            case UNDER_INVESTIGATION -> 4;
            case PATCH_AVAILABLE -> 3;
            case CORRELATED -> 2;
            case DISCOVERED -> 1;
            case ACCEPTED_RISK, FALSE_POSITIVE -> 0;
        };
    }

    private Map<String, List<VulnerabilityTarget>> loadPurlTargets(List<BomComponent> components) {
        Set<String> keys = components.stream()
                .map(BomComponent::getPurl)
                .map(this::normalizePurl)
                .filter(value -> !value.isBlank())
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
        if (keys.isEmpty()) {
            return Map.of();
        }
        return groupTargetsByNormalizedKey(
                vulnerabilityTargetRepository.findByTargetTypeAndNormalizedTargetKeyIn(VulnerabilityTargetType.PURL, keys)
        );
    }

    private Map<String, List<VulnerabilityTarget>> loadCoordTargets(List<BomComponent> components) {
        Set<String> keys = components.stream()
                .map(this::deriveCoordKey)
                .filter(value -> !value.isBlank())
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
        if (keys.isEmpty()) {
            return Map.of();
        }
        Map<String, List<VulnerabilityTarget>> grouped = new LinkedHashMap<>(groupTargetsByNormalizedKey(
                vulnerabilityTargetRepository.findByTargetTypeAndNormalizedTargetKeyIn(VulnerabilityTargetType.COORD, keys)
        ));
        groupTargetsByNormalizedKey(
                vulnerabilityTargetRepository.findByTargetTypeAndNormalizedTargetKeyIn(VulnerabilityTargetType.ADVISORY_PACKAGE, keys)
        ).forEach((key, value) -> grouped.computeIfAbsent(key, ignored -> new ArrayList<>()).addAll(value));
        return grouped;
    }

    private Map<String, UUID> loadCpeDimIds(List<BomComponent> components) {
        Set<String> normalizedCpes = components.stream()
                .map(BomComponent::getCpe)
                .map(this::normalizeCpe)
                .filter(value -> !value.isBlank())
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
        if (normalizedCpes.isEmpty()) {
            return Map.of();
        }
        Map<String, UUID> idsByNormalized = new LinkedHashMap<>();
        cpeDimensionService.resolveOrCreateAllByNormalizedCpe(normalizedCpes)
                .forEach((normalized, dim) -> {
                    if (dim != null && dim.getId() != null) {
                        idsByNormalized.put(normalized, dim.getId());
                    }
                });
        return idsByNormalized;
    }

    private Map<UUID, List<VulnerabilityTarget>> loadCpeTargets(Collection<UUID> cpeIds) {
        if (cpeIds == null || cpeIds.isEmpty()) {
            return Map.of();
        }
        Map<UUID, List<VulnerabilityTarget>> grouped = new LinkedHashMap<>();
        for (VulnerabilityTarget target : vulnerabilityTargetRepository.findByTargetTypeAndCpeDim_IdIn(
                VulnerabilityTargetType.CPE,
                Set.copyOf(cpeIds)
        )) {
            if (target.getCpeDim() == null || target.getCpeDim().getId() == null) {
                continue;
            }
            grouped.computeIfAbsent(target.getCpeDim().getId(), ignored -> new ArrayList<>()).add(target);
        }
        return grouped;
    }

    private Map<String, List<VulnerabilityTarget>> groupTargetsByNormalizedKey(List<VulnerabilityTarget> targets) {
        Map<String, List<VulnerabilityTarget>> grouped = new LinkedHashMap<>();
        if (targets == null || targets.isEmpty()) {
            return grouped;
        }
        for (VulnerabilityTarget target : targets) {
            if (target == null || target.getNormalizedTargetKey() == null || target.getNormalizedTargetKey().isBlank()) {
                continue;
            }
            grouped.computeIfAbsent(target.getNormalizedTargetKey().trim(), ignored -> new ArrayList<>()).add(target);
        }
        return grouped;
    }

    private String deriveCoordKey(BomComponent component) {
        PurlUtil.ParsedPurl parsedPurl = PurlUtil.parse(component.getPurl());
        if (parsedPurl != null && parsedPurl.full() != null && parsedPurl.full().startsWith("pkg:")) {
            return IdentityUtil.coordKey(parsedPurl.ecosystem(), parsedPurl.namespace(), parsedPurl.packageName());
        }
        String packageName = blankToNull(component.getName());
        if (packageName == null) {
            return "";
        }
        String namespace = blankToNull(component.getGroupName());
        return IdentityUtil.coordKey("unknown", namespace == null ? "" : namespace, packageName);
    }

    private String normalizePurl(String purl) {
        String normalized = IdentityUtil.normalizePurl(purl);
        return normalized == null ? "" : normalized.trim();
    }

    private String normalizeCpe(String cpe) {
        String normalized = com.prototype.vulnwatch.util.CpeUtil.normalizeCpe23(cpe);
        return normalized == null ? "" : normalized;
    }

    private String buildCorrelationEvidenceJson(BomComponent component, VulnerabilityTarget target, String matchSource) {
        try {
            return objectMapper.createObjectNode()
                    .put("matchSource", matchSource)
                    .put("componentName", safe(component.getName()))
                    .put("componentVersion", safe(component.getVersion()))
                    .put("componentPurl", safe(component.getPurl()))
                    .put("componentCpe", safe(component.getCpe()))
                    .put("targetType", target.getTargetType() == null ? "" : target.getTargetType().name())
                    .put("targetKey", safe(target.getNormalizedTargetKey()))
                    .put("targetSource", safe(target.getSource()))
                    .toString();
        } catch (Exception ignored) {
            return null;
        }
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    private String resolvePrimaryCpe(JsonNode node) {
        String cpe = blankToNull(node.path("cpe").asText(null));
        if (cpe != null) {
            return cpe;
        }
        JsonNode cpes = node.path("cpes");
        if (cpes.isArray() && !cpes.isEmpty()) {
            return blankToNull(cpes.get(0).asText(null));
        }
        JsonNode externalRefs = node.path("externalReferences");
        if (externalRefs.isArray()) {
            for (JsonNode ref : externalRefs) {
                if ("cpe23Type".equalsIgnoreCase(ref.path("type").asText(""))) {
                    String url = blankToNull(ref.path("url").asText(null));
                    if (url != null) {
                        return url;
                    }
                }
            }
        }
        return null;
    }

    private String resolveGroupName(JsonNode node, String purl) {
        String groupName = blankToNull(node.path("group").asText(null));
        if (groupName != null) {
            return groupName;
        }
        JsonNode supplier = node.path("supplier");
        String supplierName = blankToNull(supplier.path("name").asText(null));
        if (supplierName != null) {
            return supplierName;
        }
        PurlUtil.ParsedPurl parsedPurl = PurlUtil.parse(purl);
        return blankToNull(parsedPurl.namespace());
    }

    private String resolveSwid(JsonNode node) {
        JsonNode externalRefs = node.path("externalReferences");
        if (externalRefs.isArray()) {
            for (JsonNode ref : externalRefs) {
                if ("swid".equalsIgnoreCase(ref.path("type").asText(""))) {
                    String url = blankToNull(ref.path("url").asText(null));
                    if (url != null) {
                        return url;
                    }
                }
            }
        }
        return blankToNull(node.path("swid").asText(null));
    }

    private String resolveExternalReferences(JsonNode node) {
        JsonNode refs = node.path("externalReferences");
        if (refs.isArray() && !refs.isEmpty()) {
            return writeJson(refs);
        }
        JsonNode externalRefs = node.path("externalRefs");
        if (externalRefs.isArray() && !externalRefs.isEmpty()) {
            return writeJson(externalRefs);
        }
        return null;
    }

    private String writeJson(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        if ((node.isArray() || node.isObject()) && node.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(node);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String resolvePrimaryXmlCpe(Element componentElement) {
        Element cpes = sbomParserService.xmlFirstChild(componentElement, "cpe");
        if (cpes != null) {
            return blankToNull(cpes.getTextContent());
        }
        Element externalReferences = sbomParserService.xmlFirstChild(componentElement, "externalReferences");
        if (externalReferences != null) {
            NodeList refs = externalReferences.getChildNodes();
            for (int i = 0; i < refs.getLength(); i++) {
                Node node = refs.item(i);
                if (node.getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                }
                Element ref = (Element) node;
                String type = blankToNull(ref.getAttribute("type"));
                if ("cpe23Type".equalsIgnoreCase(type)) {
                    return blankToNull(sbomParserService.xmlChildText(ref, "url"));
                }
            }
        }
        return null;
    }

    private String resolveXmlGroupName(Element componentElement, String purl) {
        String group = sbomParserService.xmlChildText(componentElement, "group");
        if (group != null && !group.isBlank()) {
            return group.trim();
        }
        Element supplier = sbomParserService.xmlFirstChild(componentElement, "supplier");
        if (supplier != null) {
            String supplierName = sbomParserService.xmlChildText(supplier, "name");
            if (supplierName != null && !supplierName.isBlank()) {
                return supplierName.trim();
            }
        }
        PurlUtil.ParsedPurl parsedPurl = PurlUtil.parse(purl);
        return blankToNull(parsedPurl.namespace());
    }

    private String resolveXmlSwid(Element componentElement) {
        Element swid = sbomParserService.xmlFirstChild(componentElement, "swid");
        if (swid == null) {
            return null;
        }
        String tagId = blankToNull(swid.getAttribute("tagId"));
        if (tagId != null) {
            return tagId;
        }
        return blankToNull(swid.getTextContent());
    }

    private String extractXmlHashes(Element componentElement) {
        Element hashes = sbomParserService.xmlFirstChild(componentElement, "hashes");
        return hashes == null ? null : blankToNull(hashes.getTextContent());
    }

    private String extractXmlExternalReferences(Element componentElement) {
        Element externalReferences = sbomParserService.xmlFirstChild(componentElement, "externalReferences");
        return externalReferences == null ? null : blankToNull(externalReferences.getTextContent());
    }

    /**
     * Returns [serialNumber, specVersion] from a CycloneDX XML {@code <bom>} root element.
     * Both values may be null if not present.
     */
    private String[] extractXmlBomAttributes(byte[] content) throws IOException {
        try {
            Document doc = sbomParserService.buildXmlDocument(content);
            Element bom = doc.getDocumentElement();
            String serial = blankToNull(bom.getAttribute("serialNumber"));
            String spec = blankToNull(bom.getAttribute("specVersion"));
            if (spec == null) {
                // Fall back: derive version from namespace URI (e.g. "http://cyclonedx.org/schema/bom/1.4")
                String ns = bom.getNamespaceURI();
                if (ns != null && ns.startsWith("http://cyclonedx.org/schema/bom/")) {
                    spec = blankToNull(ns.substring("http://cyclonedx.org/schema/bom/".length()));
                }
            }
            return new String[]{serial, spec};
        } catch (Exception e) {
            throw new IOException("Failed to inspect XML BOM metadata", e);
        }
    }

    private boolean isXmlContent(byte[] content) {
        if (content == null || content.length == 0) return false;
        // Skip BOM / whitespace
        int i = 0;
        while (i < content.length && (content[i] == 0x20 || content[i] == 0x09 || content[i] == 0x0A || content[i] == 0x0D)) {
            i++;
        }
        return i < content.length && content[i] == '<';
    }
}
