package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.CiAlias;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiAliasRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class CiResolutionService {

    private final CiRepository ciRepository;
    private final CiAliasRepository ciAliasRepository;
    private final AssetRepository assetRepository;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final ServiceNowCmdbConfigService serviceNowCmdbConfigService;

    @Value("${app.cmdb.servicenow.base-url:}")
    private String serviceNowBaseUrl;

    @Value("${app.cmdb.servicenow.username:}")
    private String serviceNowUsername;

    @Value("${app.cmdb.servicenow.password:}")
    private String serviceNowPassword;

    public CiResolutionService(
            CiRepository ciRepository,
            CiAliasRepository ciAliasRepository,
            AssetRepository assetRepository,
            RestTemplate restTemplate,
            ObjectMapper objectMapper,
            ServiceNowCmdbConfigService serviceNowCmdbConfigService
    ) {
        this.ciRepository = ciRepository;
        this.ciAliasRepository = ciAliasRepository;
        this.assetRepository = assetRepository;
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
        this.serviceNowCmdbConfigService = serviceNowCmdbConfigService;
    }

    @Transactional
    public Resolution resolve(
            Tenant tenant,
            String requestedSysId,
            String hostName,
            String environment,
            String ownerEmail,
            BusinessCriticality businessCriticality,
            String sourceSystem
    ) {
        String normalizedSource = normalizeSource(sourceSystem);
        String normalizedHost = normalizeAlias(hostName);
        BusinessCriticality resolvedCriticality = businessCriticality == null ? BusinessCriticality.MEDIUM : businessCriticality;

        if (hasText(requestedSysId)) {
            return upsertCi(
                    tenant,
                    requestedSysId.trim(),
                    hostName,
                    environment,
                    ownerEmail,
                    resolvedCriticality,
                    normalizedSource,
                    false,
                    "sys_id"
            );
        }

        Resolution aliasResolution = resolveByAlias(tenant, hostName, environment, normalizedSource);
        if (aliasResolution != null) {
            updateAlias(aliasResolution.ci(), hostName, normalizedHost, normalizedSource, aliasResolution.lowConfidence() ? 0.75 : 0.9);
            return aliasResolution;
        }

        ServiceNowCiLookup lookup = lookupInServiceNow(tenant, hostName);
        if (lookup != null && hasText(lookup.sysId())) {
            return upsertCi(
                    tenant,
                    lookup.sysId(),
                    lookup.displayName() == null ? hostName : lookup.displayName(),
                    environment,
                    ownerEmail,
                    resolvedCriticality,
                    normalizedSource,
                    false,
                    "servicenow-api"
            );
        }

        String fallbackSysId = normalizedSource + ":" + (normalizedHost.isBlank() ? UUID.randomUUID() : normalizedHost);
        return upsertCi(
                tenant,
                fallbackSysId,
                hostName,
                environment,
                ownerEmail,
                resolvedCriticality,
                normalizedSource,
                true,
                "fallback-alias"
        );
    }

    @Transactional
    public BatchResolutionContext prepareBatchContext(
            Tenant tenant,
            String sourceSystem,
            Collection<HostLookupInput> inputs
    ) {
        if (tenant == null || tenant.getId() == null) {
            return new BatchResolutionContext(tenant, normalizeSource(sourceSystem), new LinkedHashMap<>(), new LinkedHashMap<>(), new LinkedHashMap<>(), new LinkedHashMap<>());
        }

        Set<String> sysIds = new LinkedHashSet<>();
        Set<String> aliasNames = new LinkedHashSet<>();
        Set<String> assetIdentifiers = new LinkedHashSet<>();
        for (HostLookupInput input : inputs == null ? List.<HostLookupInput>of() : inputs) {
            if (input == null) {
                continue;
            }
            String normalizedSysId = trimToNull(input.requestedSysId());
            if (hasText(normalizedSysId)) {
                sysIds.add(normalizedSysId);
                assetIdentifiers.add(assetIdentifier(normalizedSysId));
            }
            String normalizedHost = normalizeAlias(input.hostName());
            if (!normalizedHost.isBlank()) {
                aliasNames.add(normalizedHost);
                String shortHost = shortHost(normalizedHost);
                if (!shortHost.equals(normalizedHost)) {
                    aliasNames.add(shortHost);
                }
            }
        }

        Map<String, Ci> ciBySysId = new LinkedHashMap<>();
        if (!sysIds.isEmpty()) {
            for (Ci ci : ciRepository.findByTenant_IdAndSysIdIn(tenant.getId(), sysIds)) {
                if (ci != null && hasText(ci.getSysId())) {
                    ciBySysId.put(ci.getSysId(), ci);
                }
            }
        }

        Map<String, Asset> assetsByIdentifier = new LinkedHashMap<>();
        if (!assetIdentifiers.isEmpty()) {
            for (Asset asset : assetRepository.findByTenant_IdAndIdentifierIn(tenant.getId(), assetIdentifiers)) {
                if (asset != null && hasText(asset.getIdentifier())) {
                    assetsByIdentifier.put(asset.getIdentifier(), asset);
                }
            }
        }
        for (Ci ci : ciBySysId.values()) {
            if (ci.getAsset() != null && hasText(ci.getAsset().getIdentifier())) {
                assetsByIdentifier.putIfAbsent(ci.getAsset().getIdentifier(), ci.getAsset());
            }
        }

        Map<String, CiAlias> aliasBySourceAndName = new LinkedHashMap<>();
        Map<String, List<CiAlias>> aliasesByNormalizedName = new LinkedHashMap<>();
        if (!aliasNames.isEmpty()) {
            for (CiAlias alias : ciAliasRepository.findByTenant_IdAndNormalizedAliasNameIn(tenant.getId(), aliasNames)) {
                if (alias == null || !hasText(alias.getNormalizedAliasName())) {
                    continue;
                }
                if (alias.getCi() != null && hasText(alias.getCi().getSysId())) {
                    ciBySysId.putIfAbsent(alias.getCi().getSysId(), alias.getCi());
                    if (alias.getCi().getAsset() != null && hasText(alias.getCi().getAsset().getIdentifier())) {
                        assetsByIdentifier.putIfAbsent(alias.getCi().getAsset().getIdentifier(), alias.getCi().getAsset());
                    }
                }
                aliasesByNormalizedName.computeIfAbsent(alias.getNormalizedAliasName(), ignored -> new ArrayList<>()).add(alias);
                aliasBySourceAndName.put(aliasSourceKey(alias.getSourceSystem(), alias.getNormalizedAliasName()), alias);
            }
        }

        return new BatchResolutionContext(
                tenant,
                normalizeSource(sourceSystem),
                ciBySysId,
                assetsByIdentifier,
                aliasBySourceAndName,
                aliasesByNormalizedName
        );
    }

    @Transactional
    public Resolution resolve(
            BatchResolutionContext context,
            Tenant tenant,
            String requestedSysId,
            String hostName,
            String environment,
            String ownerEmail,
            BusinessCriticality businessCriticality,
            String sourceSystem
    ) {
        if (context == null) {
            return resolve(tenant, requestedSysId, hostName, environment, ownerEmail, businessCriticality, sourceSystem);
        }

        String normalizedSource = normalizeSource(sourceSystem);
        String normalizedHost = normalizeAlias(hostName);
        BusinessCriticality resolvedCriticality = businessCriticality == null ? BusinessCriticality.MEDIUM : businessCriticality;

        if (hasText(requestedSysId)) {
            return upsertCi(
                    context,
                    tenant,
                    requestedSysId.trim(),
                    hostName,
                    environment,
                    ownerEmail,
                    resolvedCriticality,
                    normalizedSource,
                    false,
                    "sys_id"
            );
        }

        Resolution aliasResolution = resolveByAlias(context, hostName, environment, normalizedSource);
        if (aliasResolution != null) {
            updateAlias(context, aliasResolution.ci(), hostName, normalizedHost, normalizedSource, aliasResolution.lowConfidence() ? 0.75 : 0.9);
            return aliasResolution;
        }

        ServiceNowCiLookup lookup = lookupInServiceNow(tenant, hostName);
        if (lookup != null && hasText(lookup.sysId())) {
            return upsertCi(
                    context,
                    tenant,
                    lookup.sysId(),
                    lookup.displayName() == null ? hostName : lookup.displayName(),
                    environment,
                    ownerEmail,
                    resolvedCriticality,
                    normalizedSource,
                    false,
                    "servicenow-api"
            );
        }

        String fallbackSysId = normalizedSource + ":" + (normalizedHost.isBlank() ? UUID.randomUUID() : normalizedHost);
        return upsertCi(
                context,
                tenant,
                fallbackSysId,
                hostName,
                environment,
                ownerEmail,
                resolvedCriticality,
                normalizedSource,
                true,
                "fallback-alias"
        );
    }

    private Resolution resolveByAlias(Tenant tenant, String hostName, String environment, String sourceSystem) {
        String normalized = normalizeAlias(hostName);
        if (!hasText(normalized) || tenant == null || tenant.getId() == null) {
            return null;
        }
        return ciAliasRepository.findByTenant_IdAndNormalizedAliasNameAndSourceSystem(
                        tenant.getId(),
                        normalized,
                        sourceSystem
                )
                .map(alias -> new Resolution(alias.getCi(), false, false, isLowConfidence(alias.getConfidence()), "alias-cache"))
                .orElseGet(() -> {
                    List<CiAlias> aliases = ciAliasRepository.findByTenant_IdAndNormalizedAliasName(tenant.getId(), normalized);
                    if (aliases.isEmpty()) {
                        String shortHost = shortHost(normalized);
                        if (!shortHost.equals(normalized)) {
                            aliases = ciAliasRepository.findByTenant_IdAndNormalizedAliasName(tenant.getId(), shortHost);
                        }
                    }
                    if (aliases.isEmpty()) {
                        return null;
                    }
                    CiAlias selected = aliases.stream()
                            .sorted(Comparator
                                    .comparing((CiAlias alias) -> matchesEnvironment(alias, environment)).reversed()
                                    .thenComparing(alias -> isLowConfidence(alias.getConfidence()))
                                    .thenComparing(alias -> alias.getCi().getSysId()))
                            .findFirst()
                            .orElse(null);
                    if (selected == null || selected.getCi() == null) {
                        return null;
                    }
                    boolean lowConfidence = aliases.size() > 1 || isLowConfidence(selected.getConfidence());
                    return new Resolution(selected.getCi(), false, false, lowConfidence, aliases.size() > 1 ? "alias-ambiguous" : "alias");
                });
    }

    private Resolution resolveByAlias(BatchResolutionContext context, String hostName, String environment, String sourceSystem) {
        String normalized = normalizeAlias(hostName);
        if (!hasText(normalized) || context == null || context.tenant() == null || context.tenant().getId() == null) {
            return null;
        }

        CiAlias sourceAlias = context.aliasBySourceAndName().get(aliasSourceKey(sourceSystem, normalized));
        if (sourceAlias != null && sourceAlias.getCi() != null) {
            return new Resolution(sourceAlias.getCi(), false, false, isLowConfidence(sourceAlias.getConfidence()), "alias-cache");
        }

        List<CiAlias> aliases = context.aliasesByNormalizedName().getOrDefault(normalized, List.of());
        if (aliases.isEmpty()) {
            String shortHost = shortHost(normalized);
            if (!shortHost.equals(normalized)) {
                aliases = context.aliasesByNormalizedName().getOrDefault(shortHost, List.of());
            }
        }
        if (aliases.isEmpty()) {
            return null;
        }
        CiAlias selected = aliases.stream()
                .sorted(Comparator
                        .comparing((CiAlias alias) -> matchesEnvironment(alias, environment)).reversed()
                        .thenComparing(alias -> isLowConfidence(alias.getConfidence()))
                        .thenComparing(alias -> alias.getCi().getSysId()))
                .findFirst()
                .orElse(null);
        if (selected == null || selected.getCi() == null) {
            return null;
        }
        boolean lowConfidence = aliases.size() > 1 || isLowConfidence(selected.getConfidence());
        return new Resolution(selected.getCi(), false, false, lowConfidence, aliases.size() > 1 ? "alias-ambiguous" : "alias");
    }

    private Resolution upsertCi(
            Tenant tenant,
            String sysId,
            String hostName,
            String environment,
            String ownerEmail,
            BusinessCriticality businessCriticality,
            String sourceSystem,
            boolean lowConfidence,
            String method
    ) {
        Instant now = Instant.now();
        Ci ci = ciRepository.findByTenantAndSysId(tenant, sysId).orElse(null);
        boolean created = ci == null;
        Asset asset = null;
        if (created) {
            ci = new Ci();
            ci.setTenant(tenant);
            ci.setSysId(sysId);
        } else {
            asset = ci.getAsset();
        }
        if (asset == null) {
            String assetIdentifier = "ci:" + sysId.toLowerCase(Locale.ROOT);
            asset = assetRepository.findByTenantAndIdentifier(tenant, assetIdentifier).orElseGet(Asset::new);
            if (asset.getId() == null) {
                asset.setTenant(tenant);
                asset.setIdentifier(assetIdentifier);
                asset.setType(AssetType.HOST);
            }
        }

        asset.setType(AssetType.HOST);
        asset.setName(trimToFallback(hostName, sysId));
        asset.setEnvironment(trimToNull(environment));
        asset.setOwnerEmail(trimToNull(ownerEmail));
        asset.setBusinessCriticality(businessCriticality);
        asset.setState(AssetState.ACTIVE);
        asset.setLastCmdbSyncAt(now);
        asset = assetRepository.save(asset);

        ci.setAsset(asset);
        ci.setDisplayName(trimToFallback(hostName, sysId));
        ci.setEnvironment(trimToNull(environment));
        ci.setOwnerEmail(trimToNull(ownerEmail));
        ci.setBusinessCriticality(businessCriticality);
        ci.setLastCmdbSyncAt(now);
        ci.touch();
        ci = ciRepository.save(ci);

        boolean aliasCreated = updateAlias(ci, hostName, normalizeAlias(hostName), sourceSystem, lowConfidence ? 0.5 : 1.0);
        return new Resolution(ci, created, aliasCreated, lowConfidence, method);
    }

    private Resolution upsertCi(
            BatchResolutionContext context,
            Tenant tenant,
            String sysId,
            String hostName,
            String environment,
            String ownerEmail,
            BusinessCriticality businessCriticality,
            String sourceSystem,
            boolean lowConfidence,
            String method
    ) {
        Instant now = Instant.now();
        String normalizedSysId = trimToNull(sysId);
        Ci ci = context.ciBySysId().get(normalizedSysId);
        boolean created = ci == null;
        Asset asset = null;
        if (created) {
            ci = new Ci();
            ci.setTenant(tenant);
            ci.setSysId(normalizedSysId);
        } else {
            asset = ci.getAsset();
        }
        String assetIdentifier = assetIdentifier(normalizedSysId);
        if (asset == null) {
            asset = context.assetsByIdentifier().get(assetIdentifier);
            if (asset == null) {
                asset = new Asset();
                asset.setTenant(tenant);
                asset.setIdentifier(assetIdentifier);
                asset.setType(AssetType.HOST);
            }
        }

        asset.setType(AssetType.HOST);
        asset.setName(trimToFallback(hostName, normalizedSysId));
        asset.setEnvironment(trimToNull(environment));
        asset.setOwnerEmail(trimToNull(ownerEmail));
        asset.setBusinessCriticality(businessCriticality);
        asset.setState(AssetState.ACTIVE);
        asset.setLastCmdbSyncAt(now);
        asset = assetRepository.save(asset);
        context.assetsByIdentifier().put(assetIdentifier, asset);

        ci.setAsset(asset);
        ci.setDisplayName(trimToFallback(hostName, normalizedSysId));
        ci.setEnvironment(trimToNull(environment));
        ci.setOwnerEmail(trimToNull(ownerEmail));
        ci.setBusinessCriticality(businessCriticality);
        ci.setLastCmdbSyncAt(now);
        ci.touch();
        ci = ciRepository.save(ci);
        context.ciBySysId().put(normalizedSysId, ci);

        boolean aliasCreated = updateAlias(context, ci, hostName, normalizeAlias(hostName), sourceSystem, lowConfidence ? 0.5 : 1.0);
        return new Resolution(ci, created, aliasCreated, lowConfidence, method);
    }

    private boolean updateAlias(Ci ci, String aliasName, String normalizedAliasName, String sourceSystem, double confidence) {
        if (ci == null || ci.getTenant() == null || ci.getTenant().getId() == null || !hasText(normalizedAliasName)) {
            return false;
        }
        Instant now = Instant.now();
        CiAlias alias = ciAliasRepository.findByTenant_IdAndNormalizedAliasNameAndSourceSystem(
                        ci.getTenant().getId(),
                        normalizedAliasName,
                        sourceSystem
                )
                .orElseGet(CiAlias::new);
        boolean created = alias.getId() == null;
        alias.setTenant(ci.getTenant());
        alias.setCi(ci);
        alias.setAliasName(trimToFallback(aliasName, ci.getDisplayName()));
        alias.setNormalizedAliasName(normalizedAliasName);
        alias.setSourceSystem(sourceSystem);
        if (created) {
            alias.setFirstSeenAt(now);
        }
        alias.setLastSeenAt(now);
        alias.setConfidence(confidence);
        ciAliasRepository.save(alias);

        String shortHost = shortHost(normalizedAliasName);
        if (hasText(shortHost) && !shortHost.equals(normalizedAliasName)) {
            updateAlias(ci, shortHost, shortHost, sourceSystem, confidence);
        }
        return created;
    }

    private boolean updateAlias(
            BatchResolutionContext context,
            Ci ci,
            String aliasName,
            String normalizedAliasName,
            String sourceSystem,
            double confidence
    ) {
        if (context == null || ci == null || ci.getTenant() == null || ci.getTenant().getId() == null || !hasText(normalizedAliasName)) {
            return false;
        }
        Instant now = Instant.now();
        String aliasKey = aliasSourceKey(sourceSystem, normalizedAliasName);
        CiAlias alias = context.aliasBySourceAndName().get(aliasKey);
        if (alias == null) {
            alias = new CiAlias();
        }
        boolean created = alias.getId() == null;
        alias.setTenant(ci.getTenant());
        alias.setCi(ci);
        alias.setAliasName(trimToFallback(aliasName, ci.getDisplayName()));
        alias.setNormalizedAliasName(normalizedAliasName);
        alias.setSourceSystem(sourceSystem);
        if (created) {
            alias.setFirstSeenAt(now);
        }
        alias.setLastSeenAt(now);
        alias.setConfidence(confidence);
        alias = ciAliasRepository.save(alias);
        context.aliasBySourceAndName().put(aliasKey, alias);
        context.aliasesByNormalizedName()
                .computeIfAbsent(normalizedAliasName, ignored -> new ArrayList<>());
        List<CiAlias> aliases = context.aliasesByNormalizedName().get(normalizedAliasName);
        if (!aliases.contains(alias)) {
            aliases.add(alias);
        }

        String shortHost = shortHost(normalizedAliasName);
        if (hasText(shortHost) && !shortHost.equals(normalizedAliasName)) {
            updateAlias(context, ci, shortHost, shortHost, sourceSystem, confidence);
        }
        return created;
    }

    private ServiceNowCiLookup lookupInServiceNow(Tenant tenant, String hostName) {
        if (!hasText(hostName)) {
            return null;
        }
        ServiceNowCmdbConfigService.ServiceNowRuntimeConfig runtimeConfig = serviceNowCmdbConfigService.resolveRuntimeConfig(tenant)
                .orElseGet(() -> new ServiceNowCmdbConfigService.ServiceNowRuntimeConfig(
                        trimToNull(serviceNowBaseUrl),
                        com.prototype.vulnwatch.domain.ServiceNowAuthType.BASIC,
                        trimToNull(serviceNowUsername),
                        trimToNull(serviceNowPassword),
                        "cmdb_sam_sw_install",
                        "cmdb_sam_sw_discovery_model",
                        "cmdb_ci",
                        null,
                        null,
                        ServiceNowCmdbConfigService.DEFAULT_INSTALL_FIELDS,
                        ServiceNowCmdbConfigService.DEFAULT_DISCOVERY_FIELDS,
                        1000,
                        true,
                        false,
                        1440
                ));
        if (!hasText(runtimeConfig.baseUrl()) || !hasText(runtimeConfig.ciTable())) {
            return null;
        }
        try {
            String uri = UriComponentsBuilder.fromHttpUrl(runtimeConfig.baseUrl())
                    .path("/api/now/table/{tableName}")
                    .queryParam("sysparm_fields", "sys_id,name,sys_class_name")
                    .queryParam("sysparm_query", "name=" + hostName)
                    .queryParam("sysparm_display_value", "all")
                    .buildAndExpand(runtimeConfig.ciTable())
                    .toUriString();
            HttpHeaders headers = new HttpHeaders();
            if (runtimeConfig.authType() == com.prototype.vulnwatch.domain.ServiceNowAuthType.BEARER) {
                headers.setBearerAuth(runtimeConfig.credentialSecret());
            } else if (hasText(runtimeConfig.username())) {
                headers.setBasicAuth(
                        runtimeConfig.username(),
                        runtimeConfig.credentialSecret() == null ? "" : runtimeConfig.credentialSecret(),
                        StandardCharsets.UTF_8
                );
            }
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            ResponseEntity<String> response = restTemplate.exchange(uri, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            if (!response.getStatusCode().is2xxSuccessful() || !hasText(response.getBody())) {
                return null;
            }
            JsonNode root = objectMapper.readTree(response.getBody());
            JsonNode results = root.path("result");
            if (!results.isArray() || results.isEmpty()) {
                return null;
            }
            JsonNode selected = results.get(0);
            String sysId = fieldValue(selected.path("sys_id"));
            String displayName = fieldValue(selected.path("name"));
            return hasText(sysId) ? new ServiceNowCiLookup(sysId, displayName) : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private boolean matchesEnvironment(CiAlias alias, String environment) {
        if (alias == null || alias.getCi() == null) {
            return false;
        }
        String left = normalizeAlias(alias.getCi().getEnvironment());
        String right = normalizeAlias(environment);
        return hasText(left) && left.equals(right);
    }

    private boolean isLowConfidence(Double confidence) {
        return confidence != null && confidence < 0.8;
    }

    private String fieldValue(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        if (node.isObject()) {
            String value = trimToNull(node.path("value").asText(null));
            if (hasText(value)) {
                return value;
            }
            return trimToNull(node.path("display_value").asText(null));
        }
        return trimToNull(node.asText(null));
    }

    private String shortHost(String normalizedHost) {
        if (!hasText(normalizedHost)) {
            return "";
        }
        int dot = normalizedHost.indexOf('.');
        return dot > 0 ? normalizedHost.substring(0, dot) : normalizedHost;
    }

    private String assetIdentifier(String sysId) {
        return "ci:" + sysId.toLowerCase(Locale.ROOT);
    }

    private String aliasSourceKey(String sourceSystem, String normalizedAliasName) {
        return normalizeSource(sourceSystem) + "::" + normalizedAliasName;
    }

    private String normalizeAlias(String value) {
        if (value == null) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeSource(String value) {
        return value == null || value.isBlank() ? "unknown" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String trimToFallback(String value, String fallback) {
        String trimmed = trimToNull(value);
        return trimmed == null ? fallback : trimmed;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    public record Resolution(
            Ci ci,
            boolean created,
            boolean aliasCreated,
            boolean lowConfidence,
            String resolutionMethod
    ) {
    }

    public record HostLookupInput(
            String requestedSysId,
            String hostName
    ) {
    }

    public record BatchResolutionContext(
            Tenant tenant,
            String sourceSystem,
            Map<String, Ci> ciBySysId,
            Map<String, Asset> assetsByIdentifier,
            Map<String, CiAlias> aliasBySourceAndName,
            Map<String, List<CiAlias>> aliasesByNormalizedName
    ) {
    }

    private record ServiceNowCiLookup(
            String sysId,
            String displayName
    ) {
    }
}
