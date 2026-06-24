package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * BLG-016: EPSS (Exploit Prediction Scoring System) integration.
 *
 * Fetches exploitation probability scores from the FIRST.org EPSS API and
 * updates the epss_score and epss_updated_at columns on Vulnerability rows.
 *
 * The FIRST.org API accepts up to 100 CVE IDs per request and returns the
 * current daily score (0.0–1.0) and percentile for each one.
 *
 * Refresh runs daily (configurable). Only rows whose epss_updated_at is null
 * or older than 25 hours are fetched, avoiding redundant API calls.
 *
 * API reference: https://www.first.org/epss/api
 */
@Service
public class EpssRefreshService {

    private static final Logger LOG = LoggerFactory.getLogger(EpssRefreshService.class);

    @Value("${app.epss.base-url:https://api.first.org/data/v1/epss}")
    private String epssBaseUrl;

    @Value("${app.epss.batch-size:100}")
    private int batchSize;

    @Value("${app.epss.enabled:true}")
    private boolean enabled;

    private final VulnerabilityRepository vulnerabilityRepository;
    private final FindingDeltaQueueService findingDeltaQueueService;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;

    public EpssRefreshService(
            VulnerabilityRepository vulnerabilityRepository,
            FindingDeltaQueueService findingDeltaQueueService,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper
    ) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.findingDeltaQueueService = findingDeltaQueueService;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
    }

    /**
     * Daily refresh at 03:15 UTC — runs after the FIRST.org daily publication window.
     * Cron is configurable via {@code app.epss.refresh-cron}.
     */
    @Scheduled(cron = "${app.epss.refresh-cron:0 15 3 * * *}")
    public void refreshAll() {
        TenantContext.runAsPlatform(this::refreshAllInPlatformContext);
    }

    private void refreshAllInPlatformContext() {
        if (!enabled) {
            LOG.debug("EPSS refresh is disabled; skipping");
            return;
        }
        LOG.info("Starting daily EPSS refresh");
        int updated = 0;
        int page = 0;
        Instant staleBefore = Instant.now().minus(25, ChronoUnit.HOURS);

        while (true) {
            Page<Vulnerability> stale = vulnerabilityRepository.findStaleEpssRows(
                    staleBefore, PageRequest.of(page, batchSize));
            if (stale.isEmpty()) {
                break;
            }
            updated += refreshBatch(stale.getContent());
            if (!stale.hasNext()) {
                break;
            }
            page++;
        }
        LOG.info("EPSS refresh complete — updated {} vulnerabilities", updated);
    }

    // -------------------------------------------------------------------------
    // Visible for testing
    // -------------------------------------------------------------------------

    @Transactional
    int refreshBatch(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return 0;
        }
        List<String> cveIds = vulnerabilities.stream()
                .map(Vulnerability::getExternalId)
                .filter(id -> id != null && id.toUpperCase(Locale.ROOT).startsWith("CVE-"))
                .collect(Collectors.toList());

        if (cveIds.isEmpty()) {
            return 0;
        }

        String url = UriComponentsBuilder.fromHttpUrl(epssBaseUrl)
                .queryParam("cve", String.join(",", cveIds))
                .build()
                .toUriString();

        String payload;
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.set("User-Agent", "vulnwatch-backend/1.0");
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class,
                    "EPSS batch API",
                    outboundPolicy(),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException runtimeException
                                    ? runtimeException
                                    : new RuntimeException(context.error())
                    )
            );
            payload = response.getBody();
        } catch (Exception e) {
            LOG.warn("EPSS API request failed for batch of {} CVEs: {}", cveIds.size(), e.getMessage());
            return 0;
        }

        if (payload == null || payload.isBlank()) {
            return 0;
        }

        java.util.Map<String, Double> epssMap = parseEpssResponse(payload);
        if (epssMap.isEmpty()) {
            return 0;
        }

        Instant now = Instant.now();
        int updated = 0;
        List<Vulnerability> toSave = new ArrayList<>();
        Set<UUID> changedVulnerabilityIds = new java.util.LinkedHashSet<>();
        for (Vulnerability vuln : vulnerabilities) {
            Double score = epssMap.get(vuln.getExternalId().toUpperCase(Locale.ROOT));
            if (score != null) {
                Double previousScore = vuln.getEpssScore();
                vuln.setEpssScore(score);
                vuln.setEpssUpdatedAt(now);
                vuln.touch();
                toSave.add(vuln);
                if (vuln.getId() != null && !Objects.equals(previousScore, score)) {
                    changedVulnerabilityIds.add(vuln.getId());
                }
                updated++;
            }
        }
        if (!toSave.isEmpty()) {
            vulnerabilityRepository.saveAll(toSave);
        }
        if (!changedVulnerabilityIds.isEmpty()) {
            findingDeltaQueueService.enqueueCveMetadataDeltas(changedVulnerabilityIds, "epss-refresh");
        }
        return updated;
    }

    private java.util.Map<String, Double> parseEpssResponse(String json) {
        java.util.Map<String, Double> result = new java.util.HashMap<>();
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode data = root.path("data");
            if (!data.isArray()) {
                return result;
            }
            for (JsonNode entry : data) {
                String cve = entry.path("cve").asText("").toUpperCase(Locale.ROOT);
                String epssText = entry.path("epss").asText("");
                if (cve.isBlank() || epssText.isBlank()) {
                    continue;
                }
                try {
                    result.put(cve, Double.parseDouble(epssText));
                } catch (NumberFormatException ignored) {
                    // skip malformed entries
                }
            }
        } catch (Exception e) {
            LOG.warn("Failed to parse EPSS API response: {}", e.getMessage());
        }
        return result;
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("epss", 0L, null, null);
    }
}
