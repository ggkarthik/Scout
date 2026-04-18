package com.prototype.vulnwatch.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureContext;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

/**
 * HTTP client for the endoflife.date v1 API.
 *
 * Provides:
 *  fetchAllProducts()                               — full product catalog (slugs + CPE/PURL/aliases)
 *  fetchProductReleasesConditional(slug, lastMod)   — conditional GET with If-Modified-Since support
 *  fetchProductReleases(slug)                       — unconditional convenience wrapper
 *
 * Rate limiting: enforces a minimum interval between requests to avoid 429s.
 * Retry logic: exponential backoff on 429 and 5xx responses.
 */
@Component
public class EolApiClient {

    private static final Logger LOG = LoggerFactory.getLogger(EolApiClient.class);

    // -------------------------------------------------------------------------
    // Data records
    // -------------------------------------------------------------------------

    public record EolProductSummary(
            String slug,
            String label,
            String cpe,
            String purl,
            List<String> aliases
    ) {}

    public record EolCycleData(
            String cycle,
            LocalDate releaseDate,
            LocalDate eolDate,
            Boolean eolBoolean,
            LocalDate supportEndDate,
            LocalDate extendedSupportDate,
            LocalDate securitySupportDate,
            String latestVersion,
            LocalDate latestReleaseDate,
            boolean lts,
            boolean isEol,
            Boolean isEoas,
            Boolean isEoes,
            boolean discontinued,
            String officialSourceUrl
    ) {}

    /**
     * Result of a conditional HTTP fetch.
     * notModified=true means the server returned 304; body and responseLastModified will be null.
     */
    public record FetchResult(String body, String responseLastModified, boolean notModified) {
        public static FetchResult ofNotModified() {
            return new FetchResult(null, null, true);
        }

        public static FetchResult of(String body, String lastModified) {
            return new FetchResult(body, lastModified, false);
        }
    }

    /**
     * Result of a product-releases conditional fetch: includes the parsed cycles,
     * the new Last-Modified header value, and a notModified flag.
     */
    public record EolReleaseFetchResult(
            boolean notModified,
            List<EolCycleData> cycles,
            String lastModified
    ) {
        public static EolReleaseFetchResult ofNotModified() {
            return new EolReleaseFetchResult(true, List.of(), null);
        }
    }

    // -------------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------------

    @Value("${app.eol.base-url:https://endoflife.date/api/v1}")
    private String baseUrl;

    @Value("${app.eol.min-request-interval-ms:200}")
    private long minRequestIntervalMs;

    @Value("${app.eol.max-retries:5}")
    private int maxRetries;

    @Value("${app.eol.retry-base-backoff-ms:2000}")
    private long retryBaseBackoffMs;

    private final ObjectMapper objectMapper;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;

    public EolApiClient(
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper
    ) {
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Fetches the full product catalog from GET /products.
     * Returns a list of product summaries including CPE, PURL, and alias identifiers.
     */
    public List<EolProductSummary> fetchAllProducts() {
        String url = baseUrl + "/products";
        FetchResult result = fetchRawConditional(url, null);
        List<EolProductSummary> products = parseProductList(result.body());
        List<EolProductSummary> enriched = new ArrayList<>(products.size());
        for (EolProductSummary product : products) {
            if (product.slug() == null || product.slug().isBlank()) {
                continue;
            }
            try {
                FetchResult detail = fetchRawConditional(baseUrl + "/products/" + product.slug(), null);
                EolProductSummary detailSummary = parseProductSummary(objectMapper.readTree(detail.body()));
                enriched.add(mergeProductSummary(product, detailSummary));
            } catch (Exception ex) {
                LOG.warn("Failed to enrich EOL product '{}' from detail endpoint: {}", product.slug(), ex.getMessage());
                enriched.add(product);
            }
        }
        return enriched;
    }

    /**
     * Fetches release cycles for a product slug, supporting conditional GET.
     * Sends If-Modified-Since when ifModifiedSince is non-null; returns notModified=true on 304.
     */
    public EolReleaseFetchResult fetchProductReleasesConditional(String slug, String ifModifiedSince) {
        String url = baseUrl + "/products/" + slug;
        FetchResult raw;
        try {
            raw = fetchRawConditional(url, ifModifiedSince);
        } catch (RuntimeException ex) {
            if (ex.getMessage() != null && ex.getMessage().contains("not found")) {
                LOG.debug("EOL product slug not found, skipping: {}", slug);
                return EolReleaseFetchResult.ofNotModified(); // treat 404 as "skip"
            }
            throw ex;
        }
        if (raw.notModified()) {
            return EolReleaseFetchResult.ofNotModified();
        }
        List<EolCycleData> cycles = parseProductReleases(slug, raw.body());
        return new EolReleaseFetchResult(false, cycles, raw.responseLastModified());
    }

    /**
     * Unconditional convenience wrapper — always fetches releases regardless of last_modified.
     */
    public List<EolCycleData> fetchProductReleases(String slug) {
        return fetchProductReleasesConditional(slug, null).cycles();
    }

    // -------------------------------------------------------------------------
    // HTTP layer
    // -------------------------------------------------------------------------

    private FetchResult fetchRawConditional(String url, String ifModifiedSince) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.set("User-Agent", "vulnwatch-backend/1.0");
        if (ifModifiedSince != null && !ifModifiedSince.isBlank()) {
            headers.set(HttpHeaders.IF_MODIFIED_SINCE, ifModifiedSince);
        }
        return outboundHttpClient.execute(
                url,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class,
                "EOL API request",
                outboundPolicy(),
                this::classifyFailure,
                response -> {
                    if (response.getStatusCode().value() == 304) {
                        LOG.debug("EOL 304 Not Modified: {}", url);
                        return FetchResult.ofNotModified();
                    }
                    String responseBody = response.getBody();
                    if (responseBody == null || responseBody.isBlank()) {
                        throw new IllegalStateException("EOL API response body is empty for: " + url);
                    }
                    String lastModified = response.getHeaders().getFirst(HttpHeaders.LAST_MODIFIED);
                    return FetchResult.of(responseBody, lastModified);
                }
        );
    }

    // -------------------------------------------------------------------------
    // Parsers
    // -------------------------------------------------------------------------

    private List<EolProductSummary> parseProductList(String body) {
        List<EolProductSummary> result = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(body);
            JsonNode items = root.isArray() ? root : root.path("result");
            if (!items.isArray()) {
                LOG.warn("EOL /products response is not an array; skipping");
                return result;
            }
            for (JsonNode item : items) {
                EolProductSummary summary = parseProductSummary(item);
                if (summary != null) {
                    result.add(summary);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse EOL product list", e);
        }
        return result;
    }

    private EolProductSummary parseProductSummary(JsonNode item) {
        JsonNode effective = item;
        if (!item.isTextual()) {
            JsonNode resultNode = item.path("result");
            if (resultNode.isObject()) {
                effective = resultNode;
            }
        }

        if (effective.isTextual()) {
            return new EolProductSummary(effective.asText(), null, null, null, List.of());
        }

        String slug = textOrNull(effective.path("name"));
        if (slug == null) {
            slug = textOrNull(effective.path("slug"));
        }
        if (slug == null) {
            return null;
        }

        String label = textOrNull(effective.path("label"));
        String cpe = null;
        String purl = null;

        JsonNode identifiers = effective.path("identifiers");
        if (!identifiers.isMissingNode() && !identifiers.isNull()) {
            if (identifiers.isArray()) {
                for (JsonNode identifier : identifiers) {
                    String type = textOrNull(identifier.path("type"));
                    String id = textOrNull(identifier.path("id"));
                    if (type == null || id == null) {
                        continue;
                    }
                    String normalizedType = type.trim().toLowerCase();
                    if (cpe == null && normalizedType.contains("cpe")) {
                        cpe = id;
                    } else if (purl == null
                            && (normalizedType.contains("purl") || normalizedType.contains("package-url"))) {
                        purl = id;
                    }
                }
            } else {
                cpe = textOrNull(identifiers.path("cpe"));
                purl = textOrNull(identifiers.path("purl"));
            }
        }
        if (cpe == null) cpe = textOrNull(effective.path("cpe"));
        if (purl == null) purl = textOrNull(effective.path("purl"));

        List<String> aliases = new ArrayList<>();
        JsonNode aliasesNode = effective.path("aliases");
        if (aliasesNode.isArray()) {
            for (JsonNode a : aliasesNode) {
                if (a.isTextual() && !a.asText().isBlank()) {
                    aliases.add(a.asText().trim().toLowerCase());
                }
            }
        }
        if (!effective.equals(item)) {
            JsonNode resultAliases = item.path("aliases");
            if (resultAliases.isArray()) {
                for (JsonNode a : resultAliases) {
                    if (a.isTextual() && !a.asText().isBlank()) {
                        String alias = a.asText().trim().toLowerCase();
                        if (!aliases.contains(alias)) aliases.add(alias);
                    }
                }
            }
        }

        return new EolProductSummary(slug, label, cpe, purl, List.copyOf(aliases));
    }

    private List<EolCycleData> parseProductReleases(String slug, String body) {
        List<EolCycleData> result = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(body);

            // Response can be: array of cycles, object with "releases" array, or detail envelope
            JsonNode cycles;
            if (root.isArray()) {
                cycles = root;
            } else {
                // Try "releases" key first, then "result.releases" for detail document format
                cycles = root.path("releases");
                if (cycles.isMissingNode() || !cycles.isArray()) {
                    cycles = root.path("result").path("releases");
                }
                if (cycles.isMissingNode() || !cycles.isArray()) {
                    cycles = root;
                }
            }

            if (!cycles.isArray()) {
                LOG.warn("EOL /products/{} response has no recognizable releases array", slug);
                return result;
            }

            for (JsonNode cycle : cycles) {
                EolCycleData data = parseCycle(cycle);
                if (data != null) {
                    result.add(data);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse EOL releases for: " + slug, e);
        }
        return result;
    }

    private EolCycleData parseCycle(JsonNode node) {
        String cycle = textOrNull(node.path("cycle"));
        if (cycle == null) {
            // some API versions use "name" for the cycle identifier
            cycle = textOrNull(node.path("name"));
        }
        if (cycle == null) {
            return null;
        }

        LocalDate releaseDate = parseDate(node.path("releaseDate"));
        LocalDate supportEndDate = parseDate(node.path("support"));
        LocalDate extendedSupportDate = parseDate(node.path("extendedSupport"));
        LocalDate securitySupportDate = parseDate(node.path("securitySupport"));
        String officialSourceUrl = textOrNull(node.path("link"));
        JsonNode latestNode = node.path("latest");
        String latestVersion = textOrNull(latestNode);
        LocalDate latestReleaseDate = parseDate(node.path("latestReleaseDate"));
        if (latestNode.isObject()) {
            if (latestVersion == null) {
                latestVersion = textOrNull(latestNode.path("name"));
            }
            if (latestReleaseDate == null) {
                latestReleaseDate = parseDate(latestNode.path("date"));
            }
            if (officialSourceUrl == null) {
                officialSourceUrl = textOrNull(latestNode.path("link"));
            }
        }
        boolean lts = node.path("lts").asBoolean(false) || node.path("isLts").asBoolean(false);
        boolean discontinued = node.path("discontinued").asBoolean(false) || node.path("isDiscontinued").asBoolean(false);

        boolean isEolFlag = node.path("isEol").asBoolean(false);
        Boolean isEoas = booleanOrNull(node.path("isEoas"));
        Boolean isEoes = booleanOrNull(node.path("isEoes"));

        LocalDate eolDate = null;
        Boolean eolBoolean = null;
        JsonNode eolNode = node.path("eol");
        if (!eolNode.isMissingNode() && !eolNode.isNull()) {
            if (eolNode.isBoolean()) {
                eolBoolean = eolNode.asBoolean();
                if (eolBoolean) isEolFlag = true;
            } else if (eolNode.isTextual()) {
                eolDate = parseDate(eolNode);
                if (eolDate != null) {
                    isEolFlag = isEolFlag || eolDate.isBefore(LocalDate.now());
                }
            }
        }
        // Also check "eolFrom" field (detail document variant)
        if (eolDate == null) {
            eolDate = parseDate(node.path("eolFrom"));
            if (eolDate != null) {
                isEolFlag = isEolFlag || eolDate.isBefore(LocalDate.now());
            }
        }

        return new EolCycleData(
                cycle, releaseDate, eolDate, eolBoolean,
                supportEndDate, extendedSupportDate, securitySupportDate,
                latestVersion, latestReleaseDate,
                lts, isEolFlag, isEoas, isEoes, discontinued, officialSourceUrl
        );
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private LocalDate parseDate(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull() || !node.isTextual()) {
            return null;
        }
        String text = node.asText("").trim();
        if (text.isBlank()) return null;
        try {
            return LocalDate.parse(text);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private String textOrNull(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) return null;
        String value = node.asText("").trim();
        return value.isBlank() ? null : value;
    }

    private Boolean booleanOrNull(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull() || !node.isBoolean()) return null;
        return node.asBoolean();
    }

    private EolProductSummary mergeProductSummary(EolProductSummary base, EolProductSummary detail) {
        if (detail == null) {
            return base;
        }
        List<String> aliases = new ArrayList<>();
        if (base.aliases() != null) {
            aliases.addAll(base.aliases());
        }
        if (detail.aliases() != null) {
            for (String alias : detail.aliases()) {
                if (alias != null && !alias.isBlank() && !aliases.contains(alias)) {
                    aliases.add(alias);
                }
            }
        }
        return new EolProductSummary(
                detail.slug() != null ? detail.slug() : base.slug(),
                detail.label() != null ? detail.label() : base.label(),
                detail.cpe() != null ? detail.cpe() : base.cpe(),
                detail.purl() != null ? detail.purl() : base.purl(),
                List.copyOf(aliases)
        );
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("eol", minRequestIntervalMs, maxRetries, retryBaseBackoffMs);
    }

    private OutboundFailureDecision<RuntimeException> classifyFailure(OutboundFailureContext context) {
        Integer statusCode = context.statusCodeValue();
        if (statusCode != null) {
            if (statusCode == 404) {
                return OutboundFailureDecision.fail(
                        new RuntimeException("EOL product not found: " + context.endpoint(), context.error())
                );
            }
            RuntimeException terminal = new RuntimeException(
                    "EOL API request failed with status " + statusCode + " for: " + context.endpoint(),
                    context.error()
            );
            return new OutboundFailureDecision<>(
                    context.isRetryableByDefault(),
                    context.retryAfterDelayMs(),
                    terminal
            );
        }
        return new OutboundFailureDecision<>(
                true,
                null,
                new RuntimeException(
                        "Failed to fetch EOL API response after " + context.maxAttempts() + " attempts for: " + context.endpoint(),
                        context.error()
                )
        );
    }
}
