package com.prototype.vulnwatch.service;

import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * Fetches vendor advisory pages and extracts plain text for use as AI prompt context.
 * For MSRC CVEs, also queries the MSRC JSON API for structured patch/KB data.
 */
@Service
public class AdvisoryFetchService {

    private static final Logger log = LoggerFactory.getLogger(AdvisoryFetchService.class);
    private static final int MAX_CHARS_PER_URL = 3000;
    private static final int TOTAL_MAX_CHARS = 10000;

    private final RestTemplate restTemplate;

    public AdvisoryFetchService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * Fetches each advisory URL, strips HTML, and returns a combined text block.
     * For MSRC URLs, also queries the structured MSRC JSON API.
     */
    public String fetchAdvisoryContent(List<String> urls) {
        if (urls == null || urls.isEmpty()) return "";
        StringBuilder combined = new StringBuilder();
        for (String url : urls) {
            if (combined.length() >= TOTAL_MAX_CHARS) break;
            try {
                String text = fetchAndStrip(url);
                if (text != null && !text.isBlank()) {
                    combined.append("\n--- Advisory: ").append(url).append(" ---\n");
                    combined.append(text, 0, Math.min(text.length(), MAX_CHARS_PER_URL));
                    combined.append('\n');
                }
            } catch (Exception e) {
                log.debug("Could not fetch advisory {}: {}", url, e.getMessage());
            }
        }
        return combined.toString().trim();
    }

    /**
     * Queries the MSRC JSON API for a specific CVE and returns structured KB/patch info.
     * Returns empty string if the CVE is not a Microsoft CVE or the API is unreachable.
     */
    public String fetchMsrcPatchInfo(String cveId) {
        if (cveId == null || !cveId.toUpperCase().startsWith("CVE-")) return "";
        try {
            // MSRC affected products API — returns KB article IDs and product names
            String apiUrl = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct"
                    + "?%24filter=cveNumber%20eq%20%27" + cveId + "%27";
            HttpHeaders headers = new HttpHeaders();
            headers.set("Accept", "application/json");
            headers.set("User-Agent", "VulnWatch/1.0");
            HttpEntity<Void> req = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.exchange(apiUrl, HttpMethod.GET, req, String.class);
            String body = response.getBody();
            if (body == null || body.isBlank()) return "";
            // Truncate to avoid token bloat
            String truncated = body.length() > 4000 ? body.substring(0, 4000) : body;
            return "\n--- MSRC Affected Products API (JSON) for " + cveId + " ---\n" + truncated + "\n";
        } catch (Exception e) {
            log.debug("MSRC API query failed for {}: {}", cveId, e.getMessage());
            return "";
        }
    }

    private String fetchAndStrip(String url) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("User-Agent", "Mozilla/5.0 (compatible; VulnWatch/1.0; advisory-fetch)");
        headers.set("Accept", "text/html,application/xhtml+xml,application/json");
        HttpEntity<Void> req = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, req, String.class);
        String body = response.getBody();
        if (body == null) return null;
        // Strip HTML tags
        String text = body.replaceAll("(?s)<style[^>]*>.*?</style>", " ")
                          .replaceAll("(?s)<script[^>]*>.*?</script>", " ")
                          .replaceAll("<[^>]+>", " ")
                          .replaceAll("&amp;", "&")
                          .replaceAll("&lt;", "<")
                          .replaceAll("&gt;", ">")
                          .replaceAll("&nbsp;", " ")
                          .replaceAll("&quot;", "\"")
                          .replaceAll("\\s{2,}", " ")
                          .trim();
        // Keep only lines with meaningful content (length > 20)
        StringBuilder out = new StringBuilder();
        for (String line : text.split("\\n")) {
            String l = line.trim();
            if (l.length() > 20) {
                out.append(l).append('\n');
            }
        }
        return out.toString().trim();
    }
}
