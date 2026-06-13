package com.prototype.vulnwatch.service.sbomingestion;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

@Service
public class SbomFetchGuardService {

    private final long maxPayloadBytes;
    private final boolean allowUserAuthHeader;
    private final String allowedHostsCsv;

    public SbomFetchGuardService(
            @Value("${app.sbom-fetch.max-payload-bytes:5242880}") long maxPayloadBytes,
            @Value("${app.sbom-fetch.allow-user-auth-header:false}") boolean allowUserAuthHeader,
            @Value("${app.sbom-fetch.allowed-hosts:}") String allowedHostsCsv
    ) {
        this.maxPayloadBytes = maxPayloadBytes;
        this.allowUserAuthHeader = allowUserAuthHeader;
        this.allowedHostsCsv = allowedHostsCsv;
    }

    public HttpHeaders buildEndpointHeaders(String authorizationHeader) throws IOException {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN, MediaType.ALL));
        if (authorizationHeader != null && !authorizationHeader.isBlank()) {
            if (!allowUserAuthHeader) {
                throw new IOException("Custom authorization headers are disabled for remote SBOM fetch");
            }
            headers.set(HttpHeaders.AUTHORIZATION, authorizationHeader.trim());
        }
        return headers;
    }

    public void validateRemoteSourceUrl(String value) throws IOException {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (Exception e) {
            throw new IOException("Invalid source URL");
        }

        if (uri.getUserInfo() != null && !uri.getUserInfo().isBlank()) {
            throw new IOException("URL user info is not allowed");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IOException("Source URL host is required");
        }

        // Explicitly allowed hosts (e.g. localhost in local dev) bypass scheme and address checks
        String normalizedHost = host.trim().toLowerCase(Locale.ROOT);
        if (allowedHosts().contains(normalizedHost)) {
            return;
        }

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IOException("Only HTTPS source URLs are allowed");
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

    public void ensurePayloadWithinLimit(long bytes) throws IOException {
        if (bytes > maxPayloadBytes) {
            throw new IOException("SBOM payload exceeds max allowed size");
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
}
