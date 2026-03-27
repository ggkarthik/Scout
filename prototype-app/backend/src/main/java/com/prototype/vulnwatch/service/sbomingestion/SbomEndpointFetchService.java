package com.prototype.vulnwatch.service.sbomingestion;

import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class SbomEndpointFetchService {

    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final SbomFetchGuardService sbomFetchGuardService;
    private final SbomUploadSupportService sbomUploadSupportService;

    public SbomEndpointFetchService(
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            SbomFetchGuardService sbomFetchGuardService,
            SbomUploadSupportService sbomUploadSupportService
    ) {
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.sbomFetchGuardService = sbomFetchGuardService;
        this.sbomUploadSupportService = sbomUploadSupportService;
    }

    public SbomEndpointFetchResult fetch(SbomEndpointIngestionRequest request) throws IOException {
        String url = request.sourceUrl().trim();
        sbomFetchGuardService.validateRemoteSourceUrl(url);

        ResponseEntity<byte[]> response;
        try {
            response = outboundHttpClient.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(sbomFetchGuardService.buildEndpointHeaders(request.authorizationHeader())),
                    byte[].class,
                    "Remote SBOM fetch",
                    outboundPolicy(),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof IOException ioException
                                    ? ioException
                                    : new IOException(context.error())
                    )
            );
        } catch (IOException ioException) {
            throw ioException;
        } catch (Exception checkedException) {
            throw new IOException(checkedException);
        }

        long declaredLength = response.getHeaders().getContentLength();
        if (declaredLength > 0) {
            sbomFetchGuardService.ensurePayloadWithinLimit(declaredLength);
        }
        byte[] content = response.getBody();
        if (content == null || content.length == 0) {
            throw new IOException("Remote endpoint returned empty SBOM payload");
        }
        sbomFetchGuardService.ensurePayloadWithinLimit(content.length);

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("ingestionMode", "remote-endpoint");
        evidence.put("sourceUrl", url);
        evidence.put("statusCode", response.getStatusCode().value());
        evidence.put("responseContentType", response.getHeaders().getFirst("Content-Type"));
        evidence.put("fetchedAt", Instant.now());

        SbomIngestionSourceMetadata metadata = new SbomIngestionSourceMetadata(
                "REMOTE_ENDPOINT",
                "api",
                request.sourceLabel() == null || request.sourceLabel().isBlank() ? url : request.sourceLabel().trim(),
                url,
                response.getStatusCode().value(),
                response.getHeaders().getFirst("Content-Type"),
                response.getHeaders().getContentLength() >= 0
                        ? response.getHeaders().getContentLength()
                        : (long) content.length,
                sbomUploadSupportService.toJson(evidence)
        );
        return new SbomEndpointFetchResult(content, metadata);
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("sbom-endpoint", 0L, null, null);
    }
}
