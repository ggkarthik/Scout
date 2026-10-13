package com.prototype.vulnwatch.aisecurity.service;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/** Release boundary: execution events and their dependent features are deferred. */
public final class AiRuntimeScope {
    public static final String REASON = "RUNTIME_OUT_OF_SCOPE";
    private AiRuntimeScope() { }
    public static boolean excluded() { return true; }
    public static void requireInScope() {
        throw new ResponseStatusException(HttpStatus.GONE, REASON);
    }
    public static boolean runtimePolicy(String id, String evaluationMode) {
        return id != null && id.startsWith("AGCF-RT-")
                || evaluationMode != null && evaluationMode.startsWith("RUNTIME_");
    }
}
