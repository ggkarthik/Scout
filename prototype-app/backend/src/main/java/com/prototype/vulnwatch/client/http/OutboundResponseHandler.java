package com.prototype.vulnwatch.client.http;

import org.springframework.http.ResponseEntity;

@FunctionalInterface
public interface OutboundResponseHandler<T, R> {

    R handle(ResponseEntity<T> response) throws Exception;
}
