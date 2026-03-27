package com.prototype.vulnwatch.client.http;

@FunctionalInterface
public interface OutboundFailureClassifier<E extends Exception> {

    OutboundFailureDecision<E> classify(OutboundFailureContext context);
}
