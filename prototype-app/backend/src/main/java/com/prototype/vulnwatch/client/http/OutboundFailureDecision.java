package com.prototype.vulnwatch.client.http;

public record OutboundFailureDecision<E extends Exception>(
        boolean retryable,
        Long retryDelayMs,
        E terminalException
) {

    public static <E extends Exception> OutboundFailureDecision<E> retry(Long retryDelayMs, E terminalException) {
        return new OutboundFailureDecision<>(true, retryDelayMs, terminalException);
    }

    public static <E extends Exception> OutboundFailureDecision<E> fail(E terminalException) {
        return new OutboundFailureDecision<>(false, null, terminalException);
    }
}
