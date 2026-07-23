package com.prototype.vulnwatch.dto;

public record DemoRequestReceiptResponse(
        boolean accepted,
        String message
) {
    public static DemoRequestReceiptResponse received() {
        return new DemoRequestReceiptResponse(true, "If eligible, your demo request has been received.");
    }
}
