package com.prototype.vulnwatch.dto;

public record IngestionResult(String status, int fetched, int inserted, int updated, String message) {
}
