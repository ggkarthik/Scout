package com.prototype.vulnwatch.service;

public class DuplicateDemoRequestException extends RuntimeException {
    public DuplicateDemoRequestException(Throwable cause) {
        super("An active request already exists", cause);
    }
}
