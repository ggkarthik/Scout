package com.prototype.vulnwatch.controller;

import jakarta.persistence.EntityNotFoundException;
import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@RestControllerAdvice
public class ApiExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(EntityNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, Object> handleNotFound(EntityNotFoundException ex) {
        return error("NOT_FOUND", ex.getMessage());
    }

    @ExceptionHandler(NoResourceFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, Object> handleMissingRoute(NoResourceFoundException ex) {
        return error("NOT_FOUND", "Resource not found");
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, Object> handleMissingHandler(NoHandlerFoundException ex) {
        return error("NOT_FOUND", "Resource not found");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors()
                .forEach(fieldError -> fields.put(fieldError.getField(), fieldError.getDefaultMessage()));
        Map<String, Object> payload = error("VALIDATION_ERROR", "Validation failed");
        payload.put("fields", fields);
        return payload;
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
    public Map<String, Object> handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex) {
        return error("METHOD_NOT_ALLOWED", ex.getMessage() == null ? "Request method is not supported" : ex.getMessage());
    }

    @ExceptionHandler({IllegalArgumentException.class, HttpMessageNotReadableException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleBadRequest(Exception ex) {
        return error("BAD_REQUEST", ex.getMessage() == null ? "Invalid request" : ex.getMessage());
    }

    @ExceptionHandler(IOException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleIo(IOException ex) {
        String message = ex.getMessage() == null ? "" : ex.getMessage();
        if (message.toLowerCase().contains("already in progress")) {
            log.warn("I/O error while handling API request: {}", message);
        } else {
            log.warn("I/O error while handling API request: {}", message, ex);
        }
        return error("INGESTION_ERROR", ex.getMessage() == null ? "Failed to process ingestion request" : ex.getMessage());
    }

    @ExceptionHandler({CannotAcquireLockException.class, PessimisticLockingFailureException.class})
    @ResponseStatus(HttpStatus.CONFLICT)
    public Map<String, Object> handleLockContention(Exception ex) {
        log.warn("Lock contention while handling API request: {}", ex.getMessage(), ex);
        return error("RESOURCE_BUSY", "Another ingestion is in progress for this asset. Please retry shortly.");
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Map<String, Object> handleGeneric(Exception ex) {
        log.error("Unhandled API error", ex);
        return error("INTERNAL_ERROR", "Internal server error");
    }

    private Map<String, Object> error(String code, String message) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("timestamp", Instant.now());
        payload.put("code", code);
        payload.put("error", message);
        return payload;
    }
}
