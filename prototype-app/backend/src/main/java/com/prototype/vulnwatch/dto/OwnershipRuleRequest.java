package com.prototype.vulnwatch.dto;

public record OwnershipRuleRequest(String name, String condition, String userGroup, Integer executionOrder) {}
