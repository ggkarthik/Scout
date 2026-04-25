package com.prototype.vulnwatch.domain;

public enum AssetType {
    APPLICATION,
    HOST,
    CONTAINER_IMAGE,
    /** Generic non-host cloud resources used by non-AWS inventory sources. */
    CLOUD_RESOURCE
}
