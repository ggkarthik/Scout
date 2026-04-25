package com.prototype.vulnwatch.domain;

public enum AwsAuthType {
    /** Use EC2 instance profile / ECS task role / Lambda execution role via instance metadata service. */
    INSTANCE_METADATA,
    /** Use long-lived IAM access key ID + secret access key. */
    ACCESS_KEY,
    /** Assume a cross-account IAM role via STS AssumeRole (optionally with an external ID). */
    CROSS_ACCOUNT_ROLE
}
