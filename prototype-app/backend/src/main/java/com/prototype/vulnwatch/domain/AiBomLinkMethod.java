package com.prototype.vulnwatch.domain;

/** What justified linking a declared resource to a deployment. Recorded so a link is explainable. */
public enum AiBomLinkMethod {
    DIGEST_MATCH,
    VERSIONED_IDENTIFIER_MATCH,
    REVIEWED
}
