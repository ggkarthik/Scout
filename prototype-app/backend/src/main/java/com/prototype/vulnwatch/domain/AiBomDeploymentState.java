package com.prototype.vulnwatch.domain;

/** Whether a declared resource has been shown to correspond to a real deployment. */
public enum AiBomDeploymentState {
    /** Declared by a document and nothing more. The default, and it must be presented as such. */
    UNVERIFIED,
    /** Matched to a connector-discovered resource, or confirmed by a reviewer. */
    LINKED,
    /** Candidate deployments exist but none is unambiguous. Needs a person, not a guess. */
    AMBIGUOUS
}
