package com.prototype.vulnwatch.domain;

/**
 * How a declared resource is identified, in descending order of trustworthiness.
 *
 * <p>A display name is deliberately absent. Two unrelated models are routinely both called
 * "classifier", so matching on name would merge resources the documents never claimed were
 * the same.
 */
public enum AiBomDeclaredIdentityKind {
    /** An immutable content digest. The only identity that survives republication. */
    DIGEST,
    /** An explicit versioned identifier, such as a purl carrying a version. */
    VERSIONED_IDENTIFIER,
    /**
     * A reference scoped to the declaring source, used when the document offers nothing
     * stronger. Two sources declaring the same model this way stay separate until something
     * actually establishes the equivalence.
     */
    SOURCE_SCOPED_REF
}
