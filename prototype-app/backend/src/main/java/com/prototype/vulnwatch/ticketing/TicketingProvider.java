package com.prototype.vulnwatch.ticketing;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Optional;

/**
 * One external ticketing system, behind a provider-neutral contract.
 *
 * <p>Implementations perform the remote call and nothing else. They must not write to
 * {@code findings} — {@link TicketingService} owns that, so every provider persists the same
 * fields in the same transaction and a new provider cannot forget to record which system
 * created the ticket.
 */
public interface TicketingProvider {

    TicketingSystem system();

    /**
     * Whether this tenant has enough configuration for {@link #createForFinding} to succeed.
     * Must not make a remote call — this is evaluated on every ticket creation and on
     * connector listing.
     */
    boolean isConfigured(Tenant tenant);

    /**
     * Creates a ticket for the given finding.
     *
     * @throws org.springframework.web.server.ResponseStatusException if the tenant is not
     *         configured, or the remote system rejects or mangles the request
     */
    TicketRef createForFinding(Tenant tenant, Finding finding, TicketRequest request);

    /**
     * Current status of an existing ticket, in the provider's own vocabulary.
     * Returns empty when the ticket cannot be read, so a transient outage leaves the last
     * known status in place rather than overwriting it.
     */
    Optional<String> fetchStatus(Tenant tenant, String externalKey);
}
