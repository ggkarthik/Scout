package com.prototype.vulnwatch.ticketing;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE;

/**
 * The single entry point for raising a remediation ticket against a finding.
 *
 * <p>Owns everything that is not provider-specific: eligibility, provider selection, and the
 * write back to the finding. Providers only talk to their remote system, so a new integration
 * cannot forget to record which system holds the ticket.
 */
@Service
public class TicketingService {

    private static final Logger log = LoggerFactory.getLogger(TicketingService.class);

    private final TicketingProviderRegistry registry;
    private final FindingRepository findingRepository;

    public TicketingService(TicketingProviderRegistry registry, FindingRepository findingRepository) {
        this.registry = registry;
        this.findingRepository = findingRepository;
    }

    /**
     * Raises a ticket for the finding in the tenant's active ticketing system and links it.
     *
     * @throws ResponseStatusException 404 when the finding does not exist, 409 when it is
     *         already closed or already ticketed, 503 when no ticketing system is configured
     */
    @Transactional
    public TicketRef createTicketForFinding(Tenant tenant, UUID findingId, TicketRequest request) {
        TicketingProvider provider = registry.activeProvider(tenant)
                .orElseThrow(() -> new ResponseStatusException(SERVICE_UNAVAILABLE,
                        "No ticketing system is configured for this tenant. Configure the Jira or "
                                + "ServiceNow connector under Incident & Ticketing Tools first."));

        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Finding not found"));
        assertEligible(finding);

        TicketRef ref = provider.createForFinding(tenant, finding, request);
        link(finding, ref);
        findingRepository.save(finding);
        log.info("Linked finding {} to {} ticket {}", finding.getDisplayId(), ref.system().key(), ref.externalKey());
        return ref;
    }

    /** Where new tickets will go, and which configured systems are outranked. */
    @Transactional(readOnly = true)
    public TicketingStatus status(Tenant tenant) {
        List<TicketingSystem> configured = registry.configuredSystems(tenant);
        TicketingSystem active = configured.isEmpty() ? null : configured.get(0);
        List<TicketingSystem> overridden = configured.isEmpty()
                ? List.of()
                : configured.subList(1, configured.size());
        return new TicketingStatus(active, configured, overridden);
    }

    /**
     * The system that owns an existing ticket on a finding.
     *
     * <p>Findings ticketed before provider tracking existed carry no provider, and every one of
     * those came from ServiceNow — it was the only integration. Defaulting them there keeps
     * their status sync working instead of silently dropping it.
     */
    public Optional<TicketingSystem> owningSystem(Finding finding) {
        if (finding == null || finding.getIncidentId() == null || finding.getIncidentId().isBlank()) {
            return Optional.empty();
        }
        return Optional.of(TicketingSystem.fromKey(finding.getIncidentProvider())
                .orElse(TicketingSystem.SERVICENOW));
    }

    private void link(Finding finding, TicketRef ref) {
        finding.setIncidentId(ref.externalKey());
        finding.setIncidentStatus(ref.status());
        finding.setIncidentProvider(ref.system().key());
        finding.touch();
    }

    /**
     * A closed finding has nothing left to remediate, and a finding that already has a ticket
     * must not get a second one — a duplicate would overwrite the link and orphan the first.
     */
    private void assertEligible(Finding finding) {
        if (finding.getStatus() == FindingStatus.RESOLVED || finding.getStatus() == FindingStatus.AUTO_CLOSED) {
            throw new ResponseStatusException(CONFLICT, "Closed findings are not eligible for a new ticket");
        }
        if (finding.getIncidentId() != null && !finding.getIncidentId().isBlank()) {
            TicketingSystem existing = owningSystem(finding).orElse(TicketingSystem.SERVICENOW);
            throw new ResponseStatusException(CONFLICT,
                    "This finding is already linked to " + existing.displayName() + " ticket "
                            + finding.getIncidentId());
        }
    }

    /**
     * @param active      where new tickets go, or null when nothing is configured
     * @param configured  every configured system, highest precedence first
     * @param overridden  configured systems that {@code active} outranks
     */
    public record TicketingStatus(
            TicketingSystem active,
            List<TicketingSystem> configured,
            List<TicketingSystem> overridden
    ) {
    }
}
