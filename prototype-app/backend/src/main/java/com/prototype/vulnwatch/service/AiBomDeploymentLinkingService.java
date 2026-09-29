package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AiBomDeclaredIdentityKind;
import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomDeclaredResourceKind;
import com.prototype.vulnwatch.domain.AiBomDeploymentState;
import com.prototype.vulnwatch.domain.AiBomLinkMethod;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Attempts to match a declared AI-BOM resource to a real, connector-discovered
 * {@code ai_security_artifacts} row -- so a declaration can eventually be shown as verified
 * rather than sitting in the unlinked queue forever.
 *
 * <p>Conservative by design, per the schema's own {@link AiBomLinkMethod}: a declaration is
 * never presented as a deployment on anything less than a real match. When a candidate artifact
 * exposes both a name and a version, both must match. When it only exposes a name (the common
 * case for AWS Bedrock models today -- version is usually baked into the name/ARN string
 * itself, not a separate field), a name-only match is accepted only when it is the single
 * unambiguous candidate; two or more same-named candidates become {@code AMBIGUOUS} rather than
 * a guess.
 *
 * <p>Only {@code MODEL} resources identified by a {@code VERSIONED_IDENTIFIER} are matched here.
 * {@code DIGEST}-identified resources have nothing to match against: no provider today exposes
 * a comparable content digest for a model artifact. {@code DATASET} resources have no
 * connector-observed counterpart in the current artifact taxonomy ({@code DATA_STORE} artifacts
 * are storage accounts/capacities, not "this training dataset is deployed"). {@code
 * SOURCE_SCOPED_REF} resources have no automatic {@link AiBomLinkMethod} at all -- they can only
 * be linked through a human-reviewed mapping, which this service does not perform.
 */
@Service
public class AiBomDeploymentLinkingService {

    private final NamedParameterJdbcTemplate jdbc;

    public AiBomDeploymentLinkingService(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void attemptLink(Tenant tenant, AiBomDeclaredResource declared) {
        if (declared.getResourceKind() != AiBomDeclaredResourceKind.MODEL
                || declared.getIdentityKind() != AiBomDeclaredIdentityKind.VERSIONED_IDENTIFIER) {
            return;
        }
        String name = declared.getName() == null ? "" : declared.getName().trim().toLowerCase(Locale.ROOT);
        if (name.isBlank()) {
            return;
        }
        String version = declared.getVersion() == null
                ? null
                : declared.getVersion().trim().toLowerCase(Locale.ROOT);

        List<Candidate> candidates = jdbc.query("""
                select id, attributes_json ->> 'modelVersion' as model_version
                  from ai_security_artifacts
                 where tenant_id = :tenantId and artifact_type = 'AI_MODEL' and active = true
                   and (lower(name) = :name or lower(attributes_json ->> 'modelName') = :name)
                """,
                Map.of("tenantId", tenant.getId(), "name", name),
                (rs, rowNum) -> new Candidate(
                        rs.getObject("id", UUID.class), rs.getString("model_version")));

        if (candidates.isEmpty()) {
            return;
        }

        boolean anyCandidateHasAVersion = candidates.stream().anyMatch(c -> c.modelVersion() != null);
        List<Candidate> eligible = (version != null && anyCandidateHasAVersion)
                ? candidates.stream()
                        .filter(c -> c.modelVersion() != null
                                && version.equals(c.modelVersion().trim().toLowerCase(Locale.ROOT)))
                        .toList()
                : candidates;

        if (eligible.size() == 1) {
            declared.setDeploymentState(AiBomDeploymentState.LINKED);
            declared.setLinkedArtifactId(eligible.get(0).artifactId());
            declared.setLinkMethod(AiBomLinkMethod.VERSIONED_IDENTIFIER_MATCH);
        } else if (eligible.size() > 1) {
            declared.setDeploymentState(AiBomDeploymentState.AMBIGUOUS);
        }
        // eligible.isEmpty(): a version was required but no candidate's version matched.
        // Leave the declaration exactly as it was rather than guessing.
    }

    // Package-private (not private) so the unit test can construct query results directly
    // without going through a mocked ResultSet/RowMapper round trip.
    record Candidate(UUID artifactId, String modelVersion) {
    }
}
