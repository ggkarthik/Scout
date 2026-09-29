import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { pathForAiBomDeclaredResources, pathForFindingDetail } from '../app/routes';
import { useActor } from '../features/auth/context';
import { hasAnyRole } from '../features/auth/roles';
import { InventoryShell } from '../features/inventory/InventoryShell';

type AiBomDeclaredResourceDetailPageProps = {
  resourceId: string;
};

function fmtDt(value?: string | null): string {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="fd3-panel">
      <div className="fd3-panel-title">{title}</div>
      <div className="fd3-panel-body">{children}</div>
    </div>
  );
}

function KVRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="fd3-kv-row">
      <span className="fd3-kv-key">{label}</span>
      <span className="fd3-kv-val">{children ?? <span className="fd3-empty">—</span>}</span>
    </div>
  );
}

export function AiBomDeclaredResourceDetailPage({ resourceId }: AiBomDeclaredResourceDetailPageProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const actor = useActor();
  const canPropose = hasAnyRole(actor, ['SECURITY_ANALYST', 'INVENTORY_ADMIN', 'TENANT_ADMIN', 'CREATOR']);
  const canApproveOrRemove = hasAnyRole(actor, ['INVENTORY_ADMIN', 'TENANT_ADMIN', 'CREATOR']);
  const [artifactId, setArtifactId] = React.useState('');
  const [actionError, setActionError] = React.useState<string | null>(null);

  const detailQuery = useQuery({
    queryKey: ['ai-bom-declared-resource', resourceId],
    queryFn: () => api.getAiBomDeclaredResource(resourceId),
  });
  const findingsQuery = useQuery({
    queryKey: ['ai-bom-declared-resource-findings', resourceId],
    queryFn: () => api.getAiBomDeclaredResourceFindings(resourceId),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['ai-bom-declared-resource', resourceId] });
    queryClient.invalidateQueries({ queryKey: ['ai-bom-setup-actions'] });
    queryClient.invalidateQueries({ queryKey: ['ai-bom-declared-resources'] });
  };

  const proposeMutation = useMutation({
    mutationFn: () => api.proposeAiBomMapping(resourceId, artifactId.trim()),
    onSuccess: () => { setActionError(null); setArtifactId(''); invalidate(); },
    onError: (error: unknown) => setActionError(error instanceof Error ? error.message : 'Failed to propose mapping'),
  });
  const approveMutation = useMutation({
    mutationFn: () => api.approveAiBomMapping(resourceId),
    onSuccess: () => { setActionError(null); invalidate(); },
    onError: (error: unknown) => setActionError(error instanceof Error ? error.message : 'Failed to approve mapping'),
  });
  const removeMutation = useMutation({
    mutationFn: () => api.removeAiBomMapping(resourceId),
    onSuccess: () => { setActionError(null); invalidate(); },
    onError: (error: unknown) => setActionError(error instanceof Error ? error.message : 'Failed to remove mapping'),
  });

  if (detailQuery.isLoading) {
    return <InventoryShell title="Declared AI Resource" legacyClassName="ai-security-page"><div className="empty-state"><p>Loading…</p></div></InventoryShell>;
  }
  if (detailQuery.isError || !detailQuery.data) {
    return <InventoryShell title="Declared AI Resource" legacyClassName="ai-security-page"><div className="notice error">This declared resource could not be loaded.</div></InventoryShell>;
  }

  const detail = detailQuery.data;
  const resource = detail.resource;
  const findings = findingsQuery.data ?? [];

  return (
    <InventoryShell
      eyebrow={resource.resourceKind}
      title={resource.name}
      description={resource.version ? `Version ${resource.version}` : undefined}
      legacyClassName="ai-security-page"
      actions={<button type="button" className="btn btn-secondary" onClick={() => navigate(pathForAiBomDeclaredResources())}>Back to declared resources</button>}
    >
      {actionError ? <div className="notice error">{actionError}</div> : null}

      <div className="fd3-panel-grid">
        <Panel title="Declaration">
          <KVRow label="Deployment state">{resource.deploymentState}</KVRow>
          <KVRow label="Identity kind">{resource.identityKind}</KVRow>
          <KVRow label="Identity value">{resource.identityValue}</KVRow>
          <KVRow label="Declaring BOM version">{resource.bomId}</KVRow>
          <KVRow label="First declared">{fmtDt(resource.firstDeclaredAt)}</KVRow>
          <KVRow label="Last declared">{fmtDt(resource.lastDeclaredAt)}</KVRow>
        </Panel>

        <Panel title="BOM Source">
          <KVRow label="BOM type">{detail.sourceBomType}</KVRow>
          <KVRow label="Source state">{detail.sourceState}</KVRow>
          <KVRow label="Revision">{detail.sourceRevision}</KVRow>
          <KVRow label="Completeness">{detail.completeness?.completeness}</KVRow>
          <KVRow label="Asserted by">{detail.completeness?.assertedBy}</KVRow>
          <KVRow label="Asserted at">{fmtDt(detail.completeness?.assertedAt)}</KVRow>
        </Panel>

        <Panel title="Component">
          {detail.component ? (
            <>
              <KVRow label="Name">{detail.component.name}</KVRow>
              <KVRow label="Version">{detail.component.version}</KVRow>
              <KVRow label="Purl">{detail.component.purl}</KVRow>
              <KVRow label="License">{detail.component.license}</KVRow>
              <KVRow label="Scope">{detail.component.scope}</KVRow>
            </>
          ) : <p className="panel-caption">No backing BOM component recorded.</p>}
        </Panel>

        <Panel title="Projection Status">
          <KVRow label="Provenance projected">{detail.projection.provenanceProjected ? 'Yes' : 'No'}</KVRow>
          <KVRow label="Projected at">{fmtDt(detail.projection.provenanceProjectedAt)}</KVRow>
          <KVRow label="BOM format">{detail.projection.bomFormat}</KVRow>
          <KVRow label="Spec version">{detail.projection.specVersion}</KVRow>
          <KVRow label="Latest receipt">{detail.projection.latestReceiptOperation}</KVRow>
          <KVRow label="Receipt completed">{fmtDt(detail.projection.latestReceiptCompletedAt)}</KVRow>
        </Panel>
      </div>

      <Panel title="Deployment Mapping">
        {resource.deploymentState === 'LINKED' ? (
          <>
            <KVRow label="Linked artifact">{resource.linkedArtifactId}</KVRow>
            <KVRow label="Link method">{resource.linkMethod}</KVRow>
            <KVRow label="Reviewed by">{resource.linkReviewedBy}</KVRow>
            <KVRow label="Reviewed at">{fmtDt(resource.linkReviewedAt)}</KVRow>
            {canApproveOrRemove ? (
              <button type="button" className="btn btn-secondary" disabled={removeMutation.isPending} onClick={() => removeMutation.mutate()}>
                {removeMutation.isPending ? 'Removing…' : 'Remove mapping'}
              </button>
            ) : null}
          </>
        ) : resource.proposedArtifactId ? (
          <>
            <KVRow label="Proposed artifact">{resource.proposedArtifactId}</KVRow>
            <KVRow label="Proposed by">{resource.proposedBy}</KVRow>
            <KVRow label="Proposed at">{fmtDt(resource.proposedAt)}</KVRow>
            {canApproveOrRemove ? (
              <div className="fd3-actions">
                <button type="button" className="btn btn-primary" disabled={approveMutation.isPending} onClick={() => approveMutation.mutate()}>
                  {approveMutation.isPending ? 'Approving…' : 'Approve mapping'}
                </button>
                <button type="button" className="btn btn-secondary" disabled={removeMutation.isPending} onClick={() => removeMutation.mutate()}>
                  {removeMutation.isPending ? 'Discarding…' : 'Discard proposal'}
                </button>
              </div>
            ) : <p className="panel-caption">Awaiting approval from an inventory admin or tenant admin.</p>}
          </>
        ) : canPropose ? (
          <div className="fd3-actions">
            <input
              type="text"
              value={artifactId}
              onChange={(event) => setArtifactId(event.target.value)}
              placeholder="AI Security artifact ID"
              aria-label="Artifact ID to propose"
            />
            <button
              type="button"
              className="btn btn-primary"
              disabled={proposeMutation.isPending || artifactId.trim().length === 0}
              onClick={() => proposeMutation.mutate()}
            >
              {proposeMutation.isPending ? 'Proposing…' : 'Propose mapping'}
            </button>
          </div>
        ) : (
          <p className="panel-caption">This declaration is not yet matched to a real deployment.</p>
        )}
      </Panel>

      <Panel title="Findings Affecting This Resource">
        {findingsQuery.isLoading ? (
          <p className="panel-caption">Loading…</p>
        ) : findings.length === 0 ? (
          <p className="panel-caption">No open vulnerability findings transitively affect this resource.</p>
        ) : (
          <table className="data-table">
            <thead><tr><th>Finding</th><th>Package</th><th>Severity</th><th>Status</th></tr></thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id} onClick={() => navigate(pathForFindingDetail(finding.displayId || finding.id))}>
                  <td>{finding.displayId}</td>
                  <td>{finding.packageName}<small>{finding.packageVersion}</small></td>
                  <td><span className={`severity-badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span></td>
                  <td><span className="status-pill">{finding.status.replace(/_/g, ' ')}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </InventoryShell>
  );
}
