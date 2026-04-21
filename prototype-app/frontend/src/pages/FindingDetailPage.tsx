import React from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import type { Finding } from '../features/findings/types';

function formatDate(value?: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function formatDateTime(value?: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function statusPillClass(status: string): string {
  if (status === 'OPEN') return 'status-open';
  if (status === 'RESOLVED') return 'status-resolved';
  if (status === 'SUPPRESSED') return 'status-suppressed';
  return '';
}

const LIFECYCLE_STEPS = ['Detected', 'Triaged', 'In Review', 'Remediation', 'Verification', 'Closed'];

function getLifecycleStep(finding: Finding): number {
  if (finding.status === 'RESOLVED' || finding.status === 'AUTO_CLOSED') return 5;
  if (finding.decisionState === 'FIXED') return 4;
  if (finding.decisionState === 'AFFECTED') return 3;
  if (finding.decisionState === 'UNDER_INVESTIGATION') return 2;
  return 1; // NEEDS_REVIEW
}

function CollapsibleSection({ title, defaultOpen = true, children }: {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = React.useState(defaultOpen);
  return (
    <section className="fd-section">
      <button type="button" className="fd-section-header" onClick={() => setOpen((o) => !o)}>
        <span>{title}</span>
        <span className="fd-section-chevron">{open ? '▲' : '▼'}</span>
      </button>
      {open && <div className="fd-section-body">{children}</div>}
    </section>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="fd-field">
      <dt className="fd-field-label">{label}</dt>
      <dd className="fd-field-value">{children ?? '—'}</dd>
    </div>
  );
}

export function FindingDetailPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const finding = (location.state as { finding?: Finding } | null)?.finding ?? null;
  const returnTo = searchParams.get('returnTo') || '/findings';

  if (!finding) {
    return (
      <div className="page-grid">
        <section className="panel">
          <div className="fd-not-found">
            <h2>Finding not available</h2>
            <p>This finding could not be loaded. Navigate here from the Findings list or the CVE Assessment Workbench.</p>
            <button type="button" className="btn btn-secondary" onClick={() => navigate(returnTo)}>
              ← Back to Findings
            </button>
          </div>
        </section>
      </div>
    );
  }

  const lifecycleStep = getLifecycleStep(finding);

  return (
    <div className="fd-page">
      {/* Top bar */}
      <div className="fd-topbar">
        <button type="button" className="fd-back-btn" onClick={() => navigate(returnTo)}>
          ← Back
        </button>
        <span className="fd-display-id mono">{finding.displayId || finding.id}</span>
        <span className="fd-vuln-id">{finding.vulnerabilityId}</span>
        <div style={{ flex: 1 }} />
        <span className={`severity-pill severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
        {finding.inKev && <span className="kev-badge kev-badge--sm">KEV</span>}
        <span className={`status-pill ${statusPillClass(finding.status)}`}>{finding.status.replace('_', ' ')}</span>
      </div>

      {/* Lifecycle strip */}
      <div className="fd-lifecycle">
        {LIFECYCLE_STEPS.map((step, i) => (
          <React.Fragment key={step}>
            <div className={`fd-lifecycle-step${i === lifecycleStep ? ' active' : i < lifecycleStep ? ' done' : ''}`}>
              <div className="fd-lifecycle-dot" />
              <span className="fd-lifecycle-label">{step}</span>
            </div>
            {i < LIFECYCLE_STEPS.length - 1 && (
              <div className={`fd-lifecycle-connector${i < lifecycleStep ? ' done' : ''}`} />
            )}
          </React.Fragment>
        ))}
      </div>

      {/* KPI strip */}
      <div className="fd-kpi-strip">
        <div className="fd-kpi-card">
          <div className="fd-kpi-label">Risk Score</div>
          <div className="fd-kpi-value">{Math.round(finding.riskScore * 100)}%</div>
        </div>
        <div className="fd-kpi-card">
          <div className="fd-kpi-label">Confidence</div>
          <div className="fd-kpi-value">{Math.round(finding.confidenceScore * 100)}%</div>
        </div>
        <div className="fd-kpi-card">
          <div className="fd-kpi-label">Due Date</div>
          <div className="fd-kpi-value">{formatDate(finding.dueAt)}</div>
        </div>
        <div className="fd-kpi-card">
          <div className="fd-kpi-label">Assigned To</div>
          <div className="fd-kpi-value" title={finding.assignedTo}>{finding.assignedTo || '—'}</div>
        </div>
        <div className="fd-kpi-card">
          <div className="fd-kpi-label">Decision</div>
          <div className="fd-kpi-value">{finding.decisionState.replace(/_/g, ' ')}</div>
        </div>
        {finding.epss != null && (
          <div className="fd-kpi-card">
            <div className="fd-kpi-label">EPSS</div>
            <div className="fd-kpi-value">{(finding.epss * 100).toFixed(1)}%</div>
          </div>
        )}
      </div>

      {/* Sections */}
      <div className="fd-content">
        <CollapsibleSection title="Vulnerability & Impact">
          <dl className="fd-fields">
            <Field label="CVE ID">
              <span className="mono">{finding.vulnerabilityId}</span>
            </Field>
            <Field label="Severity">
              <span className={`severity-pill severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
            </Field>
            <Field label="In KEV">{finding.inKev ? 'Yes' : 'No'}</Field>
            {finding.epss != null && (
              <Field label="EPSS Score">{(finding.epss * 100).toFixed(2)}%</Field>
            )}
            {finding.impactReason && <Field label="Impact Reason">{finding.impactReason}</Field>}
            <Field label="Source">{finding.source}</Field>
            <Field label="Match Method">
              <span className="mono">{finding.matchedBy}</span>
            </Field>
          </dl>
        </CollapsibleSection>

        <CollapsibleSection title="Affected Asset">
          <dl className="fd-fields">
            <Field label="Asset Name">{finding.assetName}</Field>
            <Field label="Asset Identifier">
              <span className="mono">{finding.assetIdentifier}</span>
            </Field>
            <Field label="Asset Type">{finding.assetType}</Field>
            <Field label="Package">
              <span className="mono">{finding.packageName}</span>
            </Field>
            <Field label="Version">
              <span className="mono">{finding.packageVersion || '—'}</span>
            </Field>
          </dl>
        </CollapsibleSection>

        <CollapsibleSection title="Item Details">
          <dl className="fd-fields">
            <Field label="Status">
              <span className={`status-pill ${statusPillClass(finding.status)}`}>
                {finding.status.replace('_', ' ')}
              </span>
            </Field>
            <Field label="Decision State">{finding.decisionState.replace(/_/g, ' ')}</Field>
            <Field label="Risk Score">{Math.round(finding.riskScore * 100)}%</Field>
            <Field label="Confidence">{Math.round(finding.confidenceScore * 100)}%</Field>
            <Field label="Assigned To">{finding.assignedTo}</Field>
            <Field label="Due Date">{formatDate(finding.dueAt)}</Field>
            {finding.suppressionReason && (
              <Field label="Suppression Reason">{finding.suppressionReason}</Field>
            )}
            {finding.suppressedUntil && (
              <Field label="Suppressed Until">{formatDate(finding.suppressedUntil)}</Field>
            )}
            <Field label="First Observed">{formatDateTime(finding.firstObservedAt)}</Field>
            <Field label="Last Observed">{formatDateTime(finding.lastObservedAt)}</Field>
            <Field label="Last Updated">{formatDateTime(finding.updatedAt)}</Field>
          </dl>
        </CollapsibleSection>

        {(finding.vexStatus || finding.isEol) && (
          <CollapsibleSection title="VEX & End-of-Life">
            <dl className="fd-fields">
              {finding.vexStatus && <Field label="VEX Status">{finding.vexStatus}</Field>}
              {finding.vexProvider && <Field label="VEX Provider">{finding.vexProvider}</Field>}
              {finding.vexFreshness && <Field label="VEX Freshness">{finding.vexFreshness}</Field>}
              {finding.matchedVexAssertionId && (
                <Field label="VEX Assertion">
                  <span className="mono">{finding.matchedVexAssertionId}</span>
                </Field>
              )}
              {finding.isEol != null && (
                <Field label="End of Life">{finding.isEol ? 'Yes' : 'No'}</Field>
              )}
              {finding.eolDate && <Field label="EOL Date">{formatDate(finding.eolDate)}</Field>}
              {finding.eolDaysRemaining != null && (
                <Field label="Days Until EOL">{String(finding.eolDaysRemaining)}</Field>
              )}
              {finding.eolSlug && (
                <Field label="EOL Slug">
                  <span className="mono">{finding.eolSlug}</span>
                </Field>
              )}
              {finding.eolCycle && <Field label="EOL Cycle">{finding.eolCycle}</Field>}
            </dl>
          </CollapsibleSection>
        )}

        {finding.evidence && (
          <CollapsibleSection title="Match Evidence" defaultOpen={false}>
            <pre className="fd-evidence">{finding.evidence}</pre>
          </CollapsibleSection>
        )}
      </div>
    </div>
  );
}
