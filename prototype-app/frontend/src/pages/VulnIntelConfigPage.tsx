import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { VulnIntelSourceStatus, VulnIntelSourcesSummary } from '../api/client';
import type {
  SyncTriggerResponse,
  VulnerabilitySourceFilterConfig,
  VulnerabilitySourceFilterConfigRequest,
  VulnerabilitySourceSystem
} from '../features/connect/types';
import { useSourceFilterConfigQuery } from '../features/connect/queries';
import { useActor } from '../features/auth/context';
import { canManageSourceFilters } from '../features/auth/roles';

const SEVERITY_OPTIONS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

function timeAgo(iso?: string): string | null {
  if (!iso) return null;
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} hr ago`;
  const days = Math.floor(hrs / 24);
  return `${days} day${days === 1 ? '' : 's'} ago`;
}

function formatTimestamp(value?: string): string {
  if (!value) return '-';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function isNotFoundError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.message.includes('[NOT_FOUND]') || error.message.includes('(404)');
}

type SourceFilterForm = VulnerabilitySourceFilterConfigRequest;

function defaultSourceFilterForm(sourceSystem: VulnerabilitySourceSystem): SourceFilterForm {
  switch (sourceSystem) {
    case 'nvd':
      return { hasKev: false, cvssV3Severity: '', cvssV4Severity: '' };
    case 'kev':
      return { dateAddedFrom: '', dateAddedTo: '', knownRansomwareCampaignUse: false };
    case 'ghsa':
      return { severity: '' };
    case 'redhat':
      return { severity: '', cvssScore: undefined, cvss3Score: undefined };
  }
}

function sourceFilterFormFromConfig(
  sourceSystem: VulnerabilitySourceSystem,
  config: VulnerabilitySourceFilterConfig | null
): SourceFilterForm {
  if (!config) return defaultSourceFilterForm(sourceSystem);
  switch (config.sourceSystem) {
    case 'nvd':
      return {
        hasKev: config.hasKev,
        cvssV3Severity: config.cvssV3Severity ?? '',
        cvssV4Severity: config.cvssV4Severity ?? ''
      };
    case 'kev':
      return {
        dateAddedFrom: config.dateAddedFrom ?? '',
        dateAddedTo: config.dateAddedTo ?? '',
        knownRansomwareCampaignUse: config.knownRansomwareCampaignUse
      };
    case 'ghsa':
      return { severity: config.severity ?? '' };
    case 'redhat':
      return {
        severity: config.severity ?? '',
        cvssScore: config.cvssScore,
        cvss3Score: config.cvss3Score
      };
  }
}

function normalizeSourceFilterForm(
  sourceSystem: VulnerabilitySourceSystem,
  form: SourceFilterForm
): VulnerabilitySourceFilterConfigRequest {
  const trim = (value?: string): string | undefined => {
    if (value == null) return undefined;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  };
  const numberOrUndefined = (value?: number): number | undefined => (
    typeof value === 'number' && !Number.isNaN(value) ? value : undefined
  );
  switch (sourceSystem) {
    case 'nvd':
      return {
        hasKev: form.hasKev === true,
        cvssV3Severity: trim(form.cvssV3Severity),
        cvssV4Severity: trim(form.cvssV4Severity)
      };
    case 'kev':
      return {
        dateAddedFrom: trim(form.dateAddedFrom),
        dateAddedTo: trim(form.dateAddedTo),
        knownRansomwareCampaignUse: form.knownRansomwareCampaignUse === true
      };
    case 'ghsa':
      return { severity: trim(form.severity) };
    case 'redhat':
      return {
        severity: trim(form.severity),
        cvssScore: numberOrUndefined(form.cvssScore),
        cvss3Score: numberOrUndefined(form.cvss3Score)
      };
  }
}

function SourceFilterControls({ sourceSystem }: { sourceSystem: VulnerabilitySourceSystem }) {
  const actor = useActor();
  const queryClient = useQueryClient();
  const canEdit = canManageSourceFilters(actor);
  const filterQuery = useSourceFilterConfigQuery(sourceSystem, true);
  const [form, setForm] = React.useState<SourceFilterForm>(() => defaultSourceFilterForm(sourceSystem));
  const [config, setConfig] = React.useState<VulnerabilitySourceFilterConfig | null>(null);
  const [isDirty, setIsDirty] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [message, setMessage] = React.useState('');

  React.useEffect(() => {
    if (filterQuery.data) {
      setConfig(filterQuery.data);
      setForm(sourceFilterFormFromConfig(sourceSystem, filterQuery.data));
      setIsDirty(false);
      return;
    }
    if (filterQuery.error && isNotFoundError(filterQuery.error)) {
      setConfig(null);
      setForm(defaultSourceFilterForm(sourceSystem));
      setIsDirty(false);
    }
  }, [filterQuery.data, filterQuery.error, sourceSystem]);

  const updateField = <K extends keyof SourceFilterForm>(key: K, value: SourceFilterForm[K]) => {
    setIsDirty(true);
    setForm((current) => {
      const next = { ...current, [key]: value };
      if (key === 'cvssV3Severity' && typeof value === 'string' && value.trim().length > 0) {
        next.cvssV4Severity = '';
      }
      if (key === 'cvssV4Severity' && typeof value === 'string' && value.trim().length > 0) {
        next.cvssV3Severity = '';
      }
      return next;
    });
  };

  const save = async () => {
    if (!canEdit) {
      setMessage('Your role can view tenant source filters, but cannot update them.');
      return;
    }
    setSaving(true);
    setMessage('');
    try {
      const saved = await api.saveVulnerabilitySourceFilterConfig(
        sourceSystem,
        normalizeSourceFilterForm(sourceSystem, form)
      );
      queryClient.setQueryData(['source-filter-config', sourceSystem], saved);
      setConfig(saved);
      setForm(sourceFilterFormFromConfig(sourceSystem, saved));
      setIsDirty(false);
      setMessage(`${saved.sourceSystem.toUpperCase()} filters saved.`);
    } catch (e) {
      if (isNotFoundError(e)) {
        setMessage('Source filters are not available until the backend is refreshed.');
      } else {
        setMessage(e instanceof Error ? e.message : String(e));
      }
    } finally {
      setSaving(false);
    }
  };

  if (filterQuery.isLoading && config == null) {
    return <div className="panel-caption">Loading saved filters...</div>;
  }

  return (
    <div className="vi-source-filters">
      <div className="vi-source-filters-header">
        <span className="vi-source-filters-title">Ingestion Filters</span>
        {config?.updatedAt && (
          <span className="panel-caption">Last saved {new Date(config.updatedAt).toLocaleString()}</span>
        )}
      </div>

      {sourceSystem === 'nvd' && (
        <>
          <p className="field-hint" style={{ marginBottom: 8 }}>
            Select CVSS v3 <em>or</em> CVSS v4 severity — choosing one automatically clears the other.
          </p>
          <div className="source-filter-grid">
            <label className="source-filter-field">
              <span>CVSS v3 Severity</span>
              <select
                value={form.cvssV3Severity ?? ''}
                onChange={(e) => updateField('cvssV3Severity', e.target.value)}
                disabled={!canEdit}
              >
                <option value="">Any</option>
                {SEVERITY_OPTIONS.map((option) => (
                  <option key={option} value={option}>{option}</option>
                ))}
              </select>
            </label>
            <label className="source-filter-field">
              <span>CVSS v4 Severity</span>
              <select
                value={form.cvssV4Severity ?? ''}
                onChange={(e) => updateField('cvssV4Severity', e.target.value)}
                disabled={!canEdit}
              >
                <option value="">Any</option>
                {SEVERITY_OPTIONS.map((option) => (
                  <option key={option} value={option}>{option}</option>
                ))}
              </select>
            </label>
            <label className="source-filter-field">
              <span>Known Exploitation</span>
              <select
                value={form.hasKev === true ? 'KEV_ONLY' : ''}
                onChange={(e) => updateField('hasKev', e.target.value === 'KEV_ONLY')}
                disabled={!canEdit}
              >
                <option value="">Any</option>
                <option value="KEV_ONLY">Known exploited only</option>
              </select>
              <span className="field-hint">Only ingest CVEs already linked to CISA KEV.</span>
            </label>
          </div>
        </>
      )}

      {sourceSystem === 'kev' && (
        <div className="source-filter-grid">
          <label className="source-filter-field">
            <span>Date Added From</span>
            <input
              type="date"
              value={form.dateAddedFrom ?? ''}
              onChange={(e) => updateField('dateAddedFrom', e.target.value)}
              disabled={!canEdit}
            />
          </label>
          <label className="source-filter-field">
            <span>Date Added To</span>
            <input
              type="date"
              value={form.dateAddedTo ?? ''}
              onChange={(e) => updateField('dateAddedTo', e.target.value)}
              disabled={!canEdit}
            />
          </label>
          <label className="source-filter-field">
            <span>Known Ransomware Campaign Use</span>
            <select
              value={form.knownRansomwareCampaignUse === true ? 'KNOWN' : ''}
              onChange={(e) => updateField('knownRansomwareCampaignUse', e.target.value === 'KNOWN')}
              disabled={!canEdit}
            >
              <option value="">Any</option>
              <option value="KNOWN">Known ransomware campaign use</option>
            </select>
          </label>
        </div>
      )}

      {sourceSystem === 'ghsa' && (
        <div className="source-filter-grid">
          <label className="source-filter-field">
            <span>Severity</span>
            <select
              value={form.severity ?? ''}
              onChange={(e) => updateField('severity', e.target.value)}
              disabled={!canEdit}
            >
              <option value="">Any</option>
              {SEVERITY_OPTIONS.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
          </label>
        </div>
      )}

      {sourceSystem === 'redhat' && (
        <div className="source-filter-grid">
          <label className="source-filter-field">
            <span>Severity</span>
            <select
              value={form.severity ?? ''}
              onChange={(e) => updateField('severity', e.target.value)}
              disabled={!canEdit}
            >
              <option value="">Any</option>
              {SEVERITY_OPTIONS.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
          </label>
          <label className="source-filter-field">
            <span>CVSS Score ≥</span>
            <input
              type="number"
              min="0"
              max="10"
              step="0.1"
              value={form.cvssScore ?? ''}
              onChange={(e) => updateField(
                'cvssScore',
                e.target.value === '' ? undefined : Number(e.target.value)
              )}
              placeholder="7.0"
              disabled={!canEdit}
            />
          </label>
          <label className="source-filter-field">
            <span>CVSS v3 Score ≥</span>
            <input
              type="number"
              min="0"
              max="10"
              step="0.1"
              value={form.cvss3Score ?? ''}
              onChange={(e) => updateField(
                'cvss3Score',
                e.target.value === '' ? undefined : Number(e.target.value)
              )}
              placeholder="7.0"
              disabled={!canEdit}
            />
          </label>
        </div>
      )}

      <div className="source-filter-actions">
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          disabled={saving || !canEdit || !isDirty}
          onClick={() => void save()}
        >
          {saving ? 'Saving...' : 'Save Filters'}
        </button>
        {!canEdit && (
          <span className="filter-unsaved-indicator">Read-only for your role</span>
        )}
        {canEdit && isDirty && (
          <span className="filter-unsaved-indicator">Unsaved changes</span>
        )}
        {message && <span className="panel-caption">{message}</span>}
      </div>
    </div>
  );
}

type SourceSectionProps = {
  icon: string;
  name: string;
  lastRun?: VulnIntelSourceStatus;
  configFields?: React.ReactNode;
  triggerSync?: () => Promise<SyncTriggerResponse>;
  note?: string;
};

const RUN_EVERY_OPTIONS = [1, 2, 4, 6, 12, 24, 48, 72, 168];

function SourceSection({ icon, name, lastRun, configFields, triggerSync, note }: SourceSectionProps) {
  const [running, setRunning] = React.useState(false);
  const [result, setResult] = React.useState<SyncTriggerResponse | null>(null);
  const [error, setError] = React.useState('');
  const [runEveryHours, setRunEveryHours] = React.useState(24);

  const trigger = async () => {
    if (!triggerSync) return;
    setRunning(true);
    setError('');
    setResult(null);
    try {
      const res = await triggerSync();
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  };

  const hasLastRun = lastRun && lastRun.status !== 'never';
  const isFailed = lastRun?.status === 'failed';
  const totalRecords = (lastRun?.recordsInserted ?? 0) + (lastRun?.recordsUpdated ?? 0);
  const lastRunAgo = timeAgo(lastRun?.completedAt);

  const dotClass = isFailed
    ? 'connect-source-dot--fail'
    : hasLastRun
    ? 'connect-source-dot--ok'
    : 'connect-source-dot--warn';

  return (
    <div className="vi-source-section">
      <div className="vi-source-header">
        <span className="vi-source-icon" aria-hidden="true">{icon}</span>
        <span className="vi-source-name">{name}</span>
        <span className={`connect-source-dot ${dotClass}`} />
        {hasLastRun && !isFailed && lastRunAgo && (
          <span className="vi-source-meta">
            Last run · {lastRunAgo}
            {totalRecords > 0 && ` · ${totalRecords.toLocaleString()} records`}
          </span>
        )}
        {isFailed && lastRunAgo && (
          <span className="vi-source-meta vi-source-meta--fail">Failed · {lastRunAgo}</span>
        )}
      </div>

      {isFailed && (
        <div className="sn-status-row sn-status-row--error">
          <span className="sn-status-pill sn-status-fail">Failed</span>
          <span className="sn-status-meta">{formatTimestamp(lastRun?.completedAt)}</span>
          {lastRun?.errorMessage && (
            <span className="sn-status-error-msg" title={lastRun.errorMessage}>
              {lastRun.errorMessage.length > 100
                ? lastRun.errorMessage.slice(0, 100) + '…'
                : lastRun.errorMessage}
            </span>
          )}
        </div>
      )}

      {note && <p className="vi-source-note">{note}</p>}
      {configFields && <div className="vi-source-config">{configFields}</div>}

      {triggerSync && (
        <div className="vi-source-config">
          <div className="vi-run-every-row">
            <label className="vi-run-every-label">
              <span>Run every</span>
              <select
                className="vi-run-every-select"
                value={runEveryHours}
                onChange={(e) => setRunEveryHours(Number(e.target.value))}
              >
                {RUN_EVERY_OPTIONS.map((h) => (
                  <option key={h} value={h}>
                    {h === 1 ? '1 hour' : h === 168 ? '7 days' : `${h} hours`}
                  </option>
                ))}
              </select>
            </label>
            {(() => {
              const base = lastRun?.completedAt ? new Date(lastRun.completedAt) : null;
              if (!base || Number.isNaN(base.getTime())) return null;
              const next = new Date(base.getTime() + runEveryHours * 3600 * 1000);
              return (
                <span className="vi-run-every-next">
                  Next run · {next.toLocaleString()}
                </span>
              );
            })()}
          </div>
        </div>
      )}

      {error && <div className="notice error">{error}</div>}
      {result && (
        <div className="notice">
          <strong>Integration queued.</strong>{result.message ? ` ${result.message}` : ''}
        </div>
      )}

      {triggerSync && (
        <div className="vi-source-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => void trigger()}
            disabled={running}
          >
            {running ? 'Running…' : 'Run Integration now'}
          </button>
        </div>
      )}
    </div>
  );
}

type Props = {
  vulnSummary?: VulnIntelSourcesSummary | null;
};

export function VulnIntelConfigPage({ vulnSummary }: Props) {
  const [nvdApiKey, setNvdApiKey] = React.useState('');
  const [showNvdKey, setShowNvdKey] = React.useState(false);

  const s = vulnSummary?.sources;

  const nvdConfigFields = (
    <>
      <div className="form-grid">
        <label>
          <span>
            NVD API Key{' '}
            <span
              className="sn-tooltip"
              title="Optional. Requests without a key are rate-limited to 5 req/30s. A free key raises the limit to 50 req/30s."
            >
              ⓘ
            </span>
          </span>
          <div className="secure-input-row">
            <input
              type={showNvdKey ? 'text' : 'password'}
              value={nvdApiKey}
              onChange={(e) => setNvdApiKey(e.target.value)}
              placeholder="Leave blank to use anonymous rate limits"
              autoComplete="off"
            />
            <button
              type="button"
              className="btn btn-secondary btn-inline"
              onClick={() => setShowNvdKey((v) => !v)}
            >
              {showNvdKey ? 'Hide' : 'Show'}
            </button>
          </div>
        </label>
      </div>
      <SourceFilterControls sourceSystem="nvd" />
    </>
  );

  const SOURCES: SourceSectionProps[] = [
    {
      icon: '🛡️',
      name: 'NVD Vulnerability Feed',
      lastRun: s?.['NVD'],
      configFields: nvdConfigFields,
      triggerSync: () => api.syncNvd(),
    },
    {
      icon: '⚠️',
      name: 'CISA KEV Feed',
      lastRun: s?.['KEV'],
      note: 'Known-exploited vulnerabilities catalog from CISA. No credentials required — publicly accessible.',
      configFields: <SourceFilterControls sourceSystem="kev" />,
      triggerSync: () => api.syncKev(),
    },
    {
      icon: '🐙',
      name: 'GitHub Advisory Database (GHSA)',
      lastRun: s?.['GHSA'],
      note: 'Advisories with package-version applicability for correlation. GitHub token is configured server-side in backend/secrets/github-api-token or via GITHUB_API_TOKEN.',
      configFields: <SourceFilterControls sourceSystem="ghsa" />,
      triggerSync: () => api.syncGhsa(),
    },
    {
      icon: '🪟',
      name: 'Microsoft CSAF + VEX',
      lastRun: s?.['CSAF_MICROSOFT'],
      note: 'Microsoft CSAF advisories and VEX applicability data from the MSRC public feed. No credentials required.',
      triggerSync: () => api.syncMicrosoftCsaf(),
    },
    {
      icon: '🎩',
      name: 'Red Hat CSAF + VEX',
      lastRun: s?.['CSAF_REDHAT'],
      note: 'Red Hat CSAF advisories and VEX applicability data from the Red Hat Security Data API. No credentials required.',
      configFields: <SourceFilterControls sourceSystem="redhat" />,
      triggerSync: () => api.syncRedhatCsaf(),
    },
    {
      icon: '🧠',
      name: 'Advisory Imports',
      lastRun: s?.['ADVISORY'],
      note: 'Curated vendor advisories imported via API (POST /api/ingestion/advisories). No scheduled sync — imports are triggered on demand.',
    },
    {
      icon: '🇪🇺',
      name: 'EUVD Feed',
      lastRun: s?.['EUVD'],
      note: 'European Union Vulnerability Database ingestion for supplemental regional vulnerability intelligence.',
      triggerSync: () => api.syncEuvd(),
    },
    {
      icon: '🇯🇵',
      name: 'JVN Feed',
      lastRun: s?.['JVN'],
      note: 'Japan Vulnerability Notes Database ingestion for regional advisories and JVNDB mappings.',
      triggerSync: () => api.syncJvn(),
    },
  ];

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>Vulnerability Intelligence Sources</h3>
        <span className="panel-caption">
          Configure ingestion filters and run NVD, KEV, GHSA, CSAF/VEX, and advisory feeds.
        </span>
      </div>
      {SOURCES.map((src, i) => (
        <React.Fragment key={src.name}>
          {i > 0 && <div className="vi-source-divider" />}
          <SourceSection {...src} />
        </React.Fragment>
      ))}
    </section>
  );
}
