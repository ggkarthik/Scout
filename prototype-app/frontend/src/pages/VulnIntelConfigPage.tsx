import React from 'react';
import { api } from '../api/client';
import type { VulnIntelSourceStatus, VulnIntelSourcesSummary } from '../api/client';
import type { SyncTriggerResponse } from '../features/connect/types';

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
      triggerSync: () => api.syncKev(),
    },
    {
      icon: '🐙',
      name: 'GitHub Advisory Database (GHSA)',
      lastRun: s?.['GHSA'],
      note: 'Advisories with package-version applicability for correlation. GitHub token is configured server-side in backend/secrets/github-api-token or via GITHUB_API_TOKEN.',
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
      triggerSync: () => api.syncRedhatCsaf(),
    },
    {
      icon: '🧠',
      name: 'Advisory Imports',
      lastRun: s?.['ADVISORY'],
      note: 'Curated vendor advisories imported via API (POST /api/ingestion/advisories). No scheduled sync — imports are triggered on demand.',
    },
  ];

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>Vulnerability Intelligence Sources</h3>
        <span className="panel-caption">
          Configure and run NVD, KEV, GHSA, CSAF/VEX, and advisory feeds.
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
