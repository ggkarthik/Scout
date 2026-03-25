import React from 'react';
import { api } from '../api/client';
import {
  SyncRun,
  SyncRunSnapshot,
  VexAssertionRepairSummary,
  VulnerabilitySourceFilterConfig,
  VulnerabilitySourceFilterConfigRequest,
  VulnerabilitySourceSystem
} from '../types';
import { ResizableTable } from '../components/ResizableTable';

type FocusSource = 'all' | 'vuln-only' | 'processing' | 'nvd' | 'kev' | 'ghsa' | 'github' | 'microsoft-csaf' | 'redhat-csaf' | 'advisories';
type Props = {
  focusSource?: FocusSource;
  title?: string;
  caption?: string;
  hideHeader?: boolean;
  showTriggers?: boolean;
  showQueue?: boolean;
  refreshSignal?: number;
};

const NVD_FULL_SYNC_API_KEY_STORAGE_KEY = 'scoutai-nvd-full-sync-api-key';
const SEVERITY_OPTIONS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

type SourceFilterForm = VulnerabilitySourceFilterConfigRequest;

function isNotFoundError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }
  return error.message.includes('[NOT_FOUND]') || error.message.includes('(404)');
}

function readStoredNvdFullSyncApiKey(): string {
  try {
    return window.localStorage.getItem(NVD_FULL_SYNC_API_KEY_STORAGE_KEY) ?? '';
  } catch {
    return '';
  }
}

function maskSecret(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    return 'Not saved';
  }
  if (trimmed.length <= 4) {
    return '•'.repeat(trimmed.length);
  }
  return `${trimmed.slice(0, 2)}${'•'.repeat(Math.max(4, trimmed.length - 4))}${trimmed.slice(-2)}`;
}

function humanDuration(startedAt: string, completedAt?: string): string {
  if (!completedAt) return 'In progress';
  const start = new Date(startedAt).getTime();
  const end = new Date(completedAt).getTime();
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) {
    return 'n/a';
  }
  const seconds = Math.round((end - start) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

function isRunning(status: string): boolean {
  const value = status.trim().toUpperCase();
  return value === 'RUNNING' || value === 'STARTED' || value === 'QUEUED';
}

function includesType(run: SyncRun, needle: string): boolean {
  return run.syncType.toUpperCase().includes(needle.toUpperCase());
}

function isRunDomain(run: SyncRun, runDomain: SyncRun['runDomain']): boolean {
  return run.runDomain === runDomain;
}

function formatRunClass(runClass: SyncRun['runClass']): string {
  return runClass
    .split('_')
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1).toLowerCase())
    .join(' ');
}

function queuePositionLabel(run: SyncRun): string {
  if (!isRunning(run.status) || run.queuePosition == null) {
    return '-';
  }
  return run.queuePosition === 1 ? 'Running now' : `#${run.queuePosition}`;
}

function renderSnapshot(snapshot?: SyncRunSnapshot, emptyLabel = 'No run yet') {
  if (!snapshot) {
    return emptyLabel;
  }
  return (
    <>
      <div>{snapshot.status}</div>
      <div className="panel-caption">
        {snapshot.startedAt ? new Date(snapshot.startedAt).toLocaleString() : 'No start time'}
      </div>
      {snapshot.errorMessage && (
        <div className="panel-caption">{snapshot.errorMessage}</div>
      )}
    </>
  );
}

function deltaLabel(before: number, after: number): string {
  const delta = after - before;
  if (delta === 0) {
    return `${after} (no change)`;
  }
  return `${after} (${delta > 0 ? '+' : ''}${delta})`;
}

function sourceFilterSourceKey(focusSource: FocusSource): VulnerabilitySourceSystem | null {
  switch (focusSource) {
    case 'nvd':
      return 'nvd';
    case 'kev':
      return 'kev';
    case 'ghsa':
      return 'ghsa';
    case 'redhat-csaf':
      return 'redhat';
    default:
      return null;
  }
}

function defaultSourceFilterForm(sourceSystem: VulnerabilitySourceSystem): SourceFilterForm {
  switch (sourceSystem) {
    case 'nvd':
      return {
        hasKev: false,
        cvssV3Severity: '',
        cvssV4Severity: ''
      };
    case 'kev':
      return {
        dateAddedFrom: '',
        dateAddedTo: '',
        knownRansomwareCampaignUse: false
      };
    case 'ghsa':
      return {
        severity: ''
      };
    case 'redhat':
      return {
        severity: '',
        cvssScore: undefined,
        cvss3Score: undefined
      };
  }
}

function sourceFilterFormFromConfig(
  sourceSystem: VulnerabilitySourceSystem,
  config: VulnerabilitySourceFilterConfig | null
): SourceFilterForm {
  if (!config) {
    return defaultSourceFilterForm(sourceSystem);
  }
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
      return {
        severity: config.severity ?? ''
      };
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
      return {
        severity: trim(form.severity)
      };
    case 'redhat':
      return {
        severity: trim(form.severity),
        cvssScore: numberOrUndefined(form.cvssScore),
        cvss3Score: numberOrUndefined(form.cvss3Score)
      };
  }
}

export function SourcesPage({
  focusSource = 'all',
  title = 'Source Ingestion',
  caption = 'Ingest NVD/KEV/CSAF/VEX/advisories and normalize vulnerability intelligence',
  hideHeader = false,
  showTriggers = true,
  showQueue = true,
  refreshSignal = 0
}: Props) {
  const [syncRuns, setSyncRuns] = React.useState<SyncRun[]>([]);
  const [message, setMessage] = React.useState('');
  const [busy, setBusy] = React.useState<string | null>(null);
  const [loadingRuns, setLoadingRuns] = React.useState(false);
  const [confirmFullSync, setConfirmFullSync] = React.useState(false);
  const [nvdFullSyncApiKey, setNvdFullSyncApiKey] = React.useState(readStoredNvdFullSyncApiKey);
  const [nvdFullSyncApiKeyRequired, setNvdFullSyncApiKeyRequired] = React.useState(false);
  const [vexRepairSummary, setVexRepairSummary] = React.useState<VexAssertionRepairSummary | null>(null);
  const [loadingVexRepairSummary, setLoadingVexRepairSummary] = React.useState(false);
  const activeSourceFilterKey = sourceFilterSourceKey(focusSource);
  const [sourceFilters, setSourceFilters] = React.useState<SourceFilterForm>(
    activeSourceFilterKey == null ? {} : defaultSourceFilterForm(activeSourceFilterKey)
  );
  const [sourceFilterConfig, setSourceFilterConfig] = React.useState<VulnerabilitySourceFilterConfig | null>(null);
  const [loadingSourceFilters, setLoadingSourceFilters] = React.useState(false);
  const [savingSourceFilters, setSavingSourceFilters] = React.useState(false);
  const [isDirty, setIsDirty] = React.useState(false);
  const nvdFullSyncApiKeyInputRef = React.useRef<HTMLInputElement | null>(null);
  const showConnectorStatus = !showQueue && (focusSource === 'microsoft-csaf' || focusSource === 'redhat-csaf');
  const showVexRepairPanel = focusSource === 'processing';
  const shouldLoadVexRepairSummary = showVexRepairPanel;
  const showProcessingTriggers = focusSource === 'processing';
  const showNvdStatus = focusSource === 'nvd' && !showQueue;
  const shouldLoadRuns = showQueue || showConnectorStatus || showNvdStatus;
  const showNvdConnectorHero = showTriggers && focusSource === 'nvd' && !showQueue;
  const showSourceFilters = showTriggers && !showQueue && activeSourceFilterKey != null;
  const currentNvdFullSyncApiKey = nvdFullSyncApiKey.trim();

  const refreshRuns = React.useCallback(async () => {
    setLoadingRuns(true);
    try {
      const rows = await api.listSyncRuns(
        focusSource === 'github'
          ? { category: 'inventory', limit: 50 }
          : focusSource === 'processing'
            ? { category: 'processing', limit: 50 }
          : focusSource === 'all'
            ? { category: 'all', limit: 25 }
            : { category: 'vuln-intel', limit: 50 }
      );
      setSyncRuns(rows);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingRuns(false);
    }
  }, [focusSource]);

  const refreshVexRepairSummary = React.useCallback(async () => {
    if (!shouldLoadVexRepairSummary) {
      return;
    }
    setLoadingVexRepairSummary(true);
    try {
      const summary = await api.getVexAssertionRepairSummary();
      setVexRepairSummary(summary);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingVexRepairSummary(false);
    }
  }, [shouldLoadVexRepairSummary]);

  const refreshSourceFilters = React.useCallback(async () => {
    if (activeSourceFilterKey == null) {
      setSourceFilterConfig(null);
      setSourceFilters({});
      return;
    }
    setLoadingSourceFilters(true);
    try {
      const config = await api.getVulnerabilitySourceFilterConfig(activeSourceFilterKey);
      setSourceFilterConfig(config);
      setSourceFilters(sourceFilterFormFromConfig(activeSourceFilterKey, config));
      setIsDirty(false);
    } catch (e) {
      if (isNotFoundError(e)) {
        setSourceFilterConfig(null);
        setSourceFilters(defaultSourceFilterForm(activeSourceFilterKey));
        setIsDirty(false);
        return;
      }
      setMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingSourceFilters(false);
    }
  }, [activeSourceFilterKey]);

  React.useEffect(() => {
    if (!shouldLoadRuns) {
      return;
    }
    refreshRuns();
  }, [refreshRuns, shouldLoadRuns, refreshSignal]);

  React.useEffect(() => {
    refreshVexRepairSummary();
  }, [refreshSignal, refreshVexRepairSummary]);

  React.useEffect(() => {
    if (!showSourceFilters) {
      return;
    }
    void refreshSourceFilters();
  }, [showSourceFilters, refreshSourceFilters, refreshSignal]);

  React.useEffect(() => {
    try {
      if (!currentNvdFullSyncApiKey) {
        window.localStorage.removeItem(NVD_FULL_SYNC_API_KEY_STORAGE_KEY);
        return;
      }
      window.localStorage.setItem(NVD_FULL_SYNC_API_KEY_STORAGE_KEY, currentNvdFullSyncApiKey);
    } catch {
      // Browser-only persistence for the full-sync helper.
    }
  }, [currentNvdFullSyncApiKey]);

  React.useEffect(() => {
    if (currentNvdFullSyncApiKey && nvdFullSyncApiKeyRequired) {
      setNvdFullSyncApiKeyRequired(false);
    }
  }, [currentNvdFullSyncApiKey, nvdFullSyncApiKeyRequired]);

  React.useEffect(() => {
    if (!shouldLoadRuns) {
      return undefined;
    }
    if (!syncRuns.some((run) => isRunning(run.status))) {
      return undefined;
    }
    const id = window.setInterval(() => {
      refreshRuns();
      refreshVexRepairSummary();
    }, 3000);
    return () => window.clearInterval(id);
  }, [syncRuns, refreshRuns, refreshVexRepairSummary, shouldLoadRuns]);

  const runAction = async (
    label: string,
    fn: () => Promise<{ runId?: string; status?: string; message?: string } | unknown>
  ): Promise<void> => {
    setBusy(label);
    setMessage(`${label} started...`);
    try {
      const response = await fn();
      if (response && typeof response === 'object' && 'runId' in response) {
        const typed = response as { runId?: string; status?: string; message?: string };
        setMessage(`${label} queued: ${typed.runId ?? 'n/a'} (${typed.status ?? 'queued'})`);
      } else if (response && typeof response === 'object' && 'inserted' in response) {
        const typed = response as { inserted?: number; updated?: number };
        setMessage(`${label} finished. Inserted ${typed.inserted ?? 0}, updated ${typed.updated ?? 0}.`);
      } else {
        setMessage(`${label} completed`);
      }
      if (shouldLoadRuns) {
        await refreshRuns();
      }
      await refreshVexRepairSummary();
    } catch (e) {
      setMessage(`${label} failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(null);
    }
  };

  const saveSourceFilters = React.useCallback(async (silent = false): Promise<boolean> => {
    if (activeSourceFilterKey == null) {
      return true;
    }
    setSavingSourceFilters(true);
    try {
      const saved = await api.saveVulnerabilitySourceFilterConfig(
        activeSourceFilterKey,
        normalizeSourceFilterForm(activeSourceFilterKey, sourceFilters)
      );
      setSourceFilterConfig(saved);
      setSourceFilters(sourceFilterFormFromConfig(activeSourceFilterKey, saved));
      setIsDirty(false);
      if (!silent) {
        setMessage(`${saved.sourceSystem.toUpperCase()} filters saved.`);
      }
      return true;
    } catch (e) {
      if (isNotFoundError(e)) {
        if (!silent) {
          setMessage('Source filters are not available until the backend is refreshed.');
        }
        return silent;
      }
      setMessage(e instanceof Error ? e.message : String(e));
      return false;
    } finally {
      setSavingSourceFilters(false);
    }
  }, [activeSourceFilterKey, sourceFilters]);

  const runSourceAction = React.useCallback(async (
    label: string,
    fn: () => Promise<{ runId?: string; status?: string; message?: string } | unknown>
  ): Promise<void> => {
    if (activeSourceFilterKey != null) {
      const saved = await saveSourceFilters(true);
      if (!saved) {
        return;
      }
    }
    await runAction(label, fn);
  }, [activeSourceFilterKey, saveSourceFilters]);

  const runNvdFullSync = (): void => {
    if (!currentNvdFullSyncApiKey) {
      setNvdFullSyncApiKeyRequired(true);
      setMessage('Enter an NVD API key before starting the full corpus sync.');
      window.requestAnimationFrame(() => {
        nvdFullSyncApiKeyInputRef.current?.focus();
      });
      return;
    }
    void runSourceAction('NVD Full Sync', () => api.syncNvdFull({ apiKey: currentNvdFullSyncApiKey }));
  };

  const updateSourceFilterField = <K extends keyof SourceFilterForm>(key: K, value: SourceFilterForm[K]) => {
    setIsDirty(true);
    setSourceFilters((current) => {
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

  const visibleRuns = syncRuns.filter((run) => {
    if (focusSource === 'vuln-only') {
      return isRunDomain(run, 'VULN_INTEL');
    }
    if (focusSource === 'processing') {
      return isRunDomain(run, 'PROCESSING');
    }
    if (focusSource === 'nvd') {
      return includesType(run, 'NVD');
    }
    if (focusSource === 'kev') {
      return includesType(run, 'KEV');
    }
    if (focusSource === 'ghsa') {
      return includesType(run, 'GHSA');
    }
    if (focusSource === 'github') {
      return includesType(run, 'GITHUB_');
    }
    if (focusSource === 'advisories') {
      return includesType(run, 'ADVISORY') || includesType(run, 'RECOMPUTE');
    }
    if (focusSource === 'microsoft-csaf') {
      return includesType(run, 'CSAF_MICROSOFT');
    }
    if (focusSource === 'redhat-csaf') {
      return includesType(run, 'CSAF_REDHAT');
    }
    return true;
  });
  const orderedVisibleRuns = [...visibleRuns].sort(
    (left, right) => new Date(right.startedAt).getTime() - new Date(left.startedAt).getTime()
  );
  const latestConnectorRun = showConnectorStatus ? orderedVisibleRuns[0] : undefined;
  const connectorRunLabel = focusSource === 'microsoft-csaf' ? 'Latest Microsoft CSAF/VEX sync' : 'Latest Red Hat CSAF/VEX sync';

  const renderSyncRunSummary = (run?: SyncRun, emptyLabel = 'No run yet') => {
    if (!run) {
      return emptyLabel;
    }
    return (
      <>
        <div>{run.status}</div>
        <div className="panel-caption">{new Date(run.startedAt).toLocaleString()}</div>
        {run.errorMessage && <div className="panel-caption">{run.errorMessage}</div>}
      </>
    );
  };

  return (
    <div className="panel">
      {!hideHeader && (
        <div className="panel-header">
          <h3>{title}</h3>
          <span className="panel-caption">{caption}</span>
        </div>
      )}

      {(showTriggers || showQueue) && (
      <div className="button-row section-actions">
        {showTriggers && (focusSource === 'all' || focusSource === 'kev') && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy !== null || savingSourceFilters}
            onClick={() => runSourceAction('KEV Sync', () => api.syncKev())}
          >
            {busy === 'KEV Sync' ? 'Running...' : 'Run KEV Sync'}
          </button>
        )}
        {showTriggers && (focusSource === 'all' || focusSource === 'ghsa') && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy !== null || savingSourceFilters}
            onClick={() => runSourceAction('GHSA Sync', () => api.syncGhsa())}
          >
            {busy === 'GHSA Sync' ? 'Running...' : 'Run GHSA Sync'}
          </button>
        )}
        {showTriggers && (focusSource === 'all' || focusSource === 'microsoft-csaf') && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy !== null}
            onClick={() => runAction('Microsoft CSAF/VEX Sync', () => api.syncMicrosoftCsaf())}
          >
            {busy === 'Microsoft CSAF/VEX Sync' ? 'Running...' : 'Run Microsoft CSAF/VEX Sync'}
          </button>
        )}
        {showTriggers && (focusSource === 'all' || focusSource === 'redhat-csaf') && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy !== null || savingSourceFilters}
            onClick={() => runSourceAction('Red Hat CSAF/VEX Sync', () => api.syncRedhatCsaf())}
          >
            {busy === 'Red Hat CSAF/VEX Sync' ? 'Running...' : 'Run Red Hat CSAF/VEX Sync'}
          </button>
        )}
        {showTriggers && showProcessingTriggers && (
          <button
            type="button"
            className="btn btn-secondary"
            disabled={
              busy !== null
              || (vexRepairSummary != null && (!vexRepairSummary.vexRolloutControlsEnabled || !vexRepairSummary.vexRolloutBackfillEnabled))
            }
            onClick={() => runAction('Vendor VEX Backfill', () => api.triggerVexRolloutBackfill())}
          >
            {busy === 'Vendor VEX Backfill' ? 'Running...' : 'Run Vendor VEX Backfill'}
          </button>
        )}
        {showTriggers && showProcessingTriggers && (
          <button
            type="button"
            className="btn btn-secondary"
            disabled={busy !== null || (vexRepairSummary != null && !vexRepairSummary.vexRolloutControlsEnabled)}
            onClick={() => runAction('VEX Assertion Repair', () => api.triggerVexAssertionRepair())}
          >
            {busy === 'VEX Assertion Repair' ? 'Running...' : 'Rebuild Persisted VEX State'}
          </button>
        )}
        {showTriggers && (focusSource === 'all' || focusSource === 'advisories') && (
          <>
            <button
              type="button"
              className="btn btn-secondary"
              disabled={busy !== null}
              onClick={() => runAction('Seed Demo', () => api.seedDemo())}
            >
              {busy === 'Seed Demo' ? 'Running...' : 'Seed Demo Advisories'}
            </button>
          </>
        )}
      </div>
      )}

      {showNvdStatus && (
        <div className="nvd-overview-card">
          <div className="nvd-overview-meta">
            <p className="source-focus-description">
              Pulls CVE data from the National Vulnerability Database — CVSS scores, CPE mappings, and Known Exploited Vulnerability flags.
              Powers core vulnerability correlation across all your assets.
            </p>
            <div className="source-focus-pill-row">
              <span className="info-badge info-badge-blue">Scheduled daily at 01:00</span>
              <span className="info-badge info-badge-neutral">Delta sync by default</span>
            </div>
          </div>
          <div className="nvd-overview-status">
            <span className="connector-status-label">Last Sync</span>
            {orderedVisibleRuns[0] ? (
              <>
                <span className={`status-pill ${isRunning(orderedVisibleRuns[0].status) ? 'status-open' : 'status-resolved'}`}>
                  {orderedVisibleRuns[0].status}
                </span>
                <div className="panel-caption">{new Date(orderedVisibleRuns[0].startedAt).toLocaleString()}</div>
              </>
            ) : (
              <div className="panel-caption">{loadingRuns ? 'Loading...' : 'No sync run recorded yet'}</div>
            )}
          </div>
        </div>
      )}

      {showSourceFilters && activeSourceFilterKey != null && (
        <div className="section-block">
          <div className="source-filter-card">
            <div>
              <h4 className="section-title">Sync Configuration</h4>
              {sourceFilterConfig?.updatedAt && (
                <div className="panel-caption" style={{ marginTop: 8 }}>
                  Last saved {new Date(sourceFilterConfig.updatedAt).toLocaleString()}
                </div>
              )}
            </div>

            {loadingSourceFilters ? (
              <div className="panel-caption">Loading saved filters...</div>
            ) : (
              <>
                {activeSourceFilterKey === 'nvd' && (
                  <div>
                    <p className="field-hint" style={{ marginBottom: 12 }}>
                      Select CVSS v3 <em>or</em> CVSS v4 severity — choosing one automatically clears the other.
                    </p>
                    <div className="source-filter-grid">
                      <label className="source-filter-field">
                        <span>CVSS v3 Severity</span>
                        <select
                          value={sourceFilters.cvssV3Severity ?? ''}
                          onChange={(event) => updateSourceFilterField('cvssV3Severity', event.target.value)}
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
                          value={sourceFilters.cvssV4Severity ?? ''}
                          onChange={(event) => updateSourceFilterField('cvssV4Severity', event.target.value)}
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
                          value={sourceFilters.hasKev === true ? 'KEV_ONLY' : ''}
                          onChange={(event) => updateSourceFilterField('hasKev', event.target.value === 'KEV_ONLY')}
                        >
                          <option value="">Any</option>
                          <option value="KEV_ONLY">Known exploited only</option>
                        </select>
                        <span className="field-hint">Only returns CVEs already linked to CISA KEV.</span>
                      </label>
                    </div>
                  </div>
                )}

                {activeSourceFilterKey === 'kev' && (
                  <div className="source-filter-grid">
                    <label className="source-filter-field">
                      <span>Date Added From</span>
                      <input
                        type="date"
                        value={sourceFilters.dateAddedFrom ?? ''}
                        onChange={(event) => updateSourceFilterField('dateAddedFrom', event.target.value)}
                      />
                    </label>

                    <label className="source-filter-field">
                      <span>Date Added To</span>
                      <input
                        type="date"
                        value={sourceFilters.dateAddedTo ?? ''}
                        onChange={(event) => updateSourceFilterField('dateAddedTo', event.target.value)}
                      />
                    </label>

                    <label className="source-filter-field">
                      <span>Known Ransomware Campaign Use</span>
                      <select
                        value={sourceFilters.knownRansomwareCampaignUse === true ? 'KNOWN' : ''}
                        onChange={(event) => updateSourceFilterField('knownRansomwareCampaignUse', event.target.value === 'KNOWN')}
                      >
                        <option value="">Any</option>
                        <option value="KNOWN">Known ransomware campaign use</option>
                      </select>
                    </label>
                  </div>
                )}

                {activeSourceFilterKey === 'ghsa' && (
                  <div className="source-filter-grid">
                    <label className="source-filter-field">
                      <span>Severity</span>
                      <select
                        value={sourceFilters.severity ?? ''}
                        onChange={(event) => updateSourceFilterField('severity', event.target.value)}
                      >
                        <option value="">Any</option>
                        {SEVERITY_OPTIONS.map((option) => (
                          <option key={option} value={option}>{option}</option>
                        ))}
                      </select>
                    </label>
                  </div>
                )}

                {activeSourceFilterKey === 'redhat' && (
                  <div className="source-filter-grid">
                    <label className="source-filter-field">
                      <span>Severity</span>
                      <select
                        value={sourceFilters.severity ?? ''}
                        onChange={(event) => updateSourceFilterField('severity', event.target.value)}
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
                        value={sourceFilters.cvssScore ?? ''}
                        onChange={(event) => updateSourceFilterField(
                          'cvssScore',
                          event.target.value === '' ? undefined : Number(event.target.value)
                        )}
                        placeholder="7.0"
                      />
                    </label>

                    <label className="source-filter-field">
                      <span>CVSS v3 Score ≥</span>
                      <input
                        type="number"
                        min="0"
                        max="10"
                        step="0.1"
                        value={sourceFilters.cvss3Score ?? ''}
                        onChange={(event) => updateSourceFilterField(
                          'cvss3Score',
                          event.target.value === '' ? undefined : Number(event.target.value)
                        )}
                        placeholder="7.0"
                      />
                    </label>
                  </div>
                )}

                <div className="source-filter-actions">
                  <button
                    type="button"
                    className="btn btn-secondary"
                    disabled={savingSourceFilters || busy !== null}
                    onClick={() => {
                      void saveSourceFilters();
                    }}
                  >
                    {savingSourceFilters ? 'Saving...' : 'Save Filters'}
                  </button>
                  {isDirty && (
                    <span className="filter-unsaved-indicator">Unsaved changes</span>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {showNvdConnectorHero && (
        <div className="source-focus-hero">
          <div className="source-focus-hero-copy">
            <span className="source-focus-kicker">Recommended</span>
            <h4 className="source-focus-title">Sync Latest CVE Changes</h4>
            <div className="source-focus-pill-row">
              <span className="info-badge info-badge-blue">24h Delta</span>
              <span className="info-badge info-badge-amber">Lower DB Load</span>
            </div>
          </div>
          <div className="source-focus-hero-actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy !== null || savingSourceFilters}
              onClick={() => runSourceAction('NVD Sync', () => api.syncNvd())}
            >
              {busy === 'NVD Sync' ? 'Running...' : 'Run 24h Sync'}
            </button>
            <span className="panel-caption">Best for daily refreshes and repeat validation.</span>
          </div>
        </div>
      )}

      {showConnectorStatus && (
        <div className="connector-status-grid section-block">
          <div className="connector-status-card">
            <div className="connector-status-label">{connectorRunLabel}</div>
            <div className="connector-status-value">{renderSyncRunSummary(latestConnectorRun, 'No sync run recorded yet.')}</div>
          </div>
        </div>
      )}

      {showVexRepairPanel && (
        <div className="section-block">
          <h4 className="section-title">Shared VEX Maintenance</h4>
          <div className="panel-caption">
            Run vendor CSAF/VEX backfill and persisted assertion repair from one place, then compare current VEX coverage,
            rollout impact, and latest cross-vendor maintenance activity.
          </div>
          {vexRepairSummary && (
            <div className="panel-caption" style={{ marginTop: 8 }}>
              Controls: {vexRepairSummary.vexRolloutControlsEnabled ? 'enabled' : 'disabled'} | Backfill: {vexRepairSummary.vexRolloutBackfillEnabled ? 'enabled' : 'disabled'} |
              VEX policy: {vexRepairSummary.vexPolicyEnabled ? 'enabled' : 'disabled'} | Risk modifiers: {vexRepairSummary.vexRiskModifiersEnabled ? 'enabled' : 'disabled'}
            </div>
          )}
          {vexRepairSummary ? (
            <div className="table-scroll">
              <ResizableTable storageKey="vex-repair-summary-widths">
                <thead>
                  <tr>
                    <th>VEX-like Targets</th>
                    <th>Persisted Assertions</th>
                    <th>Matched Active States</th>
                    <th>Applicable Awaiting VEX</th>
                    <th>Source Systems</th>
                    <th>Latest Backfill Run</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>{vexRepairSummary.vexLikeTargetCount}</td>
                    <td>{vexRepairSummary.persistedAssertionCount}</td>
                    <td>{vexRepairSummary.activeMatchedComponentCount}</td>
                    <td>{vexRepairSummary.activeApplicableAwaitingVexCount}</td>
                    <td>{vexRepairSummary.sourceSystems.length > 0 ? vexRepairSummary.sourceSystems.join(', ') : '-'}</td>
                    <td>{renderSnapshot(vexRepairSummary.latestBackfillRun, 'No backfill run yet')}</td>
                  </tr>
                </tbody>
              </ResizableTable>
            </div>
          ) : (
            <div className="empty-state">
              <p>{loadingVexRepairSummary ? 'Loading VEX repair summary...' : 'No VEX repair summary available yet.'}</p>
            </div>
          )}
          {vexRepairSummary?.latestBackfillComparison && (
            <div className="table-scroll" style={{ marginTop: 12 }}>
              <ResizableTable storageKey="vex-rollout-comparison-widths">
                <thead>
                  <tr>
                    <th>Metric</th>
                    <th>Before Backfill</th>
                    <th>After Backfill</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>VEX-like Targets</td>
                    <td>{vexRepairSummary.latestBackfillComparison.before.vexLikeTargetCount}</td>
                    <td>{deltaLabel(
                      vexRepairSummary.latestBackfillComparison.before.vexLikeTargetCount,
                      vexRepairSummary.latestBackfillComparison.after.vexLikeTargetCount
                    )}</td>
                  </tr>
                  <tr>
                    <td>Persisted Assertions</td>
                    <td>{vexRepairSummary.latestBackfillComparison.before.persistedAssertionCount}</td>
                    <td>{deltaLabel(
                      vexRepairSummary.latestBackfillComparison.before.persistedAssertionCount,
                      vexRepairSummary.latestBackfillComparison.after.persistedAssertionCount
                    )}</td>
                  </tr>
                  <tr>
                    <td>Matched Active States</td>
                    <td>{vexRepairSummary.latestBackfillComparison.before.activeMatchedComponentCount}</td>
                    <td>{deltaLabel(
                      vexRepairSummary.latestBackfillComparison.before.activeMatchedComponentCount,
                      vexRepairSummary.latestBackfillComparison.after.activeMatchedComponentCount
                    )}</td>
                  </tr>
                  <tr>
                    <td>Applicable Awaiting VEX</td>
                    <td>{vexRepairSummary.latestBackfillComparison.before.activeApplicableAwaitingVexCount}</td>
                    <td>{deltaLabel(
                      vexRepairSummary.latestBackfillComparison.before.activeApplicableAwaitingVexCount,
                      vexRepairSummary.latestBackfillComparison.after.activeApplicableAwaitingVexCount
                    )}</td>
                  </tr>
                </tbody>
              </ResizableTable>
            </div>
          )}
          {vexRepairSummary && (
            <div className="table-scroll" style={{ marginTop: 12 }}>
              <ResizableTable storageKey="vex-rollout-runs-widths">
                <thead>
                  <tr>
                    <th>Microsoft CSAF/VEX</th>
                    <th>Red Hat CSAF/VEX</th>
                    <th>Persisted VEX Repair</th>
                    <th>Summary Generated</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>{renderSnapshot(vexRepairSummary.latestMicrosoftRun, 'No Microsoft sync yet')}</td>
                    <td>{renderSnapshot(vexRepairSummary.latestRedhatRun, 'No Red Hat sync yet')}</td>
                    <td>{renderSnapshot(vexRepairSummary.latestRepairRun, 'No repair run yet')}</td>
                    <td>{new Date(vexRepairSummary.generatedAt).toLocaleString()}</td>
                  </tr>
                </tbody>
              </ResizableTable>
            </div>
          )}
        </div>
      )}

      {showTriggers && (focusSource === 'all' || focusSource === 'nvd') && (
        <>
          <div className="section-block">
            <div className="nvd-api-key-block">
              <div className="nvd-api-key-label-row">
                <span className="connector-status-label">NVD API Key</span>
                {currentNvdFullSyncApiKey && (
                  <span className="panel-caption">{maskSecret(currentNvdFullSyncApiKey)}</span>
                )}
              </div>
              <input
                ref={nvdFullSyncApiKeyInputRef}
                type="password"
                value={nvdFullSyncApiKey}
                onChange={(event) => setNvdFullSyncApiKey(event.target.value)}
                placeholder="Paste NVD API key (saved locally in your browser)"
                autoComplete="off"
              />
              {nvdFullSyncApiKeyRequired && (
                <div className="sync-danger-error">An NVD API key is required for the full corpus sync.</div>
              )}
            </div>
          </div>

          <div className="section-block">
            <div className="sync-danger-card">
              <div className="sync-danger-copy">
                <span className="sync-danger-kicker">Danger Zone</span>
                <h4 className="sync-danger-title">Run NVD Full Corpus Sync</h4>
              </div>
              <div className="sync-danger-actions">
                <label className="bulk-checkbox sync-danger-checkbox">
                  <input
                    type="checkbox"
                    checked={confirmFullSync}
                    onChange={(event) => setConfirmFullSync(event.target.checked)}
                  />
                  <span className="sync-danger-checkbox-copy">I understand the runtime and database impact.</span>
                </label>
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={busy !== null || savingSourceFilters || !confirmFullSync}
                  onClick={runNvdFullSync}
                >
                  {busy === 'NVD Full Sync' ? 'Running...' : 'Run NVD Full Sync'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {message && <div className="notice">{message}</div>}

      {showQueue && (
        <>
          <div className="section-title-row section-divider">
            <h4 className="section-title" style={{ margin: 0 }}>
              {focusSource === 'processing' ? 'Recent Processing Jobs' : 'Recent Sync Runs'}
            </h4>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={loadingRuns || loadingVexRepairSummary}
              onClick={async () => {
                await refreshRuns();
                await refreshVexRepairSummary();
              }}
            >
              {loadingRuns || loadingVexRepairSummary ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
          {focusSource === 'github' && (
            <div className="panel-caption" style={{ marginBottom: 12 }}>
              GitHub ingestion runs use <span className="mono">Fetched</span> for discovered images or repositories,
              <span className="mono"> Inserted</span> for ingested components, <span className="mono"> Updated</span> for generated findings,
              and <span className="mono"> Failed</span> for assets that did not ingest successfully.
            </div>
          )}
          {focusSource === 'processing' && (
            <div className="panel-caption" style={{ marginBottom: 12 }}>
              Processing jobs track internal maintenance work like persisted VEX repair and rollout backfills. They do not represent upstream feed fetches.
            </div>
          )}
                {orderedVisibleRuns.length === 0 ? (
            <div className="empty-state">
              <p>{focusSource === 'processing'
                ? 'No processing jobs have been recorded yet.'
                : 'No sync runs yet. Run a sync to see results here.'}</p>
            </div>
          ) : (
            <div className="table-scroll">
              <ResizableTable storageKey="sync-runs-table-widths">
                <thead>
                <tr>
                  <th>Type</th>
                  <th>Trigger</th>
                  <th>Status</th>
                  <th>Queue Pos</th>
                  <th>Records (F / I / U / E)</th>
                  <th>Started</th>
                  <th>Completed</th>
                  <th>Duration</th>
                </tr>
                </thead>
                <tbody>
                {orderedVisibleRuns.map((run) => (
                  <tr key={run.id}>
                    <td>{run.syncType}</td>
                    <td>{formatRunClass(run.runClass)}</td>
                    <td>
                      <span className={`status-pill ${isRunning(run.status) ? 'status-open' : 'status-resolved'}`}>
                        {run.status}
                      </span>
                      {run.errorMessage && (
                        <div className="panel-caption" style={{ marginTop: 4, color: 'var(--critical)' }}>{run.errorMessage}</div>
                      )}
                    </td>
                    <td>{queuePositionLabel(run)}</td>
                    <td className="mono">{run.recordsFetched} / {run.recordsInserted} / {run.recordsUpdated} / {run.recordsFailed ?? 0}</td>
                    <td>{new Date(run.startedAt).toLocaleString()}</td>
                    <td>{run.completedAt ? new Date(run.completedAt).toLocaleString() : 'In progress'}</td>
                    <td>{humanDuration(run.startedAt, run.completedAt)}</td>
                  </tr>
                ))}
                </tbody>
              </ResizableTable>
            </div>
          )}
        </>
      )}
    </div>
  );
}
