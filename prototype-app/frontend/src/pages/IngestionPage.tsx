import React from 'react';
import { api, uploadSbom } from '../api/client';
import { GithubRepoIngestionResult, SbomUploadEvidence } from '../types';
import { ResizableTable } from '../components/ResizableTable';

export type IngestionMode = 'upload' | 'endpoint' | 'github';
type Props = {
  onDone?: () => void;
  initialMode?: IngestionMode;
  hideModeToggle?: boolean;
  title?: string;
  caption?: string;
};
const MODE_QUERY_KEY = 'ingestMode';

function formatBytes(bytes?: number): string {
  if (!bytes || bytes <= 0) return 'N/A';
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = bytes;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}

function parseEvidenceJson(value?: string): string {
  if (!value || !value.trim()) {
    return '{}';
  }
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

function formatStatusLabel(value: 'IN_PROGRESS' | 'SUCCESS' | 'FAILURE'): string {
  return value.replace('_', ' ');
}

function statusClassName(value: 'IN_PROGRESS' | 'SUCCESS' | 'FAILURE'): string {
  return `status-${value.toLowerCase().replace('_', '-')}`;
}

function isMode(value: string | null): value is IngestionMode {
  return value === 'upload' || value === 'endpoint' || value === 'github';
}

function readModeFromQuery(): IngestionMode {
  const value = new URLSearchParams(window.location.search).get(MODE_QUERY_KEY);
  return isMode(value) ? value : 'upload';
}

function writeModeToQuery(mode: IngestionMode): void {
  const url = new URL(window.location.href);
  if (mode === 'upload') {
    url.searchParams.delete(MODE_QUERY_KEY);
  } else {
    url.searchParams.set(MODE_QUERY_KEY, mode);
  }
  window.history.replaceState({}, '', `${url.pathname}?${url.searchParams.toString()}`);
}

export function IngestionPage({
  onDone,
  initialMode,
  hideModeToggle = false,
  title = 'SBOM Ingestion',
  caption = 'Upload files or fetch SBOM JSON from GitHub/tool endpoints with evidence retention'
}: Props) {
  const [mode, setMode] = React.useState<IngestionMode>(() => initialMode ?? readModeFromQuery());
  const [assetType, setAssetType] = React.useState<'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'>('APPLICATION');
  const [assetName, setAssetName] = React.useState('');
  const [assetIdentifier, setAssetIdentifier] = React.useState('');
  const [showGithubAssetOverrides, setShowGithubAssetOverrides] = React.useState(false);
  const [file, setFile] = React.useState<File | null>(null);

  const [sourceUrl, setSourceUrl] = React.useState('');
  const [sourceLabel, setSourceLabel] = React.useState('');
  const [authorizationHeader, setAuthorizationHeader] = React.useState('');
  const [showAuthorizationHeader, setShowAuthorizationHeader] = React.useState(false);

  const [githubOwner, setGithubOwner] = React.useState('');
  const [githubRepo, setGithubRepo] = React.useState('');
  const [githubRunResults, setGithubRunResults] = React.useState<GithubRepoIngestionResult[]>([]);

  const [uploads, setUploads] = React.useState<SbomUploadEvidence[]>([]);
  const [result, setResult] = React.useState('');
  const [error, setError] = React.useState('');
  const [loading, setLoading] = React.useState(false);

  const loadUploads = React.useCallback(async () => {
    try {
      const rows = await api.listSbomUploads();
      setUploads(rows);
    } catch (e) {
      setError(`Failed to load upload history: ${e instanceof Error ? e.message : String(e)}`);
    }
  }, []);

  React.useEffect(() => {
    setError('');
    loadUploads();
  }, [loadUploads]);

  React.useEffect(() => {
    if (initialMode && mode !== initialMode) {
      setMode(initialMode);
      return;
    }
    if (!hideModeToggle) {
      writeModeToQuery(mode);
    }
  }, [mode, initialMode, hideModeToggle]);

  const validateCommon = (currentMode: IngestionMode): string | null => {
    if (currentMode === 'github') {
      return null;
    }
    if (!assetName.trim()) return 'Asset Name is required';
    if (!assetIdentifier.trim()) return 'Asset Identifier is required';
    return null;
  };

  const submit = async (): Promise<void> => {
    const commonError = validateCommon(mode);
    if (commonError) {
      setError(commonError);
      return;
    }

    setError('');
    setResult('');
    setGithubRunResults([]);
    const githubOwnerValue = githubOwner.trim();
    const githubRepoValue = githubRepo.trim();
    if (mode === 'github') {
      if (!githubOwnerValue) {
        setError('GitHub owner/account is required in GitHub mode');
        return;
      }
      if (!githubRepoValue) {
        const proceed = window.confirm(
          `Repository is empty. This will ingest SBOMs for all repositories under "${githubOwnerValue}". Continue?`
        );
        if (!proceed) {
          return;
        }
      }
    }
    setLoading(true);
    try {
      if (mode === 'upload') {
        if (!file) {
          throw new Error('Please choose an SBOM file for upload mode');
        }
        const response = await uploadSbom({
          assetType,
          assetName: assetName.trim(),
          assetIdentifier: assetIdentifier.trim(),
          file
        });
        setResult(`Ingested successfully. Components: ${response.componentsIngested}`);
      } else if (mode === 'endpoint') {
        if (!sourceUrl.trim()) {
          throw new Error('Source URL is required in endpoint mode');
        }
        const response = await api.fetchSbomFromEndpoint({
          assetType,
          assetName: assetName.trim(),
          assetIdentifier: assetIdentifier.trim(),
          sourceUrl: sourceUrl.trim(),
          sourceLabel: sourceLabel.trim() || undefined,
          authorizationHeader: authorizationHeader.trim() || undefined
        });
        setResult(`Ingested successfully. Components: ${response.componentsIngested}`);
      } else {
        const response = await api.fetchSbomFromGithub({
          owner: githubOwnerValue,
          repo: githubRepoValue || undefined,
          includeAllRepos: !githubRepoValue,
          assetType: showGithubAssetOverrides ? assetType : undefined,
          assetName: showGithubAssetOverrides && githubRepoValue ? assetName.trim() || undefined : undefined,
          assetIdentifier: showGithubAssetOverrides && githubRepoValue ? assetIdentifier.trim() || undefined : undefined
        });
        setGithubRunResults(response.results || []);
        setResult(
          `GitHub ingestion complete. Processed ${response.repositoriesProcessed}/${response.repositoriesDiscovered} repos `
          + `(success: ${response.repositoriesSucceeded}, failed: ${response.repositoriesFailed}). `
          + `Components: ${response.componentsIngested}`
        );
      }

      await loadUploads();
      onDone?.();
    } catch (e) {
      setError(`SBOM ingestion failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  };

  const isGithubSingleRepo = githubRepo.trim().length > 0;

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>{title}</h3>
        <span className="panel-caption">{caption}</span>
      </div>

      <div className="section-block">
        {!hideModeToggle && (
          <div className="mode-toggle">
            <button type="button" className={mode === 'upload' ? 'mode-btn active' : 'mode-btn'} onClick={() => setMode('upload')}>
              File Upload
            </button>
            <button type="button" className={mode === 'endpoint' ? 'mode-btn active' : 'mode-btn'} onClick={() => setMode('endpoint')}>
              API Endpoint
            </button>
            <button type="button" className={mode === 'github' ? 'mode-btn active' : 'mode-btn'} onClick={() => setMode('github')}>
              GitHub Source
            </button>
          </div>
        )}

        <div className="form-grid ingestion-grid">
          {mode !== 'github' && (
            <>
              <label>Asset Type
                <select value={assetType} onChange={(e) => setAssetType(e.target.value as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE')}>
                  <option value="APPLICATION">Application</option>
                  <option value="HOST">Host</option>
                  <option value="CONTAINER_IMAGE">Container Image</option>
                </select>
              </label>

              <label>Asset Name
                <input
                  value={assetName}
                  onChange={(e) => setAssetName(e.target.value)}
                  placeholder="payments-api-prod"
                />
              </label>

              <label>Asset Identifier
                <input
                  value={assetIdentifier}
                  onChange={(e) => setAssetIdentifier(e.target.value)}
                  placeholder="host-001 or image digest"
                />
              </label>
            </>
          )}

          {mode === 'upload' && (
            <label>SBOM File (CycloneDX or SPDX)
              <input type="file" accept="application/json,.json" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            </label>
          )}

          {mode === 'endpoint' && (
            <>
              <label>SBOM Endpoint URL
                <input
                  value={sourceUrl}
                  onChange={(e) => setSourceUrl(e.target.value)}
                  placeholder="https://tool.example.com/api/sbom/project-a"
                />
              </label>

              <label>Source Label (optional)
                <input
                  value={sourceLabel}
                  onChange={(e) => setSourceLabel(e.target.value)}
                  placeholder="Prod CycloneDX Generator"
                />
              </label>

              <label>Authorization Header (optional)
                <div className="secure-input-row">
                  <input
                    type={showAuthorizationHeader ? 'text' : 'password'}
                    value={authorizationHeader}
                    onChange={(e) => setAuthorizationHeader(e.target.value)}
                    placeholder="Bearer <token> or Basic <base64>"
                    autoComplete="off"
                  />
                  <button
                    type="button"
                    className="btn btn-secondary btn-inline"
                    onClick={() => setShowAuthorizationHeader((current) => !current)}
                  >
                    {showAuthorizationHeader ? 'Hide' : 'Show'}
                  </button>
                </div>
              </label>
            </>
          )}

          {mode === 'github' && (
            <>
              <label>GitHub Owner
                <input value={githubOwner} onChange={(e) => setGithubOwner(e.target.value)} placeholder="org-name" />
              </label>

              <label>GitHub Repo (optional)
                <input
                  value={githubRepo}
                  onChange={(e) => setGithubRepo(e.target.value)}
                  placeholder="service-repo (leave empty to ingest all repos)"
                />
              </label>

              <div className="inline-note">
                Default asset classification is <span className="mono">APPLICATION</span>. If repo is empty, the app confirms and ingests all
                repositories in the owner account. Each repository is normalized into a unique asset using{' '}
                <span className="mono">github:owner/repo</span>, and org/repo lineage is stored in upload evidence.
              </div>

              <div className="button-row form-submit-row">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowGithubAssetOverrides((current) => !current)}
                >
                  {showGithubAssetOverrides ? 'Hide Asset Overrides' : 'Show Asset Overrides'}
                </button>
              </div>

              {showGithubAssetOverrides && (
                <>
                  <label>Asset Type Override
                    <select value={assetType} onChange={(e) => setAssetType(e.target.value as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE')}>
                      <option value="APPLICATION">Application</option>
                      <option value="HOST">Host</option>
                      <option value="CONTAINER_IMAGE">Container Image</option>
                    </select>
                  </label>
                  {isGithubSingleRepo ? (
                    <>
                      <label>Asset Name Override (optional)
                        <input
                          value={assetName}
                          onChange={(e) => setAssetName(e.target.value)}
                          placeholder="repo-name default"
                        />
                      </label>
                      <label>Asset Identifier Override (optional)
                        <input
                          value={assetIdentifier}
                          onChange={(e) => setAssetIdentifier(e.target.value)}
                          placeholder="github:owner/repo default"
                        />
                      </label>
                    </>
                  ) : (
                    <div className="inline-note">
                      Repo is empty, so account-wide ingestion will always set asset name/identifier per repository to preserve{' '}
                      <span className="mono">org/repo</span> lineage.
                    </div>
                  )}
                </>
              )}

              <div className="inline-note">
                GitHub mode pulls the generated SBOM from <span className="mono">/repos/&lt;owner&gt;/&lt;repo&gt;/dependency-graph/sbom</span>.
                API tokens are configured server-side via secure env/file settings and are never stored in pipeline records.
                Auto-ingestion pipelines are configured from the <span className="mono">Configurations</span> section.
              </div>
            </>
          )}
        </div>

        <div className="button-row form-submit-row">
          <button type="button" className="btn btn-primary" onClick={submit} disabled={loading}>
            {loading ? 'Ingesting...' : 'Ingest SBOM'}
          </button>
        </div>
      </div>

      {result && <div className="notice">{result}</div>}
      {error && <div className="notice error">{error}</div>}
      {mode === 'github' && githubRunResults.length > 0 && (
        <>
          <h4 className="section-title section-divider">Latest GitHub Repo Processing</h4>
          <div className="table-scroll">
            <ResizableTable storageKey="github-latest-run-table-widths">
              <thead>
              <tr>
                <th>Org</th>
                <th>Repo</th>
                <th>Status</th>
                <th>Asset Identifier</th>
                <th>Components</th>
                <th>Details</th>
              </tr>
              </thead>
              <tbody>
              {githubRunResults.map((row) => (
                <tr key={`${row.owner}/${row.repo}`}>
                  <td>{row.owner}</td>
                  <td>{row.repo}</td>
                  <td>
                    <span className={`status-pill ${row.status === 'SUCCESS' ? 'status-success' : 'status-failure'}`}>
                      {row.status}
                    </span>
                  </td>
                  <td className="mono">{row.assetIdentifier}</td>
                  <td>{row.componentsIngested ?? '-'}</td>
                  <td>{row.message || '-'}</td>
                </tr>
              ))}
              </tbody>
            </ResizableTable>
          </div>
        </>
      )}

      <h4 className="section-title section-divider">SBOM Upload Evidence</h4>
      {uploads.length === 0 ? (
        <div className="empty-state">
          <p>No SBOM uploads yet. Upload a CycloneDX/SPDX file or fetch from API/GitHub to build evidence history.</p>
        </div>
      ) : (
        <div className="table-scroll">
          <ResizableTable storageKey="sbom-evidence-table-widths">
            <thead>
            <tr>
              <th>Uploaded</th>
              <th>Status</th>
              <th>Asset</th>
              <th>Source</th>
              <th>Format</th>
              <th>Size</th>
              <th>Components</th>
              <th>Evidence</th>
            </tr>
            </thead>
            <tbody>
            {uploads.map((upload) => (
              <tr key={upload.id}>
                <td>{new Date(upload.uploadedAt).toLocaleString()}</td>
                <td>
                  <span className={`status-pill ${statusClassName(upload.status)}`}>
                    {formatStatusLabel(upload.status)}
                  </span>
                </td>
                <td>{`${upload.assetName} (${upload.assetIdentifier})`}</td>
                <td>
                  <div>{upload.ingestionSourceType ?? 'UNKNOWN'}</div>
                  <div className="panel-caption">{upload.sourceReference ?? upload.originalFilename}</div>
                </td>
                <td>{upload.format}</td>
                <td>{formatBytes(upload.contentLengthBytes)}</td>
                <td>{upload.componentCount ?? 'N/A'}</td>
                <td>
                  <details className="evidence-details">
                    <summary>View</summary>
                    <pre>{parseEvidenceJson(upload.evidenceJson)}</pre>
                  </details>
                </td>
              </tr>
            ))}
            </tbody>
          </ResizableTable>
        </div>
      )}
    </div>
  );
}
