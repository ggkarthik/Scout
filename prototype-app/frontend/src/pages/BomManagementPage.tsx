import React from 'react';
import { api, type BomFetchPayload, type BomIngestionResult, type BomType } from '../api/client';
import { GithubPipelineManager } from '../components/GithubPipelineManager';

type AssetType = 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
type IngestMode = 'url' | 'file';

const BOM_TYPES: { value: BomType; label: string; description: string }[] = [
  { value: 'SBOM', label: 'SBOM', description: 'Software Bill of Materials (CycloneDX / SPDX)' },
  { value: 'AI_BOM', label: 'AI BOM', description: 'AI/ML model bill of materials (CycloneDX 1.5+)' },
  { value: 'CBOM', label: 'CBOM', description: 'Cryptography bill of materials' },
  { value: 'VENDOR', label: 'Vendor BOM', description: 'Vendor-supplied BOM for third-party products' },
];

const ASSET_TYPES: { value: AssetType; label: string }[] = [
  { value: 'APPLICATION', label: 'Application' },
  { value: 'HOST', label: 'Host' },
  { value: 'CONTAINER_IMAGE', label: 'Container Image' },
];

const BOM_ICONS: Record<BomType, string> = {
  SBOM: '📦',
  AI_BOM: '🤖',
  CBOM: '🔐',
  VENDOR: '🏭',
};

type Props = {
  title?: string;
  caption?: string;
  includeGithubSources?: boolean;
};

// ── BOM metadata extraction ──────────────────────────────────────────────────

type ExtractedMeta = {
  assetType?: AssetType;
  assetName?: string;
  assetIdentifier?: string;
  supplier?: string;
};

function mapCycloneDxType(type: string): AssetType {
  const t = (type ?? '').toLowerCase();
  if (t === 'container') return 'CONTAINER_IMAGE';
  if (t === 'device' || t === 'firmware') return 'HOST';
  return 'APPLICATION';
}

function extractCycloneDxMeta(root: Record<string, unknown>): ExtractedMeta {
  const meta = root['metadata'] as Record<string, unknown> | undefined;
  const comp = meta?.['component'] as Record<string, unknown> | undefined;
  const supplierNode = (meta?.['supplier'] ?? meta?.['manufacturer']) as Record<string, unknown> | undefined;

  const name = comp?.['name'] as string | undefined;
  const purl = comp?.['purl'] as string | undefined;
  const version = comp?.['version'] as string | undefined;
  const type = comp?.['type'] as string | undefined;
  const supplierName = supplierNode?.['name'] as string | undefined;

  const identifier = purl || (name && version ? `pkg:generic/${name}@${version}` : name) || '';

  return {
    assetType: type ? mapCycloneDxType(type) : 'APPLICATION',
    assetName: name,
    assetIdentifier: identifier || undefined,
    supplier: supplierName,
  };
}

function extractSpdxMeta(root: Record<string, unknown>): ExtractedMeta {
  const docName = root['name'] as string | undefined;
  const ns = root['documentNamespace'] as string | undefined;
  const packages = root['packages'] as Array<Record<string, unknown>> | undefined;
  // First package that is NOT NOASSERTION and has a meaningful SPDXID
  const primary = packages?.find(
    (p) => p['SPDXID'] === 'SPDXRef-Package' || p['SPDXID'] === 'SPDXRef-RootPackage'
  ) ?? packages?.[0];

  const name = (primary?.['name'] as string) || docName;
  const version = primary?.['versionInfo'] as string | undefined;

  let purl: string | undefined;
  const refs = primary?.['externalRefs'] as Array<Record<string, unknown>> | undefined;
  if (refs) {
    const purlRef = refs.find((r) => (r['referenceType'] as string)?.toLowerCase() === 'purl');
    purl = purlRef?.['referenceLocator'] as string | undefined;
  }
  const identifier = purl || ns || (name && version ? `pkg:generic/${name}@${version}` : undefined);

  let supplierName: string | undefined;
  const rawSupplier = primary?.['supplier'] as string | undefined;
  if (rawSupplier && rawSupplier !== 'NOASSERTION') {
    supplierName = rawSupplier.replace(/^Organization:\s*/i, '').replace(/^Person:\s*/i, '').trim() || undefined;
  }

  return {
    assetType: 'APPLICATION',
    assetName: name,
    assetIdentifier: identifier,
    supplier: supplierName,
  };
}

function extractCycloneDxXmlMeta(doc: Document): ExtractedMeta | null {
  // Direct-child-only search by local name (namespace-agnostic)
  function firstEl(parent: Element, tag: string): Element | null {
    const nodes = parent.childNodes;
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (n.nodeType === 1 && (n as Element).localName === tag) return n as Element;
    }
    return null;
  }
  function text(parent: Element, tag: string): string | undefined {
    return firstEl(parent, tag)?.textContent?.trim() || undefined;
  }

  const bom = doc.documentElement;
  if (!bom || bom.localName !== 'bom') return null;
  const metadata = firstEl(bom, 'metadata');
  if (!metadata) return null;
  const comp = firstEl(metadata, 'component');
  if (!comp) return null;

  const name = text(comp, 'name');
  const version = text(comp, 'version');
  const purl = text(comp, 'purl');
  const typeAttr = comp.getAttribute('type') ?? undefined;

  const supplierEl = firstEl(metadata, 'supplier') ?? firstEl(metadata, 'manufacturer');
  const supplierName = supplierEl ? text(supplierEl, 'name') : undefined;

  const identifier = purl || (name && version ? `pkg:generic/${name}@${version}` : name) || undefined;
  if (!name && !identifier) return null;

  return {
    assetType: typeAttr ? mapCycloneDxType(typeAttr) : 'APPLICATION',
    assetName: name,
    assetIdentifier: identifier,
    supplier: supplierName,
  };
}

function parseBomMeta(text: string): ExtractedMeta | null {
  // Try JSON first (CycloneDX JSON or SPDX JSON)
  try {
    const root = JSON.parse(text) as Record<string, unknown>;
    const unwrapped = (root['sbom'] as Record<string, unknown>) ?? root;
    if (unwrapped['bomFormat'] || unwrapped['components'] || unwrapped['metadata']) {
      return extractCycloneDxMeta(unwrapped);
    }
    if (unwrapped['spdxVersion'] || unwrapped['packages']) {
      return extractSpdxMeta(unwrapped);
    }
    return null;
  } catch {
    // Fall through to XML
  }
  // Try CycloneDX XML
  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(text, 'application/xml');
    if (doc.querySelector('parsererror')) return null;
    if (doc.documentElement.localName === 'bom') {
      return extractCycloneDxXmlMeta(doc);
    }
    return null;
  } catch {
    return null;
  }
}

// ── Component ────────────────────────────────────────────────────────────────

export function BomManagementPage({
  title = 'BOM Management',
  caption = 'Ingest SBOM, AI BOM, CBOM, and Vendor BOM files via URL fetch or file upload.',
  includeGithubSources = true,
}: Props) {
  const [bomType, setBomType] = React.useState<BomType>('SBOM');
  const [mode, setMode] = React.useState<IngestMode>('url');
  const [assetType, setAssetType] = React.useState<AssetType>('APPLICATION');
  const [assetName, setAssetName] = React.useState('');
  const [assetIdentifier, setAssetIdentifier] = React.useState('');
  const [supplier, setSupplier] = React.useState('');
  const [metaSource, setMetaSource] = React.useState<string | null>(null); // which file/url populated fields

  // URL fetch fields
  const [sourceUrl, setSourceUrl] = React.useState('');
  const [authorizationHeader, setAuthorizationHeader] = React.useState('');
  const [showAuthHeader, setShowAuthHeader] = React.useState(false);
  const [urlParsing, setUrlParsing] = React.useState(false);

  // File upload fields
  const [file, setFile] = React.useState<File | null>(null);
  const [parseWarning, setParseWarning] = React.useState('');
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState('');
  const [result, setResult] = React.useState<BomIngestionResult | null>(null);
  function applyMeta(meta: ExtractedMeta, sourceName: string) {
    if (meta.assetType) setAssetType(meta.assetType);
    if (meta.assetName) setAssetName(meta.assetName);
    if (meta.assetIdentifier) setAssetIdentifier(meta.assetIdentifier);
    if (meta.supplier) setSupplier(meta.supplier);
    setMetaSource(sourceName);
  }

  function clearMeta() {
    setMetaSource(null);
    setParseWarning('');
  }

  function resetResult() {
    setError('');
    setResult(null);
  }

  // ── File selected: parse + auto-fill ──
  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0] ?? null;
    setFile(f);
    resetResult();
    clearMeta();
    setParseWarning('');
    if (!f) return;

    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      const meta = parseBomMeta(text);
      if (meta && (meta.assetName || meta.assetIdentifier)) {
        applyMeta(meta, f.name);
      } else if (f.name.endsWith('.json') || f.name.endsWith('.xml')) {
        setParseWarning('Could not extract metadata from this file. Fill in the fields manually.');
      }
    };
    reader.readAsText(f);
  }

  // ── URL preview: fetch + parse (best-effort, may fail due to CORS) ──
  async function handleUrlPreview() {
    const url = sourceUrl.trim();
    if (!url) return;
    setUrlParsing(true);
    clearMeta();
    setParseWarning('');
    try {
      const headers: Record<string, string> = {};
      if (showAuthHeader && authorizationHeader.trim()) {
        headers['Authorization'] = authorizationHeader.trim();
      }
      const res = await fetch(url, { headers });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      const meta = parseBomMeta(text);
      if (meta && (meta.assetName || meta.assetIdentifier)) {
        applyMeta(meta, url);
      } else {
        setParseWarning('URL fetched but no recognisable BOM metadata found. Fill in the fields manually.');
      }
    } catch {
      setParseWarning('Could not fetch the URL to preview metadata (possible CORS restriction). Fill in the fields manually.');
    } finally {
      setUrlParsing(false);
    }
  }

  const validate = (): string | null => {
    if (!assetName.trim()) return 'Asset Name is required';
    if (!assetIdentifier.trim()) return 'Asset Identifier is required';
    if (mode === 'url' && !sourceUrl.trim()) return 'Source URL is required';
    if (mode === 'file' && !file) return 'Please select a BOM file';
    return null;
  };

  const submit = async () => {
    const validationError = validate();
    if (validationError) { setError(validationError); return; }
    setError('');
    setResult(null);
    setLoading(true);
    try {
      if (mode === 'url') {
        const payload: BomFetchPayload = {
          bomType,
          assetType,
          assetName: assetName.trim(),
          assetIdentifier: assetIdentifier.trim(),
          sourceUrl: sourceUrl.trim(),
          supplier: supplier.trim() || undefined,
          authorizationHeader: showAuthHeader && authorizationHeader.trim() ? authorizationHeader.trim() : undefined,
        };
        setResult(await api.bomFetch(payload));
      } else {
        const formData = new FormData();
        formData.append('file', file!);
        formData.append('bomType', bomType);
        formData.append('assetType', assetType);
        formData.append('assetName', assetName.trim());
        formData.append('assetIdentifier', assetIdentifier.trim());
        if (supplier.trim()) formData.append('supplier', supplier.trim());
        setResult(await api.bomUpload(formData));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ingestion failed');
    } finally {
      setLoading(false);
    }
  };

  const canIngest = mode === 'file' ? !!file : !!sourceUrl.trim();

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <section className="panel">
        <div className="panel-header">
          <h3>{title}</h3>
          <span className="panel-caption">{caption}</span>
        </div>

        <div className="ingestion-form">

          {/* ── Section 1: BOM Type ── */}
          <div className="form-section">
            <p className="form-section-title">BOM Type</p>
            <div className="bom-type-cards">
              {BOM_TYPES.map((bt) => (
                <button
                  key={bt.value}
                  type="button"
                  className={`bom-type-card${bomType === bt.value ? ' selected' : ''}`}
                  onClick={() => { setBomType(bt.value as BomType); resetResult(); }}
                >
                  <span className="bom-type-icon">{BOM_ICONS[bt.value as BomType]}</span>
                  <span className="bom-type-name">{bt.label}</span>
                  <span className="bom-type-desc">{bt.description}</span>
                </button>
              ))}
            </div>
          </div>

          {/* ── Section 2: Source ── */}
          <div className="form-section">
            <p className="form-section-title">Source</p>

            <div className="bom-mode-row">
              <div className="ingestion-mode-tabs">
                <button
                  type="button"
                  className={`connect-filter-btn${mode === 'url' ? ' active' : ''}`}
                  onClick={() => { setMode('url'); resetResult(); clearMeta(); }}
                >
                  URL Fetch
                </button>
                <button
                  type="button"
                  className={`connect-filter-btn${mode === 'file' ? ' active' : ''}`}
                  onClick={() => { setMode('file'); resetResult(); clearMeta(); }}
                >
                  File Upload
                </button>
              </div>

              {mode === 'file' && (
                <div className="bom-inline-file">
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".json,.xml,.spdx,.rdf"
                    style={{ display: 'none' }}
                    onChange={handleFileChange}
                  />
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    Choose File
                  </button>
                  {file ? (
                    <span className="file-upload-name">{file.name} ({(file.size / 1024).toFixed(1)} KB)</span>
                  ) : (
                    <span className="panel-caption">No file chosen — .json, .xml, .spdx, .rdf</span>
                  )}
                </div>
              )}

              {mode === 'url' && (
                <div className="bom-inline-url">
                  <input
                    type="url"
                    className="form-input"
                    placeholder="https://example.com/sbom.json"
                    value={sourceUrl}
                    onChange={(e) => { setSourceUrl(e.target.value); clearMeta(); resetResult(); }}
                  />
                  <button
                    type="button"
                    className="btn btn-secondary"
                    disabled={!sourceUrl.trim() || urlParsing}
                    onClick={() => void handleUrlPreview()}
                  >
                    {urlParsing ? 'Fetching…' : 'Preview Metadata'}
                  </button>
                </div>
              )}
            </div>

            {mode === 'url' && (
              <div className="form-row">
                <label className="form-checkbox-label">
                  <input
                    type="checkbox"
                    checked={showAuthHeader}
                    onChange={(e) => setShowAuthHeader(e.target.checked)}
                  />
                  Include Authorization header
                </label>
                {showAuthHeader && (
                  <input
                    type="text"
                    className="form-input"
                    placeholder="Bearer <token>"
                    value={authorizationHeader}
                    onChange={(e) => setAuthorizationHeader(e.target.value)}
                    style={{ marginTop: 6 }}
                  />
                )}
              </div>
            )}
          </div>

          {/* ── Section 3: Asset Context ── */}
          <div className="form-section">
            <p className="form-section-title">Asset Context</p>

            {metaSource && (
              <div className="notice" style={{ marginBottom: 0 }}>
                Fields auto-filled from <strong>{metaSource}</strong>. Review and edit before ingesting.
              </div>
            )}
            {parseWarning && (
              <div className="notice error" style={{ marginBottom: 0 }}>{parseWarning}</div>
            )}

            <div className="form-row-2col">
              <label className="form-label">
                Asset Name
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. my-backend-service"
                  value={assetName}
                  onChange={(e) => setAssetName(e.target.value)}
                />
              </label>
              <label className="form-label">
                Asset Type
                <select
                  className="form-select"
                  value={assetType}
                  onChange={(e) => setAssetType(e.target.value as AssetType)}
                >
                  {ASSET_TYPES.map((at) => (
                    <option key={at.value} value={at.value}>{at.label}</option>
                  ))}
                </select>
              </label>
            </div>

            <div className="form-row">
              <label className="form-label">
                Asset Identifier
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. pkg:npm/my-backend@1.0.0 or git repo URL"
                  value={assetIdentifier}
                  onChange={(e) => setAssetIdentifier(e.target.value)}
                />
              </label>
            </div>

            <div className="form-row">
              <label className="form-label">
                Supplier{' '}
                <span style={{ fontWeight: 400, color: 'var(--muted)' }}>(optional)</span>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Acme Corp"
                  value={supplier}
                  onChange={(e) => setSupplier(e.target.value)}
                />
              </label>
            </div>
          </div>

          {/* ── Action bar ── */}
          <div className="form-actions-bar">
            <button
              type="button"
              className="btn btn-primary"
              disabled={loading || !canIngest}
              onClick={() => void submit()}
            >
              {loading ? 'Ingesting…' : 'Ingest'}
            </button>
            {error && <p className="form-error" style={{ margin: 0 }}>{error}</p>}
          </div>

          {/* ── Result ── */}
          {result && (
            <div className="ingestion-result ingestion-result--success">
              <div className="ingestion-result-metrics">
                <div className="result-metric">
                  <span className="result-metric-value">{result.componentCount}</span>
                  <span className="result-metric-label">Components ingested</span>
                </div>
                <div className="result-metric">
                  <span className="result-metric-value">{result.findingsGenerated}</span>
                  <span className="result-metric-label">Findings generated</span>
                </div>
              </div>
              <div className="result-meta">
                <span>{result.action} · {result.bomType} · {result.format} {result.formatVersion}</span>
                <span>{result.specFamily} · {result.documentFormat} · {result.supportLevel}</span>
                <span>BOM ID: <code>{result.bomId}</code></span>
              </div>
              {result.warnings.length > 0 && (
                <div style={{ display: 'grid', gap: 8, marginTop: 12 }}>
                  {result.warnings.map((warning) => (
                    <div key={warning} className="notice error">{warning}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </section>


      {includeGithubSources && (
        <GithubPipelineManager
          title="GitHub BOM Sources"
          caption="Use GitHub repository and GHCR sources as BOM acquisition adapters inside the same BOM management workflow."
        />
      )}
    </div>
  );
}
