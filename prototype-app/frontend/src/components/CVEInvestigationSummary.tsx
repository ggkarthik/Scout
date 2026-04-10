import React from 'react';
import type { InvestigationSummaryResponse } from '../features/cve-workbench/types';
import {
  Document,
  HeadingLevel,
  Packer,
  Paragraph,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
} from 'docx';

const COLORS = {
  background: 'var(--panel-muted)',
  surface: 'var(--panel-solid)',
  surfaceMuted: 'color-mix(in srgb, var(--panel-muted) 88%, var(--bg))',
  accent: 'var(--accent)',
  accentStrong: 'var(--accent-strong)',
  text: 'var(--text)',
  title: 'var(--title)',
  muted: 'var(--muted)',
  danger: 'var(--critical)',
  warning: 'var(--high)',
  caution: 'var(--medium)',
  success: 'var(--low)',
  border: 'var(--border)',
  borderStrong: 'var(--border-strong)',
  track: 'var(--track)',
};

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8080/api';
const API_KEY = import.meta.env.VITE_API_KEY ?? 'change-me-in-prod';
const CREATOR_KEY = import.meta.env.VITE_CREATOR_KEY ?? 'local-creator';

const LOADING_STEPS = [
  'Analyzing 4 runbook results...',
  'Cross-referencing asset exposure...',
  'Generating remediation plan...',
];

export type InvestigationSummaryInput = {
  summary: {
    cveId: string;
    title: string;
    description?: string;
    severity: string;
    cvssScore?: number;
    epssScore?: number;
    inKev?: boolean;
    exploitAvailable?: boolean;
    patchAvailable?: boolean;
    patchVersions?: string;
  };
  investigation: {
    leadAnalyst?: string;
  };
  runbookResults: Array<{
    id: string;
    title: string;
    state: string;
  }>;
  affectedAssets: Array<{
    id: string;
    hostname: string;
    ipAddress?: string;
    os?: string;
    owner?: string;
    environment?: string;
    externalFacing?: boolean;
    critical?: boolean;
    matchedSoftware: Array<{
      software: string;
      version?: string;
    }>;
  }>;
  falsePositiveRows: Array<{
    software: string;
    version?: string;
    falsePositive: boolean;
    assetsNotImpacted?: number;
    vendorGuidance?: string;
  }>;
  eolRows: Array<{
    software: string;
    vendor?: string;
    version?: string;
    lifecycle?: string;
    endOfSupport?: string;
    endOfLife?: string;
    recommendedUpgrade?: string;
  }>;
};

type SummaryMode = 'deterministic' | 'ai';

type Props = {
  visible: boolean;
  input: InvestigationSummaryInput;
  initialSummary?: InvestigationSummaryResponse | null;
  initialMode?: SummaryMode;
  autoGenerate?: boolean;
  readOnly?: boolean;
};

function severityColor(severity: string): string {
  const normalized = severity.toUpperCase();
  if (normalized === 'CRITICAL') return COLORS.danger;
  if (normalized === 'HIGH') return COLORS.warning;
  if (normalized === 'MEDIUM') return COLORS.caution;
  return COLORS.success;
}

function timeframeColor(timeframe: string): string {
  const normalized = timeframe.toLowerCase();
  if (normalized.includes('immediate')) return COLORS.danger;
  if (normalized.includes('short')) return COLORS.warning;
  if (normalized.includes('medium')) return COLORS.caution;
  return COLORS.success;
}

function formatDateTime(value?: string): string {
  if (!value) return '—';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function riskMeterGradient(score: number): string {
  if (score >= 85) return `linear-gradient(90deg, ${COLORS.danger}, color-mix(in srgb, ${COLORS.danger} 62%, white))`;
  if (score >= 70) return `linear-gradient(90deg, ${COLORS.warning}, color-mix(in srgb, ${COLORS.warning} 58%, white))`;
  if (score >= 45) return `linear-gradient(90deg, ${COLORS.caution}, color-mix(in srgb, ${COLORS.caution} 58%, white))`;
  return `linear-gradient(90deg, ${COLORS.success}, color-mix(in srgb, ${COLORS.success} 60%, white))`;
}

function tonedSurface(color: string, strength = 14): string {
  return `color-mix(in srgb, ${color} ${strength}%, var(--panel-muted))`;
}

function tonedBorder(color: string, strength = 26): string {
  return `color-mix(in srgb, ${color} ${strength}%, var(--border))`;
}

async function generateSummaryRequest(
  input: InvestigationSummaryInput,
  mode: SummaryMode
): Promise<{ summary?: InvestigationSummaryResponse; rawText?: string; error?: string }> {
  const headers = new Headers();
  headers.set('Content-Type', 'application/json');
  headers.set('X-API-Key', API_KEY);
  if (CREATOR_KEY.trim().length > 0) headers.set('X-Creator-Key', CREATOR_KEY);
  const path = mode === 'ai' ? 'investigation-ai-summary' : 'investigation-summary';

  try {
    const response = await fetch(`${API_BASE}/cve-detail/${encodeURIComponent(input.summary.cveId)}/${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(input),
    });

    if (!response.ok) {
      const text = await response.text();
      return { error: text || `Request failed (${response.status})` };
    }

    const contentType = response.headers.get('content-type') ?? '';
    if (!contentType.includes('application/json')) {
      return { rawText: await response.text() };
    }

    return { summary: await response.json() as InvestigationSummaryResponse };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

async function exportWordDocument(input: InvestigationSummaryInput, summary: InvestigationSummaryResponse): Promise<void> {
  const externalAssets = input.affectedAssets.filter((asset) => asset.externalFacing);
  const internalAssetCount = Math.max(0, input.affectedAssets.length - externalAssets.length);
  const falsePositiveRows = input.falsePositiveRows.filter((row) => row.falsePositive);
  const eolRows = input.eolRows.filter((row) => (row.lifecycle ?? '').toLowerCase() !== 'supported');

  const doc = new Document({
    sections: [
      {
        children: [
          new Paragraph({
            text: `CVE Investigation Summary — ${input.summary.cveId}`,
            heading: HeadingLevel.TITLE,
          }),
          new Paragraph(`Date generated: ${formatDateTime(summary.generatedAt)}`),
          new Paragraph(`CVSS: ${input.summary.cvssScore ?? '—'}   Severity: ${input.summary.severity}`),
          new Paragraph({ text: 'Executive Summary', heading: HeadingLevel.HEADING_1 }),
          new Paragraph(summary.executiveSummary),
          new Paragraph({ text: 'Impact Analysis', heading: HeadingLevel.HEADING_1 }),
          new Paragraph(`Risk: ${summary.riskAnalysis.level} (${summary.riskAnalysis.score})`),
          new Paragraph(summary.riskAnalysis.rationale),
          new Paragraph({ text: 'External-Facing Assets', heading: HeadingLevel.HEADING_2 }),
          buildTable([
            ['Hostname', 'IP', 'OS', 'Owner', 'Environment'],
            ...externalAssets.map((asset) => [asset.hostname, asset.ipAddress || '—', asset.os || '—', asset.owner || '—', asset.environment || '—']),
          ]),
          new Paragraph({ text: 'Internal Assets', heading: HeadingLevel.HEADING_2 }),
          new Paragraph(`Internal asset count: ${internalAssetCount}`),
          new Paragraph({ text: 'False Positives', heading: HeadingLevel.HEADING_2 }),
          buildTable([
            ['Asset / Software', 'Reason', 'Confidence'],
            ...falsePositiveRows.map((row) => [row.software, row.vendorGuidance || 'Vendor guidance matched', 'High']),
          ]),
          new Paragraph({ text: 'End-of-Life Assets', heading: HeadingLevel.HEADING_2 }),
          buildTable([
            ['Hostname / Software', 'Product Version', 'EOL Date', 'Status'],
            ...eolRows.map((row) => [row.software, row.version || '—', row.endOfLife || '—', row.lifecycle || '—']),
          ]),
          new Paragraph({ text: 'Patch Compliance', heading: HeadingLevel.HEADING_2 }),
          new Paragraph(`Patched vs unpatched: ${input.summary.patchAvailable ? 'Patch available' : 'Patch unavailable'}; unpatched vulnerable assets: ${summary.metrics.unpatchedVulnerable}`),
          new Paragraph({ text: 'Remediation Plan', heading: HeadingLevel.HEADING_1 }),
          ...summary.remediationPlan.map((action) => new Paragraph(`${action.priority}. ${action.title} — ${action.detail} [${action.owner}; ${action.timeframe}]`)),
          new Paragraph({ text: 'Key Findings', heading: HeadingLevel.HEADING_1 }),
          ...summary.keyFindings.map((finding) => new Paragraph({ text: finding, bullet: { level: 0 } })),
          new Paragraph({ text: 'Metrics Summary', heading: HeadingLevel.HEADING_1 }),
          buildTable([
            ['Total Affected', 'True Positives', 'False Positives', 'External Facing', 'Unpatched Vulnerable', 'EOL Count'],
            [
              String(summary.metrics.totalAffected),
              String(summary.metrics.truePositives),
              String(summary.metrics.falsePositives),
              String(summary.metrics.externalFacing),
              String(summary.metrics.unpatchedVulnerable),
              String(summary.metrics.eolCount),
            ],
          ]),
          new Paragraph('Generated by T-Hub CVE Investigation Runbook'),
        ],
      },
    ],
  });

  const blob = await Packer.toBlob(doc);
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${input.summary.cveId}-investigation-summary.docx`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function buildTable(rows: string[][]): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: rows.map((row, rowIndex) => new TableRow({
      children: row.map((cell) => new TableCell({
        width: { size: 100 / row.length, type: WidthType.PERCENTAGE },
        children: [
          new Paragraph({
            children: [
              new TextRun({
                text: cell,
                bold: rowIndex === 0,
              }),
            ],
          }),
        ],
      })),
    })),
  });
}

export function CVEInvestigationSummary({
  visible,
  input,
  initialSummary = null,
  initialMode = 'deterministic',
  autoGenerate = true,
  readOnly = false,
}: Props) {
  const [summary, setSummary] = React.useState<InvestigationSummaryResponse | null>(initialSummary);
  const [error, setError] = React.useState<string | null>(null);
  const [rawText, setRawText] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [loadingIndex, setLoadingIndex] = React.useState(0);
  const [expandedExternalAssets, setExpandedExternalAssets] = React.useState(false);
  const [summaryMode, setSummaryMode] = React.useState<SummaryMode>(initialMode);
  const inputKey = React.useMemo(() => JSON.stringify(input), [input]);

  const externalAssets = React.useMemo(
    () => input.affectedAssets.filter((asset) => asset.externalFacing),
    [input.affectedAssets]
  );

  const internalAssetCount = Math.max(0, input.affectedAssets.length - externalAssets.length);

  const runGenerate = React.useCallback(async (mode: SummaryMode) => {
    setLoading(true);
    setError(null);
    setRawText(null);
    setSummaryMode(mode);
    const result = await generateSummaryRequest(input, mode);
    setSummary(result.summary ?? null);
    setRawText(result.rawText ?? null);
    setError(result.error ?? null);
    setLoading(false);
  }, [input]);

  React.useEffect(() => {
    setSummary(initialSummary);
    setSummaryMode(initialMode);
    setError(null);
    setRawText(null);
  }, [initialSummary, initialMode, inputKey]);

  React.useEffect(() => {
    if (!visible) return;
    if (!autoGenerate) return;
    void runGenerate('deterministic');
  }, [visible, inputKey, runGenerate, autoGenerate]);

  React.useEffect(() => {
    if (!loading) return;
    const id = window.setInterval(() => {
      setLoadingIndex((current) => (current + 1) % LOADING_STEPS.length);
    }, 1500);
    return () => window.clearInterval(id);
  }, [loading]);

  if (!visible) return null;

  return (
    <section style={{ display: 'grid', gap: 18 }}>
      <style>{`
        @keyframes investigationSummaryScan {
          0% { background-position: 0% 0; opacity: 0.55; }
          50% { background-position: 100% 0; opacity: 0.95; }
          100% { background-position: 0% 0; opacity: 0.55; }
        }
      `}</style>

      {loading ? (
        <div style={{
          background: COLORS.surface,
          border: `1px solid ${COLORS.border}`,
          borderRadius: 24,
          padding: 24,
          display: 'grid',
          gap: 16,
        }}>
          <div style={{ color: COLORS.accent, fontWeight: 700 }}>{LOADING_STEPS[loadingIndex]}</div>
          {Array.from({ length: 4 }).map((_, index) => (
            <div
              key={index}
              style={{
                height: index === 0 ? 92 : 120,
                borderRadius: 18,
                background: `linear-gradient(90deg, ${COLORS.surface}, ${tonedSurface(COLORS.accent, 22)}, ${COLORS.surface})`,
                backgroundSize: '200% 100%',
                animation: 'investigationSummaryScan 1.5s linear infinite',
                border: `1px solid ${COLORS.border}`,
              }}
            />
          ))}
        </div>
      ) : error ? (
        <div style={{
          background: COLORS.surface,
          border: `1px solid ${COLORS.danger}`,
          borderRadius: 24,
          padding: 24,
          display: 'grid',
          gap: 12,
        }}>
          <strong style={{ color: COLORS.text }}>Summary generation failed</strong>
          <div style={{ color: COLORS.muted }}>{error}</div>
          <div>
            <button type="button" className="btn btn-secondary btn-inline" onClick={() => void runGenerate(summaryMode)}>Retry</button>
          </div>
        </div>
      ) : rawText ? (
        <div style={{
          background: COLORS.surface,
          border: `1px solid ${COLORS.border}`,
          borderRadius: 24,
          padding: 24,
          display: 'grid',
          gap: 12,
        }}>
          <strong style={{ color: COLORS.text }}>Summary response</strong>
          <pre style={{
            margin: 0,
            padding: 16,
            background: COLORS.background,
            color: COLORS.title,
            borderRadius: 16,
            overflow: 'auto',
            maxHeight: 280,
          }}>{rawText}</pre>
        </div>
      ) : summary ? (
        <div style={{ display: 'grid', gap: 18 }}>
          <div style={{
            background: COLORS.surface,
            border: `1px solid ${COLORS.border}`,
            borderRadius: 24,
            padding: 24,
            display: 'flex',
            justifyContent: 'space-between',
            gap: 16,
            alignItems: 'center',
            flexWrap: 'wrap',
          }}>
            <div style={{ display: 'grid', gap: 10 }}>
              <div style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 28, fontWeight: 800, color: COLORS.title }}>
                {input.summary.cveId}
              </div>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                <span style={pillStyle(severityColor(input.summary.severity), true)}>{input.summary.severity}</span>
                <span style={pillStyle(COLORS.text, false, { background: COLORS.background, borderColor: COLORS.border })}>
                  CVSS {input.summary.cvssScore ?? '—'}
                </span>
                {input.summary.inKev ? <span style={pillStyle(COLORS.warning, false)}>KEV</span> : null}
                <span
                  style={pillStyle(
                    summaryMode === 'ai' ? COLORS.accent : COLORS.text,
                    false,
                    summaryMode === 'ai'
                      ? undefined
                      : { background: COLORS.background, borderColor: COLORS.borderStrong }
                  )}
                >
                  {summaryMode === 'ai' ? 'AI Summary' : 'Deterministic Summary'}
                </span>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              {!readOnly ? (
                <>
                  <button type="button" className="btn btn-secondary btn-inline" onClick={() => void runGenerate('deterministic')}>Regenerate</button>
                  <button type="button" className="btn btn-secondary btn-inline" onClick={() => void runGenerate('ai')}>Generate AI Summary</button>
                </>
              ) : null}
              <button type="button" className="btn btn-primary btn-inline" onClick={() => void exportWordDocument(input, summary)}>Export Word Doc</button>
            </div>
          </div>

          <div style={{
            background: COLORS.surface,
            border: `1px solid ${COLORS.border}`,
            borderLeft: `4px solid ${COLORS.accent}`,
            borderRadius: 24,
            padding: 24,
            color: COLORS.text,
            lineHeight: 1.7,
          }}>
            <div style={sectionTitleStyle}>Executive Summary</div>
            <div style={{ color: COLORS.text }}>{summary.executiveSummary}</div>
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: '1.1fr 1.2fr 1fr',
            gap: 16,
          }}>
            <div style={cardStyle}>
              <div style={sectionTitleStyle}>Impact Analysis</div>
              <div style={{ display: 'grid', gap: 14 }}>
                <div style={{ fontSize: 14, color: COLORS.muted }}>Risk meter</div>
                <div style={{ height: 12, borderRadius: 999, background: COLORS.track, overflow: 'hidden' }}>
                  <div style={{ width: `${summary.riskAnalysis.score}%`, height: '100%', background: riskMeterGradient(summary.riskAnalysis.score) }} />
                </div>
                <div style={{ color: COLORS.title, fontSize: 32, fontWeight: 800 }}>{summary.riskAnalysis.level}</div>
                <div style={{ color: COLORS.muted, lineHeight: 1.7 }}>{summary.riskAnalysis.rationale}</div>
              </div>
            </div>

            <div style={cardStyle}>
              <div style={sectionTitleStyle}>Asset Exposure Breakdown</div>
              <div style={{ display: 'grid', gap: 14 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div style={miniStatStyle}>
                    <div style={{ color: COLORS.accent }}>External</div>
                    <strong style={{ fontSize: 28, color: COLORS.text }}>{summary.impactAnalysis.externalFacingCount}</strong>
                  </div>
                  <div style={miniStatStyle}>
                    <div style={{ color: COLORS.muted }}>Internal</div>
                    <strong style={{ fontSize: 28, color: COLORS.text }}>{summary.impactAnalysis.internalAssetCount}</strong>
                  </div>
                </div>
                <button
                  type="button"
                  className="btn-link"
                  style={{ color: COLORS.accent, justifySelf: 'start' }}
                  onClick={() => setExpandedExternalAssets((current) => !current)}
                >
                  {expandedExternalAssets ? 'Hide' : 'Show'} external-facing assets
                </button>
                {expandedExternalAssets ? (
                  <div style={{ display: 'grid', gap: 10 }}>
                    {externalAssets.map((asset) => (
                      <div key={asset.id} style={{
                        border: `1px solid ${COLORS.border}`,
                        borderRadius: 16,
                        padding: 14,
                        background: COLORS.background,
                        display: 'grid',
                        gap: 6,
                      }}>
                        <strong style={{ color: COLORS.text }}>{asset.hostname}</strong>
                        <div style={{ color: COLORS.muted }}>{asset.owner || 'Unassigned'} · {asset.os || 'Unknown OS'}</div>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                          <span style={pillStyle(COLORS.text, false, { background: COLORS.surfaceMuted, borderColor: COLORS.border })}>
                            {asset.environment || 'Unknown environment'}
                          </span>
                          <span style={pillStyle(COLORS.danger, false)}>External Facing</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            </div>

            <div style={{ display: 'grid', gap: 12 }}>
              <div style={cardStyle}>
                <div style={sectionTitleStyle}>False Positive Summary</div>
                <div style={{ color: COLORS.text }}>{summary.impactAnalysis.falsePositiveSummary}</div>
              </div>
              <div style={cardStyle}>
                <div style={sectionTitleStyle}>EOL Risk</div>
                <div style={{ color: COLORS.text }}>{summary.impactAnalysis.eolRiskSummary}</div>
              </div>
              <div style={cardStyle}>
                <div style={sectionTitleStyle}>Patch Gap</div>
                <div style={{ color: COLORS.text }}>{summary.impactAnalysis.patchGapSummary}</div>
              </div>
            </div>
          </div>

          <div style={cardStyle}>
            <div style={sectionTitleStyle}>Remediation Plan</div>
            <div style={{ display: 'grid', gap: 12 }}>
              {summary.remediationPlan.map((action) => (
                <div key={action.priority} style={{
                  border: `1px solid ${COLORS.border}`,
                  borderRadius: 18,
                  padding: 18,
                  background: COLORS.background,
                  display: 'grid',
                  gap: 8,
                }}>
                  <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={pillStyle(severityColor(action.priorityLabel === 'P1' ? 'CRITICAL' : action.priorityLabel === 'P2' ? 'HIGH' : 'MEDIUM'), false)}>{action.priorityLabel}</span>
                    <strong style={{ color: COLORS.text }}>{action.title}</strong>
                    <span style={{ ...pillStyle(timeframeColor(action.timeframe), false), marginLeft: 'auto' }}>{action.timeframe}</span>
                  </div>
                  <div style={{ color: COLORS.text }}>{action.detail}</div>
                  <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                    <span style={pillStyle(COLORS.text, false, { background: COLORS.surfaceMuted, borderColor: COLORS.border })}>{action.owner}</span>
                    <span style={pillStyle(COLORS.text, false, { background: COLORS.surfaceMuted, borderColor: COLORS.border })}>{action.type}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={cardStyle}>
            <div style={sectionTitleStyle}>Key Findings</div>
            <ul style={{ margin: 0, paddingLeft: 20, color: COLORS.text, display: 'grid', gap: 8 }}>
              {summary.keyFindings.map((finding) => (
                <li key={finding} style={{ lineHeight: 1.7 }}>
                  <span style={{ color: COLORS.accent }}>{finding}</span>
                </li>
              ))}
            </ul>
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(6, minmax(0, 1fr))',
            gap: 12,
          }}>
            {[
              ['Total Affected', summary.metrics.totalAffected],
              ['True Positives', summary.metrics.truePositives],
              ['False Positives', summary.metrics.falsePositives],
              ['External Facing', summary.metrics.externalFacing],
              ['Unpatched Vulnerable', summary.metrics.unpatchedVulnerable],
              ['EOL Count', summary.metrics.eolCount],
            ].map(([label, value]) => (
              <div key={label} style={miniStatStyle}>
                <div style={{ color: COLORS.muted, fontSize: 12 }}>{label}</div>
                <strong style={{ color: COLORS.text, fontSize: 26 }}>{value}</strong>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}

function pillStyle(
  color: string,
  outline: boolean,
  options?: {
    background?: string;
    borderColor?: string;
  }
): React.CSSProperties {
  return {
    display: 'inline-flex',
    alignItems: 'center',
    padding: '6px 12px',
    borderRadius: 999,
    border: `1px solid ${options?.borderColor ?? (outline ? tonedBorder(color, 42) : tonedBorder(color))}`,
    background: options?.background ?? (outline ? 'transparent' : tonedSurface(color)),
    color,
    fontWeight: 700,
    fontSize: 13,
  };
}

const cardStyle: React.CSSProperties = {
  background: COLORS.surface,
  border: `1px solid ${COLORS.border}`,
  borderRadius: 24,
  padding: 24,
  display: 'grid',
  gap: 14,
};

const miniStatStyle: React.CSSProperties = {
  background: COLORS.surfaceMuted,
  border: `1px solid ${COLORS.border}`,
  borderRadius: 18,
  padding: 18,
  display: 'grid',
  gap: 8,
};

const sectionTitleStyle: React.CSSProperties = {
  color: COLORS.title,
  fontSize: 14,
  letterSpacing: '0.12em',
  textTransform: 'uppercase',
  fontWeight: 800,
};
