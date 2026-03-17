import React from 'react';
import { api } from '../api/client';
import { ComponentEolStatus, EolComponentPage, EolSummary } from '../types';
import { EolBadge } from '../components/EolBadge';
import { EolDetailDrawer } from '../components/EolDetailDrawer';
import { NEAR_EOL_DAYS } from '../features/cve-workbench/eol-helpers';

type EolFilter = 'all' | 'eol' | 'near-eol' | 'ok' | 'unknown';

const PAGE_SIZE = 25;

function filterLabel(key: EolFilter, summary: EolSummary | null): string {
  const counts: Record<EolFilter, number | null> = {
    all:       summary ? summary.eolCount + summary.nearEolCount + summary.supportedCount + summary.unknownCount : null,
    eol:       summary ? summary.eolCount : null,
    'near-eol': summary ? summary.nearEolCount : null,
    ok:        summary ? summary.supportedCount : null,
    unknown:   summary ? summary.unknownCount : null,
  };
  const labels: Record<EolFilter, string> = {
    all:       'All',
    eol:       'EOL',
    'near-eol': `Near EOL ≤${NEAR_EOL_DAYS}d`,
    ok:        'Supported',
    unknown:   'Unknown',
  };
  const count = counts[key];
  return count !== null ? `${labels[key]}  ${count.toLocaleString()}` : labels[key];
}

export function EolPage() {
  const [filter, setFilter] = React.useState<EolFilter>('all');
  const [page, setPage]     = React.useState(0);
  const [data, setData]     = React.useState<EolComponentPage | null>(null);
  const [summary, setSummary] = React.useState<EolSummary | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError]   = React.useState<string | null>(null);
  const [drawer, setDrawer] = React.useState<ComponentEolStatus | null>(null);

  const [unresolvedList, setUnresolvedList] = React.useState<
    Array<{ vendor: string; product: string; displayName: string; normalizedKey: string }> | null
  >(null);
  const [confirmSlug, setConfirmSlug] = React.useState<Record<string, string>>({});
  const [unresolvedOpen, setUnresolvedOpen] = React.useState(false);

  // Load summary counts once (drives filter tab badges)
  React.useEffect(() => {
    api.getEolSummary()
      .then(s => setSummary(s))
      .catch(() => {});
  }, []);

  // Load table data whenever filter or page changes
  React.useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    api.getEolComponentStatuses({ filter: filter === 'all' ? undefined : filter, page, size: PAGE_SIZE })
      .then(d => { if (active) { setData(d); setLoading(false); } })
      .catch(e => { if (active) { setError(e instanceof Error ? e.message : String(e)); setLoading(false); } });
    return () => { active = false; };
  }, [filter, page]);

  // Load unresolved mappings once
  React.useEffect(() => {
    api.listEolUnresolvedMappings()
      .then(list => setUnresolvedList(list))
      .catch(() => {});
  }, []);

  function handleFilterChange(newFilter: EolFilter) {
    setFilter(newFilter);
    setPage(0);
  }

  function exportCsv() {
    if (!data) return;
    const header = 'Component,Ecosystem,Version,Asset,EOL Slug,Cycle,EOL Date,Status,Days Remaining';
    const rows = data.content.map(r =>
      [
        r.packageName,
        r.ecosystem,
        r.version ?? '',
        r.assetName,
        r.eolSlug ?? '',
        r.eolCycle ?? '',
        r.eolDate ?? '',
        r.isEol === true ? 'EOL' : r.isEol === false ? 'Supported' : 'Unknown',
        r.eolDaysRemaining ?? ''
      ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')
    );
    const csv = [header, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = 'eol-components.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 100);
  }

  async function handleConfirmMapping(normalizedKey: string) {
    const slug = confirmSlug[normalizedKey];
    if (!slug?.trim()) return;
    try {
      await api.confirmEolMapping(normalizedKey, slug.trim());
      setUnresolvedList(prev => prev?.filter(i => i.normalizedKey !== normalizedKey) ?? null);
    } catch (e) {
      alert(`Failed to confirm mapping: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  const filterKeys: EolFilter[] = ['all', 'eol', 'near-eol', 'ok', 'unknown'];

  const emptyMessages: Record<EolFilter, string> = {
    all:       'No components in inventory.',
    eol:       'No end-of-life components found.',
    'near-eol': 'No components approaching end of life within 90 days.',
    ok:        'No actively supported components found.',
    unknown:   'All components have resolved EOL mappings.',
  };

  return (
    <div className="page-grid">

      {/* ── Main panel ── */}
      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>End-of-Life Components</h3>
            <span className="panel-caption">
              Inventory components grouped by lifecycle status. Use filters to focus a category.
            </span>
          </div>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={exportCsv}
            disabled={!data || data.content.length === 0}
          >
            Export CSV
          </button>
        </div>

        {/* Category filter tabs with counts */}
        <div className="eol-filter-tabs">
          {filterKeys.map(key => (
            <button
              key={key}
              type="button"
              className={`eol-filter-tab${filter === key ? ' eol-filter-tab--active' : ''} eol-filter-tab--${key === 'near-eol' ? 'near-eol' : key}`}
              onClick={() => handleFilterChange(key)}
            >
              {filterLabel(key, summary)}
            </button>
          ))}
        </div>

        {error && (
          <div className="notice error" style={{ margin: '0 0 12px' }}>
            Error: {error}
          </div>
        )}

        {loading ? (
          <div className="panel-caption" style={{ padding: '24px 0' }}>Loading...</div>
        ) : (
          <>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Component</th>
                    <th>Version</th>
                    <th>Asset</th>
                    <th>EOL Product</th>
                    <th>Cycle</th>
                    <th>EOL Date</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {!data || data.content.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: '32px 0' }}>
                        <span className="panel-caption">{emptyMessages[filter]}</span>
                      </td>
                    </tr>
                  ) : data.content.map(row => (
                    <tr key={row.componentId}>
                      <td>
                        <span className="mono">{row.ecosystem}:{row.packageName}</span>
                      </td>
                      <td className="mono">{row.version ?? '-'}</td>
                      <td>{row.assetName}</td>
                      <td className="mono">{row.eolSlug ?? '-'}</td>
                      <td className="mono">{row.eolCycle ?? '-'}</td>
                      <td>{row.eolDate ?? '-'}</td>
                      <td>
                        <EolBadge
                          isEol={row.isEol}
                          daysRemaining={row.eolDaysRemaining}
                          eolDate={row.eolDate}
                          onClick={row.eolSlug ? () => setDrawer(row) : undefined}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {data && data.totalPages > 1 && (
              <div className="pagination-row">
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={page === 0}
                  onClick={() => setPage(p => p - 1)}
                >
                  Previous
                </button>
                <span className="panel-caption">
                  Page {data.number + 1} of {data.totalPages}
                  {' · '}{data.totalElements.toLocaleString()} components
                </span>
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={page >= data.totalPages - 1}
                  onClick={() => setPage(p => p + 1)}
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </section>

      {/* ── Unresolved mappings (collapsible) ── */}
      {unresolvedList && unresolvedList.length > 0 && (
        <section className="panel">
          <button
            type="button"
            className="eol-unresolved-toggle"
            onClick={() => setUnresolvedOpen(o => !o)}
          >
            <span>
              Unresolved Mappings
              <span className="eol-unresolved-badge">{unresolvedList.length}</span>
            </span>
            <span className="panel-caption">
              {unresolvedOpen ? 'Collapse ▲' : 'Expand ▼'}
            </span>
          </button>

          {unresolvedOpen && (
            <>
              <p className="panel-caption" style={{ margin: '0 0 12px' }}>
                These software identities have no endoflife.date match. Enter the correct slug and confirm to resolve.
              </p>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Software</th>
                      <th>Vendor</th>
                      <th>EOL Slug</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {unresolvedList.slice(0, 50).map(item => (
                      <tr key={item.normalizedKey}>
                        <td>{item.displayName}</td>
                        <td className="mono">{item.vendor || '-'}</td>
                        <td>
                          <input
                            type="text"
                            className="filter-input"
                            placeholder="e.g. ubuntu, python, java"
                            value={confirmSlug[item.normalizedKey] ?? ''}
                            onChange={e => setConfirmSlug(prev => ({ ...prev, [item.normalizedKey]: e.target.value }))}
                            style={{ width: '160px' }}
                          />
                        </td>
                        <td>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            disabled={!confirmSlug[item.normalizedKey]?.trim()}
                            onClick={() => handleConfirmMapping(item.normalizedKey)}
                          >
                            Confirm
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </section>
      )}

      {drawer && drawer.eolSlug && (
        <EolDetailDrawer
          slug={drawer.eolSlug}
          cycle={drawer.eolCycle}
          packageName={`${drawer.ecosystem}:${drawer.packageName}`}
          version={drawer.version}
          isEol={drawer.isEol}
          eolDate={drawer.eolDate}
          daysRemaining={drawer.eolDaysRemaining}
          onClose={() => setDrawer(null)}
        />
      )}
    </div>
  );
}
