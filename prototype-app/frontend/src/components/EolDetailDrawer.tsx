import React from 'react';
import { api } from '../api/client';
import { EolRelease } from '../types';
import { EolBadge } from './EolBadge';

type EolDetailDrawerProps = {
  slug: string;
  cycle?: string;
  packageName?: string;
  version?: string;
  isEol?: boolean;
  eolDate?: string;
  daysRemaining?: number;
  onClose: () => void;
};

export function EolDetailDrawer({
  slug,
  cycle,
  packageName,
  version,
  isEol,
  eolDate,
  daysRemaining,
  onClose
}: EolDetailDrawerProps) {
  const [releases, setReleases] = React.useState<EolRelease[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const stopPropagation = React.useCallback((e: React.MouseEvent) => e.stopPropagation(), []);

  React.useEffect(() => {
    let active = true;
    api.listEolProductReleases(slug)
      .then(r => { if (active) setReleases(r); })
      .catch(e => { if (active) setError(e instanceof Error ? e.message : String(e)); });
    return () => { active = false; };
  }, [slug]);

  const thisRelease = releases?.find(r => r.cycle === cycle);
  const hasStatusContext = isEol != null || daysRemaining != null || eolDate != null;

  return (
    <div className="eol-drawer-overlay" onClick={onClose}>
      <div className="eol-drawer" onClick={stopPropagation}>
        <div className="eol-drawer-header">
          <div>
            <h3 className="eol-drawer-title">End-of-Life Details</h3>
            {packageName && (
              <div className="panel-caption mono">{packageName}{version ? `@${version}` : ''}</div>
            )}
          </div>
          <button type="button" className="eol-drawer-close" onClick={onClose} aria-label="Close">✕</button>
        </div>

        <div className="eol-drawer-body">
          <div className="eol-drawer-section">
            <div className="eol-drawer-row">
              <span className="eol-drawer-label">Product</span>
              <span className="eol-drawer-value mono">{slug}</span>
            </div>
            {cycle && (
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">Selected Cycle</span>
                <span className="eol-drawer-value mono">{cycle}</span>
              </div>
            )}
            {hasStatusContext && (
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">Status</span>
                <span className="eol-drawer-value">
                  <EolBadge isEol={isEol} daysRemaining={daysRemaining} eolDate={eolDate} />
                </span>
              </div>
            )}
            {eolDate && (
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">EOL Date</span>
                <span className="eol-drawer-value">{eolDate}</span>
              </div>
            )}
            {thisRelease?.supportPhase && (
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">Support Phase</span>
                <span className="eol-drawer-value">{thisRelease.supportPhase}</span>
              </div>
            )}
            {thisRelease?.supportEndDate && (
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">Active Support Ends</span>
                <span className="eol-drawer-value">{thisRelease.supportEndDate}</span>
              </div>
            )}
            {thisRelease?.extendedSupportDate && (
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">Extended Support Ends</span>
                <span className="eol-drawer-value">{thisRelease.extendedSupportDate}</span>
              </div>
            )}
            {thisRelease?.securitySupportDate && (
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">Security Support Ends</span>
                <span className="eol-drawer-value">{thisRelease.securitySupportDate}</span>
              </div>
            )}
            {thisRelease?.latestVersion && (
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">Latest Version</span>
                <span className="eol-drawer-value mono">{thisRelease.latestVersion}</span>
              </div>
            )}
            {thisRelease?.lts && (
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">LTS</span>
                <span className="eol-drawer-value">Yes</span>
              </div>
            )}
          </div>

          <div className="eol-drawer-section">
            <div className="eol-drawer-section-title">All Release Cycles</div>
            {error && <div className="panel-caption">Failed to load cycles: {error}</div>}
            {!releases && !error && <div className="panel-caption">Loading...</div>}
            {releases && (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Cycle</th>
                      <th>EOL Date</th>
                      <th>Support End</th>
                      <th>Latest</th>
                      <th>LTS</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {releases.map(r => (
                      <tr key={r.cycle} className={r.cycle === cycle ? 'eol-drawer-row-highlight' : ''}>
                        <td className="mono">{r.cycle}</td>
                        <td>{r.eolDate ?? (r.eolBoolean === true ? 'EOL' : r.eolBoolean === false ? 'Not yet' : '-')}</td>
                        <td>{r.supportEndDate ?? '-'}</td>
                        <td className="mono">{r.latestVersion ?? '-'}</td>
                        <td>{r.lts ? 'LTS' : '-'}</td>
                        <td>
                          <EolBadge
                            isEol={r.isEol}
                            eolDate={r.eolDate}
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="eol-drawer-footer">
            {thisRelease?.officialSourceUrl && (
              <a
                href={thisRelease.officialSourceUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-secondary eol-drawer-link"
              >
                Official Documentation ↗
              </a>
            )}
            <a
              href={`https://endoflife.date/${slug}`}
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-secondary eol-drawer-link"
            >
              View on endoflife.date ↗
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
