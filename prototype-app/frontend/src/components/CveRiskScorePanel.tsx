import React from 'react';
import type { OrgSpecificCveExposureRecord } from '../features/cve-workbench/types';
import { useRiskPolicyQuery } from '../features/cve-workbench/queries';
import { computeCveRiskScore } from '../lib/riskScoring';

type Props = {
  item: OrgSpecificCveExposureRecord;
};

/**
 * S.AI Risk Score panel — shown at the top of the assessment workbench.
 * Renders a horizontal left-to-right timeline of phases, each showing how
 * the score was built up (or reduced) as more context was discovered.
 */
export function CveRiskScorePanel({ item }: Props) {
  const [expanded, setExpanded] = React.useState(true);
  const policyQuery = useRiskPolicyQuery();
  const result = React.useMemo(
    () => computeCveRiskScore(item, policyQuery.data),
    [item, policyQuery.data],
  );

  const hasJourney = result.journey.length > 1;

  return (
    <div className="cvrs-panel">

      {/* ── Header row ────────────────────────────────────────────────── */}
      <div className="cvrs-header">
        <div className="cvrs-header-left">
          <span className="cvrs-title">S.AI Risk Score</span>
          <div className="cvrs-badge" style={{ background: result.color }}>
            <span className="cvrs-badge-num">{result.score.toFixed(1)}</span>
            <span className="cvrs-badge-label">{result.label}</span>
          </div>
          {result.topReasons.length > 0 && (
            <div className="cvrs-reasons">
              {result.topReasons.map((r, i) => (
                <span key={i} className="cvrs-reason-tag">{r}</span>
              ))}
            </div>
          )}
        </div>
        {hasJourney && (
          <button
            type="button"
            className="cvrs-toggle"
            onClick={() => setExpanded(v => !v)}
          >
            {expanded ? 'Hide journey' : 'Show journey'}
          </button>
        )}
      </div>

      {/* ── Timeline ──────────────────────────────────────────────────── */}
      {expanded && hasJourney && (
        <div className="cvrs-timeline" role="list" aria-label="Risk score journey">
          {result.journey.map((event, i) => {
            const isFirst = i === 0;
            const isLast = i === result.journey.length - 1;
            return (
              <div
                key={i}
                className={`cvrs-phase${event.isNote ? ' cvrs-phase--note' : ''}`}
                role="listitem"
              >
                {/* Track: left-segment — dot — right-segment */}
                <div className="cvrs-phase-track">
                  <div className={`cvrs-track-seg${isFirst ? ' cvrs-track-seg--hidden' : ''}`} />
                  <div
                    className={`cvrs-track-dot${isLast ? ' cvrs-track-dot--final' : ''}`}
                    style={isLast && !event.isNote ? { background: result.color, borderColor: result.color } : undefined}
                  />
                  <div className={`cvrs-track-seg${isLast ? ' cvrs-track-seg--hidden' : ''}`} />
                </div>

                {/* Content below the track */}
                <div className="cvrs-phase-body">
                  <span className="cvrs-phase-name">{event.stage}</span>
                  {!event.isNote && (
                    <div className="cvrs-phase-metrics">
                      {event.delta !== 0 && (
                        <span className={`cvrs-phase-delta${event.delta > 0 ? ' cvrs-phase-delta--up' : ' cvrs-phase-delta--down'}`}>
                          {event.delta > 0 ? '+' : ''}{event.delta.toFixed(1)}
                        </span>
                      )}
                      <span className="cvrs-phase-score">{event.score.toFixed(1)}</span>
                    </div>
                  )}
                  <span className="cvrs-phase-reason">{event.reason}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
