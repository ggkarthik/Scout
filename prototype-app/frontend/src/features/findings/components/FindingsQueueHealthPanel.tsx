import React from 'react';
import { HBarChart, WidgetCard } from '../../widgets/FplWidgets';
import type { FindingQueueAnalytics, FindingQueueAnalyticsTrendPoint } from '../types';

function formatDays(value: number): string {
  return `${value.toLocaleString()}d`;
}

function QueueTrendChart({ points }: { points: FindingQueueAnalyticsTrendPoint[] }) {
  const max = Math.max(1, ...points.flatMap((point) => [point.openedCount, point.resolvedCount, point.reopenedCount]));
  return (
    <div style={{ display: 'grid', gap: 8 }}>
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.max(points.length, 1)}, minmax(0, 1fr))`, gap: 6, alignItems: 'end', minHeight: 108 }}>
        {points.map((point) => (
          <div key={point.date} style={{ display: 'grid', gap: 4, justifyItems: 'center' }}>
            <div style={{ display: 'flex', gap: 3, alignItems: 'end', minHeight: 78 }}>
              <div title={`${point.date}: Opened ${point.openedCount}`} style={{ width: 8, height: `${Math.max(6, (point.openedCount / max) * 72)}px`, background: '#3b82f6', borderRadius: 999 }} />
              <div title={`${point.date}: Resolved ${point.resolvedCount}`} style={{ width: 8, height: `${Math.max(6, (point.resolvedCount / max) * 72)}px`, background: '#22c55e', borderRadius: 999 }} />
              <div title={`${point.date}: Reopened ${point.reopenedCount}`} style={{ width: 8, height: `${Math.max(6, (point.reopenedCount / max) * 72)}px`, background: '#f97316', borderRadius: 999 }} />
            </div>
            <span style={{ fontSize: 11, color: 'var(--muted,#6b7280)' }}>{point.date.slice(5)}</span>
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, fontSize: 12, color: 'var(--muted,#6b7280)' }}>
        <span><span style={{ display: 'inline-block', width: 10, height: 10, borderRadius: 999, background: '#3b82f6', marginRight: 6 }} />Opened</span>
        <span><span style={{ display: 'inline-block', width: 10, height: 10, borderRadius: 999, background: '#22c55e', marginRight: 6 }} />Resolved</span>
        <span><span style={{ display: 'inline-block', width: 10, height: 10, borderRadius: 999, background: '#f97316', marginRight: 6 }} />Reopened</span>
      </div>
    </div>
  );
}

export function FindingsQueueHealthPanel({
  title,
  analytics,
  trendPoints,
  error,
}: {
  title: string;
  analytics?: FindingQueueAnalytics;
  trendPoints: FindingQueueAnalyticsTrendPoint[];
  error?: Error | null;
}) {
  return (
    <div className="panel" style={{ marginBottom: 16 }}>
      <div className="panel-header" style={{ marginBottom: 12 }}>
        <div>
          <h3 style={{ margin: 0 }}>{title}</h3>
          <div className="panel-caption">Current-scope queue analytics across backlog age, ownership load, incident coverage, and recent lifecycle trends.</div>
        </div>
      </div>
      {error ? (
        <div className="notice error" style={{ marginBottom: 0 }}>{error.message}</div>
      ) : (
        <div style={{ display: 'grid', gap: 16 }}>
          <div className="fpl-kpi-grid">
            {[
              { label: 'Median Open Age', value: formatDays(analytics?.medianOpenAgeDays ?? 0), color: '#0f766e' },
              { label: 'Oldest Open', value: formatDays(analytics?.oldestOpenAgeDays ?? 0), color: '#7c3aed' },
              { label: 'Reopen Rate (30d)', value: `${(analytics?.reopenRatePercent ?? 0).toFixed(1)}%`, color: '#ea580c' },
              { label: 'Reopened (30d)', value: (analytics?.reopenedCountLast30Days ?? 0).toLocaleString(), color: '#1d4ed8' },
            ].map((kpi) => (
              <div key={kpi.label} className="fpl-kpi-card" style={{ '--kpi-color': kpi.color } as React.CSSProperties}>
                <div className="fpl-kpi-num">{kpi.value}</div>
                <div className="fpl-kpi-label">{kpi.label}</div>
              </div>
            ))}
          </div>

          <div className="fpl-widgets" style={{ marginTop: 0 }}>
            <WidgetCard title="Backlog Aging">
              <HBarChart items={(analytics?.agingBuckets ?? []).map((bucket, index) => ({
                key: bucket.key,
                label: bucket.key,
                value: bucket.count,
                color: ['#22c55e', '#eab308', '#f97316', '#ef4444'][index] ?? '#64748b',
              }))} />
            </WidgetCard>

            <WidgetCard title="Owner Workload">
              {(analytics?.topOwners?.length ?? 0) === 0
                ? <div className="fpl-widget-empty">No open owner backlog</div>
                : <HBarChart items={(analytics?.topOwners ?? []).map((item, index) => ({
                    key: item.label,
                    label: item.label,
                    value: item.count,
                    color: ['#3b82f6', '#2563eb', '#1d4ed8', '#1e40af', '#1e3a8a'][index] ?? '#3b82f6',
                  }))}
                />}
            </WidgetCard>

            <WidgetCard title="Support Group Load">
              {(analytics?.topSupportGroups?.length ?? 0) === 0
                ? <div className="fpl-widget-empty">No support-group backlog</div>
                : <HBarChart items={(analytics?.topSupportGroups ?? []).map((item, index) => ({
                    key: item.label,
                    label: item.label,
                    value: item.count,
                    color: ['#8b5cf6', '#7c3aed', '#6d28d9', '#5b21b6', '#4c1d95'][index] ?? '#8b5cf6',
                  }))}
                />}
            </WidgetCard>

            <WidgetCard title="Assignment & Incident Coverage">
              <div style={{ display: 'grid', gap: 10 }}>
                <div className="fpl-group-item"><span>Assigned Open</span><strong>{(analytics?.assignedOpenCount ?? 0).toLocaleString()}</strong></div>
                <div className="fpl-group-item"><span>Unassigned Open</span><strong>{(analytics?.unassignedOpenCount ?? 0).toLocaleString()}</strong></div>
                <div className="fpl-group-item"><span>With Incident</span><strong>{(analytics?.withIncidentCount ?? 0).toLocaleString()}</strong></div>
                <div className="fpl-group-item"><span>Without Incident</span><strong>{(analytics?.withoutIncidentCount ?? 0).toLocaleString()}</strong></div>
              </div>
            </WidgetCard>
          </div>

          <div className="fpl-group-card" style={{ padding: 16 }}>
            <div className="fpl-group-title" style={{ marginBottom: 6 }}>30-Day Queue Trend</div>
            <div className="panel-caption" style={{ marginBottom: 10 }}>
              Current-scope trend based on findings that match the active queue and narrowing filters today.
            </div>
            {trendPoints.length === 0 ? <div className="fpl-widget-empty">No queue trend activity in the selected window</div> : <QueueTrendChart points={trendPoints} />}
          </div>
        </div>
      )}
    </div>
  );
}
