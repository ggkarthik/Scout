import React from 'react';
import { HBarChart, WidgetCard } from '../../widgets/FplWidgets';
import type { FindingPortfolioRollup } from '../types';

export function FindingsPortfolioRollupsPanel({
  rollup,
  error,
}: {
  rollup?: FindingPortfolioRollup;
  error?: Error | null;
}) {
  return (
    <div className="panel" style={{ marginBottom: 16 }}>
      <div className="panel-header" style={{ marginBottom: 12 }}>
        <div>
          <h3 style={{ margin: 0 }}>Portfolio Rollups</h3>
          <div className="panel-caption">Tenant-wide backlog rollups across queues, owner groups, and support groups.</div>
        </div>
      </div>
      {error ? (
        <div className="notice error" style={{ marginBottom: 0 }}>{error.message}</div>
      ) : (
        <div style={{ display: 'grid', gap: 16 }}>
          <div className="fpl-kpi-grid">
            {[
              { label: 'Total Open', value: (rollup?.totalOpenCount ?? 0).toLocaleString(), color: '#1d4ed8' },
              { label: 'Critical Open', value: (rollup?.totalCriticalOpenCount ?? 0).toLocaleString(), color: '#b91c1c' },
              { label: 'Overdue Open', value: (rollup?.totalOverdueOpenCount ?? 0).toLocaleString(), color: '#ea580c' },
            ].map((kpi) => (
              <div key={kpi.label} className="fpl-kpi-card" style={{ '--kpi-color': kpi.color } as React.CSSProperties}>
                <div className="fpl-kpi-num">{kpi.value}</div>
                <div className="fpl-kpi-label">{kpi.label}</div>
              </div>
            ))}
          </div>

          <div className="fpl-widgets" style={{ marginTop: 0 }}>
            <WidgetCard title="Queue Backlog">
              {(rollup?.queueRollups.length ?? 0) === 0
                ? <div className="fpl-widget-empty">No queue rollups available</div>
                : <HBarChart items={(rollup?.queueRollups ?? []).slice(0, 6).map((item, index) => ({
                    key: item.queueKey,
                    label: item.title,
                    value: item.matchingCount,
                    color: ['#2563eb', '#3b82f6', '#60a5fa', '#93c5fd', '#1d4ed8', '#1e40af'][index] ?? '#2563eb',
                  }))}
                />}
            </WidgetCard>

            <WidgetCard title="Top Owner Groups">
              {(rollup?.topOwnerGroups.length ?? 0) === 0
                ? <div className="fpl-widget-empty">No owner-group backlog</div>
                : <HBarChart items={(rollup?.topOwnerGroups ?? []).map((item, index) => ({
                    key: item.label,
                    label: item.label,
                    value: item.count,
                    color: ['#0f766e', '#0d9488', '#14b8a6', '#2dd4bf', '#5eead4'][index] ?? '#0f766e',
                  }))}
                />}
            </WidgetCard>

            <WidgetCard title="Top Support Groups">
              {(rollup?.topSupportGroups.length ?? 0) === 0
                ? <div className="fpl-widget-empty">No support backlog</div>
                : <HBarChart items={(rollup?.topSupportGroups ?? []).map((item, index) => ({
                    key: item.label,
                    label: item.label,
                    value: item.count,
                    color: ['#7c3aed', '#8b5cf6', '#a78bfa', '#c4b5fd', '#ddd6fe'][index] ?? '#7c3aed',
                  }))}
                />}
            </WidgetCard>
          </div>

          {(rollup?.queueRollups.length ?? 0) > 0 && (
            <div className="fpl-group-card" style={{ padding: 16 }}>
              <div className="fpl-group-title" style={{ marginBottom: 10 }}>Queue Portfolio Snapshot</div>
              <div style={{ display: 'grid', gap: 10 }}>
                {(rollup?.queueRollups ?? []).slice(0, 6).map((queue) => (
                  <div key={queue.queueKey} className="fpl-group-item">
                    <span>{queue.title}</span>
                    <strong>{queue.matchingCount.toLocaleString()} total · {queue.openCount.toLocaleString()} open · {queue.overdueOpenCount.toLocaleString()} overdue</strong>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
