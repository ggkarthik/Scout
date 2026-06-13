import React from 'react';
import type { FindingProjectionStatus } from '../types';

type Props = {
  projectionStatus?: FindingProjectionStatus;
  queueActionError: string;
  projectionError?: Error | null;
  workspaceError?: Error | null;
  workspaceTitle: string;
};

export function FindingsWorkspaceHeader({
  projectionStatus,
  queueActionError,
  projectionError,
  workspaceError,
  workspaceTitle,
}: Props) {
  return (
    <>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', justifyContent: 'space-between', marginBottom: 12, flexWrap: 'wrap' }}>
        <div>
          <h1 style={{ margin: 0 }}>Findings</h1>
        </div>
      </div>

      {workspaceError && (
        <div className="notice error" style={{ marginBottom: 12 }}>
          {workspaceError.message}
        </div>
      )}

      {queueActionError && (
        <div className="notice error" style={{ marginBottom: 12 }}>
          {queueActionError}
        </div>
      )}

      <div className="panel-caption" style={{ marginBottom: 12 }}>
        Workspace scope: {workspaceTitle}
        {projectionStatus?.lastComputedAt ? ` · authoritative as of ${new Date(projectionStatus.lastComputedAt).toLocaleString()}` : ''}
        {projectionStatus?.stale ? ' · projection refresh recommended' : ''}
      </div>

      {projectionError ? (
        <div className="panel-caption" style={{ marginBottom: 12, color: 'var(--warning,#b45309)' }}>
          Projection status unavailable: {projectionError.message}
        </div>
      ) : null}
    </>
  );
}
