import React from 'react';
import type { FindingProjectionStatus, FindingQueueDefinition } from '../types';

type Props = {
  builtInQueues: FindingQueueDefinition[];
  personalQueues: FindingQueueDefinition[];
  activeQueueKey: string;
  projectionStatus?: FindingProjectionStatus;
  queueLoading: boolean;
  queueActionError: string;
  projectionError?: Error | null;
  workspaceError?: Error | null;
  onSelectQueue: (queueKey: string) => void;
  onOpenCreateQueue: () => void;
  onOpenEditQueue: (queue: FindingQueueDefinition) => void;
  onDuplicateQueue: (queue: FindingQueueDefinition) => void;
  onSetDefaultQueue: (queue: FindingQueueDefinition) => void;
  onDeleteQueue: (queue: FindingQueueDefinition) => void;
  workspaceTitle: string;
};

export function FindingsWorkspaceHeader({
  builtInQueues,
  personalQueues,
  activeQueueKey,
  projectionStatus,
  queueLoading,
  queueActionError,
  projectionError,
  workspaceError,
  onSelectQueue,
  onOpenCreateQueue,
  onOpenEditQueue,
  onDuplicateQueue,
  onSetDefaultQueue,
  onDeleteQueue,
  workspaceTitle,
}: Props) {
  return (
    <>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', justifyContent: 'space-between', marginBottom: 12, flexWrap: 'wrap' }}>
        <div>
          <h1 style={{ margin: 0 }}>Findings</h1>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <span className="panel-caption" style={{ marginBottom: 0 }}>Built-in</span>
          {builtInQueues.map((queue) => (
            <button
              key={queue.key}
              className={`btn ${queue.key === activeQueueKey ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => onSelectQueue(queue.key)}
              style={{ padding: '6px 10px' }}
              title={queue.description ?? undefined}
            >
              {queue.title} ({queue.matchingCount})
            </button>
          ))}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="panel-caption" style={{ marginBottom: 0 }}>My Queues</span>
            {personalQueues.map((queue) => (
              <div key={queue.key} style={{ display: 'flex', gap: 4, alignItems: 'center', flexWrap: 'wrap' }}>
                <button
                  className={`btn ${queue.key === activeQueueKey ? 'btn-primary' : 'btn-secondary'}`}
                  onClick={() => onSelectQueue(queue.key)}
                  style={{ padding: '6px 10px' }}
                  title={queue.description ?? undefined}
                >
                  {queue.title}{queue.isDefault ? ' • Default' : ''} ({queue.matchingCount})
                </button>
                <button className="btn btn-secondary" style={{ padding: '6px 8px' }} onClick={() => onOpenEditQueue(queue)}>Edit</button>
                <button className="btn btn-secondary" style={{ padding: '6px 8px' }} onClick={() => onDuplicateQueue(queue)}>Copy</button>
                {!queue.isDefault && (
                  <button className="btn btn-secondary" style={{ padding: '6px 8px' }} onClick={() => onSetDefaultQueue(queue)}>Default</button>
                )}
                <button className="btn btn-secondary" style={{ padding: '6px 8px' }} onClick={() => onDeleteQueue(queue)}>Delete</button>
              </div>
            ))}
            <button className="btn btn-secondary" onClick={onOpenCreateQueue}>Save current view</button>
          </div>
          {queueLoading && <span className="panel-caption" style={{ marginBottom: 0 }}>Loading queues...</span>}
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
