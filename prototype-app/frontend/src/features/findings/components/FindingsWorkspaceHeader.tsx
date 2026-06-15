import React from 'react';
import type { FindingProjectionStatus, FindingQueueDefinition } from '../types';

type Props = {
  personalQueues: FindingQueueDefinition[];
  activeQueueKey: string;
  projectionStatus?: FindingProjectionStatus;
  queueActionError: string;
  projectionError?: Error | null;
  workspaceError?: Error | null;
  onOpenEditQueue: (queue: FindingQueueDefinition) => void;
  onDuplicateQueue: (queue: FindingQueueDefinition) => void;
  onSetDefaultQueue: (queue: FindingQueueDefinition) => void;
  onDeleteQueue: (queue: FindingQueueDefinition) => void;
  workspaceTitle: string;
};

export function FindingsWorkspaceHeader({
  personalQueues,
  activeQueueKey,
  projectionStatus,
  queueActionError,
  projectionError,
  workspaceError,
  onOpenEditQueue,
  onDuplicateQueue,
  onSetDefaultQueue,
  onDeleteQueue,
  workspaceTitle,
}: Props) {
  const editableActiveQueue = personalQueues.find((queue) => queue.key === activeQueueKey) ?? null;

  return (
    <>
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

      {projectionError ? (
        <div className="panel-caption" style={{ marginBottom: 12, color: 'var(--warning,#b45309)' }}>
          Projection status unavailable: {projectionError.message}
        </div>
      ) : null}
    </>
  );
}
