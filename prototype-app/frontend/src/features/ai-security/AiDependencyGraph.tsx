import { useQuery } from '@tanstack/react-query';
import { Background, Controls, Handle, Position, ReactFlow, ReactFlowProvider } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import React from 'react';
import { api } from '../../api/client';
import { formatLabel } from '../cve-workbench/formatting';
import { layoutDependencyGraph, type DependencyGraphNodeData } from './graph-layout';
import type { AiRuntimeGraphEdge, AiRuntimeGraphGroup, AiSecurityArtifact, AiSecurityGraph, AiSecurityPolicy } from './types';

const ARTIFACT_TYPE_ICON: Record<string, string> = {
  AI_AGENT: '🤖',
  AI_AGENT_VERSION: '🧬',
  AI_PROMPT: '📝',
  AI_TOOL: '🛠️',
  AI_COMPONENT: '🧩',
  AI_MODEL: '🧠',
  OTHER_AI_ARTIFACT: '📦',
};

function formatTimestamp(value?: string | null): string {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatPiiStatus(artifact: AiSecurityArtifact): string {
  switch (artifact.piiScanStatus) {
    case 'NOT_APPLICABLE':
      return 'Not applicable';
    case 'NOT_SCANNED':
      return 'Not scanned';
    case 'SCANNED_CLEAN':
      return 'No PII found';
    case 'SCANNED_PII_FOUND':
      return `${artifact.piiFindingCount} finding${artifact.piiFindingCount === 1 ? '' : 's'}`
        + (artifact.piiInfoTypes.length > 0 ? ` (${artifact.piiInfoTypes.join(', ')})` : '');
    case 'LOOKUP_FAILED':
      return 'Lookup failed';
    default:
      return 'Not available';
  }
}

function countCriticalPolicyFailures(
  controls: { policyId: string; decision: string }[],
  policies: AiSecurityPolicy[],
): number {
  const severityByPolicyId = new Map(policies.map((policy) => [policy.id, policy.severity.toUpperCase()]));
  return controls.filter(
    (control) => control.decision === 'FAIL' && severityByPolicyId.get(control.policyId) === 'CRITICAL',
  ).length;
}

type GraphNodeDetailsPopupProps = {
  artifact: AiSecurityArtifact;
  isRoot: boolean;
  findingsCount: number;
  policies: AiSecurityPolicy[];
  onViewDetails: (artifactId: string) => void;
};

function GraphNodeDetailsPopup({ artifact, isRoot, findingsCount, policies, onViewDetails }: GraphNodeDetailsPopupProps) {
  const postureQuery = useQuery({
    queryKey: ['ai-security-graph-node-posture', artifact.id],
    queryFn: () => api.getAiAssetPosture(artifact.id),
  });
  const criticalPoliciesFailed = postureQuery.data
    ? countCriticalPolicyFailures(postureQuery.data.controls, policies)
    : null;

  return (
    <div className="ai-dependency-graph-popup" role="dialog" aria-label={`${artifact.name} details`}>
      <div className="ai-dependency-graph-popup-header">
        <span aria-hidden="true">{ARTIFACT_TYPE_ICON[artifact.artifactType] ?? '📦'}</span>
        <div className="ai-dependency-graph-popup-title">
          <strong>{artifact.name}</strong>
          <small>{formatLabel(artifact.artifactType)}</small>
        </div>
      </div>
      <dl className="ai-dependency-graph-popup-facts">
        <dt>Native type</dt><dd>{formatLabel(artifact.nativeKind)}</dd>
        <dt>Status</dt>
        <dd>
          <span className={`ai-dependency-graph-popup-status ${artifact.active ? 'is-active' : 'is-inactive'}`}>
            <span aria-hidden="true">{artifact.active ? '🟢' : '⚪'}</span>
            {artifact.active ? 'Active' : 'Inactive'}
          </span>
        </dd>
        <dt>Findings</dt><dd>{findingsCount}</dd>
        <dt>Criticality</dt><dd>{artifact.businessCriticality ? formatLabel(artifact.businessCriticality) : 'Not classified'}</dd>
        <dt>PII</dt><dd>{formatPiiStatus(artifact)}</dd>
        <dt>Critical policies failed</dt>
        <dd>{postureQuery.isLoading ? '…' : postureQuery.isError ? '—' : criticalPoliciesFailed}</dd>
        <dt>Last observed</dt><dd>{formatTimestamp(artifact.lastObservedAt)}</dd>
      </dl>
      <button
        type="button"
        className="btn btn-primary btn-sm ai-dependency-graph-popup-cta"
        disabled={isRoot}
        onClick={() => onViewDetails(artifact.id)}
      >
        {isRoot ? 'Currently viewing this asset' : 'View Details'}
      </button>
    </div>
  );
}

function AiArtifactNode({ data }: { data: DependencyGraphNodeData }) {
  const classes = ['ai-dependency-graph-node'];
  if (data.isRoot) classes.push('ai-dependency-graph-node--root');
  if (!data.active) classes.push('ai-dependency-graph-node--inactive');
  if (data.nodeKind === 'RUNTIME_AGGREGATE') classes.push('ai-dependency-graph-node--runtime');
  return (
    <div className={classes.join(' ')}>
      <Handle type="target" position={Position.Left} />
      <span aria-hidden="true">{data.nodeKind === 'RUNTIME_AGGREGATE' ? '⚡' : ARTIFACT_TYPE_ICON[data.artifactType] ?? '📦'}</span>
      <div className="ai-dependency-graph-node-text">
        <strong>{data.label}</strong>
        <small>{data.nativeKind}</small>
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const NODE_TYPES = { aiArtifact: AiArtifactNode };

type AiDependencyGraphProps = {
  graph: AiSecurityGraph;
  rootArtifactId?: string;
  onNodeClick?: (artifactId: string) => void;
  findingsCountByArtifactId?: Record<string, number>;
  policies?: AiSecurityPolicy[];
  onViewExecutions?: (group: AiRuntimeGraphGroup) => void;
};

function RuntimeGroupPopup({ group, onViewExecutions }: { group: AiRuntimeGraphGroup; onViewExecutions?: (group: AiRuntimeGraphGroup) => void }) {
  return <div className="ai-dependency-graph-popup" role="dialog" aria-label="Runtime activity details">
    <div className="ai-dependency-graph-popup-header"><span aria-hidden="true">⚡</span><div className="ai-dependency-graph-popup-title"><strong>Runtime activity</strong><small>{group.source}</small></div></div>
    <dl className="ai-dependency-graph-popup-facts">
      <dt>Provider</dt><dd>{group.provider}</dd><dt>Executions</dt><dd>{group.executionCount}</dd>
      <dt>Successful</dt><dd>{group.successCount}</dd><dt>Failed</dt><dd>{group.failureCount}</dd>
      <dt>Other status</dt><dd>{group.unknownCount}</dd><dt>Resolved</dt><dd>{group.resolvedCount}</dd>
      <dt>Unresolved</dt><dd>{group.unresolvedCount}</dd><dt>Not applicable</dt><dd>{group.notApplicableCount}</dd>
      <dt>First observed</dt><dd>{formatTimestamp(group.firstEvidenceTime)}</dd>
      <dt>Last observed</dt><dd>{formatTimestamp(group.lastEvidenceTime)}</dd>
    </dl>
    <button type="button" className="btn btn-primary btn-sm ai-dependency-graph-popup-cta" onClick={() => onViewExecutions?.(group)}>View executions</button>
  </div>;
}

function RuntimeEdgePopup({ edge }: { edge: AiRuntimeGraphEdge }) {
  return <div className="ai-dependency-graph-popup" role="dialog" aria-label="Runtime relationship details">
    <div className="ai-dependency-graph-popup-header"><span aria-hidden="true">↝</span><div className="ai-dependency-graph-popup-title"><strong>{edge.relationshipType.replace(/_/g, ' ')}</strong><small>{edge.participantRole ?? 'Agent association'}</small></div></div>
    <dl className="ai-dependency-graph-popup-facts">
      <dt>Executions</dt><dd>{edge.executionCount}</dd>
      <dt>First observed</dt><dd>{formatTimestamp(edge.firstEvidenceTime)}</dd>
      <dt>Last observed</dt><dd>{formatTimestamp(edge.lastEvidenceTime)}</dd>
    </dl>
  </div>;
}

export function AiDependencyGraph({
  graph,
  rootArtifactId,
  onNodeClick,
  findingsCountByArtifactId = {},
  policies = [],
  onViewExecutions,
}: AiDependencyGraphProps) {
  const { nodes, edges } = React.useMemo(
    () => layoutDependencyGraph(graph, rootArtifactId),
    [graph, rootArtifactId],
  );
  const [selectedArtifactId, setSelectedArtifactId] = React.useState<string | null>(null);
  const [selectedRuntimeGroup, setSelectedRuntimeGroup] = React.useState<AiRuntimeGraphGroup | null>(null);
  const [selectedRuntimeEdge, setSelectedRuntimeEdge] = React.useState<AiRuntimeGraphEdge | null>(null);
  const selectedArtifact = React.useMemo(
    () => graph.nodes.find((node) => node.id === selectedArtifactId) ?? null,
    [graph.nodes, selectedArtifactId],
  );

  return (
    <div className="ai-dependency-graph" role="img" aria-label="AI artifact dependency graph">
      <ReactFlowProvider>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={NODE_TYPES}
          fitView
          nodesDraggable={false}
          nodesConnectable={false}
          onNodeClick={(_event, node) => {
            const data = node.data as DependencyGraphNodeData;
            setSelectedRuntimeEdge(null);
            if (data.nodeKind === 'RUNTIME_AGGREGATE') { setSelectedArtifactId(null); setSelectedRuntimeGroup(data.runtimeGroup ?? null); }
            else { setSelectedRuntimeGroup(null); setSelectedArtifactId(node.id); }
          }}
          onEdgeClick={(_event, edge) => {
            setSelectedArtifactId(null); setSelectedRuntimeGroup(null);
            setSelectedRuntimeEdge((edge.data?.runtimeEdge as AiRuntimeGraphEdge | undefined) ?? null);
          }}
          onPaneClick={() => { setSelectedArtifactId(null); setSelectedRuntimeGroup(null); setSelectedRuntimeEdge(null); }}
          proOptions={{ hideAttribution: true }}
        >
          <Background />
          <Controls showInteractive={false} />
        </ReactFlow>
      </ReactFlowProvider>
      {selectedArtifact && (
        <GraphNodeDetailsPopup
          artifact={selectedArtifact}
          isRoot={selectedArtifact.id === rootArtifactId}
          findingsCount={findingsCountByArtifactId[selectedArtifact.id] ?? 0}
          policies={policies}
          onViewDetails={(artifactId) => {
            setSelectedArtifactId(null);
            onNodeClick?.(artifactId);
          }}
        />
      )}
      {selectedRuntimeGroup && <RuntimeGroupPopup group={selectedRuntimeGroup} onViewExecutions={onViewExecutions} />}
      {selectedRuntimeEdge && <RuntimeEdgePopup edge={selectedRuntimeEdge} />}
      {graph.runtimeOverlay && <div className="ai-dependency-graph-legend"><span>━ Definition</span><span>┄ Runtime activity</span></div>}
      {graph.truncated && <p className="panel-caption">Graph capped for safe rendering.</p>}
      {graph.runtimeOverlay?.truncated && <p className="panel-caption">Runtime activity capped for safe rendering.</p>}
    </div>
  );
}
