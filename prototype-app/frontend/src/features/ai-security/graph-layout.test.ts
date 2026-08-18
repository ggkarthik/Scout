import { describe, expect, it } from 'vitest';
import { layoutDependencyGraph } from './graph-layout';
import type { AiSecurityArtifact, AiSecurityGraph, AiSecurityRelationship } from './types';

function buildNode(overrides: Partial<AiSecurityArtifact> = {}): AiSecurityArtifact {
  return {
    id: 'artifact-1',
    provider: 'AWS',
    providerResourceId: 'arn:aws:bedrock:us-east-1:123456789012:agent/depth-agent',
    artifactType: 'AI_AGENT',
    nativeKind: 'AWS_BEDROCK_AGENT',
    name: 'depth-agent',
    accountId: '123456789012',
    region: 'us-east-1',
    active: true,
    attributes: {},
    ownerName: null,
    ownerState: 'UNOWNED',
    ownerSource: null,
    ownerConfidence: null,
    ownerConfidenceMethod: null,
    ownerConfidenceMethodVersion: null,
    businessCriticality: null,
    environment: null,
    firstObservedAt: '2026-08-01T00:00:00Z',
    lastObservedAt: '2026-08-01T00:00:00Z',
    piiScanStatus: 'NOT_APPLICABLE',
    piiSource: null,
    piiInfoTypes: [],
    piiFindingCount: 0,
    piiLastScannedAt: null,
    ...overrides,
  };
}

function buildEdge(overrides: Partial<AiSecurityRelationship> = {}): AiSecurityRelationship {
  return {
    id: 'edge-1',
    relationshipType: 'INVOKES_LAMBDA',
    sourceArtifactId: 'artifact-1',
    sourceName: 'depth-agent',
    targetArtifactId: 'artifact-2',
    targetName: 'depth-fn',
    attributes: {},
    ...overrides,
  };
}

describe('layoutDependencyGraph', () => {
  it('positions every node and marks the requested root', () => {
    const graph: AiSecurityGraph = {
      nodes: [buildNode(), buildNode({ id: 'artifact-2', name: 'depth-fn' })],
      edges: [buildEdge()],
      truncated: false,
    };

    const { nodes } = layoutDependencyGraph(graph, 'artifact-1');

    expect(nodes).toHaveLength(2);
    const root = nodes.find((node) => node.id === 'artifact-1');
    const child = nodes.find((node) => node.id === 'artifact-2');
    expect(root?.data.isRoot).toBe(true);
    expect(child?.data.isRoot).toBe(false);
    expect(root?.position).toEqual(expect.objectContaining({ x: expect.any(Number), y: expect.any(Number) }));
    expect(child?.position).not.toEqual(root?.position);
  });

  it('formats relationship types into readable edge labels', () => {
    const graph: AiSecurityGraph = {
      nodes: [buildNode(), buildNode({ id: 'artifact-2', name: 'depth-fn' })],
      edges: [buildEdge({ relationshipType: 'INVOKES_LAMBDA' })],
      truncated: false,
    };

    const { edges } = layoutDependencyGraph(graph);

    expect(edges).toEqual([
      expect.objectContaining({ id: 'edge-1', source: 'artifact-1', target: 'artifact-2', label: 'INVOKES LAMBDA' }),
    ]);
  });

  it('drops edges that reference a node outside the returned node set', () => {
    const graph: AiSecurityGraph = {
      nodes: [buildNode()],
      edges: [buildEdge()],
      truncated: false,
    };

    const { nodes, edges } = layoutDependencyGraph(graph);

    expect(nodes).toHaveLength(1);
    expect(edges).toHaveLength(1);
    expect(Number.isFinite(nodes[0]?.position.x)).toBe(true);
    expect(Number.isFinite(nodes[0]?.position.y)).toBe(true);
  });

  it('returns no nodes or edges for an empty graph', () => {
    const graph: AiSecurityGraph = { nodes: [], edges: [], truncated: false };
    expect(layoutDependencyGraph(graph)).toEqual({ nodes: [], edges: [] });
  });
});
