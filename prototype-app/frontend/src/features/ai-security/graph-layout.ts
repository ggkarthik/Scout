import dagre from '@dagrejs/dagre';
import type { Edge, Node } from '@xyflow/react';
import type { AiRuntimeGraphGroup, AiSecurityGraph } from './types';

const NODE_WIDTH = 220;
const NODE_HEIGHT = 56;

export type DependencyGraphNodeData = {
  label: string;
  artifactType: string;
  nativeKind: string;
  active: boolean;
  isRoot: boolean;
  nodeKind: 'ARTIFACT' | 'RUNTIME_AGGREGATE';
  runtimeGroup?: AiRuntimeGraphGroup;
};

export type DependencyGraphLayout = {
  nodes: Node<DependencyGraphNodeData>[];
  edges: Edge[];
};

/** Pure layout math: turns the graph API's flat nodes/edges into positioned React Flow
 * nodes via dagre. No JSX — icon/label rendering lives in the node component. */
export function layoutDependencyGraph(graph: AiSecurityGraph, rootArtifactId?: string): DependencyGraphLayout {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({ rankdir: 'LR', nodesep: 32, ranksep: 96 });

  graph.nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  });
  graph.runtimeOverlay?.groups.forEach((group) => {
    dagreGraph.setNode(group.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  });
  graph.edges.forEach((edge) => {
    if (dagreGraph.hasNode(edge.sourceArtifactId) && dagreGraph.hasNode(edge.targetArtifactId)) {
      dagreGraph.setEdge(edge.sourceArtifactId, edge.targetArtifactId);
    }
  });
  graph.runtimeOverlay?.edges.forEach((edge) => {
    const source = edge.relationshipType === 'EXECUTED_AS' ? edge.runtimeGroupId : edge.artifactId;
    const target = edge.relationshipType === 'EXECUTED_AS' ? edge.artifactId : edge.runtimeGroupId;
    if (dagreGraph.hasNode(source) && dagreGraph.hasNode(target)) dagreGraph.setEdge(source, target);
  });

  dagre.layout(dagreGraph);

  const nodes: Node<DependencyGraphNodeData>[] = graph.nodes.map((node) => {
    const position = dagreGraph.node(node.id);
    return {
      id: node.id,
      type: 'aiArtifact',
      position: position
        ? { x: position.x - NODE_WIDTH / 2, y: position.y - NODE_HEIGHT / 2 }
        : { x: 0, y: 0 },
      data: {
        label: node.name,
        artifactType: node.artifactType,
        nativeKind: node.nativeKind,
        active: node.active,
        isRoot: node.id === rootArtifactId,
        nodeKind: 'ARTIFACT',
      },
      style: { width: NODE_WIDTH },
    };
  });

  const runtimeNodes: Node<DependencyGraphNodeData>[] = (graph.runtimeOverlay?.groups ?? []).map((group) => {
    const position = dagreGraph.node(group.id);
    return {
      id: group.id,
      type: 'aiArtifact',
      position: position ? { x: position.x - NODE_WIDTH / 2, y: position.y - NODE_HEIGHT / 2 } : { x: 0, y: 0 },
      data: {
        label: `${group.executionCount.toLocaleString()} execution${group.executionCount === 1 ? '' : 's'}`,
        artifactType: 'RUNTIME_AGGREGATE',
        nativeKind: group.source,
        active: true,
        isRoot: false,
        nodeKind: 'RUNTIME_AGGREGATE',
        runtimeGroup: group,
      },
      style: { width: NODE_WIDTH },
    };
  });

  const edges: Edge[] = graph.edges.map((edge) => ({
    id: edge.id,
    source: edge.sourceArtifactId,
    target: edge.targetArtifactId,
    label: edge.relationshipType.replace(/_/g, ' '),
  }));

  const runtimeEdges: Edge[] = (graph.runtimeOverlay?.edges ?? []).map((edge) => ({
    id: edge.id,
    source: edge.relationshipType === 'EXECUTED_AS' ? edge.runtimeGroupId : edge.artifactId,
    target: edge.relationshipType === 'EXECUTED_AS' ? edge.artifactId : edge.runtimeGroupId,
    label: edge.participantRole ? `${edge.relationshipType.replace(/_/g, ' ')} · ${edge.participantRole}` : edge.relationshipType.replace(/_/g, ' '),
    data: { runtimeEdge: edge },
    animated: true,
    style: { strokeDasharray: '6 4', strokeWidth: Math.min(5, 1 + Math.log2(Math.max(1, edge.executionCount))), stroke: 'var(--accent, #6366f1)' },
  }));

  return { nodes: [...nodes, ...runtimeNodes], edges: [...edges, ...runtimeEdges] };
}
