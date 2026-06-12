export type GraphStageId = 'cve' | 'cwe' | 'capec' | 'attack' | 'd3fend';

export type GraphRenderNode = {
  id: string;
  layer: GraphStageId;
  label?: string;
  title?: string;
  badge?: string;
};

export type GraphRenderNodePlacement = GraphRenderNode & {
  bucket: 'canonical' | 'alternative';
  primary: boolean;
  x: number;
  y: number;
};

export type GraphRenderStage = {
  layer: GraphStageId;
  label: string;
  x: number;
  nodes: GraphRenderNodePlacement[];
  hiddenAlternatives: number;
};

export type GraphRenderPlan = {
  stages: GraphRenderStage[];
  contentHeight: number;
  visibleNodeCount: number;
  hiddenAlternativeCount: number;
};

export const GRAPH_VIEWPORT_HEIGHT = 640;
export const GRAPH_ROW_SPACING = 106;
export const GRAPH_TOP_OFFSET = 104;
export const GRAPH_BOTTOM_PADDING = 108;
export const GRAPH_ALTERNATIVE_LIMIT = 3;

export const GRAPH_STAGE_LAYOUT: Array<{ layer: GraphStageId; label: string; x: number }> = [
  { layer: 'cve', label: 'CVE', x: 90 },
  { layer: 'cwe', label: 'CWE', x: 292 },
  { layer: 'capec', label: 'CAPEC', x: 500 },
  { layer: 'attack', label: 'MITRE ATT&CK', x: 708 },
  { layer: 'd3fend', label: 'D3FEND', x: 910 },
];

const BADGE_PRIORITY: Record<string, number> = {
  official: 0,
  baseline: 1,
  conditional: 2,
  analytical_inferred: 3,
  post_exploitation: 4,
  unknown: 5,
};

export function buildGraphRenderPlan(params: {
  nodes: GraphRenderNode[];
  canonicalPathIds: string[];
  alternativeLimit?: number;
}): GraphRenderPlan {
  const canonicalOrder = new Map(params.canonicalPathIds.map((id, index) => [id, index] as const));
  const alternativeLimit = params.alternativeLimit ?? GRAPH_ALTERNATIVE_LIMIT;
  const stages = GRAPH_STAGE_LAYOUT.map((stage) => {
    const stageNodes = params.nodes.filter((node) => node.layer === stage.layer);
    const canonical = stageNodes
      .filter((node) => canonicalOrder.has(node.id))
      .sort((left, right) => (canonicalOrder.get(left.id) ?? 0) - (canonicalOrder.get(right.id) ?? 0) || left.id.localeCompare(right.id));
    const alternatives = stageNodes
      .filter((node) => !canonicalOrder.has(node.id))
      .sort(compareGraphAlternatives);
    const visibleAlternatives = alternatives.slice(0, alternativeLimit);
    const visibleNodes = [...canonical, ...visibleAlternatives];
    const hiddenAlternatives = Math.max(0, alternatives.length - visibleAlternatives.length);

    return {
      ...stage,
      hiddenAlternatives,
      nodes: visibleNodes.map((node, index) => ({
        ...node,
        bucket: index < canonical.length ? 'canonical' as const : 'alternative' as const,
        primary: index < canonical.length,
        x: stage.x,
        y: GRAPH_TOP_OFFSET + index * GRAPH_ROW_SPACING,
      })),
    } satisfies GraphRenderStage;
  });

  const visibleNodeCount = stages.reduce((sum, stage) => sum + stage.nodes.length, 0);
  const hiddenAlternativeCount = stages.reduce((sum, stage) => sum + stage.hiddenAlternatives, 0);
  const maxRows = Math.max(
    1,
    ...stages.map((stage) => stage.nodes.length + (stage.hiddenAlternatives > 0 ? 1 : 0)),
  );
  const contentHeight = Math.max(
    GRAPH_VIEWPORT_HEIGHT,
    GRAPH_TOP_OFFSET + maxRows * GRAPH_ROW_SPACING + GRAPH_BOTTOM_PADDING,
  );

  return {
    stages,
    contentHeight,
    visibleNodeCount,
    hiddenAlternativeCount,
  };
}

function compareGraphAlternatives(left: GraphRenderNode, right: GraphRenderNode): number {
  const leftPriority = BADGE_PRIORITY[left.badge ?? 'unknown'] ?? BADGE_PRIORITY.unknown;
  const rightPriority = BADGE_PRIORITY[right.badge ?? 'unknown'] ?? BADGE_PRIORITY.unknown;
  if (leftPriority !== rightPriority) return leftPriority - rightPriority;
  const leftLabel = (left.label ?? left.title ?? left.id).toLowerCase();
  const rightLabel = (right.label ?? right.title ?? right.id).toLowerCase();
  return leftLabel.localeCompare(rightLabel) || left.id.localeCompare(right.id);
}
