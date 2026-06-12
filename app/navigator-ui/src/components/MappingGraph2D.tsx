import { useMemo } from 'react';
import type { RouteViewEdge, RouteViewNode, RouteLayer } from '../lib/routeViewModel';
import {
  buildGraphRenderPlan,
  GRAPH_VIEWPORT_HEIGHT,
  type GraphRenderNode,
  type GraphRenderNodePlacement,
} from '../graph/graphRenderPlan.ts';

export interface MappingGraph2DProps {
  nodes: RouteViewNode[];
  edges: RouteViewEdge[];
  canonicalPath: RouteViewNode[];
  warnings?: string[];
  isPreview?: boolean;
}

const STAGE_LABELS: Record<RouteLayer, string> = {
  cve: 'CVE',
  cwe: 'CWE',
  capec: 'CAPEC',
  attack: 'MITRE ATT&CK',
  d3fend: 'D3FEND',
  control: 'Control',
  detection: 'Detection',
  evidence: 'Evidence',
  gap: 'Gap',
  action: 'Action',
};

export function MappingGraph2D({ nodes, edges, canonicalPath, warnings = [], isPreview = false }: MappingGraph2DProps) {
  const renderNodes = useMemo(
    () => nodes.map(toRenderNode).filter((node): node is GraphRenderNode => node !== null),
    [nodes],
  );
  const plan = useMemo(
    () => buildGraphRenderPlan({
      nodes: renderNodes,
      canonicalPathIds: canonicalPath.map((node) => node.id),
    }),
    [renderNodes, canonicalPath],
  );

  const positions = useMemo(() => {
    const map = new Map<string, { x: number; y: number }>();
    for (const stage of plan.stages) {
      for (const node of stage.nodes) {
        map.set(node.id, { x: node.x, y: node.y });
      }
    }
    return map;
  }, [plan]);

  const visibleEdges = useMemo(
    () => edges.filter((edge) => positions.has(edge.source) && positions.has(edge.target)),
    [edges, positions],
  );
  const hasRoute = plan.visibleNodeCount > 0;
  return (
    <section className={`a2d-graph-card${isPreview ? ' a2d-graph-preview' : ''}`}>
      <div className="a2d-graph-head">
        <div>
          <h2>Attack2Defend Mapping Graph</h2>
          <p>CVE -&gt; CWE -&gt; CAPEC -&gt; ATT&amp;CK -&gt; D3FEND</p>
        </div>
        <div className="a2d-graph-actions">
          {isPreview ? (
            <span className="a2d-preview-badge">Preview / Not Canonical</span>
          ) : (
            <>
              <span>Static-first</span>
              <span>Bundle route</span>
            </>
          )}
        </div>
      </div>

      <div className="a2d-graph-stage" style={{ height: GRAPH_VIEWPORT_HEIGHT }}>
        <div className="a2d-graph-stage-inner" style={{ height: plan.contentHeight }}>
          <svg className="a2d-edge-layer" viewBox={`0 0 1000 ${plan.contentHeight}`} preserveAspectRatio="none" aria-hidden="true">
            {visibleEdges.map((edge) => {
              const source = positions.get(edge.source);
              const target = positions.get(edge.target);
              if (!source || !target) return null;
              const sourceOffset = source.x < target.x ? 74 : -74;
              const targetOffset = source.x < target.x ? -74 : 74;
              const startX = source.x + sourceOffset;
              const endX = target.x + targetOffset;
              const midX = startX + (endX - startX) / 2;
              const dashed = edge.isConditional || edge.isInferred || edge.badge === 'conditional' || edge.badge === 'analytical_inferred';
              return (
                <path
                  key={edge.id}
                  d={`M ${startX} ${source.y} C ${midX} ${source.y}, ${midX} ${target.y}, ${endX} ${target.y}`}
                  className={`a2d-edge ${dashed ? 'a2d-edge-dashed' : 'a2d-edge-primary'}`}
                />
              );
            })}
          </svg>

          {plan.stages.map((stage) => (
            <div key={stage.layer}>
              <div className={`a2d-stage-label a2d-layer-${stage.layer}`} style={{ left: `${stage.x / 10}%` }}>
                {stage.label}
              </div>
              {stage.nodes.map((node) => (
                <GraphNode key={node.id} node={node} />
              ))}
              {stage.hiddenAlternatives > 0 && (
                <div className={`a2d-stage-more a2d-layer-${stage.layer}`} style={{ left: `${stage.x / 10}%`, top: plan.contentHeight - 72 }}>
                  +{stage.hiddenAlternatives} more hidden
                </div>
              )}
            </div>
          ))}

          {hasRoute && plan.hiddenAlternativeCount > 0 && (
            <div className="a2d-graph-more-note">
              Showing canonical path plus up to 3 alternatives per stage.
            </div>
          )}

          {!hasRoute && (
            <div className="a2d-empty-graph">
              <strong>No hay ruta disponible en el bundle local para este input.</strong>
              <span>Ingresa un CVE, CWE, CAPEC, ATT&amp;CK o D3FEND disponible y ejecuta Analyze.</span>
            </div>
          )}

          {hasRoute && !plan.stages.find((stage) => stage.layer === 'd3fend')?.nodes.length && (
            <div className="a2d-graph-gap">
              No hay capacidad defensiva D3FEND asociada en el bundle local.
            </div>
          )}
        </div>
      </div>

      {warnings.length > 0 && (
        <div className="a2d-graph-warnings">
          {warnings.map((warning) => <span key={warning}>{warning}</span>)}
        </div>
      )}
    </section>
  );
}

function GraphNode({ node }: { node: GraphRenderNodePlacement }) {
  return (
    <div
      className={`a2d-graph-node a2d-layer-${node.layer} ${node.primary ? 'a2d-node-primary' : 'a2d-node-secondary'} a2d-node-${node.bucket}`}
      style={{ left: `${node.x / 10}%`, top: node.y }}
    >
      <strong>{node.id}</strong>
      <span>{node.label?.replace(`${node.id} · `, '') ?? node.title ?? node.id}</span>
      {node.badge && <em className={`a2d-badge a2d-badge-${node.badge}`}>{node.badge}</em>}
    </div>
  );
}

function toRenderNode(node: RouteViewNode): GraphRenderNode | null {
  if (!isGraphStageLayer(node.layer)) return null;
  return {
    id: node.id,
    layer: node.layer,
    label: node.label,
    title: node.description ?? node.label,
    badge: node.badge,
  };
}

function isGraphStageLayer(layer: RouteLayer): layer is 'cve' | 'cwe' | 'capec' | 'attack' | 'd3fend' {
  return layer === 'cve' || layer === 'cwe' || layer === 'capec' || layer === 'attack' || layer === 'd3fend';
}
