import type { RouteViewEdge, RouteViewNode, RouteLayer } from '../lib/routeViewModel';

export interface MappingGraph2DProps {
  nodes: RouteViewNode[];
  edges: RouteViewEdge[];
  canonicalPath: RouteViewNode[];
  warnings?: string[];
  isPreview?: boolean;
}

const stages: Array<{ layer: RouteLayer; label: string; x: number }> = [
  { layer: 'cve', label: 'CVE', x: 90 },
  { layer: 'cwe', label: 'CWE', x: 292 },
  { layer: 'capec', label: 'CAPEC', x: 500 },
  { layer: 'attack', label: 'MITRE ATT&CK', x: 708 },
  { layer: 'd3fend', label: 'D3FEND', x: 910 },
];

export function MappingGraph2D({ nodes, edges, canonicalPath, warnings = [], isPreview = false }: MappingGraph2DProps) {
  const primaryIds = new Set(canonicalPath.map((node) => node.id));
  const grouped = stages.map((stage) => {
    const stageNodes = nodes.filter((node) => node.layer === stage.layer);
    const primary = stageNodes.filter((node) => primaryIds.has(node.id));
    const secondary = stageNodes.filter((node) => !primaryIds.has(node.id));
    return { ...stage, nodes: [...primary, ...secondary] };
  });
  const maxRows = Math.max(1, ...grouped.map((stage) => stage.nodes.length));
  const graphHeight = Math.max(470, 148 + maxRows * 116);
  const positions = new Map<string, { x: number; y: number }>();

  grouped.forEach((stage) => {
    stage.nodes.forEach((node, index) => {
      positions.set(node.id, { x: stage.x, y: 118 + index * 116 });
    });
  });

  const visibleEdges = edges.filter((edge) => positions.has(edge.source) && positions.has(edge.target));
  const hasRoute = nodes.length > 0;

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

      <div className="a2d-graph-stage" style={{ minHeight: graphHeight }}>
        <svg className="a2d-edge-layer" viewBox={`0 0 1000 ${graphHeight}`} preserveAspectRatio="none" aria-hidden="true">
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

        {stages.map((stage) => (
          <div key={stage.layer} className={`a2d-stage-label a2d-layer-${stage.layer}`} style={{ left: `${stage.x / 10}%` }}>
            {stage.label}
          </div>
        ))}

        {grouped.flatMap((stage) => stage.nodes.map((node, index) => (
          <GraphNode key={node.id} node={node} stageX={stage.x} top={82 + index * 116} primary={primaryIds.has(node.id)} isPreview={isPreview} />
        )))}

        {!hasRoute && (
          <div className="a2d-empty-graph">
            <strong>No hay ruta disponible en el bundle local para este input.</strong>
            <span>Ingresa un CVE, CWE, CAPEC, ATT&amp;CK o D3FEND disponible y ejecuta Analyze.</span>
          </div>
        )}

        {hasRoute && grouped.find((stage) => stage.layer === 'd3fend')?.nodes.length === 0 && (
          <div className="a2d-graph-gap">
            No hay capacidad defensiva D3FEND asociada en el bundle local.
          </div>
        )}
      </div>

      {warnings.length > 0 && (
        <div className="a2d-graph-warnings">
          {warnings.map((warning) => <span key={warning}>{warning}</span>)}
        </div>
      )}
    </section>
  );
}

function GraphNode({ node, stageX, top, primary, isPreview }: { node: RouteViewNode; stageX: number; top: number; primary: boolean; isPreview: boolean }) {
  return (
    <div
      className={`a2d-graph-node a2d-layer-${node.layer} ${primary ? 'a2d-node-primary' : 'a2d-node-secondary'}${isPreview ? ' a2d-node-preview' : ''}`}
      style={{ left: `${stageX / 10}%`, top }}
    >
      <strong>{node.id}</strong>
      <span>{node.label.replace(`${node.id} · `, '')}</span>
      {node.badge && <em className={`a2d-badge a2d-badge-${node.badge}`}>{node.badge}</em>}
    </div>
  );
}
