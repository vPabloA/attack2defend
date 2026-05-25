import ForceGraph2D from 'react-force-graph-2d';
import type { GraphLink, GraphNode, GraphViewModel } from '../graph/graphModel';
import type { GraphSelection } from './GraphInspector';

type ForceNode = GraphNode & { x?: number; y?: number };
type ForceLink = GraphLink & { source: string | ForceNode; target: string | ForceNode };

type ForceGraphData = {
  nodes: ForceNode[];
  links: ForceLink[];
};

export function GraphExplorer2D({ view, onSelectNode, onSelectionChange }: { view: GraphViewModel; onSelectNode: (id: string) => void; onSelectionChange: (selection: GraphSelection) => void }) {
  const data: ForceGraphData = {
    nodes: view.nodes as ForceNode[],
    links: view.links as ForceLink[],
  };

  return (
    <section className="graph-card graph-canvas-card">
      <div className="graph-canvas-header">
        <div>
          <h3>2D Graph</h3>
          <p>{view.principle}</p>
        </div>
        <div className="graph-stats-mini">
          <span>{view.stats.totalNodes} nodes</span>
          <span>{view.stats.totalLinks} links</span>
          <span>{view.visibleScope}</span>
        </div>
      </div>
      <div className="graph-canvas-frame">
        <ForceGraph2D
          graphData={data}
          width={900}
          height={560}
          nodeLabel={(node) => `${(node as ForceNode).id} · ${(node as ForceNode).rawNode.name}`}
          linkLabel={(link) => `${(link as ForceLink).relationship} · ${(link as ForceLink).confidence}`}
          nodeVal={(node) => (node as ForceNode).val}
          nodeCanvasObject={(node, ctx, globalScale) => paintNode(node as ForceNode, ctx, globalScale)}
          linkDirectionalArrowLength={4}
          linkDirectionalArrowRelPos={1}
          linkDirectionalParticles={1}
          linkDirectionalParticleWidth={1.2}
          onNodeClick={(node) => {
            const graphNode = node as ForceNode;
            onSelectionChange({ kind: 'node', item: graphNode });
            onSelectNode(graphNode.id);
          }}
          onNodeHover={(node) => onSelectionChange(node ? { kind: 'node', item: node as ForceNode } : null)}
          onLinkHover={(link) => onSelectionChange(link ? { kind: 'link', item: normalizeLink(link as ForceLink) } : null)}
        />
      </div>
    </section>
  );
}

function paintNode(node: ForceNode, ctx: CanvasRenderingContext2D, globalScale: number) {
  const label = node.id;
  const radius = Math.max(5, node.val);
  ctx.beginPath();
  ctx.arc(node.x ?? 0, node.y ?? 0, radius, 0, 2 * Math.PI, false);
  ctx.fillStyle = colorForType(node.type);
  ctx.fill();
  ctx.lineWidth = node.type === 'gap' ? 3 : 1.5;
  ctx.strokeStyle = node.type === 'gap' ? '#a50e0e' : '#ffffff';
  ctx.stroke();

  const fontSize = Math.max(9, 12 / globalScale);
  ctx.font = `${fontSize}px Inter, system-ui, sans-serif`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  ctx.fillStyle = '#202124';
  ctx.fillText(label, node.x ?? 0, (node.y ?? 0) + radius + 3);
}

function normalizeLink(link: ForceLink): GraphLink {
  return {
    ...link,
    source: typeof link.source === 'string' ? link.source : link.source.id,
    target: typeof link.target === 'string' ? link.target : link.target.id,
  };
}

function colorForType(type: GraphNode['type']): string {
  if (type === 'cve') return '#ea4335';
  if (type === 'cwe') return '#fbbc04';
  if (type === 'capec') return '#f29900';
  if (type === 'attack') return '#a142f4';
  if (type === 'd3fend') return '#34a853';
  if (type === 'control') return '#1e8e3e';
  if (type === 'detection') return '#1a73e8';
  if (type === 'evidence') return '#00acc1';
  if (type === 'gap') return '#c5221f';
  if (type === 'action') return '#174ea6';
  return '#5f6368';
}
