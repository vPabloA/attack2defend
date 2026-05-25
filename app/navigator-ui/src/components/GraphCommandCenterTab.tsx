import { useMemo, useState } from 'react';
import type { KnowledgeBundle, RouteEdge, RouteNode } from '../types/attack2defend';
import type { GraphScope } from '../graph/graphFilters';
import { buildGraphViewModel } from '../graph/graphModel';
import { GraphAiAssistPanel } from './GraphAiAssistPanel';
import { GraphExplorer2D } from './GraphExplorer2D';
import { GraphExportPanel } from './GraphExportPanel';
import { GraphFilters } from './GraphFilters';
import { GraphInspector, type GraphSelection } from './GraphInspector';
import { GraphLegend } from './GraphLegend';

export function GraphCommandCenterTab({
  bundle,
  routeNodes,
  routeEdges,
  input,
  bundleSource,
  onSelect,
}: {
  bundle: KnowledgeBundle;
  routeNodes: RouteNode[];
  routeEdges: RouteEdge[];
  input: string;
  bundleSource: 'generated' | 'fallback';
  onSelect: (id: string) => void;
}) {
  const [scope, setScope] = useState<GraphScope>('canonical_chain');
  const [selection, setSelection] = useState<GraphSelection>(null);
  const view = useMemo(
    () => buildGraphViewModel({ bundle, routeNodes, routeEdges, input, filters: { scope }, aiTask: 'explain_visible_graph' }),
    [bundle, routeNodes, routeEdges, input, scope],
  );

  return (
    <section className="graph-command-center">
      <header className="panel graph-command-hero">
        <div>
          <p className="eyebrow">Graph Command Center</p>
          <h2>Defense Decision Graph 2D</h2>
          <p>CVE → CWE → CAPEC → ATT&CK → D3FEND como columna vertebral. La extensión defensiva aterriza controles, detecciones, evidencia, gaps y acciones.</p>
        </div>
        <div className="graph-command-kpis">
          <span><strong>{view.stats.totalNodes}</strong>nodes</span>
          <span><strong>{view.stats.totalLinks}</strong>links</span>
          <span><strong>{view.stats.gapNodes}</strong>gaps</span>
          <span><strong>{bundleSource}</strong>bundle</span>
        </div>
      </header>

      {view.warnings.length > 0 && (
        <section className="graph-warning-bar">
          {view.warnings.map((warning) => <span key={warning}>{warning}</span>)}
        </section>
      )}

      <div className="graph-command-layout">
        <div className="graph-command-main">
          <GraphFilters scope={scope} onScopeChange={setScope} />
          <GraphExplorer2D view={view} onSelectNode={onSelect} onSelectionChange={setSelection} />
          <GraphAiAssistPanel view={view} />
          <GraphExportPanel view={view} />
        </div>
        <div className="graph-command-side">
          <GraphInspector selection={selection} />
          <GraphLegend />
        </div>
      </div>
    </section>
  );
}
