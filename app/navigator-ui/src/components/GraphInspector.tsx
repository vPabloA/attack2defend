import type { GraphLink, GraphNode } from '../graph/graphModel';

export type GraphSelection =
  | { kind: 'node'; item: GraphNode }
  | { kind: 'link'; item: GraphLink }
  | null;

export function GraphInspector({ selection }: { selection: GraphSelection }) {
  if (!selection) {
    return (
      <aside className="graph-card graph-inspector">
        <h3>Inspector</h3>
        <p>Selecciona un nodo o una relación para ver source_ref, confidence, owner, estado y trazabilidad.</p>
      </aside>
    );
  }

  if (selection.kind === 'node') {
    const node = selection.item;
    return (
      <aside className="graph-card graph-inspector">
        <h3>{node.id}</h3>
        <span className={`graph-node-chip ${node.type}`}>{node.type}</span>
        <dl>
          <dt>Nombre</dt><dd>{node.rawNode.name}</dd>
          <dt>Estado</dt><dd>{node.status}</dd>
          <dt>Cobertura</dt><dd>{node.coverageStatus}</dd>
          <dt>Confianza</dt><dd>{node.confidenceSummary}</dd>
          <dt>Source ref</dt><dd><code>{node.sourceRef}</code></dd>
          <dt>Trust</dt><dd>{node.trustLevel}</dd>
          <dt>Owners</dt><dd>{node.owners.length ? node.owners.join(', ') : 'not assigned'}</dd>
          {node.officialLink && <><dt>Official link</dt><dd><a href={node.officialLink} target="_blank" rel="noreferrer">Abrir fuente</a></dd></>}
        </dl>
        {node.rawNode.description && <p className="graph-inspector-description">{node.rawNode.description}</p>}
      </aside>
    );
  }

  const link = selection.item;
  return (
    <aside className="graph-card graph-inspector">
      <h3>{link.label}</h3>
      <span className="graph-node-chip relationship">relationship</span>
      <dl>
        <dt>Source</dt><dd>{link.source}</dd>
        <dt>Target</dt><dd>{link.target}</dd>
        <dt>Relationship</dt><dd>{link.relationship}</dd>
        <dt>Confidence</dt><dd>{link.confidence}</dd>
        <dt>Source ref</dt><dd><code>{link.sourceRef}</code></dd>
        <dt>Source kind</dt><dd>{link.sourceKind}</dd>
        <dt>Trust</dt><dd>{link.trustLevel}</dd>
      </dl>
    </aside>
  );
}
