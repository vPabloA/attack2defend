import { NODE_TYPE_LABELS } from '../graph/graphSemantics';
import type { NodeType } from '../types/attack2defend';

const LEGEND_TYPES: NodeType[] = ['cve', 'cwe', 'capec', 'attack', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'];

export function GraphLegend() {
  return (
    <section className="graph-card graph-legend" aria-label="Graph legend">
      <h3>Leyenda</h3>
      <div className="graph-legend-grid">
        {LEGEND_TYPES.map((type) => (
          <span key={type} className={`graph-legend-item ${type}`}>
            <i />{NODE_TYPE_LABELS[type]}
          </span>
        ))}
      </div>
      <p>CVE → CWE → CAPEC → ATT&CK → D3FEND es la cadena rectora. Control, Detection, Evidence, Gap y Action son extensión defensiva.</p>
    </section>
  );
}
