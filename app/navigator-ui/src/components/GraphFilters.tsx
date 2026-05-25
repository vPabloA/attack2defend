import type { GraphScope } from '../graph/graphFilters';

const SCOPES: Array<{ id: GraphScope; label: string; description: string }> = [
  { id: 'canonical_chain', label: 'Canonical Chain', description: 'CVE → CWE → CAPEC → ATT&CK → D3FEND' },
  { id: 'threat_route', label: 'Threat Route', description: 'Ruta de amenaza y artefactos relevantes' },
  { id: 'defense_readiness', label: 'Defense Readiness', description: 'D3FEND hacia controles, detecciones y evidencia' },
  { id: 'gaps_only', label: 'Gaps Only', description: 'Brechas, evidencia y acciones relacionadas' },
  { id: 'evidence_view', label: 'Evidence View', description: 'Detecciones y evidencia requerida' },
  { id: 'owners_view', label: 'Owners View', description: 'Responsables y acciones operativas' },
  { id: 'full_traceability', label: 'Full Traceability', description: 'Ruta activa completa y limitada' },
];

export function GraphFilters({ scope, onScopeChange }: { scope: GraphScope; onScopeChange: (scope: GraphScope) => void }) {
  return (
    <section className="graph-card graph-filters" aria-label="Graph filters">
      <h3>Scopes</h3>
      <div className="graph-filter-grid">
        {SCOPES.map((item) => (
          <button key={item.id} className={scope === item.id ? 'active' : ''} onClick={() => onScopeChange(item.id)} title={item.description}>
            <strong>{item.label}</strong>
            <span>{item.description}</span>
          </button>
        ))}
      </div>
    </section>
  );
}
