import type { CoherenceItem } from '../lib/routeViewModel';

export interface CoherencePanelProps {
  items: CoherenceItem[];
}

export function CoherencePanel({ items }: CoherencePanelProps) {
  return (
    <section className="a2d-side-card">
      <div className="a2d-panel-title">
        <h3>Lectura de coherencia</h3>
        <span>Chain</span>
      </div>
      <ol className="a2d-coherence-list">
        {items.map((item, index) => (
          <li key={`${item.layer}-${item.label}-${index}`}>
            <span>{index + 1}</span>
            <div>
              <strong>{item.label}</strong>
              <p>{item.reading}</p>
              {item.badge && <em className={`a2d-badge a2d-badge-${item.badge}`}>{item.badge}</em>}
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
