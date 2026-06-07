import type { Tier1Readout } from '../lib/routeViewModel';

export interface Tier1ReadoutPanelProps {
  readout: Tier1Readout;
  warnings?: string[];
}

export function Tier1ReadoutPanel({ readout, warnings = [] }: Tier1ReadoutPanelProps) {
  return (
    <section className="a2d-side-card">
      <div className="a2d-panel-title">
        <h3>{readout.title}</h3>
        <span>Readout</span>
      </div>
      <ul className="a2d-readout-list">
        {readout.bullets.map((bullet) => (
          <li key={bullet}>{bullet}</li>
        ))}
      </ul>
      <div className="a2d-metadata-grid">
        <Meta label="Severity" value={readout.severity ?? 'No disponible en bundle local'} />
        <Meta label="CVSS" value={readout.cvss ?? 'No disponible en bundle local'} />
        <Meta label="Vector" value={readout.vector ?? 'No disponible en bundle local'} />
        <Meta label="Confidence" value={readout.confidence ?? 'Requiere validacion'} />
      </div>
      {warnings.length > 0 && (
        <div className="a2d-warning-list">
          {warnings.map((warning) => <span key={warning}>{warning}</span>)}
        </div>
      )}
    </section>
  );
}

function Meta({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
