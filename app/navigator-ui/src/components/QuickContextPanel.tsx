export interface QuickContextPanelProps {
  context: Record<string, string>;
  warnings?: string[];
}

export function QuickContextPanel({ context, warnings = [] }: QuickContextPanelProps) {
  const entries = Object.entries(context);
  return (
    <section className="a2d-side-card a2d-quick-card">
      <div className="a2d-panel-title">
        <h3>Contexto rapido</h3>
        <span>Bundle</span>
      </div>
      <dl className="a2d-context-list">
        {entries.map(([key, value]) => (
          <div key={key}>
            <dt>{formatKey(key)}</dt>
            <dd>{value || 'No disponible en bundle local'}</dd>
          </div>
        ))}
      </dl>
      {warnings.length > 0 && (
        <div className="a2d-warning-list">
          {warnings.map((warning) => <span key={warning}>{warning}</span>)}
        </div>
      )}
    </section>
  );
}

function formatKey(value: string): string {
  return value.replace(/_/g, ' ');
}
