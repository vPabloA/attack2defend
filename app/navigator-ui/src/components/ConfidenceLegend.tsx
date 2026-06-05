const badges = [
  ['official', 'Senal oficial o fuente explicita'],
  ['analytical_inferred', 'Inferencia analitica'],
  ['baseline', 'Mapeo baseline'],
  ['conditional', 'Depende de contexto'],
  ['post_exploitation', 'Posterior a explotacion inicial'],
  ['unknown', 'Sin senal suficiente'],
] as const;

export function ConfidenceLegend() {
  return (
    <section className="a2d-legend" aria-label="Confidence legend">
      <h3>Leyenda de confianza</h3>
      <div className="a2d-legend-grid">
        {badges.map(([badge, label]) => (
          <div key={badge}>
            <span className={`a2d-legend-swatch a2d-badge-${badge}`} />
            <strong>{badge}</strong>
            <p>{label}</p>
          </div>
        ))}
        <div>
          <span className="a2d-line-sample a2d-line-primary" />
          <strong>Ruta primaria</strong>
          <p>Mayor coherencia</p>
        </div>
        <div>
          <span className="a2d-line-sample a2d-line-inferred" />
          <strong>Ruta condicional</strong>
          <p>Soporte o inferencia</p>
        </div>
      </div>
    </section>
  );
}
