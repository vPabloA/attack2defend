import type { GraphViewModel } from '../graph/graphModel';

const TASKS = [
  { id: 'explain_visible_graph', label: 'Explain visible graph', value: 'Explica la ruta visible en lenguaje SOC.' },
  { id: 'summarize_gaps', label: 'Summarize gaps', value: 'Resume gaps que bloquean el cierre.' },
  { id: 'suggest_validations', label: 'Suggest validations', value: 'Sugiere validaciones para SOC / Vulnerability Manager.' },
  { id: 'draft_detection_ideas', label: 'Draft detection ideas', value: 'Propone ideas candidatas de detección.' },
  { id: 'generate_executive_summary', label: 'Executive summary', value: 'Traduce la ruta a lenguaje ejecutivo.' },
  { id: 'create_hunting_hypothesis', label: 'Hunting hypothesis', value: 'Formula hipótesis TH basadas en ATT&CK/evidence.' },
];

export function GraphAiAssistPanel({ view }: { view: GraphViewModel }) {
  return (
    <section className="graph-card graph-ai-assist">
      <h3>AI Assist</h3>
      <p>IA habilitada como asistencia gobernada. Usa solo el subgrafo visible: no envía el bundle completo.</p>
      <div className="graph-ai-meta">
        <span>Scope: <strong>{view.visibleScope}</strong></span>
        <span>Context: <strong>{view.aiContextPacket.visible_nodes.length} nodes / {view.aiContextPacket.visible_edges.length} links</strong></span>
        <span>Trust: <strong>candidate/context</strong></span>
      </div>
      <div className="graph-ai-task-grid">
        {TASKS.map((task) => (
          <button key={task.id} disabled title="Pasada 2 exposes governed UI only. Runtime invocation is wired in a later backend/MCP pass.">
            <strong>{task.label}</strong>
            <span>{task.value}</span>
            <em>disabled: backend/MCP capability pending</em>
          </button>
        ))}
      </div>
    </section>
  );
}
