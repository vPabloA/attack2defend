import type { GraphViewModel } from '../graph/graphModel';
import { exportAiContextPacket, exportCanonicalChain, exportEvidenceRequirements, exportGapPaths, exportMcpGraphPayload, exportVisibleGraph } from '../graph/graphExport';

export function GraphExportPanel({ view }: { view: GraphViewModel }) {
  const exports = {
    canonical_chain: exportCanonicalChain(view),
    visible_graph: exportVisibleGraph(view),
    ai_context_packet: exportAiContextPacket(view),
    mcp_graph_payload: exportMcpGraphPayload(view),
    gap_paths: exportGapPaths(view),
    evidence_requirements: exportEvidenceRequirements(view),
  };

  return (
    <section className="graph-card graph-export-panel">
      <h3>Exports</h3>
      <p>Payloads derivados exactamente del modelo visible/canónico. Listos para QA y futura integración con mcp-security.</p>
      <textarea readOnly value={JSON.stringify(exports, null, 2)} />
    </section>
  );
}
