import type { Tier1Readout } from '../lib/routeViewModel';

export interface Tier1ReadoutPanelProps {
  readout: Tier1Readout;
  warnings?: string[];
  onCopy?: () => void;
  onExportMarkdown?: () => void;
  onPromote?: () => void;
  onReject?: () => void;
  onReset?: () => void;
}

export function Tier1ReadoutPanel({
  readout,
  warnings = [],
  onCopy,
  onExportMarkdown,
  onPromote,
  onReject,
  onReset,
}: Tier1ReadoutPanelProps) {
  const copyBlock = (readout.copy_paste_10_lines ?? readout.bullets).join('\n');
  return (
    <section className="a2d-side-card a2d-readout-panel">
      <div className="a2d-panel-title">
        <div>
          <h3>{readout.title}</h3>
          <span>{readout.mode === 'node' ? 'Node mode' : readout.mode === 'fallback' ? 'Fallback mode' : 'CVE mode'}</span>
        </div>
        <div className="a2d-action-row">
          {onCopy && <button type="button" onClick={onCopy}>Copy</button>}
          {onExportMarkdown && <button type="button" onClick={onExportMarkdown}>Export Markdown</button>}
          {onPromote && <button type="button" onClick={onPromote} disabled={readout.review_status === 'approved'}>Promote</button>}
          {onReject && <button type="button" onClick={onReject} disabled={readout.review_status === 'rejected'}>Reject</button>}
          {onReset && <button type="button" onClick={onReset}>Reset</button>}
        </div>
      </div>
      {readout.summary && <p className="a2d-readout-summary">{readout.summary}</p>}
      <div className="a2d-metadata-grid">
        <Meta label="Severity" value={readout.severity ?? 'No disponible en bundle local'} />
        <Meta label="CVSS" value={formatCvss(readout.cvss) ?? 'No disponible en bundle local'} />
        <Meta label="Vector" value={readout.vector ?? 'No disponible en bundle local'} />
        <Meta label="Confidence" value={readout.confidence ?? 'Requiere validacion'} />
        <Meta label="Provenance" value={readout.provenance ?? 'unknown'} />
        <Meta label="Review" value={readout.review_status ?? 'candidate'} />
      </div>
      <section className="a2d-readout-copy">
        <div className="a2d-section-title">
          <h4>Copy block</h4>
          <span>10 lines max</span>
        </div>
        <textarea readOnly value={copyBlock} />
      </section>
      {readout.associated_cves?.length ? (
        <section className="a2d-tag-block">
          <div className="a2d-section-title">
            <h4>Associated CVEs</h4>
            <span>{readout.associated_cves.length}</span>
          </div>
          <div className="a2d-chip-row">
            {readout.associated_cves.map((item) => <span key={item}>{item}</span>)}
          </div>
        </section>
      ) : null}
      <RenderList title="ATT&CK techniques" items={readout.attack_techniques?.map(formatTechnique) ?? []} />
      <RenderList title="D3FEND controls" items={readout.d3fend_controls?.map(formatD3fendControl) ?? []} />
      <RenderList title="Compensating controls" items={readout.compensating_controls?.map(formatCandidate) ?? []} />
      <RenderList title="Detection guidance" items={readout.detection_guidance?.map(formatCandidate) ?? []} />
      <RenderList title="Evidence to review" items={readout.evidence_to_review?.map(formatCandidate) ?? []} />
      <RenderList title="Gaps" items={readout.gaps?.map(formatCandidate) ?? []} />
      <RenderList title="Risk acceptance matrix" items={readout.risk_acceptance_matrix?.map((item) => `${item.label}: ${item.minimum_controls.join(', ')} — ${item.rationale}`) ?? []} />
      <RenderList title="Checklist" items={readout.checklist ?? []} />
      <RenderList title="Escalation criteria" items={readout.escalation_criteria ?? []} />
      {readout.bullets.length > 0 && (
        <ul className="a2d-readout-list">
          {readout.bullets.map((bullet) => (
            <li key={bullet}>{bullet}</li>
          ))}
        </ul>
      )}
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

function RenderList({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null;
  return (
    <section className="a2d-readout-section">
      <div className="a2d-section-title">
        <h4>{title}</h4>
        <span>{items.length}</span>
      </div>
      <ul>
        {items.map((item) => <li key={item}>{item}</li>)}
      </ul>
    </section>
  );
}

function formatTechnique(item: { id: string; name: string; justification?: string; confidence?: string; review_status?: string }) {
  return `${item.id} · ${item.name}${item.justification ? ` — ${item.justification}` : ''}`;
}

function formatD3fendControl(item: { id: string; name: string; justification: string; confidence?: string; review_status?: string }) {
  return `${item.id} · ${item.name} — ${item.justification}`;
}

function formatCandidate(item: { id: string; label: string; text: string; confidence?: string; review_status?: string }) {
  return `${item.label || item.id}: ${item.text}`;
}

function formatCvss(value: unknown): string | number | undefined {
  if (value == null) return undefined;
  if (typeof value === 'string' || typeof value === 'number') return value;
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    if (typeof record.base_score === 'number' || typeof record.base_score === 'string') return String(record.base_score);
    if (typeof record.score === 'number' || typeof record.score === 'string') return String(record.score);
  }
  return undefined;
}
