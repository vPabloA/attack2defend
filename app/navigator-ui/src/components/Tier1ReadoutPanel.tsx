import { useMemo } from 'react';
import type { Tier1Readout } from '../lib/routeViewModel';
import {
  buildTier1ReadoutPresentation,
  type ReadoutBucket,
  type ReadoutSignal,
  type ReadoutTopSection,
} from '../lib/tier1ReadoutLayout.ts';

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
  const presentation = useMemo(() => buildTier1ReadoutPresentation(readout), [readout]);
  const copyBlock = presentation.supporting.copyPasteLines.join('\n');

  return (
    <section className="a2d-side-card a2d-readout-panel">
      <div className="a2d-panel-title a2d-readout-title">
        <div>
          <h3>{readout.title}</h3>
          <span>{readout.mode === 'fallback' ? 'Fallback support' : readout.mode === 'node' ? 'Node mode' : 'CVE mode'}</span>
        </div>
        <div className="a2d-action-row">
          {onCopy && <button type="button" onClick={onCopy}>Copy</button>}
          {onExportMarkdown && <button type="button" onClick={onExportMarkdown}>Export Markdown</button>}
          {onPromote && <button type="button" onClick={onPromote} disabled={readout.review_status === 'approved'}>Promote</button>}
          {onReject && <button type="button" onClick={onReject} disabled={readout.review_status === 'rejected'}>Reject</button>}
          {onReset && <button type="button" onClick={onReset}>Reset</button>}
        </div>
      </div>

      <p className="a2d-readout-summary">{presentation.summary}</p>

      <div className="a2d-metadata-grid a2d-readout-metadata">
        {presentation.metadata.map((item) => <Meta key={item.label} label={item.label} value={item.value} />)}
      </div>

      <div className="a2d-readout-top-grid">
        {presentation.topSections.map((section) => (
          <TopSignalSection key={section.key} section={section} />
        ))}
      </div>

      <details className="a2d-collapsible a2d-readout-collapsible">
        <summary>
          <span>Lineage buckets</span>
          <strong>{formatBucketCounts(presentation.bucketCounts)}</strong>
          <em>Canonical, candidate, inferred, fallback</em>
        </summary>
        <div className="a2d-lineage-grid">
          {(['canonical', 'candidate', 'inferred', 'fallback'] as ReadoutBucket[]).map((bucket) => (
            <SignalBucket key={bucket} bucket={bucket} items={presentation.lineage[bucket]} />
          ))}
        </div>
      </details>

      <details className="a2d-collapsible a2d-readout-collapsible">
        <summary>
          <span>Supporting context</span>
          <strong>{presentation.supporting.attackTechniques.length + presentation.supporting.d3fendControls.length + presentation.supporting.compensatingControls.length}</strong>
          <em>ATT&CK, D3FEND, controls, bullets and CVEs</em>
        </summary>
        <div className="a2d-support-grid">
          <SignalSection title="ATT&CK techniques" items={presentation.supporting.attackTechniques} />
          <SignalSection title="D3FEND controls" items={presentation.supporting.d3fendControls} />
          <SignalSection title="Compensating controls" items={presentation.supporting.compensatingControls} />
          <SignalSection title="Risk acceptance" items={presentation.supporting.riskAcceptance} />
          <StringSection title="Associated CVEs" items={presentation.supporting.associatedCves} />
          <StringSection title="Bullets" items={presentation.supporting.bullets} />
          <SignalSection title="Checklist" items={presentation.supporting.checklist} />
          <SignalSection title="Escalation criteria" items={presentation.supporting.escalationCriteria} />
        </div>
      </details>

      <details className="a2d-collapsible a2d-readout-collapsible">
        <summary>
          <span>Copy block</span>
          <strong>{presentation.supporting.copyPasteLines.length}</strong>
          <em>10 lines max</em>
        </summary>
        <textarea readOnly value={copyBlock} />
      </details>

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

function TopSignalSection({ section }: { section: ReadoutTopSection }) {
  return (
    <section className="a2d-readout-top-card">
      <div className="a2d-section-title">
        <h4>{section.title}</h4>
        <span>{section.items.length}{section.hiddenCount > 0 ? ` +${section.hiddenCount}` : ''}</span>
      </div>
      {section.items.length > 0 ? (
        <div className="a2d-signal-list">
          {section.items.map((item) => <SignalCard key={item.id} signal={item} />)}
        </div>
      ) : (
        <p className="a2d-empty-state">{section.emptyText}</p>
      )}
    </section>
  );
}

function SignalSection({ title, items }: { title: string; items: ReadoutSignal[] }) {
  if (!items.length) {
    return (
      <section className="a2d-support-card">
        <div className="a2d-section-title">
          <h4>{title}</h4>
          <span>0</span>
        </div>
        <p className="a2d-empty-state">No items available.</p>
      </section>
    );
  }

  return (
    <section className="a2d-support-card">
      <div className="a2d-section-title">
        <h4>{title}</h4>
        <span>{items.length}</span>
      </div>
      <div className="a2d-signal-list a2d-signal-list-compact">
        {items.map((item) => <SignalCard key={item.id} signal={item} compact />)}
      </div>
    </section>
  );
}

function StringSection({ title, items }: { title: string; items: string[] }) {
  if (!items.length) {
    return (
      <section className="a2d-support-card">
        <div className="a2d-section-title">
          <h4>{title}</h4>
          <span>0</span>
        </div>
        <p className="a2d-empty-state">No items available.</p>
      </section>
    );
  }

  return (
    <section className="a2d-support-card">
      <div className="a2d-section-title">
        <h4>{title}</h4>
        <span>{items.length}</span>
      </div>
      <ul className="a2d-support-string-list">
        {items.map((item) => <li key={item}>{item}</li>)}
      </ul>
    </section>
  );
}

function SignalBucket({ bucket, items }: { bucket: ReadoutBucket; items: ReadoutSignal[] }) {
  return (
    <section className={`a2d-bucket-card bucket-${bucket}`}>
      <div className="a2d-section-title">
        <h4>{bucketLabel(bucket)}</h4>
        <span>{items.length}</span>
      </div>
      {items.length > 0 ? (
        <div className="a2d-signal-list a2d-signal-list-compact">
          {items.map((item) => <SignalCard key={item.id} signal={item} compact />)}
        </div>
      ) : (
        <p className="a2d-empty-state">No items in this bucket.</p>
      )}
    </section>
  );
}

function SignalCard({ signal, compact = false }: { signal: ReadoutSignal; compact?: boolean }) {
  return (
    <article className={`a2d-signal-card bucket-${signal.bucket} ${compact ? 'compact' : ''}`}>
      <div className="a2d-signal-card-head">
        <strong>{signal.id}</strong>
        <span className={`a2d-bucket-pill bucket-${signal.bucket}`}>{bucketLabel(signal.bucket)}</span>
      </div>
      <p>{signal.text}</p>
      <div className="a2d-signal-card-meta">
        {signal.review_status && <em>{signal.review_status}</em>}
        {signal.confidence && <em>{signal.confidence}</em>}
        {signal.provenance && <em>{signal.provenance}</em>}
      </div>
    </article>
  );
}

function bucketLabel(bucket: ReadoutBucket): string {
  if (bucket === 'canonical') return 'Canonical';
  if (bucket === 'candidate') return 'Candidate';
  if (bucket === 'inferred') return 'Inferred';
  return 'Fallback';
}

function formatBucketCounts(counts: Record<ReadoutBucket, number>): string {
  return `C ${counts.canonical} · Cd ${counts.candidate} · I ${counts.inferred} · F ${counts.fallback}`;
}
