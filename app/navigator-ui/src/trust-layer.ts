type TrustState = 'Oficial' | 'Derivado del grafo' | 'Sugerido' | 'Requiere validación' | 'No confirmado';

type EvidenceItem = {
  id: string;
  source: string;
  evidenceType: TrustState;
  usedFor: string;
  sourceRef: string;
  officialLink: string;
  status: TrustState;
  fact: string;
};

type ClosureItem = {
  owner: string;
  action: string;
  closureEvidence: string[];
};

const TRUST_LAYER_VERSION = '1.0';
const BADGE_CLASS = 'trust-badge';
const TRUSTED_ROOT_CLASS = 'trust-layer-applied';

const SOURCE_BY_TYPE: Record<string, { source: string; state: TrustState }> = {
  cve: { source: 'NVD / CVE.org / Vendor', state: 'Oficial' },
  cwe: { source: 'MITRE CWE', state: 'Oficial' },
  capec: { source: 'MITRE CAPEC', state: 'Oficial' },
  attack: { source: 'MITRE ATT&CK', state: 'Oficial' },
  d3fend: { source: 'MITRE D3FEND', state: 'Oficial' },
  control: { source: 'Bundle / Control mapping', state: 'Derivado del grafo' },
  detection: { source: 'Bundle / Detection mapping', state: 'Sugerido' },
  evidence: { source: 'Bundle / Evidence mapping', state: 'Derivado del grafo' },
  gap: { source: 'Bundle / Gap mapping', state: 'Requiere validación' },
  action: { source: 'Bundle / Action mapping', state: 'Sugerido' },
};

const OWNER_CLOSURE: ClosureItem[] = [
  {
    owner: 'Vulnerability Manager',
    action: 'Confirmar activos afectados, versión o condición vulnerable y prioridad de remediación.',
    closureEvidence: ['inventario/CMDB o EASM con activo identificado', 'versión instalada o estado de parche', 'referencia al advisory o CVE aplicable'],
  },
  {
    owner: 'Infra',
    action: 'Validar exposición del servicio y reducir superficie si aplica.',
    closureEvidence: ['resultado de exposición externa o interna', 'regla de firewall/WAF/SG o cambio equivalente', 'evidencia de restricción o segmentación aplicada'],
  },
  {
    owner: 'SOC',
    action: 'Revisar logs y evidencia asociada al vector sugerido.',
    closureEvidence: ['query/log export con ventana temporal', 'resultado documentado: hallazgo o descarte', 'evidencia de sesiones, autenticación o actividad posterior revisada'],
  },
  {
    owner: 'Detection Engineering',
    action: 'Validar o implementar detecciones para la ruta priorizada.',
    closureEvidence: ['regla/query versionada', 'test case ejecutado', 'criterio de falso positivo y evidencia esperada definida'],
  },
  {
    owner: 'CTI/TH',
    action: 'Revisar contexto de explotación y priorizar hipótesis de hunting.',
    closureEvidence: ['pivotes/IOCs o hipótesis documentadas', 'resultado del hunting', 'alcance y ventana de búsqueda definidos'],
  },
  {
    owner: 'CSMA',
    action: 'Dar seguimiento ejecutivo a riesgo, owner y cierre.',
    closureEvidence: ['riesgo registrado', 'owner y fecha compromiso', 'evidencia de cierre adjunta al control o caso'],
  },
];

const GAP_TRUST = [
  {
    gap: 'Inventario no confirmado',
    impact: 'No se puede saber si existe exposición real en activos propios.',
    owner: 'Vulnerability Manager / Infra',
    evidence: 'CMDB, EASM, asset inventory o escaneo controlado.',
  },
  {
    gap: 'Exposición no validada',
    impact: 'No se puede priorizar correctamente superficie pública o administrativa.',
    owner: 'Infra',
    evidence: 'Firewall/WAF/SG, rutas, puertos, escaneo o diagrama de exposición.',
  },
  {
    gap: 'Evidencia/logs no confirmados',
    impact: 'SOC no puede confirmar ni descartar explotación con base auditable.',
    owner: 'SOC / Infra',
    evidence: 'Fuente de logs, retención, consulta ejecutada y resultado.',
  },
  {
    gap: 'Detección no validada',
    impact: 'No existe prueba de que el comportamiento sea observable.',
    owner: 'Detection Engineering',
    evidence: 'Regla/query, test case, señal esperada y ajuste de falsos positivos.',
  },
  {
    gap: 'Acción de cierre no documentada',
    impact: 'El riesgo puede quedar abierto aunque exista una recomendación.',
    owner: 'CSMA / Owner técnico',
    evidence: 'Ticket, change record, evidencia de remediación y fecha de cierre.',
  },
];

let drawer: HTMLElement | null = null;
let lastEvidence: EvidenceItem[] = [];

function bootTrustLayer() {
  injectTrustStyles();
  ensureDrawer();
  applyTrustLayer();

  const observer = new MutationObserver(() => applyTrustLayer());
  observer.observe(document.body, { childList: true, subtree: true });
}

function applyTrustLayer() {
  const shell = document.querySelector('.app-shell');
  if (!shell) return;
  shell.classList.add(TRUSTED_ROOT_CLASS);

  const evidence = collectEvidenceItems();
  lastEvidence = evidence;

  decorateSummary(evidence);
  decorateTraceabilityNodes(evidence);
  decorateDetections();
  decorateGaps();
  decorateOwnerActions();
  decorateExport(evidence);
}

function decorateSummary(evidence: EvidenceItem[]) {
  const panel = findPanelByTitle('Resumen defensivo preliminar');
  if (!panel || panel.querySelector('.trust-summary-bar')) return;

  const bar = document.createElement('div');
  bar.className = 'trust-summary-bar';
  bar.append(
    makeBadge({ label: 'Source-grounded', item: evidence[0] ?? fallbackEvidence('Resumen defensivo preliminar', 'Bundle local / source_refs', 'Derivado del grafo') }),
    makeBadge({ label: 'Requiere validación', item: fallbackEvidence('Cobertura del entorno', 'Validación operacional pendiente', 'Requiere validación') }),
    makeBadge({ label: 'Validator wins', item: fallbackEvidence('Ruta curada', 'Curated route validator', 'Derivado del grafo') }),
  );
  panel.appendChild(bar);
}

function decorateTraceabilityNodes(evidence: EvidenceItem[]) {
  document.querySelectorAll<HTMLElement>('.traceability-node').forEach((nodeEl) => {
    if (nodeEl.querySelector(`.${BADGE_CLASS}`)) return;
    const id = nodeEl.querySelector('button')?.textContent?.trim() || 'unknown';
    const type = classToNodeType(nodeEl);
    const item = evidence.find((entry) => entry.id === id) ?? fallbackEvidence(id, SOURCE_BY_TYPE[type]?.source ?? 'Bundle local', SOURCE_BY_TYPE[type]?.state ?? 'Derivado del grafo');
    const footer = document.createElement('div');
    footer.className = 'trust-node-footer';
    footer.appendChild(makeBadge({ label: item.source, item }));
    footer.appendChild(makeBadge({ label: item.status, item }));
    nodeEl.appendChild(footer);
  });
}

function decorateDetections() {
  const panel = findPanelByTitle('Detecciones sugeridas');
  if (!panel || panel.querySelector('.trust-detection-note')) return;

  const note = document.createElement('p');
  note.className = 'trust-detection-note';
  note.textContent = 'Detecciones sugeridas. No confirma implementación actual en el entorno.';
  panel.insertBefore(note, panel.querySelector('.consultative-list'));

  panel.querySelectorAll<HTMLLIElement>('.consultative-list li').forEach((li) => {
    if (li.querySelector('.trust-inline-meta')) return;
    const meta = document.createElement('div');
    meta.className = 'trust-inline-meta';
    meta.append(
      makeBadge({ label: 'Sugerido', item: fallbackEvidence(li.textContent || 'Detección sugerida', 'Ruta curada / grafo', 'Sugerido') }),
      makeBadge({ label: 'Evidencia requerida', item: fallbackEvidence('Evidencia requerida', 'logs, query, test case', 'Requiere validación') }),
    );
    li.appendChild(meta);
  });
}

function decorateGaps() {
  const panel = findPanelByTitle('Brechas potenciales');
  if (!panel || panel.querySelector('.trust-gap-grid')) return;
  const chips = panel.querySelector('.chip-list');
  if (chips) chips.remove();

  const grid = document.createElement('div');
  grid.className = 'trust-gap-grid';
  GAP_TRUST.forEach((gap) => {
    const card = document.createElement('article');
    card.className = 'trust-gap-card';
    card.innerHTML = `<h3>${escapeHtml(gap.gap)}</h3><p>${escapeHtml(gap.impact)}</p><dl><dt>Owner sugerido</dt><dd>${escapeHtml(gap.owner)}</dd><dt>Evidencia requerida</dt><dd>${escapeHtml(gap.evidence)}</dd></dl>`;
    card.appendChild(makeBadge({ label: 'Requiere validación', item: fallbackEvidence(gap.gap, gap.evidence, 'Requiere validación') }));
    grid.appendChild(card);
  });
  panel.appendChild(grid);
}

function decorateOwnerActions() {
  const panel = findPanelByTitle('Acciones sugeridas por owner');
  if (!panel) return;

  panel.querySelectorAll<HTMLElement>('.owner-card').forEach((card) => {
    if (card.querySelector('.closure-criteria')) return;
    const owner = card.querySelector('h3')?.textContent?.trim() || '';
    const closure = OWNER_CLOSURE.find((item) => item.owner === owner) ?? OWNER_CLOSURE.find((item) => owner.includes(item.owner));
    if (!closure) return;

    const section = document.createElement('div');
    section.className = 'closure-criteria';
    section.innerHTML = `<strong>Evidencia de cierre esperada</strong><ul>${closure.closureEvidence.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`;
    section.appendChild(makeBadge({ label: 'Criterio de cierre', item: fallbackEvidence(owner, closure.closureEvidence.join('; '), 'Requiere validación') }));
    card.appendChild(section);
  });
}

function decorateExport(evidence: EvidenceItem[]) {
  const panel = findPanelByTitle('Exportar JSON');
  if (!panel || panel.querySelector('.trust-export-card')) return;

  const payload = buildTrustExport(evidence);
  const card = document.createElement('div');
  card.className = 'trust-export-card';
  const href = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }));
  card.innerHTML = `<strong>Product Trust Layer export</strong><p>Incluye evidence_summary, closure_criteria y trust_layer_version sin modificar el payload base.</p><a download="attack2defend-trust-layer.json" href="${href}">Descargar trust layer JSON</a>`;
  panel.insertBefore(card, panel.querySelector('textarea'));
}

function collectEvidenceItems(): EvidenceItem[] {
  const items: EvidenceItem[] = [];
  document.querySelectorAll<HTMLElement>('.traceability-node').forEach((nodeEl) => {
    const id = nodeEl.querySelector('button')?.textContent?.trim() || '';
    if (!id) return;
    const type = classToNodeType(nodeEl);
    const source = SOURCE_BY_TYPE[type] ?? { source: 'Bundle local', state: 'Derivado del grafo' as TrustState };
    const sourceRef = nodeEl.querySelector('small')?.textContent?.replace(/^source_ref:\s*/i, '').trim() || 'missing_source_ref';
    const officialLink = nodeEl.querySelector('a')?.getAttribute('href') || '';
    const name = nodeEl.querySelector('strong')?.textContent?.trim() || id;
    items.push({
      id,
      source: officialLink ? source.source : sourceRef !== 'missing_source_ref' ? source.source : 'Requiere validación',
      evidenceType: officialLink ? 'Oficial' : source.state,
      usedFor: `Selección y trazabilidad ${typeLabels[type as NodeType] ?? type}`,
      sourceRef,
      officialLink,
      status: officialLink || sourceRef !== 'missing_source_ref' ? source.state : 'Requiere validación',
      fact: name,
    });
  });
  return items;
}

function makeBadge({ label, item }: { label: string; item: EvidenceItem }) {
  const button = document.createElement('button');
  button.className = `${BADGE_CLASS} ${statusClass(item.status)}`;
  button.type = 'button';
  button.textContent = label;
  button.addEventListener('click', (event) => {
    event.preventDefault();
    event.stopPropagation();
    openDrawer(item);
  });
  return button;
}

function ensureDrawer() {
  if (drawer) return;
  drawer = document.createElement('aside');
  drawer.className = 'trust-drawer';
  drawer.setAttribute('aria-hidden', 'true');
  drawer.innerHTML = `<button class="trust-drawer-close" type="button">Cerrar</button><div class="trust-drawer-body"></div>`;
  drawer.querySelector('.trust-drawer-close')?.addEventListener('click', closeDrawer);
  document.body.appendChild(drawer);
}

function openDrawer(item: EvidenceItem) {
  ensureDrawer();
  const body = drawer?.querySelector('.trust-drawer-body');
  if (!body || !drawer) return;
  body.innerHTML = `
    <p class="eyebrow">Evidence drawer</p>
    <h2>${escapeHtml(item.id)}</h2>
    <dl>
      <dt>Fuente</dt><dd>${escapeHtml(item.source)}</dd>
      <dt>Tipo</dt><dd>${escapeHtml(item.evidenceType)}</dd>
      <dt>Usado para</dt><dd>${escapeHtml(item.usedFor)}</dd>
      <dt>Estado</dt><dd>${escapeHtml(item.status)}</dd>
      <dt>Source ref</dt><dd>${escapeHtml(item.sourceRef || 'missing_source_ref')}</dd>
      <dt>Fact / contexto</dt><dd>${escapeHtml(item.fact)}</dd>
    </dl>
    ${item.officialLink ? `<a href="${escapeHtml(item.officialLink)}" target="_blank" rel="noreferrer">Abrir referencia oficial</a>` : '<p class="trust-warning">Requiere validación: no hay official_link disponible en el bundle actual.</p>'}
  `;
  drawer.classList.add('open');
  drawer.setAttribute('aria-hidden', 'false');
}

function closeDrawer() {
  drawer?.classList.remove('open');
  drawer?.setAttribute('aria-hidden', 'true');
}

function findPanelByTitle(title: string): HTMLElement | null {
  return Array.from(document.querySelectorAll<HTMLElement>('.panel')).find((panel) => panel.querySelector('h2')?.textContent?.trim() === title) ?? null;
}

function classToNodeType(element: HTMLElement): string {
  const match = ['cve', 'cwe', 'capec', 'attack', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'].find((type) => element.classList.contains(type));
  return match ?? 'unknown';
}

function fallbackEvidence(id: string, sourceRef: string, status: TrustState): EvidenceItem {
  return {
    id,
    source: sourceRef,
    evidenceType: status,
    usedFor: id,
    sourceRef,
    officialLink: '',
    status,
    fact: sourceRef,
  };
}

function statusClass(status: TrustState) {
  return status.toLowerCase().replace(/\s+/g, '-').normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function buildTrustExport(evidence: EvidenceItem[]) {
  return {
    trust_layer_version: TRUST_LAYER_VERSION,
    evidence_summary: evidence.map((item) => ({
      id: item.id,
      source: item.source,
      status: item.status,
      source_ref: item.sourceRef,
      official_link: item.officialLink,
      used_for: item.usedFor,
    })),
    closure_criteria: OWNER_CLOSURE.map((item) => ({
      owner: item.owner,
      action: item.action,
      closure_evidence: item.closureEvidence,
    })),
    disclaimers: [
      'No confirma afectación real del entorno.',
      'No confirma implementación actual de detecciones.',
      'Toda recomendación requiere owner y evidencia de cierre.',
    ],
  };
}

function injectTrustStyles() {
  if (document.getElementById('attack2defend-trust-layer-styles')) return;
  const style = document.createElement('style');
  style.id = 'attack2defend-trust-layer-styles';
  style.textContent = `
    .trust-summary-bar,.trust-node-footer,.trust-inline-meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.trust-badge{border:1px solid #dfe5f2;border-radius:999px;background:#fff;color:#3c4043;padding:6px 10px;font-size:11px;font-weight:900;cursor:pointer;box-shadow:0 4px 12px rgba(60,64,67,.06)}.trust-badge:hover{transform:translateY(-1px);box-shadow:0 8px 18px rgba(60,64,67,.12)}.trust-badge.oficial{background:#e6f4ea;color:#137333;border-color:#ceead6}.trust-badge.derivado-del-grafo{background:#e8f0fe;color:#174ea6;border-color:#d2e3fc}.trust-badge.sugerido{background:#fef7e0;color:#7a4d00;border-color:#fde293}.trust-badge.requiere-validacion,.trust-badge.no-confirmado{background:#fce8e6;color:#a50e0e;border-color:#fad2cf}.trust-detection-note{margin:0 0 14px;border-radius:16px;background:#fff8e1;color:#7a4d00;padding:12px 14px;font-weight:800}.trust-gap-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.trust-gap-card{border:1px solid #e3e9f4;border-left:5px solid #d93025;border-radius:18px;background:#fff;padding:15px}.trust-gap-card h3{margin:0 0 8px;font-size:15px}.trust-gap-card p{margin:0 0 10px;color:#3c4043;line-height:1.45}.trust-gap-card dl,.trust-drawer dl{display:grid;grid-template-columns:140px minmax(0,1fr);gap:8px 12px}.trust-gap-card dt,.trust-drawer dt{font-size:11px;color:#5f6368;font-weight:900;text-transform:uppercase;letter-spacing:.06em}.trust-gap-card dd,.trust-drawer dd{margin:0;color:#202124;overflow-wrap:anywhere}.closure-criteria{margin-top:14px;border-top:1px solid #e3e9f4;padding-top:12px}.closure-criteria strong{display:block;margin-bottom:8px;color:#174ea6}.closure-criteria ul{margin:0 0 10px;padding-left:18px}.trust-export-card{border:1px solid #d2e3fc;border-radius:18px;background:#f8fbff;padding:14px;margin:14px 0}.trust-export-card strong{display:block;color:#202124;margin-bottom:6px}.trust-export-card p{margin:0 0 10px;color:#5f6368}.trust-export-card a{display:inline-flex;border-radius:999px;background:#1a73e8;color:#fff;padding:9px 12px}.trust-drawer{position:fixed;top:0;right:0;z-index:9999;width:min(460px,94vw);height:100vh;background:#fff;border-left:1px solid #dfe5f2;box-shadow:-22px 0 48px rgba(60,64,67,.22);transform:translateX(105%);transition:transform .18s ease;padding:22px;overflow:auto}.trust-drawer.open{transform:translateX(0)}.trust-drawer-close{float:right;border:1px solid #dfe5f2;border-radius:999px;background:#fff;padding:8px 12px;cursor:pointer;font-weight:900}.trust-drawer h2{margin:20px 0 16px;color:#202124}.trust-warning{border-radius:14px;background:#fff8e1;color:#7a4d00;padding:12px;line-height:1.45}@media(max-width:760px){.trust-gap-grid{grid-template-columns:1fr}.trust-gap-card dl,.trust-drawer dl{grid-template-columns:1fr}}
  `;
  document.head.appendChild(style);
}

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char] ?? char));
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bootTrustLayer, { once: true });
} else {
  bootTrustLayer();
}
