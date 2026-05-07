(() => {
  const VERSION = '1.0';
  const TYPES = {
    cve: ['NVD / CVE.org / Vendor', 'Oficial', 'CVE'],
    cwe: ['MITRE CWE', 'Oficial', 'CWE'],
    capec: ['MITRE CAPEC', 'Oficial', 'CAPEC'],
    attack: ['MITRE ATT&CK', 'Oficial', 'ATT&CK'],
    d3fend: ['MITRE D3FEND', 'Oficial', 'D3FEND'],
    control: ['Bundle / Control mapping', 'Derivado del grafo', 'Control'],
    detection: ['Bundle / Detection mapping', 'Sugerido', 'Detection'],
    evidence: ['Bundle / Evidence mapping', 'Derivado del grafo', 'Evidence'],
    gap: ['Bundle / Gap mapping', 'Requiere validación', 'Gap'],
    action: ['Bundle / Action mapping', 'Sugerido', 'Action'],
    unknown: ['Bundle local', 'Derivado del grafo', 'Unknown'],
  };
  const CLOSURE = [
    ['Vulnerability Manager', ['inventario/CMDB o EASM', 'versión instalada o estado de parche', 'referencia al advisory o CVE']],
    ['Infra', ['resultado de exposición', 'regla de firewall/WAF/SG', 'evidencia de restricción o segmentación']],
    ['SOC', ['query/log export con ventana temporal', 'resultado: hallazgo o descarte', 'evidencia de sesiones/autenticación revisada']],
    ['Detection Engineering', ['regla/query versionada', 'test case ejecutado', 'criterio de falso positivo definido']],
    ['CTI/TH', ['pivotes o hipótesis documentadas', 'resultado del hunting', 'alcance y ventana definidos']],
    ['CSMA', ['riesgo registrado', 'owner y fecha compromiso', 'evidencia de cierre adjunta']],
  ];
  const GAPS = [
    ['Inventario no confirmado', 'No se puede saber si existe exposición real en activos propios.', 'Vulnerability Manager / Infra', 'CMDB, EASM, asset inventory o escaneo controlado.'],
    ['Exposición no validada', 'No se puede priorizar correctamente superficie pública o administrativa.', 'Infra', 'Firewall/WAF/SG, rutas, puertos, escaneo o diagrama de exposición.'],
    ['Evidencia/logs no confirmados', 'SOC no puede confirmar ni descartar explotación con base auditable.', 'SOC / Infra', 'Fuente de logs, retención, consulta ejecutada y resultado.'],
    ['Detección no validada', 'No existe prueba de que el comportamiento sea observable.', 'Detection Engineering', 'Regla/query, test case, señal esperada y ajuste de falsos positivos.'],
    ['Acción de cierre no documentada', 'El riesgo puede quedar abierto aunque exista una recomendación.', 'CSMA / Owner técnico', 'Ticket, change record, evidencia de remediación y fecha de cierre.'],
  ];
  let drawer;

  function boot() {
    injectStyles();
    ensureDrawer();
    apply();
    new MutationObserver(apply).observe(document.body, { childList: true, subtree: true });
  }

  function apply() {
    if (!document.querySelector('.app-shell')) return;
    const evidence = collectEvidence();
    decorateSummary(evidence);
    decorateNodes(evidence);
    decorateDetections();
    decorateGaps();
    decorateOwners();
    decorateExport(evidence);
  }

  function decorateSummary(evidence) {
    const panel = panelByTitle('Resumen defensivo preliminar');
    if (!panel || panel.querySelector('.trust-summary-bar')) return;
    const bar = node('div', 'trust-summary-bar');
    bar.append(
      badge('Source-grounded', evidence[0] || fallback('Resumen defensivo preliminar', 'Bundle local / source_refs', 'Derivado del grafo')),
      badge('Requiere validación', fallback('Cobertura del entorno', 'Validación operacional pendiente', 'Requiere validación')),
      badge('Validator wins', fallback('Ruta curada', 'Curated route validator', 'Derivado del grafo')),
    );
    panel.appendChild(bar);
  }

  function decorateNodes(evidence) {
    document.querySelectorAll('.traceability-node').forEach((el) => {
      if (el.querySelector('.trust-badge')) return;
      const id = (el.querySelector('button')?.textContent || 'unknown').trim();
      const type = nodeType(el);
      const item = evidence.find((entry) => entry.id === id) || fallback(id, typeInfo(type)[0], typeInfo(type)[1]);
      const footer = node('div', 'trust-node-footer');
      footer.append(badge(item.source, item), badge(item.status, item));
      el.appendChild(footer);
    });
  }

  function decorateDetections() {
    const panel = panelByTitle('Detecciones sugeridas');
    if (!panel || panel.querySelector('.trust-detection-note')) return;
    panel.insertBefore(node('p', 'trust-detection-note', 'Detecciones sugeridas. No confirma implementación actual en el entorno.'), panel.querySelector('.consultative-list'));
    panel.querySelectorAll('.consultative-list li').forEach((li) => {
      if (li.querySelector('.trust-inline-meta')) return;
      const meta = node('div', 'trust-inline-meta');
      meta.append(
        badge('Sugerido', fallback(li.textContent || 'Detección sugerida', 'Ruta curada / grafo', 'Sugerido')),
        badge('Evidencia requerida', fallback('Evidencia requerida', 'logs, query, test case', 'Requiere validación')),
      );
      li.appendChild(meta);
    });
  }

  function decorateGaps() {
    const panel = panelByTitle('Brechas potenciales');
    if (!panel || panel.querySelector('.trust-gap-grid')) return;
    panel.querySelector('.chip-list')?.remove();
    const grid = node('div', 'trust-gap-grid');
    GAPS.forEach(([gap, impact, owner, ev]) => {
      const card = node('article', 'trust-gap-card');
      card.append(node('h3', '', gap), node('p', '', impact), fields([['Owner sugerido', owner], ['Evidencia requerida', ev]]), badge('Requiere validación', fallback(gap, ev, 'Requiere validación')));
      grid.appendChild(card);
    });
    panel.appendChild(grid);
  }

  function decorateOwners() {
    const panel = panelByTitle('Acciones sugeridas por owner');
    if (!panel) return;
    panel.querySelectorAll('.owner-card').forEach((card) => {
      if (card.querySelector('.closure-criteria')) return;
      const owner = (card.querySelector('h3')?.textContent || '').trim();
      const closure = CLOSURE.find(([name]) => name === owner || owner.includes(name));
      if (!closure) return;
      const block = node('div', 'closure-criteria');
      block.append(node('strong', '', 'Evidencia de cierre esperada'), bullets(closure[1]), badge('Criterio de cierre', fallback(owner, closure[1].join('; '), 'Requiere validación')));
      card.appendChild(block);
    });
  }

  function decorateExport(evidence) {
    const panel = panelByTitle('Exportar JSON');
    if (!panel || panel.querySelector('.trust-export-card')) return;
    const payload = {
      trust_layer_version: VERSION,
      evidence_summary: evidence.map((item) => ({ id: item.id, source: item.source, status: item.status, source_ref: item.sourceRef, official_link: item.officialLink, used_for: item.usedFor })),
      closure_criteria: CLOSURE.map(([owner, ev]) => ({ owner, closure_evidence: ev })),
      disclaimers: ['No confirma afectación real del entorno.', 'No confirma implementación actual de detecciones.', 'Toda recomendación requiere owner y evidencia de cierre.'],
    };
    const href = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }));
    const link = node('a', '', 'Descargar trust layer JSON');
    link.href = href;
    link.download = 'attack2defend-trust-layer.json';
    const card = node('div', 'trust-export-card');
    card.append(node('strong', '', 'Product Trust Layer export'), node('p', '', 'Incluye evidence_summary, closure_criteria y trust_layer_version sin modificar el payload base.'), link);
    panel.insertBefore(card, panel.querySelector('textarea'));
  }

  function collectEvidence() {
    const items = [];
    document.querySelectorAll('.traceability-node').forEach((el) => {
      const id = (el.querySelector('button')?.textContent || '').trim();
      if (!id) return;
      const type = nodeType(el);
      const [source, status, label] = typeInfo(type);
      const sourceRef = (el.querySelector('small')?.textContent || '').replace(/^source_ref:\s*/i, '').trim() || 'missing_source_ref';
      const officialLink = el.querySelector('a')?.getAttribute('href') || '';
      const grounded = officialLink || sourceRef !== 'missing_source_ref';
      items.push({ id, source: grounded ? source : 'Requiere validación', status: grounded ? status : 'Requiere validación', sourceRef, officialLink, usedFor: `Selección y trazabilidad ${label}`, fact: (el.querySelector('strong')?.textContent || id).trim() });
    });
    return items;
  }

  function ensureDrawer() {
    if (drawer) return;
    drawer = node('aside', 'trust-drawer');
    drawer.setAttribute('aria-hidden', 'true');
    const close = node('button', 'trust-drawer-close', 'Cerrar');
    close.type = 'button';
    close.onclick = () => drawer.classList.remove('open');
    drawer.append(close, node('div', 'trust-drawer-body'));
    document.body.appendChild(drawer);
  }

  function openDrawer(item) {
    ensureDrawer();
    const body = drawer.querySelector('.trust-drawer-body');
    body.textContent = '';
    body.append(node('p', 'eyebrow', 'Evidence drawer'), node('h2', '', item.id), fields([['Fuente', item.source], ['Tipo', item.status], ['Usado para', item.usedFor], ['Estado', item.status], ['Source ref', item.sourceRef || 'missing_source_ref'], ['Fact / contexto', item.fact]]));
    if (item.officialLink) {
      const a = node('a', '', 'Abrir referencia oficial');
      a.href = item.officialLink;
      a.target = '_blank';
      a.rel = 'noreferrer';
      body.appendChild(a);
    } else {
      body.appendChild(node('p', 'trust-warning', 'Requiere validación: no hay official_link disponible en el bundle actual.'));
    }
    drawer.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
  }

  function badge(label, item) {
    const b = node('button', `trust-badge ${slug(item.status)}`, label);
    b.type = 'button';
    b.onclick = (event) => {
      event.preventDefault();
      event.stopPropagation();
      openDrawer(item);
    };
    return b;
  }

  function fallback(id, sourceRef, status) {
    return { id, source: sourceRef, status, sourceRef, officialLink: '', usedFor: id, fact: sourceRef };
  }

  function nodeType(el) {
    return Object.keys(TYPES).find((type) => el.classList.contains(type)) || 'unknown';
  }

  function typeInfo(type) {
    return TYPES[type] || TYPES.unknown;
  }

  function panelByTitle(title) {
    return Array.from(document.querySelectorAll('.panel')).find((panel) => panel.querySelector('h2')?.textContent?.trim() === title) || null;
  }

  function node(tag, cls = '', text = '') {
    const element = document.createElement(tag);
    if (cls) element.className = cls;
    if (text) element.textContent = text;
    return element;
  }

  function bullets(items) {
    const ul = node('ul');
    items.forEach((item) => ul.appendChild(node('li', '', item)));
    return ul;
  }

  function fields(rows) {
    const dl = node('dl');
    rows.forEach(([key, value]) => dl.append(node('dt', '', key), node('dd', '', value)));
    return dl;
  }

  function slug(value) {
    return String(value).toLowerCase().replace(/\s+/g, '-').normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  }

  function injectStyles() {
    if (document.getElementById('attack2defend-trust-layer-styles')) return;
    const style = node('style');
    style.id = 'attack2defend-trust-layer-styles';
    style.textContent = '.trust-summary-bar,.trust-node-footer,.trust-inline-meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.trust-badge{border:1px solid #dfe5f2;border-radius:999px;background:#fff;color:#3c4043;padding:6px 10px;font-size:11px;font-weight:900;cursor:pointer;box-shadow:0 4px 12px rgba(60,64,67,.06)}.trust-badge.oficial{background:#e6f4ea;color:#137333;border-color:#ceead6}.trust-badge.derivado-del-grafo{background:#e8f0fe;color:#174ea6;border-color:#d2e3fc}.trust-badge.sugerido{background:#fef7e0;color:#7a4d00;border-color:#fde293}.trust-badge.requiere-validacion{background:#fce8e6;color:#a50e0e;border-color:#fad2cf}.trust-detection-note{margin:0 0 14px;border-radius:16px;background:#fff8e1;color:#7a4d00;padding:12px 14px;font-weight:800}.trust-gap-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.trust-gap-card{border:1px solid #e3e9f4;border-left:5px solid #d93025;border-radius:18px;background:#fff;padding:15px}.trust-gap-card h3{margin:0 0 8px;font-size:15px}.trust-gap-card p{margin:0 0 10px;color:#3c4043;line-height:1.45}.trust-gap-card dl,.trust-drawer dl{display:grid;grid-template-columns:140px minmax(0,1fr);gap:8px 12px}.trust-gap-card dt,.trust-drawer dt{font-size:11px;color:#5f6368;font-weight:900;text-transform:uppercase;letter-spacing:.06em}.trust-gap-card dd,.trust-drawer dd{margin:0;color:#202124;overflow-wrap:anywhere}.closure-criteria{margin-top:14px;border-top:1px solid #e3e9f4;padding-top:12px}.closure-criteria strong{display:block;margin-bottom:8px;color:#174ea6}.closure-criteria ul{margin:0 0 10px;padding-left:18px}.trust-export-card{border:1px solid #d2e3fc;border-radius:18px;background:#f8fbff;padding:14px;margin:14px 0}.trust-export-card strong{display:block;color:#202124;margin-bottom:6px}.trust-export-card p{margin:0 0 10px;color:#5f6368}.trust-export-card a{display:inline-flex;border-radius:999px;background:#1a73e8;color:#fff;padding:9px 12px}.trust-drawer{position:fixed;top:0;right:0;z-index:9999;width:min(460px,94vw);height:100vh;background:#fff;border-left:1px solid #dfe5f2;box-shadow:-22px 0 48px rgba(60,64,67,.22);transform:translateX(105%);transition:transform .18s ease;padding:22px;overflow:auto}.trust-drawer.open{transform:translateX(0)}.trust-drawer-close{float:right;border:1px solid #dfe5f2;border-radius:999px;background:#fff;padding:8px 12px;cursor:pointer;font-weight:900}.trust-warning{border-radius:14px;background:#fff8e1;color:#7a4d00;padding:12px;line-height:1.45}@media(max-width:760px){.trust-gap-grid{grid-template-columns:1fr}.trust-gap-card dl,.trust-drawer dl{grid-template-columns:1fr}}';
    document.head.appendChild(style);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, { once: true });
  else boot();
})();
