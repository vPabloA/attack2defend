import React, { useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import routeData from '../../../data/samples/log4shell.route.json';
import './styles.css';

type NodeType = 'cve' | 'cwe' | 'capec' | 'attack' | 'd3fend' | 'artifact' | 'control' | 'detection' | 'evidence' | 'gap';

type RouteNode = {
  id: string;
  type: NodeType;
  name: string;
  url?: string;
};

type RouteEdge = {
  source: string;
  target: string;
  relationship: string;
};

type RouteData = {
  metadata: {
    id: string;
    input: string;
    name: string;
    curation_status: string;
    notes?: string;
  };
  nodes: RouteNode[];
  edges: RouteEdge[];
};

const typedRoute = routeData as RouteData;

const typeOrder: NodeType[] = ['cve', 'cwe', 'capec', 'attack', 'd3fend'];

const typeLabels: Record<NodeType, string> = {
  cve: 'CVE',
  cwe: 'CWE',
  capec: 'CAPEC',
  attack: 'ATT&CK',
  d3fend: 'D3FEND',
  artifact: 'Artifact',
  control: 'Control',
  detection: 'Detection',
  evidence: 'Evidence',
  gap: 'Gap',
};

const routeInterpretation = {
  executiveSummary: [
    'Log4Shell starts as a vulnerable software exposure and can become initial access or remote execution when reachable input is processed by vulnerable Log4j behavior.',
    'The route moves from weakness and attack pattern into ATT&CK techniques that matter for SOC visibility: public app exploitation, command execution, tool transfer and application-layer communication.',
    'The defensive side is not one control: it combines inventory, vulnerability enumeration, software update, network traffic analysis and process analysis.',
  ],
  cti: [
    'Track CISA KEV, vendor advisories, affected products, exposed Java services and known callback infrastructure.',
    'Build a watchlist of public-facing applications, third-party products and container images that may embed vulnerable Log4j versions.',
    'Separate scanning noise from post-exploitation infrastructure by correlating exploit attempts with outbound callbacks or payload staging.',
  ],
  hunting: [
    'Hunt inbound JNDI/LDAP/RMI/DNS exploit strings in WAF, reverse proxy, load balancer and application logs.',
    'Correlate inbound attempts with outbound DNS, LDAP, RMI or HTTP/S callbacks from backend Java workloads.',
    'Hunt java or application-server parent processes spawning shell, script interpreters, curl, wget, PowerShell, bash or Python.',
    'Search for post-exploitation download and execution from temporary paths or unusual working directories.',
  ],
  soc: [
    'Create detections for exploit attempt, outbound callback and Java child-process execution.',
    'Escalate if callback, payload download, shell execution, credential access or cloud metadata access is observed.',
    'Document missing telemetry explicitly: application logs, DNS/proxy visibility, EDR process tree, container runtime events.',
  ],
  appsec: [
    'Validate vulnerable log4j-core versions, transitive dependencies, vendor packages and container images.',
    'Patch or remove vulnerable components and validate the fix through SCA/SBOM and runtime verification.',
  ],
  infra: [
    'Restrict outbound traffic from application workloads and validate WAF virtual patch coverage while remediation is completed.',
    'Prioritize internet-facing and business-critical assets before internal-only or non-critical systems.',
  ],
};

const coverage = [
  { item: 'WAF / reverse proxy logs', status: 'partial', owner: 'SOC / Infra', note: 'Useful for inbound exploit attempt visibility.' },
  { item: 'DNS / proxy / egress logs', status: 'missing', owner: 'Network / SOC', note: 'Required to confirm outbound callback or exfil path.' },
  { item: 'EDR process tree', status: 'partial', owner: 'SOC', note: 'Required to confirm java spawning shell or downloader.' },
  { item: 'SCA / SBOM inventory', status: 'covered', owner: 'AppSec', note: 'Required to find vulnerable dependencies and residual exposure.' },
  { item: 'Patch / software update evidence', status: 'unknown', owner: 'AppSec / Infra', note: 'Closure requires validation, not only ticket completion.' },
];

function App() {
  const [selectedId, setSelectedId] = useState<string>(typedRoute.metadata.input);
  const [activeTab, setActiveTab] = useState<'route' | 'actions' | 'graph' | 'mitre' | 'coverage' | 'export'>('route');

  const selectedNode = typedRoute.nodes.find((node) => node.id === selectedId) ?? typedRoute.nodes[0];
  const nodesByType = useMemo(() => {
    const grouped = new Map<NodeType, RouteNode[]>();
    for (const node of typedRoute.nodes) {
      grouped.set(node.type, [...(grouped.get(node.type) ?? []), node]);
    }
    return grouped;
  }, []);

  const relatedEdges = typedRoute.edges.filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id);
  const markdownExport = buildMarkdownExport();

  return (
    <main className="app-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Attack2Defend Navigator · MVP Route UI</p>
          <h1>{typedRoute.metadata.name}</h1>
          <p className="hero-copy">Route-first UX for CVE → CWE → CAPEC → ATT&CK → D3FEND, with CTI, Threat Hunting and coverage actions.</p>
        </div>
        <div className="search-card">
          <label htmlFor="route-search">Search / selected input</label>
          <input id="route-search" value={selectedId} onChange={(event) => setSelectedId(event.target.value.trim())} placeholder="CVE-2021-44228" />
          <button onClick={() => setSelectedId(typedRoute.metadata.input)}>Load Log4Shell sample</button>
        </div>
      </header>

      <nav className="tabs" aria-label="Navigator tabs">
        {[
          ['route', 'Route'],
          ['actions', 'Actions'],
          ['graph', 'Graph'],
          ['mitre', 'MITRE Views'],
          ['coverage', 'Coverage'],
          ['export', 'Export'],
        ].map(([id, label]) => (
          <button key={id} className={activeTab === id ? 'active' : ''} onClick={() => setActiveTab(id as typeof activeTab)}>
            {label}
          </button>
        ))}
      </nav>

      {activeTab === 'route' && (
        <section className="grid route-layout">
          <div className="panel wide">
            <PanelTitle title="Framework Route" subtitle="Simple first: navigate the path before opening graphs or native MITRE views." />
            <div className="columns">
              {typeOrder.map((type) => (
                <div key={type} className="framework-column">
                  <h3>{typeLabels[type]}</h3>
                  {(nodesByType.get(type) ?? []).map((node) => (
                    <button key={node.id} className={`node-pill ${node.type} ${selectedNode.id === node.id ? 'selected' : ''}`} onClick={() => setSelectedId(node.id)}>
                      <strong>{node.id}</strong>
                      <span>{node.name}</span>
                    </button>
                  ))}
                </div>
              ))}
            </div>
          </div>
          <NodeDetail node={selectedNode} relatedEdges={relatedEdges} />
          <RouteAnalyst />
        </section>
      )}

      {activeTab === 'actions' && <ActionsTab />}
      {activeTab === 'graph' && <GraphTab selectedId={selectedNode.id} setSelectedId={setSelectedId} />}
      {activeTab === 'mitre' && <MitreViewsTab />}
      {activeTab === 'coverage' && <CoverageTab />}
      {activeTab === 'export' && <ExportTab markdown={markdownExport} />}
    </main>
  );
}

function PanelTitle({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="panel-title">
      <h2>{title}</h2>
      <p>{subtitle}</p>
    </div>
  );
}

function NodeDetail({ node, relatedEdges }: { node: RouteNode; relatedEdges: RouteEdge[] }) {
  return (
    <aside className="panel">
      <PanelTitle title="Selected Node" subtitle="Official meaning and direct relationships." />
      <div className={`detail-badge ${node.type}`}>{typeLabels[node.type]}</div>
      <h3>{node.id}</h3>
      <p className="node-name">{node.name}</p>
      {node.url && <a href={node.url} target="_blank" rel="noreferrer">Open official reference</a>}
      <h4>Direct relationships</h4>
      <ul className="edge-list">
        {relatedEdges.length === 0 && <li>No direct edges found for current input.</li>}
        {relatedEdges.map((edge) => (
          <li key={`${edge.source}-${edge.relationship}-${edge.target}`}>
            <code>{edge.source}</code> <span>{edge.relationship}</span> <code>{edge.target}</code>
          </li>
        ))}
      </ul>
    </aside>
  );
}

function RouteAnalyst() {
  return (
    <aside className="panel analyst-card">
      <PanelTitle title="AI Route Analyst Preview" subtitle="Deterministic route, AI-assisted interpretation." />
      {routeInterpretation.executiveSummary.map((item) => <p key={item}>{item}</p>)}
      <div className="decision-card">
        <span>Recommended decision</span>
        <strong>VALIDATE + MITIGATE + HUNT</strong>
      </div>
    </aside>
  );
}

function ActionsTab() {
  return (
    <section className="grid two-col">
      <ActionPanel title="CTI Actions" items={routeInterpretation.cti} />
      <ActionPanel title="Threat Hunting Hypotheses" items={routeInterpretation.hunting} />
      <ActionPanel title="SOC / Detection Actions" items={routeInterpretation.soc} />
      <ActionPanel title="AppSec Actions" items={routeInterpretation.appsec} />
      <ActionPanel title="Infra / Cloud Actions" items={routeInterpretation.infra} />
    </section>
  );
}

function ActionPanel({ title, items }: { title: string; items: string[] }) {
  return (
    <section className="panel">
      <PanelTitle title={title} subtitle="Actionable output from the current route." />
      <ul className="action-list">
        {items.map((item) => <li key={item}>{item}</li>)}
      </ul>
    </section>
  );
}

function GraphTab({ selectedId, setSelectedId }: { selectedId: string; setSelectedId: (id: string) => void }) {
  const ordered = ['CVE-2021-44228', 'CWE-917', 'CAPEC-136', 'CAPEC-248', 'T1190', 'T1059', 'T1105', 'T1071'];
  const defenses = ['D3-AI', 'D3-AVE', 'D3-SU', 'D3-NTA', 'D3-PA', 'D3-PSA'];
  return (
    <section className="panel">
      <PanelTitle title="Route Graph" subtitle="Auto-generated graph of the sample path. Graph is depth, not the default experience." />
      <div className="graph-flow">
        {ordered.map((id, index) => {
          const node = typedRoute.nodes.find((item) => item.id === id);
          return (
            <React.Fragment key={id}>
              <button className={`graph-node ${node?.type ?? ''} ${selectedId === id ? 'selected' : ''}`} onClick={() => setSelectedId(id)}>
                <strong>{id}</strong>
                <span>{node?.name}</span>
              </button>
              {index < ordered.length - 1 && <span className="graph-arrow">→</span>}
            </React.Fragment>
          );
        })}
      </div>
      <div className="defense-branch">
        <h3>D3FEND defensive branch</h3>
        <div className="defense-grid">
          {defenses.map((id) => {
            const node = typedRoute.nodes.find((item) => item.id === id);
            return (
              <button key={id} className={`graph-node d3fend ${selectedId === id ? 'selected' : ''}`} onClick={() => setSelectedId(id)}>
                <strong>{id}</strong>
                <span>{node?.name}</span>
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
}

function MitreViewsTab() {
  const attackNodes = typedRoute.nodes.filter((node) => node.type === 'attack');
  const d3fendNodes = typedRoute.nodes.filter((node) => node.type === 'd3fend');
  return (
    <section className="grid two-col">
      <section className="panel">
        <PanelTitle title="ATT&CK Native Links" subtitle="MVP uses deep links; later export ATT&CK Navigator layers." />
        <ul className="link-list">
          {attackNodes.map((node) => <li key={node.id}><a href={node.url} target="_blank" rel="noreferrer">{node.id} · {node.name}</a></li>)}
        </ul>
      </section>
      <section className="panel">
        <PanelTitle title="D3FEND Native Links" subtitle="MVP uses deep links; later export D3FEND CAD-compatible graph." />
        <ul className="link-list">
          {d3fendNodes.map((node) => <li key={node.id}><a href={node.url} target="_blank" rel="noreferrer">{node.id} · {node.name}</a></li>)}
        </ul>
      </section>
      <section className="panel wide">
        <PanelTitle title="Navigator strategy" subtitle="Keep native MITRE value without cloning native tools." />
        <div className="strategy-grid">
          <StrategyItem title="Now" text="Official links and local route visualization." />
          <StrategyItem title="Next" text="Export selected ATT&CK techniques as a Navigator layer." />
          <StrategyItem title="Later" text="Export route graph in a D3FEND CAD-compatible structure if useful." />
        </div>
      </section>
    </section>
  );
}

function StrategyItem({ title, text }: { title: string; text: string }) {
  return <div className="strategy-item"><strong>{title}</strong><span>{text}</span></div>;
}

function CoverageTab() {
  return (
    <section className="panel">
      <PanelTitle title="Coverage" subtitle="Internal coverage is curated. Public data updates must never overwrite it." />
      <div className="coverage-table">
        {coverage.map((row) => (
          <div className="coverage-row" key={row.item}>
            <span className={`status ${row.status}`}>{row.status}</span>
            <strong>{row.item}</strong>
            <span>{row.owner}</span>
            <p>{row.note}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function ExportTab({ markdown }: { markdown: string }) {
  return (
    <section className="grid two-col">
      <section className="panel">
        <PanelTitle title="Markdown Export" subtitle="Ready for CTI/TH/SOC notes." />
        <textarea value={markdown} readOnly />
      </section>
      <section className="panel">
        <PanelTitle title="JSON Export" subtitle="Route sample consumed by this MVP UI." />
        <textarea value={JSON.stringify(typedRoute, null, 2)} readOnly />
      </section>
    </section>
  );
}

function buildMarkdownExport() {
  return `# ${typedRoute.metadata.name}

## Route

${typeOrder.map((type) => {
  const nodes = typedRoute.nodes.filter((node) => node.type === type);
  return `### ${typeLabels[type]}\n${nodes.map((node) => `- ${node.id} - ${node.name}`).join('\n')}`;
}).join('\n\n')}

## Recommended decision

VALIDATE + MITIGATE + HUNT

## CTI Actions
${routeInterpretation.cti.map((item) => `- ${item}`).join('\n')}

## Threat Hunting Hypotheses
${routeInterpretation.hunting.map((item) => `- ${item}`).join('\n')}

## SOC Actions
${routeInterpretation.soc.map((item) => `- ${item}`).join('\n')}

## Missing Evidence / Coverage Gaps
${coverage.filter((item) => item.status !== 'covered').map((item) => `- ${item.item}: ${item.note}`).join('\n')}
`;
}

createRoot(document.getElementById('root')!).render(<App />);
