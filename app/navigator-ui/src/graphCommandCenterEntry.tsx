import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import fallbackRoute from './data/log4shell.route.json';
import { GraphCommandCenterTab } from './components/GraphCommandCenterTab';
import type { KnowledgeBundle, RouteEdge, RouteNode } from './types/attack2defend';

type BundleSource = 'generated' | 'fallback';
type LegacyRouteData = {
  metadata: { id: string; input: string; name: string; curation_status?: string; notes?: string; file?: string };
  nodes: RouteNode[];
  edges: RouteEdge[];
  coverage?: KnowledgeBundle['coverage'];
};

type ResolvedGraphRoute = { root: string; nodes: string[]; edges: RouteEdge[] };

const legacyRoute = fallbackRoute as LegacyRouteData;
const fallbackBundle: KnowledgeBundle = {
  metadata: {
    contract_version: 'attack2defend.knowledge_bundle.v1',
    builder_version: 'fallback-local-route',
    mode: 'fallback_local_sample',
    counts: { nodes: legacyRoute.nodes.length, edges: legacyRoute.edges.length, routes: 1 },
  },
  nodes: legacyRoute.nodes,
  edges: legacyRoute.edges,
  coverage: legacyRoute.coverage ?? {},
  routes: [legacyRoute.metadata],
};

const allowedForwardTypeTransitions: Partial<Record<RouteNode['type'], RouteNode['type'][]>> = {
  cve: ['artifact', 'cwe', 'capec', 'attack', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'],
  artifact: ['cwe', 'capec', 'attack', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'],
  cwe: ['cwe', 'capec', 'attack', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'],
  capec: ['attack', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'],
  attack: ['artifact', 'd3fend', 'control', 'detection', 'evidence', 'gap', 'action'],
  d3fend: ['artifact', 'control', 'detection', 'evidence', 'gap', 'action'],
  control: ['detection', 'evidence', 'gap', 'action'],
  detection: ['evidence', 'gap', 'action'],
  evidence: ['gap', 'action'],
  gap: ['action'],
  action: [],
};

function GraphCommandCenterRuntime() {
  const [bundle, setBundle] = useState<KnowledgeBundle>(fallbackBundle);
  const [bundleSource, setBundleSource] = useState<BundleSource>('fallback');
  const [input, setInput] = useState<string>('');
  const [isVisible, setIsVisible] = useState<boolean>(document.body.classList.contains('graph-command-mode'));

  useEffect(() => {
    fetch('/data/knowledge-bundle.json')
      .then((response) => {
        if (!response.ok) throw new Error(`Bundle not found: ${response.status}`);
        return response.json() as Promise<KnowledgeBundle>;
      })
      .then((nextBundle) => {
        if (Array.isArray(nextBundle.nodes) && Array.isArray(nextBundle.edges)) {
          setBundle(nextBundle);
          setBundleSource('generated');
        }
      })
      .catch(() => {
        setBundle(fallbackBundle);
        setBundleSource('fallback');
      });
  }, []);

  useEffect(() => {
    const sync = () => {
      setIsVisible(document.body.classList.contains('graph-command-mode'));
      const current = (document.getElementById('route-search') as HTMLInputElement | null)?.value?.trim() ?? '';
      setInput(current);
    };
    window.addEventListener('graph-command-center:show', sync);
    window.addEventListener('graph-command-center:hide', sync);
    document.addEventListener('input', sync, true);
    sync();
    return () => {
      window.removeEventListener('graph-command-center:show', sync);
      window.removeEventListener('graph-command-center:hide', sync);
      document.removeEventListener('input', sync, true);
    };
  }, []);

  const nodeMap = useMemo(() => new Map(bundle.nodes.map((node) => [node.id, node])), [bundle.nodes]);
  const selectedNode = input ? findNode(bundle, input) : null;
  const activeRoute = useMemo(() => (selectedNode ? resolveRoute(bundle, [selectedNode.id]) : null), [bundle, selectedNode]);
  const routeNodes = useMemo(() => activeRoute ? activeRoute.nodes.map((id) => nodeMap.get(id)).filter((node): node is RouteNode => Boolean(node)) : [], [activeRoute, nodeMap]);

  if (!isVisible) return null;

  if (!selectedNode || !activeRoute) {
    return (
      <section className="graph-command-standalone panel">
        <p className="eyebrow">Graph Command Center</p>
        <h2>Busca primero una CVE, CWE, CAPEC, ATT&CK, D3FEND o nodo defensivo.</h2>
        <p>El grafo no se inventa: se deriva del input activo y del bundle local. Usa la búsqueda superior y vuelve a este tab.</p>
      </section>
    );
  }

  return (
    <GraphCommandCenterTab
      bundle={bundle}
      routeNodes={routeNodes}
      routeEdges={activeRoute.edges}
      input={selectedNode.id}
      bundleSource={bundleSource}
      onSelect={(id) => {
        const inputElement = document.getElementById('route-search') as HTMLInputElement | null;
        if (inputElement) {
          inputElement.value = id;
          inputElement.dispatchEvent(new Event('input', { bubbles: true }));
        }
        setInput(id);
      }}
    />
  );
}

function findNode(bundle: KnowledgeBundle, query: string): RouteNode | null {
  const term = query.trim();
  if (!term) return null;
  const candidate = term.toUpperCase();
  return bundle.nodes.find((node) => node.id === candidate) ?? bundle.nodes.find((node) => `${node.id} ${node.name}`.toLowerCase().includes(term.toLowerCase())) ?? null;
}

function resolveRoute(bundle: KnowledgeBundle, roots: string[]): ResolvedGraphRoute {
  const starts = roots.map((item) => item.toUpperCase()).filter(Boolean);
  const nodeMap = new Map(bundle.nodes.map((node) => [node.id, node]));
  const outgoing = new Map<string, RouteEdge[]>();
  for (const edge of bundle.edges) {
    const current = outgoing.get(edge.source) ?? [];
    current.push(edge);
    outgoing.set(edge.source, current);
  }

  const queue: Array<{ id: string; depth: number }> = starts.filter((id) => nodeMap.has(id)).map((id) => ({ id, depth: 0 }));
  const visited = new Set<string>(queue.map((item) => item.id));
  const routeEdges: RouteEdge[] = [];

  while (queue.length) {
    const current = queue.shift();
    if (!current || current.depth >= 5) continue;
    const currentNode = nodeMap.get(current.id);
    if (!currentNode) continue;
    for (const edge of outgoing.get(current.id) ?? []) {
      const nextNode = nodeMap.get(edge.target);
      if (!nextNode) continue;
      if (!(allowedForwardTypeTransitions[currentNode.type] ?? []).includes(nextNode.type)) continue;
      routeEdges.push(edge);
      if (visited.has(nextNode.id)) continue;
      visited.add(nextNode.id);
      queue.push({ id: nextNode.id, depth: current.depth + 1 });
    }
  }

  return { root: starts[0], nodes: Array.from(visited), edges: dedupeEdges(routeEdges) };
}

function dedupeEdges(edges: RouteEdge[]) {
  const seen = new Set<string>();
  return edges.filter((edge) => {
    const key = `${edge.source}|${edge.relationship}|${edge.target}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function installGraphCommandTab() {
  const nav = document.querySelector('nav.tabs');
  if (!nav || document.getElementById('graph-command-tab-button')) return;
  const button = document.createElement('button');
  button.id = 'graph-command-tab-button';
  button.textContent = 'Graph Command Center';
  button.addEventListener('click', () => {
    document.body.classList.add('graph-command-mode');
    nav.querySelectorAll('button').forEach((item) => item.classList.remove('active'));
    button.classList.add('active');
    window.dispatchEvent(new Event('graph-command-center:show'));
  });
  nav.querySelectorAll('button').forEach((item) => {
    item.addEventListener('click', () => {
      document.body.classList.remove('graph-command-mode');
      button.classList.remove('active');
      window.dispatchEvent(new Event('graph-command-center:hide'));
    });
  });
  nav.appendChild(button);
}

const root = document.getElementById('graph-command-root');
if (root) {
  installGraphCommandTab();
  const observer = new MutationObserver(installGraphCommandTab);
  observer.observe(document.body, { childList: true, subtree: true });
  createRoot(root).render(<GraphCommandCenterRuntime />);
}
