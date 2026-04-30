import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './styles.css'
import fallback from './data/log4shell.route.json'

type Route = { found: boolean; ordered_path: string[]; warnings: string[] }
type Node = { id: string; type: string; name: string }
type Bundle = { metadata: Record<string, unknown>; nodes: Node[]; routes: Record<string, Route>; coverage?: { records?: Array<Record<string, unknown>> } }
const tabs = ['Route', 'Actions', 'Graph', 'MITRE Views', 'Coverage', 'Export'] as const

function App() {
  const [bundle, setBundle] = useState<Bundle>(fallback as Bundle)
  const [query, setQuery] = useState('CVE-2021-44228')
  const [tab, setTab] = useState<(typeof tabs)[number]>('Route')

  useEffect(() => {
    fetch('/data/knowledge-bundle.json').then(r => (r.ok ? r.json() : Promise.reject())).then(setBundle).catch(() => setBundle(fallback as Bundle))
  }, [])

  const suggestions = useMemo(() => {
    const q = query.toLowerCase()
    return bundle.nodes.filter(n => n.id.toLowerCase().includes(q) || n.name.toLowerCase().includes(q)).slice(0, 8)
  }, [bundle.nodes, query])

  const selected = suggestions[0]?.id ?? query
  const route = bundle.routes[selected]

  return <div className="app"><h1>Attack2Defend Navigator MVP</h1>
    <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search CVE/CWE/CAPEC/ATT&CK/D3FEND" />
    <div className="chips">{suggestions.map(s => <button key={s.id} onClick={() => setQuery(s.id)}>{s.id}</button>)}</div>
    <div className="tabs">{tabs.map(t => <button className={tab===t?'active':''} key={t} onClick={()=>setTab(t)}>{t}</button>)}</div>
    <section>
      {!route ? <p>No results</p> : tab==='Route' ? <ol>{route.ordered_path.map(p => <li key={p}>{p}</li>)}</ol> : null}
      {route && tab==='Actions' ? <ul><li>CTI: pivot on {selected}</li><li>TH: create hunt hypothesis from route</li></ul> : null}
      {route && tab==='Graph' ? <pre>{route.ordered_path.join(' -> ')}</pre> : null}
      {route && tab==='MITRE Views' ? <p>ATT&CK starter layer for {selected} ready in Export tab.</p> : null}
      {route && tab==='Coverage' ? <pre>{JSON.stringify(bundle.coverage?.records ?? [], null, 2)}</pre> : null}
      {route && tab==='Export' ? <Export route={route} seed={selected} /> : null}
    </section>
  </div>
}

function Export({ route, seed }: { route: Route; seed: string }) {
  const markdown = `# Route ${seed}\n\n${route.ordered_path.map((r, i) => `${i + 1}. ${r}`).join('\n')}`
  const layer = { version: '4.5', name: `A2D-${seed}`, domain: 'enterprise-attack', techniques: route.ordered_path.filter(p => /^T\d+/.test(p)).map(techniqueID => ({ techniqueID })) }
  return <>
    <h3>Markdown</h3><pre>{markdown}</pre>
    <h3>JSON</h3><pre>{JSON.stringify({ seed, route }, null, 2)}</pre>
    <h3>ATT&CK Navigator Layer (starter)</h3><pre>{JSON.stringify(layer, null, 2)}</pre>
  </>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
