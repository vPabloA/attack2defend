const TOKEN_RE = /(CVE-\d{4}-\d{4,7}|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d{3})?|D3-[A-Z0-9-]+)/gi;
const CANONICAL_ORDER = ['cve', 'cwe', 'capec', 'attack', 'd3fend'];
const PREVIOUS_TYPE = {
  d3fend: 'attack',
  attack: 'capec',
  capec: 'cwe',
  cwe: 'cve',
};

function normalizeId(value) {
  return String(value ?? '').trim().toUpperCase();
}

function unique(values) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    const item = normalizeId(value);
    if (!item || seen.has(item)) continue;
    seen.add(item);
    out.push(item);
  }
  return out;
}

function asArray(value) {
  return Array.isArray(value) ? value.map((item) => normalizeId(item)).filter(Boolean) : [];
}

function nodeTypeFromId(nodeId) {
  const id = normalizeId(nodeId);
  if (id.startsWith('CVE-')) return 'cve';
  if (id.startsWith('CWE-')) return 'cwe';
  if (id.startsWith('CAPEC-')) return 'capec';
  if (/^T\d{4}(?:\.\d{3})?$/.test(id)) return 'attack';
  if (id.startsWith('D3-')) return 'd3fend';
  if (id.startsWith('CTRL-')) return 'control';
  if (id.startsWith('DET-')) return 'detection';
  if (id.startsWith('EV-')) return 'evidence';
  if (id.startsWith('GAP-')) return 'gap';
  if (id.startsWith('ACT-')) return 'action';
  return 'unknown';
}

export function extractSearchTokens(raw) {
  const text = String(raw ?? '').trim();
  if (!text) return [];
  const tokens = [];
  for (const match of text.matchAll(TOKEN_RE)) {
    tokens.push(normalizeId(match[0]));
  }
  if (tokens.length) return unique(tokens);
  return text
    .split(/[\n,;|]+/g)
    .map((part) => normalizeId(part))
    .filter(Boolean);
}

export function buildReverseIndex(bundle) {
  const reverse = bundle?.reverse_index ?? bundle?.indexes?.reverse ?? {};
  return {
    by_cwe: normalizeReverseBucket(
      reverse.by_cwe ??
      reverse.cwe_to_cve ??
      reverse.cwe ??
      reverse.cwe_to_cves,
    ),
    by_capec: normalizeReverseBucket(
      reverse.by_capec ??
      reverse.capec_to_cve ??
      reverse.capec ??
      reverse.capec_to_cves,
    ),
    by_attack: normalizeReverseBucket(
      reverse.by_attack ??
      reverse.attack_to_cve ??
      reverse.attack ??
      reverse.attack_to_cves,
    ),
    by_d3fend: normalizeReverseBucket(
      reverse.by_d3fend ??
      reverse.d3fend_to_cve ??
      reverse.d3fend ??
      reverse.d3fend_to_cves,
    ),
  };
}

export function buildSearchIndex(bundle) {
  const nodeMap = new Map();
  for (const node of bundle?.nodes ?? []) {
    if (!node || typeof node !== 'object') continue;
    const id = normalizeId(node.id);
    if (!id) continue;
    nodeMap.set(id, {
      id,
      type: normalizeId(node.type).toLowerCase(),
      name: String(node.name ?? id),
    });
  }
  for (const [id, record] of Object.entries(bundle?.cves ?? {})) {
    const normalized = normalizeId(id);
    if (!normalized || nodeMap.has(normalized)) continue;
    nodeMap.set(normalized, {
      id: normalized,
      type: 'cve',
      name: String(record?.label ?? record?.id ?? normalized),
    });
  }
  return {
    nodeMap,
    reverseIndex: buildReverseIndex(bundle),
  };
}

export function resolveSearchSelection(bundle, rawQuery, options = {}) {
  const normalizedQuery = String(rawQuery ?? '').trim();
  const tokens = extractSearchTokens(normalizedQuery);
  const maxRoots = Number.isFinite(options.maxRoots) ? Math.max(1, Math.floor(options.maxRoots)) : 8;
  const maxReverseMatches = Number.isFinite(options.maxReverseMatches) ? Math.max(1, Math.floor(options.maxReverseMatches)) : 12;
  const { nodeMap, reverseIndex } = buildSearchIndex(bundle);

  if (!tokens.length) {
    return {
      normalizedQuery,
      tokens: [],
      selectedIds: [],
      associatedCves: [],
      mode: 'empty',
      primaryId: null,
      reverseAnchor: null,
      message: '',
      hits: [],
    };
  }

  const hits = [];
  const directMatches = [];
  const reverseMatches = [];
  let reverseAnchor = null;

  for (const token of tokens) {
    const node = nodeMap.get(token);
    const type = node?.type ?? nodeTypeFromId(token);
    const entry = { token, type, matches: [] };

    if (type === 'cve') {
      directMatches.push(token);
      entry.matches.push(token);
      hits.push(entry);
      continue;
    }

    const explicitReverse = lookupReverse(reverseIndex, type, token);
    const graphReverse = explicitReverse.length ? explicitReverse : collectReverseCvesFromGraph(bundle, token, maxReverseMatches);
    const associated = unique(graphReverse).slice(0, maxReverseMatches);
    if (associated.length) {
      reverseAnchor = reverseAnchor ?? token;
      reverseMatches.push(...associated);
      entry.matches.push(...associated);
    } else if (node) {
      directMatches.push(token);
      entry.matches.push(token);
    }
    hits.push(entry);
  }

  const selectedIds = unique([...directMatches, ...reverseMatches]).slice(0, maxRoots);
  const associatedCves = unique(reverseMatches);
  let mode = 'mixed';
  if (tokens.length === 1 && selectedIds.length && selectedIds[0] === tokens[0] && nodeTypeFromId(tokens[0]) === 'cve') {
    mode = 'direct';
  } else if (tokens.length === 1 && associatedCves.length && nodeTypeFromId(tokens[0]) !== 'cve') {
    mode = 'reverse';
  } else if (tokens.length > 1) {
    mode = directMatches.length && reverseMatches.length ? 'mixed' : 'batch';
  } else if (directMatches.length && !reverseMatches.length) {
    mode = 'direct';
  } else if (reverseMatches.length && !directMatches.length) {
    mode = 'reverse';
  }

  const primaryId = selectedIds[0] ?? null;
  const message = buildSearchMessage({ tokens, selectedIds, associatedCves, reverseAnchor, mode });

  return {
    normalizedQuery,
    tokens,
    selectedIds,
    associatedCves,
    mode,
    primaryId,
    reverseAnchor,
    message,
    hits,
  };
}

function lookupReverse(reverseIndex, type, token) {
  const key = normalizeId(token);
  if (type === 'cwe') return asArray(reverseIndex.by_cwe?.[key]);
  if (type === 'capec') return asArray(reverseIndex.by_capec?.[key]);
  if (type === 'attack') return asArray(reverseIndex.by_attack?.[key]);
  if (type === 'd3fend') return asArray(reverseIndex.by_d3fend?.[key]);
  return [];
}

function collectReverseCvesFromGraph(bundle, startId, maxResults) {
  const nodeMap = new Map();
  for (const node of bundle?.nodes ?? []) {
    if (!node || typeof node !== 'object') continue;
    const id = normalizeId(node.id);
    if (!id) continue;
    nodeMap.set(id, {
      id,
      type: normalizeId(node.type).toLowerCase(),
    });
  }
  for (const [id, record] of Object.entries(bundle?.cves ?? {})) {
    const normalized = normalizeId(id);
    if (!nodeMap.has(normalized)) {
      nodeMap.set(normalized, { id: normalized, type: 'cve', record });
    }
  }
  const incoming = new Map();
  for (const edge of bundle?.edges ?? []) {
    if (!edge || typeof edge !== 'object') continue;
    const source = normalizeId(edge.source);
    const target = normalizeId(edge.target);
    if (!source || !target) continue;
    const list = incoming.get(target) ?? [];
    list.push({ source, target });
    incoming.set(target, list);
  }

  const start = normalizeId(startId);
  const queue = [start];
  const seen = new Set([start]);
  const result = [];
  let steps = 0;

  while (queue.length && steps < 1000 && result.length < maxResults) {
    const current = queue.shift();
    steps += 1;
    const currentType = nodeMap.get(current)?.type ?? nodeTypeFromId(current);
    const sources = incoming.get(current) ?? [];
    for (const edge of sources) {
      const next = edge.source;
      const nextType = nodeMap.get(next)?.type ?? nodeTypeFromId(next);
      if (nextType === 'cve') {
        result.push(next);
        continue;
      }
      const expected = PREVIOUS_TYPE[currentType];
      if (expected && nextType === expected && !seen.has(next)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }

  return unique(result).slice(0, maxResults);
}

function normalizeReverseBucket(bucket) {
  const out = {};
  if (!bucket || typeof bucket !== 'object') return out;
  for (const [key, value] of Object.entries(bucket)) {
    const normalizedKey = normalizeId(key);
    if (!normalizedKey) continue;
    out[normalizedKey] = asArray(value);
  }
  return out;
}

function buildSearchMessage({ tokens, selectedIds, associatedCves, reverseAnchor, mode }) {
  if (!tokens.length) return '';
  if (mode === 'reverse') {
    return reverseAnchor
      ? `Reverse search for ${reverseAnchor} resolved ${associatedCves.length} CVEs.`
      : `Reverse search resolved ${associatedCves.length} CVEs.`;
  }
  if (mode === 'batch') {
    return `Batch import resolved ${selectedIds.length} CVEs from ${tokens.length} tokens.`;
  }
  if (mode === 'mixed') {
    return `Mixed search resolved ${selectedIds.length} root IDs with ${associatedCves.length} reverse hits.`;
  }
  return selectedIds.length ? `Resolved ${selectedIds.length} root IDs from direct match.` : 'No local match found.';
}
