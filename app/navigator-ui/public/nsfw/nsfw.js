/**
 * Attack2Defend NSFW-compatible static navigator.
 *
 * Loads canonical mapping files (NSFW format), builds inverted indexes in
 * memory, and resolves a query bidirectionally across CVE/CWE/CAPEC/ATT&CK/
 * D3FEND/CPE. Mirrors the behaviour of frncscrlnd/nsfw and Galeax/CVE2CAPEC
 * with no backend or runtime API calls.
 */
(function () {
  'use strict';

  const DATA_BASE = './data';
  const status = document.getElementById('status');
  const search = document.getElementById('search');
  const searchBtn = document.getElementById('search-button');
  const clearBtn = document.getElementById('clear-button');
  const errorEl = document.getElementById('search-error');
  const result = document.getElementById('result');
  const autocompleteEl = document.getElementById('autocomplete');

  const selectedId = document.getElementById('selected-id');
  const selectedDetail = document.getElementById('selected-detail');
  const selectedBadges = document.getElementById('selected-badges');

  const lists = {
    cveToCwe: document.getElementById('list-cve-cwe'),
    cweToCapec: document.getElementById('list-cwe-capec'),
    capecToAttack: document.getElementById('list-capec-attack'),
    attackToD3fend: document.getElementById('list-attack-defend'),
    cveToCpe: document.getElementById('list-cve-cpe'),
    reverse: document.getElementById('list-reverse'),
  };

  const data = {
    cveCwe: {},
    cweCapec: {},
    capecAttack: {},
    attackDefend: {},
    cveCpe: {},
    cveCvss: {},
    tacticsTechniques: {},
    d3fendTactics: {},
    kevs: new Set(),
    reverse: {
      cweCve: {},
      capecCwe: {},
      attackCapec: {},
      defendAttack: {},
      cpeCve: {},
    },
    allIds: new Set(),
  };

  function fetchJson(filename) {
    return fetch(`${DATA_BASE}/${filename}`).then((response) => {
      if (!response.ok) throw new Error(`Failed to load ${filename}: ${response.status}`);
      return response.json();
    });
  }

  function fetchText(filename) {
    return fetch(`${DATA_BASE}/${filename}`).then((response) => {
      if (!response.ok) throw new Error(`Failed to load ${filename}: ${response.status}`);
      return response.text();
    });
  }

  function buildReverse(forward, target) {
    Object.keys(forward).forEach((source) => {
      (forward[source] || []).forEach((value) => {
        if (!target[value]) target[value] = [];
        if (!target[value].includes(source)) target[value].push(source);
      });
    });
    Object.keys(target).forEach((key) => target[key].sort());
  }

  function indexAllIds() {
    const all = new Set();
    function add(map) {
      Object.keys(map).forEach((key) => {
        all.add(key);
        (map[key] || []).forEach((v) => all.add(v));
      });
    }
    add(data.cveCwe);
    add(data.cweCapec);
    add(data.capecAttack);
    add(data.attackDefend);
    add(data.cveCpe);
    data.kevs.forEach((id) => all.add(id));
    data.allIds = all;
  }

  function detectType(id) {
    const value = String(id || '').trim().toUpperCase();
    if (/^CVE-\d{4}-\d{4,}$/.test(value)) return 'CVE';
    if (/^CWE-\d+$/.test(value)) return 'CWE';
    if (/^CAPEC-\d+$/.test(value)) return 'CAPEC';
    if (/^T\d{4}(?:\.\d{3})?$/.test(value)) return 'ATT&CK';
    if (/^D3-/.test(value)) return 'D3FEND';
    if (/^CPE:?2\.3/.test(value)) return 'CPE';
    return 'Unknown';
  }

  function renderList(target, items, formatLabel) {
    target.innerHTML = '';
    if (!items || items.length === 0) {
      const li = document.createElement('li');
      li.className = 'empty';
      li.textContent = '—';
      target.appendChild(li);
      return;
    }
    items.forEach((id) => {
      const li = document.createElement('li');
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = formatLabel ? formatLabel(id) : id;
      button.dataset.id = id;
      button.addEventListener('click', () => resolve(id));
      li.appendChild(button);
      target.appendChild(li);
    });
  }

  function resolve(rawQuery) {
    const id = String(rawQuery || '').trim().toUpperCase();
    errorEl.hidden = true;
    autocompleteEl.innerHTML = '';
    if (!id) return;
    if (!data.allIds.has(id)) {
      const matches = Array.from(data.allIds)
        .filter((candidate) => candidate.includes(id))
        .slice(0, 8);
      if (matches.length === 0) {
        errorEl.textContent = `No mapping found for "${id}".`;
        errorEl.hidden = false;
        result.hidden = true;
        return;
      }
      matches.forEach((candidate) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = candidate;
        button.addEventListener('click', () => {
          search.value = candidate;
          resolve(candidate);
        });
        autocompleteEl.appendChild(button);
      });
      result.hidden = true;
      return;
    }

    const type = detectType(id);
    selectedId.textContent = id;
    selectedDetail.textContent = `Type: ${type}`;
    selectedBadges.innerHTML = '';

    const typeBadge = document.createElement('span');
    typeBadge.className = 'badge type';
    typeBadge.textContent = type;
    selectedBadges.appendChild(typeBadge);

    if (data.kevs.has(id)) {
      const kev = document.createElement('span');
      kev.className = 'badge kev';
      kev.textContent = 'CISA KEV';
      selectedBadges.appendChild(kev);
    }

    if (data.cveCvss[id]) {
      const score = data.cveCvss[id].cvss_v3_base_score || data.cveCvss[id].cvss_v3 || data.cveCvss[id].cvss_v2_base_score;
      if (score) {
        const cvss = document.createElement('span');
        cvss.className = 'badge';
        cvss.textContent = `CVSS ${score}`;
        selectedBadges.appendChild(cvss);
      }
    }

    renderList(lists.cveToCwe, type === 'CVE' ? data.cveCwe[id] : []);
    renderList(lists.cweToCapec, type === 'CWE' ? data.cweCapec[id] : []);
    renderList(lists.capecToAttack, type === 'CAPEC' ? data.capecAttack[id] : []);
    renderList(lists.attackToD3fend, type === 'ATT&CK' ? data.attackDefend[id] : []);
    renderList(lists.cveToCpe, type === 'CVE' ? data.cveCpe[id] : []);

    const reverse = [];
    if (type === 'CWE') reverse.push(...(data.reverse.cweCve[id] || []));
    if (type === 'CAPEC') reverse.push(...(data.reverse.capecCwe[id] || []));
    if (type === 'ATT&CK') reverse.push(...(data.reverse.attackCapec[id] || []));
    if (type === 'D3FEND') reverse.push(...(data.reverse.defendAttack[id] || []));
    if (type === 'CPE') reverse.push(...(data.reverse.cpeCve[id] || []));
    renderList(lists.reverse, reverse);

    result.hidden = false;
  }

  function showAutocomplete(query) {
    autocompleteEl.innerHTML = '';
    const term = String(query || '').trim().toUpperCase();
    if (!term) return;
    const matches = Array.from(data.allIds)
      .filter((candidate) => candidate.includes(term))
      .slice(0, 10);
    matches.forEach((candidate) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = candidate;
      button.addEventListener('click', () => {
        search.value = candidate;
        resolve(candidate);
      });
      autocompleteEl.appendChild(button);
    });
  }

  function init() {
    Promise.all([
      fetchJson('cve_cwe.json').then((value) => (data.cveCwe = value || {})),
      fetchJson('cwe_capec.json').then((value) => (data.cweCapec = value || {})),
      fetchJson('capec_attack.json').then((value) => (data.capecAttack = value || {})),
      fetchJson('attack_defend.json').then((value) => (data.attackDefend = value || {})),
      fetchJson('cve_cpe.json').then((value) => (data.cveCpe = value || {})),
      fetchJson('cve_cvss.json').then((value) => (data.cveCvss = value || {})).catch(() => (data.cveCvss = {})),
      fetchJson('tactics_techniques.json').then((value) => (data.tacticsTechniques = value || {})).catch(() => (data.tacticsTechniques = {})),
      fetchJson('d3fend_tactics.json').then((value) => (data.d3fendTactics = value || {})).catch(() => (data.d3fendTactics = {})),
      fetchText('kevs.txt').then((value) => {
        data.kevs = new Set(
          value
            .split(/\r?\n/)
            .map((line) => line.trim().toUpperCase())
            .filter(Boolean),
        );
      }).catch(() => (data.kevs = new Set())),
    ])
      .then(() => {
        buildReverse(data.cveCwe, data.reverse.cweCve);
        buildReverse(data.cweCapec, data.reverse.capecCwe);
        buildReverse(data.capecAttack, data.reverse.attackCapec);
        buildReverse(data.attackDefend, data.reverse.defendAttack);
        buildReverse(data.cveCpe, data.reverse.cpeCve);
        indexAllIds();

        const cveCount = Object.keys(data.cveCwe).length;
        const cweCount = Object.keys(data.cweCapec).length;
        const capecCount = Object.keys(data.capecAttack).length;
        const attackCount = Object.keys(data.attackDefend).length;
        const cpeCount = Object.keys(data.cveCpe).length;
        const kevCount = data.kevs.size;
        status.classList.remove('error');
        status.textContent = `Loaded · ${cveCount} CVE→CWE · ${cweCount} CWE→CAPEC · ${capecCount} CAPEC→ATT&CK · ${attackCount} ATT&CK→D3FEND · ${cpeCount} CVE→CPE · ${kevCount} KEV`;
        searchBtn.disabled = false;
      })
      .catch((error) => {
        status.classList.add('error');
        status.textContent = `Failed to load canonical mapping bundle: ${error.message}`;
      });
  }

  search.addEventListener('input', () => showAutocomplete(search.value));
  search.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') resolve(search.value);
  });
  searchBtn.addEventListener('click', () => resolve(search.value));
  clearBtn.addEventListener('click', () => {
    search.value = '';
    autocompleteEl.innerHTML = '';
    errorEl.hidden = true;
    result.hidden = true;
  });

  init();
})();
