"""D3FEND API resolver.

Queries d3fend.mitre.org API endpoints to resolve ATT&CK→D3FEND and CWE→D3FEND
mappings. Falls back to cache and then to local bundle.

Key endpoints used:
  /api/offensive-technique/attack/{technique_id}.json  → D3FEND countermeasures
  /api/technique/d3f:{D3FEND_ID}.json                 → D3FEND technique details
  /api/weakness/cwe/{cwe_num}.json                     → D3FEND for a CWE
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import cache as _cache

_D3FEND_BASE = "https://d3fend.mitre.org"
_TIMEOUT = 12
_SOURCE_ATTACK = "d3fend_attack"
_SOURCE_CWE = "d3fend_cwe"


def resolve_for_attack(technique_id: str, use_cache: bool = True, cache_dir: Path | None = None) -> list[dict[str, Any]]:
    """Return list of D3FEND countermeasures for an ATT&CK technique ID."""
    normalized = technique_id.upper()
    cache_key = f"attack_{normalized}"

    if use_cache:
        cached = _cache.load(cache_key, _SOURCE_ATTACK, cache_dir)
        if cached is not None:
            return cached.get("items", [])

    items = _fetch_for_attack(normalized)
    if use_cache:
        _cache.save(cache_key, _SOURCE_ATTACK, {"items": items}, cache_dir)
    return items


def resolve_for_cwe(cwe_id: str, use_cache: bool = True, cache_dir: Path | None = None) -> list[dict[str, Any]]:
    """Return list of D3FEND countermeasures for a CWE."""
    num = cwe_id.replace("CWE-", "").strip()
    cache_key = f"cwe_{cwe_id.upper()}"

    if use_cache:
        cached = _cache.load(cache_key, _SOURCE_CWE, cache_dir)
        if cached is not None:
            return cached.get("items", [])

    items = _fetch_for_cwe(num)
    if use_cache:
        _cache.save(cache_key, _SOURCE_CWE, {"items": items}, cache_dir)
    return items


def _fetch_for_attack(technique_id: str) -> list[dict[str, Any]]:
    # D3FEND uses the technique ID with dots as sub-technique separator
    tid = technique_id.replace(".", "/")
    url = f"{_D3FEND_BASE}/api/offensive-technique/attack/{tid}.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "attack2defend/1.0", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return []

    return _parse_d3fend_response(raw)


def _fetch_for_cwe(cwe_num: str) -> list[dict[str, Any]]:
    url = f"{_D3FEND_BASE}/api/weakness/cwe/{cwe_num}.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "attack2defend/1.0", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return []

    return _parse_d3fend_response(raw)


def _parse_d3fend_response(raw: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    # D3FEND API returns various structures; handle common ones
    results = raw.get("results", raw) if isinstance(raw, dict) else {}
    bindings = (
        results.get("bindings", [])
        if isinstance(results, dict)
        else []
    )

    seen: set[str] = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        d3id_raw = (
            binding.get("def_tech_id", {}).get("value")
            or binding.get("d3fend_id", {}).get("value")
            or binding.get("technique_id", {}).get("value")
            or ""
        )
        d3name_raw = (
            binding.get("def_tech_label", {}).get("value")
            or binding.get("d3fend_label", {}).get("value")
            or binding.get("technique_label", {}).get("value")
            or ""
        )
        if not d3id_raw:
            continue
        # Normalize: strip full URI if present
        d3id = d3id_raw.split(":")[-1] if ":" in d3id_raw else d3id_raw
        if not d3id.startswith("D3-"):
            d3id = f"D3-{d3id}"
        if d3id in seen:
            continue
        seen.add(d3id)
        items.append({
            "id": d3id,
            "name": str(d3name_raw),
            "url": f"https://d3fend.mitre.org/technique/{d3id}/",
            "source": "d3fend_api",
        })

    return items
