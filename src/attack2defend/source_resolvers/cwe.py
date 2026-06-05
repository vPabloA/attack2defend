"""CWE resolver using MITRE's published data.

Uses the MITRE CWE REST API (cwe.mitre.org) or falls back to
the local bundle's CWE nodes.  Returns name, description, and
related CAPEC IDs for a given CWE identifier.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import cache as _cache

_CWE_API = "https://cwe.mitre.org/data/definitions/{id}.json"
_SOURCE = "cwe_mitre"
_TIMEOUT = 12


def resolve(cwe_id: str, use_cache: bool = True, cache_dir: Path | None = None) -> dict[str, Any]:
    """Return normalized CWE data. Includes related_capec_ids when available."""
    normalized = cwe_id.upper()
    if not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"

    if use_cache:
        cached = _cache.load(normalized, _SOURCE, cache_dir)
        if cached is not None:
            return cached

    data = _fetch(normalized)
    if data and use_cache:
        _cache.save(normalized, _SOURCE, data, cache_dir)
    return data or _stub(normalized)


def _numeric(cwe_id: str) -> str:
    return cwe_id.replace("CWE-", "").strip()


def _fetch(cwe_id: str) -> dict[str, Any] | None:
    num = _numeric(cwe_id)
    url = _CWE_API.format(id=num)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "attack2defend/1.0", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None

    return _normalize(cwe_id, raw)


def _normalize(cwe_id: str, raw: dict[str, Any]) -> dict[str, Any]:
    # The MITRE CWE JSON structure varies; handle common patterns
    weakness = raw if "Name" in raw else raw.get("Weakness", raw)
    name = weakness.get("Name") or weakness.get("name") or cwe_id
    desc = ""
    desc_block = weakness.get("Description") or weakness.get("description") or {}
    if isinstance(desc_block, dict):
        desc = desc_block.get("#text") or desc_block.get("text") or ""
    elif isinstance(desc_block, str):
        desc = desc_block

    # Related attack patterns (CAPEC)
    capec_ids: list[str] = []
    related = weakness.get("Related_Attack_Patterns") or weakness.get("related_attack_patterns") or {}
    if isinstance(related, dict):
        entries = related.get("Related_Attack_Pattern") or []
        if isinstance(entries, dict):
            entries = [entries]
        for entry in entries:
            capec_id = entry.get("@CAPEC_ID") or entry.get("capec_id") or ""
            if capec_id:
                capec_ids.append(f"CAPEC-{capec_id}")

    return {
        "id": cwe_id,
        "name": str(name),
        "description": str(desc)[:800],
        "related_capec_ids": list(dict.fromkeys(capec_ids)),
        "url": f"https://cwe.mitre.org/data/definitions/{_numeric(cwe_id)}.html",
        "source": "cwe_mitre",
    }


def _stub(cwe_id: str) -> dict[str, Any]:
    return {
        "id": cwe_id,
        "name": cwe_id,
        "description": "",
        "related_capec_ids": [],
        "url": f"https://cwe.mitre.org/data/definitions/{_numeric(cwe_id)}.html",
        "source": "stub",
    }
