"""CAPEC resolver using MITRE's published data.

Queries capec.mitre.org or uses local bundle data to resolve CAPEC patterns,
their descriptions, and ATT&CK Related Patterns.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import cache as _cache

_CAPEC_API = "https://capec.mitre.org/data/definitions/{id}.json"
_SOURCE = "capec_mitre"
_TIMEOUT = 12


def resolve(capec_id: str, use_cache: bool = True, cache_dir: Path | None = None) -> dict[str, Any]:
    normalized = capec_id.upper()
    if not normalized.startswith("CAPEC-"):
        normalized = f"CAPEC-{normalized}"

    if use_cache:
        cached = _cache.load(normalized, _SOURCE, cache_dir)
        if cached is not None:
            return cached

    data = _fetch(normalized)
    if data and use_cache:
        _cache.save(normalized, _SOURCE, data, cache_dir)
    return data or _stub(normalized)


def _numeric(capec_id: str) -> str:
    return capec_id.replace("CAPEC-", "").strip()


def _fetch(capec_id: str) -> dict[str, Any] | None:
    num = _numeric(capec_id)
    url = _CAPEC_API.format(id=num)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "attack2defend/1.0", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None

    return _normalize(capec_id, raw)


def _normalize(capec_id: str, raw: dict[str, Any]) -> dict[str, Any]:
    pattern = raw if "Name" in raw else raw.get("Attack_Pattern", raw)
    name = pattern.get("Name") or pattern.get("name") or capec_id
    desc_block = pattern.get("Description") or {}
    if isinstance(desc_block, dict):
        desc = desc_block.get("#text") or desc_block.get("text") or ""
    elif isinstance(desc_block, str):
        desc = desc_block
    else:
        desc = ""

    # ATT&CK Related Patterns
    attack_ids: list[str] = []
    related = pattern.get("Related_Attack_Patterns") or {}
    entries = related.get("Related_Attack_Pattern") or []
    if isinstance(entries, dict):
        entries = [entries]
    for entry in entries:
        nature = entry.get("@Nature") or entry.get("nature") or ""
        if nature in ("ChildOf", "CanPrecede", ""):
            pass  # include all
        capec_ref = entry.get("@CAPEC_ID") or ""
        _ = capec_ref  # related CAPEC (not ATT&CK)

    # ATT&CK mappings from "Taxonomy_Mappings" section
    for tm in (pattern.get("Taxonomy_Mappings") or {}).get("Taxonomy_Mapping") or []:
        if isinstance(tm, dict):
            tname = tm.get("@Taxonomy_Name") or ""
            if "ATT&CK" in tname or "ATTACK" in tname.upper():
                entry_id = tm.get("Entry_ID") or tm.get("entry_id") or ""
                if entry_id:
                    tid = entry_id if entry_id.startswith("T") else f"T{entry_id}"
                    attack_ids.append(tid)

    return {
        "id": capec_id,
        "name": str(name),
        "description": str(desc)[:800],
        "attack_technique_ids": list(dict.fromkeys(attack_ids)),
        "url": f"https://capec.mitre.org/data/definitions/{_numeric(capec_id)}.html",
        "source": "capec_mitre",
    }


def _stub(capec_id: str) -> dict[str, Any]:
    return {
        "id": capec_id,
        "name": capec_id,
        "description": "",
        "attack_technique_ids": [],
        "url": f"https://capec.mitre.org/data/definitions/{_numeric(capec_id)}.html",
        "source": "stub",
    }
