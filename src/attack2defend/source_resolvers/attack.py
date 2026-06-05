"""ATT&CK STIX resolver.

Uses the MITRE ATT&CK TAXII/STIX data or the local bundle to resolve
ATT&CK techniques, sub-techniques, and their CAPEC relationships.
Falls back to the local bundle indexes when network is unavailable.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import cache as _cache

_ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
_SOURCE = "attack_stix"
_TIMEOUT = 20

# Lightweight in-memory index once loaded
_STIX_INDEX: dict[str, dict[str, Any]] | None = None


def resolve(technique_id: str, use_cache: bool = True, cache_dir: Path | None = None) -> dict[str, Any]:
    normalized = technique_id.upper()

    if use_cache:
        cached = _cache.load(normalized, _SOURCE, cache_dir)
        if cached is not None:
            return cached

    data = _lookup(normalized)
    if data and use_cache:
        _cache.save(normalized, _SOURCE, data, cache_dir)
    return data or _stub(normalized)


def _lookup(technique_id: str) -> dict[str, Any] | None:
    global _STIX_INDEX
    if _STIX_INDEX is None:
        _STIX_INDEX = _build_index()
    if _STIX_INDEX is None:
        return None
    return _STIX_INDEX.get(technique_id)


def _build_index() -> dict[str, dict[str, Any]] | None:
    try:
        req = urllib.request.Request(_ATTACK_STIX_URL, headers={"User-Agent": "attack2defend/1.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            bundle = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None

    index: dict[str, dict[str, Any]] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext = obj.get("external_references", [])
        tid = None
        for ref in ext:
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id")
                break
        if not tid:
            continue

        capec_ids = [
            r.get("external_id")
            for r in ext
            if r.get("source_name") == "capec" and r.get("external_id")
        ]

        index[tid] = {
            "id": tid,
            "name": obj.get("name", tid),
            "description": (obj.get("description") or "")[:600],
            "capec_ids": capec_ids,
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            "source": "attack_stix",
        }

    return index or None


def _stub(technique_id: str) -> dict[str, Any]:
    return {
        "id": technique_id,
        "name": technique_id,
        "description": "",
        "capec_ids": [],
        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        "source": "stub",
    }
