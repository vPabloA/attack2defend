"""Simple disk cache for source resolver results.

Stores JSON files under data/source-cache/{normalized_id}/{source}.json.
Cache entries never expire automatically — use --no-cache to bypass.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def _safe_key(identifier: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", identifier.upper())


def cache_path(identifier: str, source: str, cache_dir: Path) -> Path:
    return cache_dir / _safe_key(identifier) / f"{source}.json"


def load(identifier: str, source: str, cache_dir: Path | None = None) -> dict[str, Any] | None:
    """Return cached data, or None if cache_dir is None (no-cache mode) or entry missing."""
    if cache_dir is None:
        return None
    path = cache_path(identifier, source, cache_dir)
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


def save(identifier: str, source: str, data: dict[str, Any], cache_dir: Path | None = None) -> None:
    """Write data to cache. No-op when cache_dir is None (no-cache mode)."""
    if cache_dir is None:
        return
    path = cache_path(identifier, source, cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
