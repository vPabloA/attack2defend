"""Simple disk cache for source resolver results.

Stores JSON files under data/source-cache/{normalized_id}/{source}.json.
Cache entries never expire automatically — use --no-cache to bypass.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_DEFAULT_CACHE_DIR = Path(__file__).parents[4] / "data" / "source-cache"


def _safe_key(identifier: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", identifier.upper())


def cache_path(identifier: str, source: str, cache_dir: Path | None = None) -> Path:
    root = cache_dir or _DEFAULT_CACHE_DIR
    return root / _safe_key(identifier) / f"{source}.json"


def load(identifier: str, source: str, cache_dir: Path | None = None) -> dict[str, Any] | None:
    path = cache_path(identifier, source, cache_dir)
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


def save(identifier: str, source: str, data: dict[str, Any], cache_dir: Path | None = None) -> None:
    path = cache_path(identifier, source, cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
