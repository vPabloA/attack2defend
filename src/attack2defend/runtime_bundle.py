"""Runtime bundle publishing helpers.

The canonical builder can keep expensive builder-time artifacts, but the
Navigator UI must receive a deterministic static payload that is small enough to
parse in the browser. Today the largest offender is `semantic_routes`: it is a
precomputed cache and the UI resolves routes from nodes/edges/indexes instead.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

HEAVY_TOP_LEVEL_FIELDS = {"semantic_routes"}
STREAM_THRESHOLD_BYTES = 150 * 1024 * 1024
_TOP_LEVEL_KEY_RE = re.compile(rb'^  "([^"]+)":')


def compact_runtime_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Return a UI-safe bundle without builder-only heavyweight fields."""

    runtime = {key: value for key, value in bundle.items() if key not in HEAVY_TOP_LEVEL_FIELDS}
    metadata = deepcopy(runtime.get("metadata") if isinstance(runtime.get("metadata"), dict) else {})
    counts = dict(metadata.get("counts") if isinstance(metadata.get("counts"), dict) else {})

    omitted = sorted(key for key in HEAVY_TOP_LEVEL_FIELDS if key in bundle)
    if omitted:
        metadata["runtime_bundle"] = {
            "strategy": "static_runtime_compact",
            "omitted_top_level_fields": omitted,
            "reason": "Builder-time route caches are not required by the UI runtime resolver.",
        }
        for key in omitted:
            value = bundle.get(key)
            if isinstance(value, list):
                counts[f"{key}_omitted"] = len(value)
    metadata["counts"] = counts
    runtime["metadata"] = metadata
    return runtime


def write_runtime_bundle(path: str | Path, bundle: dict[str, Any], *, pretty: bool = False) -> None:
    """Write the compact runtime bundle to `path`."""

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    runtime = compact_runtime_bundle(bundle)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(runtime, handle, ensure_ascii=False, indent=2 if pretty else None, sort_keys=pretty)
        handle.write("\n")


def publish_runtime_bundle(
    source: str | Path,
    output: str | Path,
    *,
    pretty: bool = False,
    stream_threshold_bytes: int = STREAM_THRESHOLD_BYTES,
) -> dict[str, Any]:
    """Publish a UI runtime bundle from a canonical bundle path.

    Large canonical bundles are first reduced by streaming out top-level fields
    such as `semantic_routes`; the reduced object is then parsed and emitted as a
    compact JSON payload. This avoids loading a multi-GB route cache into memory
    just to remove one top-level key.
    """

    source_path = Path(source)
    output_path = Path(output)
    source_size = source_path.stat().st_size
    loaded_from = source_path
    temp_paths: list[Path] = []
    stream_omitted: list[str] = []

    if source_size > stream_threshold_bytes:
        reduced_path = _temp_path(output_path)
        stream_omitted = _write_without_top_level_keys(source_path, reduced_path, HEAVY_TOP_LEVEL_FIELDS)
        loaded_from = reduced_path
        temp_paths.append(reduced_path)

    try:
        with loaded_from.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError(f"Expected JSON object in {loaded_from}")
        runtime = compact_runtime_bundle(payload)
        if stream_omitted:
            metadata = dict(runtime.get("metadata") if isinstance(runtime.get("metadata"), dict) else {})
            metadata["runtime_bundle"] = {
                "strategy": "static_runtime_compact",
                "omitted_top_level_fields": stream_omitted,
                "reason": "Builder-time route caches are not required by the UI runtime resolver.",
            }
            runtime["metadata"] = metadata
        _write_json_atomic(output_path, runtime, pretty=pretty)
        return {
            "source": str(source_path),
            "output": str(output_path),
            "source_bytes": source_size,
            "output_bytes": output_path.stat().st_size,
            "omitted_top_level_fields": stream_omitted or sorted(HEAVY_TOP_LEVEL_FIELDS & set(payload)),
        }
    finally:
        for path in temp_paths:
            path.unlink(missing_ok=True)


def _temp_path(output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=output_path.parent,
        delete=False,
    )
    handle.close()
    return Path(handle.name)


def _write_json_atomic(path: Path, payload: dict[str, Any], *, pretty: bool) -> None:
    temp_path = _temp_path(path)
    try:
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2 if pretty else None, sort_keys=pretty)
            handle.write("\n")
        os.replace(temp_path, path)
        path.chmod(0o644)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _write_without_top_level_keys(source: Path, output: Path, omitted_keys: set[str]) -> list[str]:
    sections = _top_level_sections(source)
    present_omitted = sorted({key for key, _, _ in sections if key in omitted_keys})
    selected = [(key, start, end) for key, start, end in sections if key not in omitted_keys]
    if not selected:
        raise ValueError(f"No top-level sections left after omitting {sorted(omitted_keys)} from {source}")

    with output.open("wb") as writer, source.open("rb") as reader:
        writer.write(b"{\n")
        for index, (_, start, end) in enumerate(selected):
            reader.seek(start)
            chunk = reader.read(end - start).rstrip()
            if chunk.endswith(b","):
                chunk = chunk[:-1].rstrip()
            writer.write(chunk)
            writer.write(b",\n" if index < len(selected) - 1 else b"\n")
        writer.write(b"}\n")
    return present_omitted


def _top_level_sections(source: Path) -> list[tuple[str, int, int]]:
    markers: list[tuple[str, int]] = []
    close_start: int | None = None
    position = 0

    with source.open("rb") as handle:
        for line in handle:
            match = _TOP_LEVEL_KEY_RE.match(line)
            if match:
                markers.append((match.group(1).decode("utf-8"), position))
            elif line.strip() == b"}" and not line.startswith(b" "):
                close_start = position
            position += len(line)

    if not markers or close_start is None:
        raise ValueError(f"Cannot stream-compact {source}: expected pretty top-level JSON sections")

    sections: list[tuple[str, int, int]] = []
    for index, (key, start) in enumerate(markers):
        end = markers[index + 1][1] if index + 1 < len(markers) else close_start
        sections.append((key, start, end))
    return sections
