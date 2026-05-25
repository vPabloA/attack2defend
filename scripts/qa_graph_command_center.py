#!/usr/bin/env python3
"""Static QA checks for Attack2Defend Graph Command Center.

This script is intentionally lightweight and dependency-free. It validates the
contractual guarantees introduced by Pasada 0-3 without requiring a browser.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAV_UI = ROOT / "app" / "navigator-ui"
SRC = NAV_UI / "src"

REQUIRED_FILES = [
    ROOT / "contracts" / "GRAPH_COMMAND_CENTER_CONTRACT.md",
    ROOT / "contracts" / "AI_ASSISTANCE_CONTRACT.md",
    ROOT / "outputs" / "qa" / "graph_scope_matrix.md",
    ROOT / "outputs" / "qa" / "graph_core_contract_report.md",
    ROOT / "outputs" / "qa" / "graph_command_center_ui_report.md",
    SRC / "types" / "attack2defend.ts",
    SRC / "types" / "provenance.ts",
    SRC / "graph" / "canonicalChain.ts",
    SRC / "graph" / "graphModel.ts",
    SRC / "graph" / "graphExport.ts",
    SRC / "graph" / "aiContextPacket.ts",
    SRC / "components" / "GraphCommandCenterTab.tsx",
    SRC / "components" / "GraphExplorer2D.tsx",
    SRC / "components" / "GraphInspector.tsx",
    SRC / "components" / "GraphAiAssistPanel.tsx",
    SRC / "components" / "GraphExportPanel.tsx",
    NAV_UI / "public" / "graphCommandCenter.css",
]

FORBIDDEN_TERMS = [
    "3d-force-graph",
    "react-force-graph-3d",
    "ForceGraph3D",
    "three",
    "War Room",
    "war room",
]

REQUIRED_EXPORT_TERMS = [
    "attack2defend.canonical_chain",
    "attack2defend.visible_graph",
    "attack2defend.ai_context_packet",
    "attack2defend.graph_explore",
    "attack2defend.graph_gap_paths",
    "attack2defend.graph_evidence_requirements",
]

CANONICAL_CHAIN = "CVE → CWE → CAPEC → ATT&CK → D3FEND"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    sys.exit(1)


def assert_required_files() -> None:
    missing = [str(path.relative_to(ROOT)) for path in REQUIRED_FILES if not path.exists()]
    if missing:
        fail("Missing required files: " + ", ".join(missing))


def assert_no_3d_scope() -> None:
    for path in [NAV_UI / "package.json", SRC / "components" / "GraphExplorer2D.tsx", SRC / "graphCommandCenterEntry.tsx"]:
        text = read_text(path)
        for term in FORBIDDEN_TERMS:
            if term in text:
                fail(f"Forbidden 3D term '{term}' found in {path.relative_to(ROOT)}")


def assert_dependency_policy() -> None:
    package = json.loads(read_text(NAV_UI / "package.json"))
    deps = package.get("dependencies", {})
    if "react-force-graph-2d" not in deps:
        fail("react-force-graph-2d dependency is required")
    for forbidden in ["force-graph", "3d-force-graph", "react-force-graph-3d", "three"]:
        if forbidden in deps:
            fail(f"Forbidden dependency present: {forbidden}")


def assert_canonical_chain() -> None:
    locations = [
        ROOT / "contracts" / "GRAPH_COMMAND_CENTER_CONTRACT.md",
        ROOT / "contracts" / "AI_ASSISTANCE_CONTRACT.md",
        SRC / "graph" / "canonicalChain.ts",
        SRC / "graph" / "graphModel.ts",
        SRC / "graph" / "graphExport.ts",
        SRC / "components" / "GraphCommandCenterTab.tsx",
    ]
    for path in locations:
        if CANONICAL_CHAIN not in read_text(path):
            fail(f"Canonical chain missing in {path.relative_to(ROOT)}")


def assert_exports() -> None:
    export_text = read_text(SRC / "graph" / "graphExport.ts")
    for term in REQUIRED_EXPORT_TERMS:
        if term not in export_text:
            fail(f"Required export capability missing: {term}")


def assert_ai_context_controls() -> None:
    text = read_text(SRC / "graph" / "aiContextPacket.ts")
    required = ["bundle_full_context_sent: false", "visible_subgraph", "cache_key_basis"]
    for term in required:
        if term not in text:
            fail(f"AI context control missing: {term}")


def main() -> None:
    assert_required_files()
    assert_dependency_policy()
    assert_no_3d_scope()
    assert_canonical_chain()
    assert_exports()
    assert_ai_context_controls()
    print("PASS: Graph Command Center static QA checks passed")


if __name__ == "__main__":
    main()
