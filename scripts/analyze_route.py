#!/usr/bin/env python3
"""Route Coherence Engine CLI.

Usage:
  python scripts/analyze_route.py --input CVE-2026-23479 --live --llm --graph --all-exports
  python scripts/analyze_route.py --input T1190 --graph --all-exports
  python scripts/analyze_route.py --input CVE-2021-44228 --live --official-only --graph

Produces artifacts/routes/{INPUT}/ with:
  route-coherence.json, route-coherence.md, graph.json,
  graph.mmd, graph.svg, graph.png, source-pack.json,
  provenance.json, validation-report.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import warnings
from pathlib import Path

# Ensure src/ is in PYTHONPATH when run directly
_REPO_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from attack2defend.coherence import engine as _engine
from attack2defend.coherence import narrative as _narrative
from attack2defend.coherence import validator as _validator
from attack2defend.coherence.schema import RouteCoherenceArtifact
from attack2defend.graph import mermaid as _mermaid
from attack2defend.graph import projection as _projection
from attack2defend.graph import render_png as _png
from attack2defend.graph import render_svg as _svg


def _load_bundle() -> tuple[list[dict], list[dict]]:
    bundle_path = _REPO_ROOT / "data" / "knowledge-bundle.json"
    if not bundle_path.exists():
        return [], []
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        return bundle.get("nodes", []), bundle.get("edges", [])
    except (json.JSONDecodeError, OSError):
        return [], []


def _build_markdown(artifact: RouteCoherenceArtifact) -> str:
    analysis = artifact.analysis_es
    provenance = artifact.provenance

    sections = [f"# {analysis.title or f'Ruta de coherencia — {artifact.input}'}\n"]

    # Canonical chain
    sections.append("## Ruta de coherencia\n")
    sections.append("> " + " → ".join(artifact.canonical_chain) + "\n")
    sections.append("")

    # Secuencia lógica
    sections.append("## Secuencia lógica\n")
    sections.append("| Nivel | Elemento | Lectura de coherencia |")
    sections.append("|---|---|---|")
    for item in analysis.logical_sequence:
        reading = item.coherence_reading.replace("|", "\\|")
        sections.append(f"| {item.level} | `{item.element}` | {reading} |")
    sections.append("")

    # Narrativa técnica
    sections.append("## Narrativa técnica\n")
    sections.append(analysis.technical_narrative or "_Narrativa no disponible._")
    sections.append("")

    # Ruta resumida
    sections.append("## Ruta resumida\n")
    sections.append("```")
    sections.append(analysis.ascii_route or " → ".join(artifact.canonical_chain))
    sections.append("```")
    sections.append("")

    # Conclusión
    sections.append("## Conclusión\n")
    sections.append(analysis.conclusion or "_Conclusión no disponible._")
    sections.append("")

    # Provenance
    sections.append("## Provenance\n")
    sections.append(f"- **Oficial explícito**: {', '.join(provenance.official_explicit) or 'ninguno'}")
    sections.append(f"- **Oficial relacionado**: {', '.join(provenance.official_related) or 'ninguno'}")
    sections.append(f"- **Inferido analítico**: {', '.join(provenance.analytical_inferred) or 'ninguno'}")
    sections.append(f"- **Condicional**: {', '.join(provenance.conditional) or 'ninguno'}")
    sections.append(f"- **No verificado**: {', '.join(provenance.unverified) or 'ninguno'}")
    sections.append("")

    # Gaps / inferencias / condicionales
    sections.append("## Gaps / inferencias / condicionales\n")
    if artifact.gaps:
        for gap in artifact.gaps:
            requires = " _(requiere curaduría)_" if gap.get("requires_curation") else ""
            sections.append(f"- **{gap.get('segment', 'gap')}**: {gap.get('description', '')}{requires}")
    else:
        sections.append("_No se identificaron gaps en esta ruta._")

    conditional = [n for n in artifact.all_nodes if n.role == "conditional"]
    if conditional:
        sections.append("")
        sections.append("### Nodos condicionales\n")
        for n in conditional:
            sections.append(f"- `{n.id}` — {n.name}: aplica solo bajo condiciones específicas de explotación.")

    inferred = [e for e in artifact.all_edges if e.mapping_basis == "analytical_inferred"]
    if inferred:
        sections.append("")
        sections.append("### Relaciones inferidas\n")
        for e in inferred:
            sections.append(f"- `{e.source}` → `{e.target}`: {e.rationale_es}")

    sections.append("")
    sections.append(f"_Generado por Attack2Defend Route Coherence Engine — {artifact.generated_at}_")
    sections.append(f"_Fuentes utilizadas: {', '.join(k for k,v in artifact.source_summary.items() if v)}_")

    return "\n".join(sections)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Attack2Defend Route Coherence Engine — analyzes CVE/CWE/CAPEC/ATT&CK/D3FEND chains"
    )
    parser.add_argument("--input", required=True, help="Input ID (e.g. CVE-2026-23479, T1190, CWE-416)")
    parser.add_argument("--live", action="store_true", help="Call live official APIs (NVD, CWE, CAPEC, ATT&CK, D3FEND)")
    parser.add_argument("--official-only", action="store_true", help="Use only official sources, no LLM reasoning")
    parser.add_argument("--llm", action="store_true", help="Use LLM for narrative generation (requires API key env var)")
    parser.add_argument("--graph", action="store_true", help="Generate graph JSON, Mermaid, SVG, PNG")
    parser.add_argument("--all-exports", action="store_true", help="Generate all export formats")
    parser.add_argument("--no-cache", action="store_true", help="Bypass source cache")
    parser.add_argument("--output-dir", default=None, help="Output directory (default: artifacts/routes/{INPUT})")
    args = parser.parse_args(argv)

    input_id = args.input.strip().upper()
    use_llm = args.llm and not args.official_only
    do_graph = args.graph or args.all_exports

    # Output directory
    output_dir = Path(args.output_dir) if args.output_dir else (_REPO_ROOT / "artifacts" / "routes" / input_id)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[analyze-route] Input: {input_id}")
    print(f"[analyze-route] Live sources: {args.live}")
    print(f"[analyze-route] LLM narrative: {use_llm}")
    print(f"[analyze-route] Output: {output_dir}")
    print()

    # Load local bundle
    t0 = time.monotonic()
    bundle_nodes, bundle_edges = _load_bundle()
    print(f"[1/9] Bundle loaded ({len(bundle_nodes)} nodes, {len(bundle_edges)} edges)")

    # Run coherence engine
    cache_dir = None if args.no_cache else (_REPO_ROOT / "data" / "source-cache")
    artifact = _engine.analyze(
        input_id=input_id,
        bundle_nodes=bundle_nodes,
        bundle_edges=bundle_edges,
        live=args.live,
        cache_dir=cache_dir,
    )
    print(f"[2/9] Coherence engine complete — status: {artifact.status}, nodes: {len(artifact.all_nodes)}, edges: {len(artifact.all_edges)}")

    # Generate narrative
    artifact.analysis_es = _narrative.generate(artifact, use_llm=use_llm)
    print(f"[3/9] Narrative generated — source: {artifact.analysis_es.narrative_source}")

    # Validate
    report = _validator.validate(artifact)
    print(f"[4/9] Validation: {'PASSED' if report.passed else 'FAILED'} ({report.to_dict()['errors']} errors, {report.to_dict()['warnings']} warnings)")

    # Save route-coherence.json
    coherence_path = output_dir / "route-coherence.json"
    coherence_path.write_text(json.dumps(artifact.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[5/9] route-coherence.json → {coherence_path}")

    # Save provenance.json
    prov_path = output_dir / "provenance.json"
    prov_path.write_text(json.dumps(artifact.provenance.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[5/9] provenance.json → {prov_path}")

    # Save source-pack.json
    source_pack = {
        "input": input_id,
        "source_summary": artifact.source_summary,
        "node_ids": [n.id for n in artifact.all_nodes],
    }
    sp_path = output_dir / "source-pack.json"
    sp_path.write_text(json.dumps(source_pack, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[5/9] source-pack.json → {sp_path}")

    # Save validation-report.json
    vr_path = output_dir / "validation-report.json"
    vr_path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[5/9] validation-report.json → {vr_path}")

    # Save Markdown
    md_content = _build_markdown(artifact)
    md_path = output_dir / "route-coherence.md"
    md_path.write_text(md_content, encoding="utf-8")
    print(f"[6/9] route-coherence.md → {md_path}")

    # Graph exports
    if do_graph:
        graph_json = _projection.build_graph_json(artifact)

        gj_path = output_dir / "graph.json"
        gj_path.write_text(json.dumps(graph_json, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[7/9] graph.json → {gj_path}")

        mmd_str = _mermaid.build(graph_json)
        mmd_path = output_dir / "graph.mmd"
        mmd_path.write_text(mmd_str, encoding="utf-8")
        print(f"[7/9] graph.mmd → {mmd_path}")

        title = f"{input_id} Knowledge Graph"
        subtitle = "CVE → CWE → CAPEC → ATT&CK → D3FEND"
        svg_str = _svg.build(graph_json, title=title, subtitle=subtitle)
        svg_path = output_dir / "graph.svg"
        svg_path.write_text(svg_str, encoding="utf-8")
        print(f"[8/9] graph.svg → {svg_path}")

        png_bytes = _png.svg_to_png(svg_str)
        suffix = ".svg" if not _png.is_png_available() else ".png"
        png_path = output_dir / f"graph{suffix}"
        png_path.write_bytes(png_bytes)
        print(f"[9/9] graph{suffix} → {png_path}")
    else:
        print("[7-9/9] Graph exports skipped (use --graph or --all-exports)")

    elapsed = time.monotonic() - t0
    print()
    print(f"Done in {elapsed:.1f}s — artifacts at {output_dir}/")

    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
