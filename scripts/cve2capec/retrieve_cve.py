#!/usr/bin/env python3
"""CVE2CAPEC parity step: retrieve_cve.

Delegates to the Attack2Defend canonical exporter to refresh the CVE database
files from the local knowledge bundle. Public collection happens upstream in
``scripts/knowledge_builder/build_knowledge_base.py``.
"""
from __future__ import annotations

import sys

from _pipeline import run_pipeline_step


def main(argv: list[str] | None = None) -> int:
    return run_pipeline_step("retrieve_cve", argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
