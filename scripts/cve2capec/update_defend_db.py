#!/usr/bin/env python3
"""CVE2CAPEC parity step: update_defend_db."""
from __future__ import annotations

import sys

from _pipeline import run_pipeline_step


def main(argv: list[str] | None = None) -> int:
    return run_pipeline_step("update_defend_db", argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
