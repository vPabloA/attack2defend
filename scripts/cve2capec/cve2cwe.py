#!/usr/bin/env python3
"""CVE2CAPEC parity step: cve2cwe."""
from __future__ import annotations

import sys

from _pipeline import run_pipeline_step


def main(argv: list[str] | None = None) -> int:
    return run_pipeline_step("cve2cwe", argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
