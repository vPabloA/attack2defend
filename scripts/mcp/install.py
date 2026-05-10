#!/usr/bin/env python3
"""Print a local MCP client configuration snippet for Attack2Defend.

This script does not mutate user config files. Copy the emitted JSON into the
client configuration you control.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    config = {
        "mcpServers": {
            "attack2defend": {
                "command": sys.executable,
                "args": [str(ROOT / "scripts" / "mcp" / "server.py")],
                "cwd": str(ROOT),
            }
        }
    }
    print(json.dumps(config, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
