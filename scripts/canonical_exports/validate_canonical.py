#!/usr/bin/env python3
"""Validate the NSFW + CVE2CAPEC canonical exports.

The validator is dependency-free so it runs in CI, cron and Debian.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_NSFW_DIR = REPO_ROOT / "data" / "canonical" / "nsfw"
DEFAULT_CVE2CAPEC_DIR = REPO_ROOT / "data" / "canonical" / "cve2capec"

NSFW_FILES = (
    "cve_cwe.json",
    "cwe_capec.json",
    "capec_attack.json",
    "attack_defend.json",
    "cve_cpe.json",
    "cve_cvss.json",
    "tactics_techniques.json",
    "d3fend_tactics.json",
    "kevs.txt",
)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_RE = re.compile(r"^CWE-\d+$")
CAPEC_RE = re.compile(r"^CAPEC-\d+$")
ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
D3FEND_RE = re.compile(r"^D3-[A-Z0-9-]+$")


def validate_nsfw(nsfw_dir: Path, errors: list[str]) -> None:
    if not nsfw_dir.is_dir():
        errors.append(f"NSFW directory missing: {nsfw_dir}")
        return
    for name in NSFW_FILES:
        path = nsfw_dir / name
        if not path.is_file():
            errors.append(f"NSFW file missing: {path}")
            continue
        if name == "kevs.txt":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - any decode error is a failure
            errors.append(f"NSFW file invalid JSON: {path}: {exc}")
            continue
        if not isinstance(payload, dict):
            errors.append(f"NSFW file must be JSON object: {path}")
    validate_id_keys(nsfw_dir / "cve_cwe.json", CVE_RE, errors)
    validate_id_keys(nsfw_dir / "cwe_capec.json", CWE_RE, errors)
    validate_id_keys(nsfw_dir / "capec_attack.json", CAPEC_RE, errors)
    validate_id_keys(nsfw_dir / "attack_defend.json", ATTACK_RE, errors)


def validate_id_keys(path: Path, pattern: re.Pattern[str], errors: list[str]) -> None:
    if not path.is_file():
        return
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return
    if not isinstance(payload, dict):
        return
    bad = [key for key in payload if not pattern.match(key)]
    if bad:
        errors.append(f"NSFW file {path.name} has unexpected keys: {bad[:5]}")


def validate_cve2capec(cve2capec_dir: Path, errors: list[str]) -> None:
    if not cve2capec_dir.is_dir():
        errors.append(f"CVE2CAPEC directory missing: {cve2capec_dir}")
        return
    database_dir = cve2capec_dir / "database"
    resources_dir = cve2capec_dir / "resources"
    results_dir = cve2capec_dir / "results"
    last_update = cve2capec_dir / "lastUpdate.txt"

    if not database_dir.is_dir():
        errors.append(f"CVE2CAPEC database directory missing: {database_dir}")
    else:
        jsonl = sorted(database_dir.glob("CVE-*.jsonl"))
        if not jsonl:
            errors.append("CVE2CAPEC database has no CVE-*.jsonl files")
        for path in jsonl:
            for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"CVE2CAPEC {path.name}:{index} not JSON: {exc}")
                    break
                if not isinstance(record, dict) or "id" not in record:
                    errors.append(f"CVE2CAPEC {path.name}:{index} missing id field")

    if not resources_dir.is_dir():
        errors.append(f"CVE2CAPEC resources directory missing: {resources_dir}")
    else:
        for name in ("cwe_db.json", "capec_db.json", "techniques_db.json", "techniques_association.json", "defend_db.jsonl"):
            path = resources_dir / name
            if not path.is_file():
                errors.append(f"CVE2CAPEC resource missing: {path}")

    if not results_dir.is_dir():
        errors.append(f"CVE2CAPEC results directory missing: {results_dir}")
    else:
        new_cves = results_dir / "new_cves.jsonl"
        if not new_cves.is_file():
            errors.append(f"CVE2CAPEC results file missing: {new_cves}")

    if not last_update.is_file():
        errors.append(f"CVE2CAPEC lastUpdate.txt missing: {last_update}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate NSFW + CVE2CAPEC canonical exports.")
    parser.add_argument("--nsfw-dir", type=Path, default=DEFAULT_NSFW_DIR)
    parser.add_argument("--cve2capec-dir", type=Path, default=DEFAULT_CVE2CAPEC_DIR)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    errors: list[str] = []
    validate_nsfw(args.nsfw_dir, errors)
    validate_cve2capec(args.cve2capec_dir, errors)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Canonical exports validated: nsfw={args.nsfw_dir} cve2capec={args.cve2capec_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
