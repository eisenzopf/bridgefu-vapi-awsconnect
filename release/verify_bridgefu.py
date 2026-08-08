#!/usr/bin/env python3
"""Verify the pinned Bridgefu checkout and crates.io rvoip graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tomllib
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    lock = json.loads((root / "bridgefu.lock.json").read_text())
    source = args.source.resolve()
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=source, text=True
    ).strip()
    if commit != lock["commit"]:
        raise SystemExit(f"Bridgefu commit mismatch: {commit}")
    payload = (source / "Cargo.lock").read_bytes()
    if hashlib.sha256(payload).hexdigest() != lock["cargo_lock_sha256"]:
        raise SystemExit("Bridgefu Cargo.lock digest mismatch")
    cargo = tomllib.loads(payload.decode())
    packages = [item for item in cargo["package"] if item["name"].startswith("rvoip")]
    if not packages:
        raise SystemExit("Bridgefu lock contains no rvoip packages")
    for package in packages:
        if package["version"] != lock["required_rvoip_version"]:
            raise SystemExit(f"unexpected rvoip version: {package['name']}")
        if package.get("source") != lock["required_rvoip_source"]:
            raise SystemExit(f"non-crates.io rvoip source: {package['name']}")
    print(f"verified {len(packages)} crates.io rvoip 0.3.7 packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
