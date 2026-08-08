#!/usr/bin/env python3
"""Fast local release invariants; remote AWS validation runs in CI."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    lock = json.loads((root / "bridgefu.lock.json").read_text())
    if lock["required_rvoip_version"] != "0.3.7":
        raise SystemExit("bridgefu.lock.json must pin rvoip 0.3.7")
    if "crates.io-index" not in lock["required_rvoip_source"]:
        raise SystemExit("rvoip source must be crates.io")
    source_templates = [root / "cloudformation" / "template.yaml"] + sorted(
        (root / "cloudformation" / "nested").glob("*.yaml")
    )
    for path in source_templates:
        text = path.read_text()
        if "VapiApiKey:" in text or "NoEcho: true" in text:
            raise SystemExit(f"raw Vapi keys are forbidden in CloudFormation: {path}")
        if re.search(r"(?i)(secret|token).*(output|value):", text):
            raise SystemExit(f"possible secret output in {path}")
    with (
        tempfile.TemporaryDirectory() as first,
        tempfile.TemporaryDirectory() as second,
    ):
        for destination in (first, second):
            subprocess.run(
                [
                    sys.executable,
                    str(root / "release" / "build_lambdas.py"),
                    "--output",
                    destination,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
        comparison = subprocess.run(["diff", "-r", first, second], check=False)
        if comparison.returncode:
            raise SystemExit("Lambda packaging is not deterministic")
    if (
        subprocess.run(
            ["sh", "-c", "command -v cfn-lint >/dev/null"], check=False
        ).returncode
        == 0
    ):
        with tempfile.TemporaryDirectory() as release:
            subprocess.run(
                [
                    sys.executable,
                    str(root / "release" / "build_release.py"),
                    "--version",
                    "0.1.0-validation",
                    "--output",
                    release,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            rendered = [Path(release) / "cloudformation" / "template.yaml"] + sorted(
                (Path(release) / "cloudformation" / "nested").glob("*.yaml")
            )
            subprocess.run(
                [
                    "cfn-lint",
                    *map(str, rendered),
                    *map(str, sorted((root / "publisher").glob("*.yaml"))),
                ],
                check=True,
            )
    print("local release validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
