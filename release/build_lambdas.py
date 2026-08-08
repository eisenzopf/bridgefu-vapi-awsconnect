#!/usr/bin/env python3
"""Build deterministic, dependency-free Lambda ZIP files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import zipfile
from pathlib import Path

HANDLERS = (
    "configuration",
    "prepare_handoff",
    "transfer_destination",
    "connect_lookup",
    "vapi_provisioner",
)
COMMON = (
    "aws_runtime.py",
    "bridgefu_handoff.py",
    "screen_pop.py",
    "vapi_provisioning.py",
)
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def build(root: Path, output: Path) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    artifacts = {}
    for handler in HANDLERS:
        inputs = [(name, root / "lambda" / "common" / name) for name in COMMON]
        inputs.append(("handler.py", root / "lambda" / handler / "handler.py"))
        if handler == "vapi_provisioner":
            inputs.extend(
                (f"assets/vapi/{path.name}", path)
                for path in sorted((root / "vapi").glob("*.json.tmpl"))
            )
        missing = [str(path) for _name, path in inputs if not path.is_file()]
        if missing:
            raise SystemExit("missing Lambda inputs: " + ", ".join(missing))
        destination = output / f"{handler}.zip"
        with zipfile.ZipFile(destination, "w", allowZip64=False) as archive:
            for name, path in sorted(inputs):
                archive.writestr(zip_info(name), path.read_bytes())
        payload = destination.read_bytes()
        artifacts[handler] = {
            "path": destination.name,
            "handler": "handler.lambda_handler",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        }
    manifest = {
        "schema": "bridgefu-vapi-awsconnect-lambdas/v1",
        "artifacts": artifacts,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("target/lambda"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output if args.output.is_absolute() else root / args.output
    build(root, output)
    print(os.fspath(output / "manifest.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
