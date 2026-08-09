#!/usr/bin/env python3
"""Assemble an immutable regional CloudFormation release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
import urllib.parse
from pathlib import Path

from build_lambdas import build as build_lambdas

VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$")
AMI = re.compile(r"^ami-[0-9a-f]{17}$")
OUTPUT_MARKER = ".bridgefu-vapi-awsconnect-release"


def token_for(region: str) -> str:
    return region.upper().replace("-", "_")


def load_region_release(root: Path, path: Path | None) -> dict[str, dict[str, str]]:
    catalog = json.loads((root / "release" / "regions.json").read_text())
    supported = [item["code"] for item in catalog["regions"]]
    if path is None:
        return {
            region: {
                "ami_id": "ami-00000000000000000",
                "bucket": f"bridgefu-vapi-awsconnect-{region}",
            }
            for region in supported
        }
    supplied = json.loads(path.read_text())
    if set(supplied) != set(supported):
        raise SystemExit(
            "--regions-file must contain exactly the regions in release/regions.json"
        )
    for region, release in supplied.items():
        if not AMI.fullmatch(release.get("ami_id", "")):
            raise SystemExit(f"invalid immutable AMI ID for {region}")
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", release.get("bucket", "")):
            raise SystemExit(f"invalid artifact bucket for {region}")
    return supplied


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def render(source: Path, destination: Path, replacements: dict[str, str]) -> None:
    text = source.read_text()
    for key, value in replacements.items():
        text = text.replace(f"__{key}__", value)
    unresolved = sorted(set(re.findall(r"__[A-Z0-9_]+__", text)))
    if unresolved:
        raise SystemExit(f"unresolved release tokens in {source}: {unresolved}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, default=Path("target/release"))
    parser.add_argument("--regions-file", type=Path)
    parser.add_argument(
        "--public-base-url",
        default="https://bridgefu-vapi-awsconnect.s3.amazonaws.com",
    )
    args = parser.parse_args()
    if not VERSION.fullmatch(args.version):
        raise SystemExit("invalid --version")

    root = Path(__file__).resolve().parents[1]
    region_release = load_region_release(root, args.regions_file)
    output = args.output if args.output.is_absolute() else root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        lambda_output = staging / "artifacts" / "lambda"
        build_lambdas(root, lambda_output)
        replacements = {
            "RELEASE_VERSION": args.version,
            "NESTED_TEMPLATE_BASE_URL": (
                f"{args.public_base_url.rstrip('/')}/releases/{args.version}/cloudformation"
            ),
            "QUALIFICATION_TEMPLATE_BASE_URL": (
                f"{args.public_base_url.rstrip('/')}/releases/{args.version}/"
                "qualification/cloudformation"
            ),
            "PRODUCT_TEMPLATE_URL": (
                f"{args.public_base_url.rstrip('/')}/releases/{args.version}/"
                "cloudformation/template.yaml"
            ),
        }
        for region, release in region_release.items():
            token = token_for(region)
            replacements[f"AMI_{token}"] = release["ami_id"]
            replacements[f"ARTIFACT_BUCKET_{token}"] = release["bucket"]
        render(
            root / "cloudformation" / "template.yaml",
            staging / "cloudformation" / "template.yaml",
            replacements,
        )
        for source in sorted((root / "cloudformation" / "nested").glob("*.yaml")):
            render(
                source,
                staging / "cloudformation" / "nested" / source.name,
                replacements,
            )
        for source in sorted(
            (root / "qualification" / "cloudformation").glob("*.yaml")
        ):
            render(
                source,
                staging / "qualification" / "cloudformation" / source.name,
                replacements,
            )
        shutil.copyfile(root / "bridgefu.lock.json", staging / "bridgefu.lock.json")
        template_url = (
            f"{args.public_base_url.rstrip('/')}/releases/{args.version}/"
            "cloudformation/template.yaml"
        )
        query = urllib.parse.urlencode(
            {
                "templateURL": template_url,
                "stackName": "bridgefu-vapi-connect",
                "param_DeploymentId": "support",
                "param_InstanceType": "t4g.large",
            }
        )
        quick_create = {
            "launch": (
                "https://console.aws.amazon.com/cloudformation/home"
                f"#/stacks/create/review?{query}"
            )
        }
        (staging / "quick-create-links.json").write_text(
            json.dumps(quick_create, indent=2, sort_keys=True) + "\n"
        )
        inventory = []
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                inventory.append(
                    {
                        "path": path.relative_to(staging).as_posix(),
                        "sha256": digest(path),
                        "size_bytes": path.stat().st_size,
                    }
                )
        lock = json.loads((root / "bridgefu.lock.json").read_text())
        manifest = {
            "schema": "bridgefu-vapi-awsconnect-release/v1",
            "version": args.version,
            "supported_regions": region_release,
            "bridgefu": lock,
            "artifacts": inventory,
            "contains_secrets": False,
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        (staging / OUTPUT_MARKER).write_text("generated release output\n")
        if output.exists():
            if not output.is_dir():
                raise SystemExit(f"release output is not a directory: {output}")
            entries = list(output.iterdir())
            if entries and not (output / OUTPUT_MARKER).is_file():
                raise SystemExit(
                    f"refusing to replace unowned non-empty release output: {output}"
                )
            if entries:
                shutil.rmtree(output)
            else:
                output.rmdir()
        staging.replace(output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    print(os.fspath(output / "manifest.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
