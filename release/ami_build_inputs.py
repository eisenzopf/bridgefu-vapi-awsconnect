#!/usr/bin/env python3
"""Validate immutable AMI build inputs and the exact AWS source image."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SCHEMA = "bridgefu-ami-build-inputs/v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
AMI = re.compile(r"^ami-[0-9a-f]{17}$")
ACCOUNT = re.compile(r"^[0-9]{12}$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)+(?:b[0-9]+)?$")
FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
HTTPS = re.compile(r"^https://amazoncloudwatch-agent\.s3\.amazonaws\.com/")


class BuildInputError(ValueError):
    """An AMI build input is mutable, malformed, or no longer available."""


def _exact_keys(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise BuildInputError(f"{label} has an invalid shape")
    return value


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildInputError("AMI build inputs are unreadable") from error
    root = _exact_keys(
        value,
        {"schema", "packer", "source_ami", "builder", "cloudwatch_agent"},
        "root",
    )
    if root["schema"] != SCHEMA:
        raise BuildInputError("AMI build input schema is invalid")
    packer = _exact_keys(
        root["packer"],
        {"core_version", "amazon_plugin_version", "amazon_plugin_zip_sha256"},
        "Packer input",
    )
    plugin_hashes = _exact_keys(
        packer["amazon_plugin_zip_sha256"],
        {"darwin_arm64", "linux_amd64", "linux_arm64"},
        "Packer plugin hashes",
    )
    if packer["core_version"] != "1.12.0" or packer["amazon_plugin_version"] != "1.3.9":
        raise BuildInputError("Packer versions changed without review")
    if any(
        not isinstance(digest, str) or not SHA256.fullmatch(digest)
        for digest in plugin_hashes.values()
    ):
        raise BuildInputError("Packer plugin hash is invalid")
    source = _exact_keys(
        root["source_ami"],
        {"architecture", "id", "name", "owner_id", "region"},
        "source AMI",
    )
    if (
        source["architecture"] != "arm64"
        or not isinstance(source["id"], str)
        or not AMI.fullmatch(source["id"])
        or not isinstance(source["owner_id"], str)
        or not ACCOUNT.fullmatch(source["owner_id"])
        or source["region"] != "us-west-2"
        or not isinstance(source["name"], str)
        or not re.fullmatch(
            r"al2023-ami-2023\.[0-9]{1,2}\.[0-9]{8}\.[0-9]+-kernel-6\.1-arm64",
            source["name"],
        )
    ):
        raise BuildInputError("source AMI identity is invalid")
    builder = _exact_keys(
        root["builder"],
        {"instance_type", "vcpu_count", "cargo_jobs"},
        "AMI builder",
    )
    if builder != {
        "instance_type": "m7g.4xlarge",
        "vcpu_count": 16,
        "cargo_jobs": 8,
    }:
        raise BuildInputError("AMI builder capacity changed without review")
    agent = _exact_keys(
        root["cloudwatch_agent"],
        {
            "version",
            "package_url",
            "package_sha256",
            "signature_url",
            "signature_sha256",
            "key_url",
            "gpg_material_sha256",
            "gpg_fingerprint",
        },
        "CloudWatch Agent input",
    )
    if not isinstance(agent["version"], str) or not VERSION.fullmatch(agent["version"]):
        raise BuildInputError("CloudWatch Agent version is invalid")
    version_path = f"/arm64/{agent['version']}/"
    for name in ("package_url", "signature_url", "key_url"):
        item = agent[name]
        if not isinstance(item, str) or not HTTPS.match(item) or "/latest/" in item:
            raise BuildInputError("CloudWatch Agent URL is not immutable")
    if (
        version_path not in agent["package_url"]
        or version_path not in agent["signature_url"]
    ):
        raise BuildInputError("CloudWatch Agent package URL is not version-bound")
    if (
        any(
            not isinstance(agent[name], str) or not SHA256.fullmatch(agent[name])
            for name in (
                "package_sha256",
                "signature_sha256",
                "gpg_material_sha256",
            )
        )
        or not isinstance(agent["gpg_fingerprint"], str)
        or not FINGERPRINT.fullmatch(agent["gpg_fingerprint"])
    ):
        raise BuildInputError("CloudWatch Agent verification input is invalid")
    return json.loads(json.dumps(value, separators=(",", ":"), sort_keys=True))


def verify_source_ami(value: Mapping[str, Any]) -> None:
    source = value["source_ami"]
    result = subprocess.run(
        [
            "aws",
            "ec2",
            "describe-images",
            "--region",
            source["region"],
            "--image-ids",
            source["id"],
            "--output",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise BuildInputError("source AMI lookup failed")
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise BuildInputError("source AMI lookup returned invalid data") from error
    images = response.get("Images") if isinstance(response, Mapping) else None
    if not isinstance(images, list) or len(images) != 1:
        raise BuildInputError("source AMI is not uniquely available")
    image = images[0]
    expected = {
        "ImageId": source["id"],
        "OwnerId": source["owner_id"],
        "Name": source["name"],
        "Architecture": source["architecture"],
        "State": "available",
        "RootDeviceType": "ebs",
        "VirtualizationType": "hvm",
    }
    if not isinstance(image, Mapping) or any(
        image.get(key) != item for key, item in expected.items()
    ):
        raise BuildInputError("source AMI no longer matches the reviewed identity")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--verify-source-ami", action="store_true")
    args = parser.parse_args()
    try:
        value = load(args.inputs)
        if args.verify_source_ami:
            verify_source_ami(value)
    except BuildInputError as error:
        print(f"AMI build input verification failed: {error}")
        return 1
    print(
        json.dumps(
            {
                "schema_version": 1,
                "producer": "bridgefu-ami-build-input-verifier@1",
                "source_ami_id": value["source_ami"]["id"],
                "verified": True,
                "redacted": True,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
